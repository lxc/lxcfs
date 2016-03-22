/* lxcfs
 *
 * Copyright © 2014-2016 Canonical, Inc
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
 *
 * See COPYING file for details.
 */

#define FUSE_USE_VERSION 26

#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>
#include <fuse.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <sched.h>
#include <pthread.h>
#include <linux/sched.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/epoll.h>
#include <wait.h>

#include "bindings.h"

#include "config.h" // for VERSION

enum {
	LXC_TYPE_CGDIR,
	LXC_TYPE_CGFILE,
	LXC_TYPE_PROC_MEMINFO,
	LXC_TYPE_PROC_CPUINFO,
	LXC_TYPE_PROC_UPTIME,
	LXC_TYPE_PROC_STAT,
	LXC_TYPE_PROC_DISKSTATS,
	LXC_TYPE_PROC_SWAPS,
};

struct file_info {
	char *controller;
	char *cgroup;
	char *file;
	int type;
	char *buf;  // unused as of yet
	int buflen;
	int size; //actual data size
	int cached;
};

/* reserve buffer size, for cpuall in /proc/stat */
#define BUF_RESERVE_SIZE 256

/*
 * A table caching which pid is init for a pid namespace.
 * When looking up which pid is init for $qpid, we first
 * 1. Stat /proc/$qpid/ns/pid.
 * 2. Check whether the ino_t is in our store.
 *   a. if not, fork a child in qpid's ns to send us
 *	 ucred.pid = 1, and read the initpid.  Cache
 *	 initpid and creation time for /proc/initpid
 *	 in a new store entry.
 *   b. if so, verify that /proc/initpid still matches
 *	 what we have saved.  If not, clear the store
 *	 entry and go back to a.  If so, return the
 *	 cached initpid.
 */
struct pidns_init_store {
	ino_t ino;          // inode number for /proc/$pid/ns/pid
	pid_t initpid;      // the pid of nit in that ns
	long int ctime;     // the time at which /proc/$initpid was created
	struct pidns_init_store *next;
	long int lastcheck;
};

/* lol - look at how they are allocated in the kernel */
#define PIDNS_HASH_SIZE 4096
#define HASH(x) ((x) % PIDNS_HASH_SIZE)

static struct pidns_init_store *pidns_hash_table[PIDNS_HASH_SIZE];
static pthread_mutex_t pidns_store_mutex = PTHREAD_MUTEX_INITIALIZER;
static void lock_mutex(pthread_mutex_t *l)
{
	int ret;

	if ((ret = pthread_mutex_lock(l)) != 0) {
		fprintf(stderr, "pthread_mutex_lock returned:%d %s\n", ret, strerror(ret));
		exit(1);
	}
}

static void unlock_mutex(pthread_mutex_t *l)
{
	int ret;

	if ((ret = pthread_mutex_unlock(l)) != 0) {
		fprintf(stderr, "pthread_mutex_unlock returned:%d %s\n", ret, strerror(ret));
		exit(1);
	}
}

static void store_lock(void)
{
	lock_mutex(&pidns_store_mutex);
}

static void store_unlock(void)
{
	unlock_mutex(&pidns_store_mutex);
}

/* Must be called under store_lock */
static bool initpid_still_valid(struct pidns_init_store *e, struct stat *nsfdsb)
{
	struct stat initsb;
	char fnam[100];

	snprintf(fnam, 100, "/proc/%d", e->initpid);
	if (stat(fnam, &initsb) < 0)
		return false;
#if DEBUG
	fprintf(stderr, "comparing ctime %ld %ld for pid %d\n",
		e->ctime, initsb.st_ctime, e->initpid);
#endif
	if (e->ctime != initsb.st_ctime)
		return false;
	return true;
}

/* Must be called under store_lock */
static void remove_initpid(struct pidns_init_store *e)
{
	struct pidns_init_store *tmp;
	int h;

#if DEBUG
	fprintf(stderr, "remove_initpid: removing entry for %d\n", e->initpid);
#endif
	h = HASH(e->ino);
	if (pidns_hash_table[h] == e) {
		pidns_hash_table[h] = e->next;
		free(e);
		return;
	}

	tmp = pidns_hash_table[h];
	while (tmp) {
		if (tmp->next == e) {
			tmp->next = e->next;
			free(e);
			return;
		}
		tmp = tmp->next;
	}
}

#define PURGE_SECS 5
/* Must be called under store_lock */
static void prune_initpid_store(void)
{
	static long int last_prune = 0;
	struct pidns_init_store *e, *prev, *delme;
	long int now, threshold;
	int i;

	if (!last_prune) {
		last_prune = time(NULL);
		return;
	}
	now = time(NULL);
	if (now < last_prune + PURGE_SECS)
		return;
#if DEBUG
	fprintf(stderr, "pruning\n");
#endif
	last_prune = now;
	threshold = now - 2 * PURGE_SECS;

	for (i = 0; i < PIDNS_HASH_SIZE; i++) {
		for (prev = NULL, e = pidns_hash_table[i]; e; ) {
			if (e->lastcheck < threshold) {
#if DEBUG
				fprintf(stderr, "Removing cached entry for %d\n", e->initpid);
#endif
				delme = e;
				if (prev)
					prev->next = e->next;
				else
					pidns_hash_table[i] = e->next;
				e = e->next;
				free(delme);
			} else {
				prev = e;
				e = e->next;
			}
		}
	}
}

/* Must be called under store_lock */
static void save_initpid(struct stat *sb, pid_t pid)
{
	struct pidns_init_store *e;
	char fpath[100];
	struct stat procsb;
	int h;

#if DEBUG
	fprintf(stderr, "save_initpid: adding entry for %d\n", pid);
#endif
	snprintf(fpath, 100, "/proc/%d", pid);
	if (stat(fpath, &procsb) < 0)
		return;
	do {
		e = malloc(sizeof(*e));
	} while (!e);
	e->ino = sb->st_ino;
	e->initpid = pid;
	e->ctime = procsb.st_ctime;
	h = HASH(e->ino);
	e->next = pidns_hash_table[h];
	e->lastcheck = time(NULL);
	pidns_hash_table[h] = e;
}

/*
 * Given the stat(2) info for a nsfd pid inode, lookup the init_pid_store
 * entry for the inode number and creation time.  Verify that the init pid
 * is still valid.  If not, remove it.  Return the entry if valid, NULL
 * otherwise.
 * Must be called under store_lock
 */
static struct pidns_init_store *lookup_verify_initpid(struct stat *sb)
{
	int h = HASH(sb->st_ino);
	struct pidns_init_store *e = pidns_hash_table[h];

	while (e) {
		if (e->ino == sb->st_ino) {
			if (initpid_still_valid(e, sb)) {
				e->lastcheck = time(NULL);
				return e;
			}
			remove_initpid(e);
			return NULL;
		}
		e = e->next;
	}

	return NULL;
}

static int is_dir(const char *path)
{
	struct stat statbuf;
	int ret = stat(path, &statbuf);
	if (ret == 0 && S_ISDIR(statbuf.st_mode))
		return 1;
	return 0;
}

static char *must_copy_string(const char *str)
{
	char *dup = NULL;
	if (!str)
		return NULL;
	do {
		dup = strdup(str);
	} while (!dup);

	return dup;
}

static inline void drop_trailing_newlines(char *s)
{
	int l;

	for (l=strlen(s); l>0 && s[l-1] == '\n'; l--)
		s[l-1] = '\0';
}

#define BATCH_SIZE 50
static void dorealloc(char **mem, size_t oldlen, size_t newlen)
{
	int newbatches = (newlen / BATCH_SIZE) + 1;
	int oldbatches = (oldlen / BATCH_SIZE) + 1;

	if (!*mem || newbatches > oldbatches) {
		char *tmp;
		do {
			tmp = realloc(*mem, newbatches * BATCH_SIZE);
		} while (!tmp);
		*mem = tmp;
	}
}
static void append_line(char **contents, size_t *len, char *line, ssize_t linelen)
{
	size_t newlen = *len + linelen;
	dorealloc(contents, *len, newlen + 1);
	memcpy(*contents + *len, line, linelen+1);
	*len = newlen;
}

static char *slurp_file(const char *from)
{
	char *line = NULL;
	char *contents = NULL;
	FILE *f = fopen(from, "r");
	size_t len = 0, fulllen = 0;
	ssize_t linelen;

	if (!f)
		return NULL;

	while ((linelen = getline(&line, &len, f)) != -1) {
		append_line(&contents, &fulllen, line, linelen);
	}
	fclose(f);

	if (contents)
		drop_trailing_newlines(contents);
	free(line);
	return contents;
}

static bool write_string(const char *fnam, const char *string)
{
	FILE *f;
	size_t len, ret;

	if (!(f = fopen(fnam, "w")))
		return false;
	len = strlen(string);
	ret = fwrite(string, 1, len, f);
	if (ret != len) {
		fprintf(stderr, "Error writing to file: %s\n", strerror(errno));
		fclose(f);
		return false;
	}
	if (fclose(f) < 0) {
		fprintf(stderr, "Error writing to file: %s\n", strerror(errno));
		return false;
	}
	return true;
}

/*
 * hierarchies, i.e. 'cpu,cpuacct'
 */
char **hierarchies;
int num_hierarchies;

struct cgfs_files {
	char *name;
	uint32_t uid, gid;
	uint32_t mode;
};

#define ALLOC_NUM 20
static bool store_hierarchy(char *stridx, char *h)
{
	if (num_hierarchies % ALLOC_NUM == 0) {
		size_t n = (num_hierarchies / ALLOC_NUM) + 1;
		n *= ALLOC_NUM;
		char **tmp = realloc(hierarchies, n * sizeof(char *));
		if (!tmp) {
			fprintf(stderr, "Out of memory\n");
			exit(1);
		}
		hierarchies = tmp;
	}
	
	hierarchies[num_hierarchies++] = must_copy_string(h);
	return true;
}

static void print_subsystems(void)
{
	int i;

	fprintf(stderr, "hierarchies:");
	for (i = 0; i < num_hierarchies; i++) {
		if (hierarchies[i])
			fprintf(stderr, " %d: %s\n", i, hierarchies[i]);
	}
}

static bool in_comma_list(const char *needle, const char *haystack)
{
	const char *s = haystack, *e;
	size_t nlen = strlen(needle);

	while (*s && (e = index(s, ','))) {
		if (nlen != e - s) {
			s = e + 1;
			continue;
		}
		if (strncmp(needle, s, nlen) == 0)
			return true;
		s = e + 1;
	}
	if (strcmp(needle, s) == 0)
		return true;
	return false;
}

/* do we need to do any massaging here?  I'm not sure... */
static char *find_mounted_controller(const char *controller)
{
	int i;

	for (i = 0; i < num_hierarchies; i++) {
		if (!hierarchies[i])
			continue;
		if (strcmp(hierarchies[i], controller) == 0)
			return hierarchies[i];
		if (in_comma_list(controller, hierarchies[i]))
			return hierarchies[i];
	}

	return NULL;
}

bool cgfs_set_value(const char *controller, const char *cgroup, const char *file,
		const char *value)
{
	size_t len;
	char *fnam, *tmpc = find_mounted_controller(controller);

	if (!tmpc)
		return false;
	/* basedir / tmpc / cgroup / file \0 */
	len = strlen(basedir) + strlen(tmpc) + strlen(cgroup) + strlen(file) + 4;
	fnam = alloca(len);
	snprintf(fnam, len, "%s/%s/%s/%s", basedir, tmpc, cgroup, file);
	
	return write_string(fnam, value);
}

// Chown all the files in the cgroup directory.  We do this when we create
// a cgroup on behalf of a user.
static void chown_all_cgroup_files(const char *dirname, uid_t uid, gid_t gid)
{
	struct dirent dirent, *direntp;
	char path[MAXPATHLEN];
	size_t len;
	DIR *d;
	int ret;

	len = strlen(dirname);
	if (len >= MAXPATHLEN) {
		fprintf(stderr, "chown_all_cgroup_files: pathname too long: %s\n", dirname);
		return;
	}

	d = opendir(dirname);
	if (!d) {
		fprintf(stderr, "chown_all_cgroup_files: failed to open %s\n", dirname);
		return;
	}

	while (readdir_r(d, &dirent, &direntp) == 0 && direntp) {
		if (!strcmp(direntp->d_name, ".") || !strcmp(direntp->d_name, ".."))
			continue;
		ret = snprintf(path, MAXPATHLEN, "%s/%s", dirname, direntp->d_name);
		if (ret < 0 || ret >= MAXPATHLEN) {
			fprintf(stderr, "chown_all_cgroup_files: pathname too long under %s\n", dirname);
			continue;
		}
		if (chown(path, uid, gid) < 0)
			fprintf(stderr, "Failed to chown file %s to %u:%u", path, uid, gid);
	}
	closedir(d);
}

int cgfs_create(const char *controller, const char *cg, uid_t uid, gid_t gid)
{
	size_t len;
	char *dirnam, *tmpc = find_mounted_controller(controller);

	if (!tmpc)
		return -EINVAL;
	/* basedir / tmpc / cg \0 */
	len = strlen(basedir) + strlen(tmpc) + strlen(cg) + 3;
	dirnam = alloca(len);
	snprintf(dirnam, len, "%s/%s/%s", basedir,tmpc, cg);

	if (mkdir(dirnam, 0755) < 0)
		return -errno;

	if (uid == 0 && gid == 0)
		return 0;

	if (chown(dirnam, uid, gid) < 0)
		return -errno;

	chown_all_cgroup_files(dirnam, uid, gid);

	return 0;
}

static bool recursive_rmdir(const char *dirname)
{
	struct dirent dirent, *direntp;
	DIR *dir;
	bool ret = false;
	char pathname[MAXPATHLEN];

	dir = opendir(dirname);
	if (!dir) {
#if DEBUG
		fprintf(stderr, "%s: failed to open %s: %s\n", __func__, dirname, strerror(errno));
#endif
		return false;
	}

	while (!readdir_r(dir, &dirent, &direntp)) {
		struct stat mystat;
		int rc;

		if (!direntp)
			break;

		if (!strcmp(direntp->d_name, ".") ||
		    !strcmp(direntp->d_name, ".."))
			continue;

		rc = snprintf(pathname, MAXPATHLEN, "%s/%s", dirname, direntp->d_name);
		if (rc < 0 || rc >= MAXPATHLEN) {
			fprintf(stderr, "pathname too long\n");
			continue;
		}

		ret = lstat(pathname, &mystat);
		if (ret) {
#if DEBUG
			fprintf(stderr, "%s: failed to stat %s: %s\n", __func__, pathname, strerror(errno));
#endif
			continue;
		}
		if (S_ISDIR(mystat.st_mode)) {
			if (!recursive_rmdir(pathname)) {
#if DEBUG
				fprintf(stderr, "Error removing %s\n", pathname);
#endif
			}
		}
	}

	ret = true;
	if (closedir(dir) < 0) {
		fprintf(stderr, "%s: failed to close directory %s: %s\n", __func__, dirname, strerror(errno));
		ret = false;
	}

	if (rmdir(dirname) < 0) {
#if DEBUG
		fprintf(stderr, "%s: failed to delete %s: %s\n", __func__, dirname, strerror(errno));
#endif
		ret = false;
	}

	return ret;
}

bool cgfs_remove(const char *controller, const char *cg)
{
	size_t len;
	char *dirnam, *tmpc = find_mounted_controller(controller);

	if (!tmpc)
		return false;
	/* basedir / tmpc / cg \0 */
	len = strlen(basedir) + strlen(tmpc) + strlen(cg) + 3;
	dirnam = alloca(len);
	snprintf(dirnam, len, "%s/%s/%s", basedir,tmpc, cg);
	return recursive_rmdir(dirnam);
}

bool cgfs_chmod_file(const char *controller, const char *file, mode_t mode)
{
	size_t len;
	char *pathname, *tmpc = find_mounted_controller(controller);

	if (!tmpc)
		return false;
	/* basedir / tmpc / file \0 */
	len = strlen(basedir) + strlen(tmpc) + strlen(file) + 3;
	pathname = alloca(len);
	snprintf(pathname, len, "%s/%s/%s", basedir, tmpc, file);
	if (chmod(pathname, mode) < 0)
		return false;
	return true;
}

static int chown_tasks_files(const char *dirname, uid_t uid, gid_t gid)
{
	size_t len;
	char *fname;

	len = strlen(dirname) + strlen("/cgroup.procs") + 1;
	fname = alloca(len);
	snprintf(fname, len, "%s/tasks", dirname);
	if (chown(fname, uid, gid) != 0)
		return -errno;
	snprintf(fname, len, "%s/cgroup.procs", dirname);
	if (chown(fname, uid, gid) != 0)
		return -errno;
	return 0;
}

int cgfs_chown_file(const char *controller, const char *file, uid_t uid, gid_t gid)
{
	size_t len;
	char *pathname, *tmpc = find_mounted_controller(controller);

	if (!tmpc)
		return -EINVAL;
	/* basedir / tmpc / file \0 */
	len = strlen(basedir) + strlen(tmpc) + strlen(file) + 3;
	pathname = alloca(len);
	snprintf(pathname, len, "%s/%s/%s", basedir, tmpc, file);
	if (chown(pathname, uid, gid) < 0)
		return -errno;

	if (is_dir(pathname))
		// like cgmanager did, we want to chown the tasks file as well
		return chown_tasks_files(pathname, uid, gid);

	return 0;
}

FILE *open_pids_file(const char *controller, const char *cgroup)
{
	size_t len;
	char *pathname, *tmpc = find_mounted_controller(controller);

	if (!tmpc)
		return NULL;
	/* basedir / tmpc / cgroup / "cgroup.procs" \0 */
	len = strlen(basedir) + strlen(tmpc) + strlen(cgroup) + 4 + strlen("cgroup.procs");
	pathname = alloca(len);
	snprintf(pathname, len, "%s/%s/%s/cgroup.procs", basedir, tmpc, cgroup);
	return fopen(pathname, "w");
}

static bool cgfs_iterate_cgroup(const char *controller, const char *cgroup, bool directories,
                                void ***list, size_t typesize,
                                void* (*iterator)(const char*, const char*, const char*))
{
	size_t len;
	char *dirname, *tmpc = find_mounted_controller(controller);
	char pathname[MAXPATHLEN];
	size_t sz = 0, asz = 0;
	struct dirent dirent, *direntp;
	DIR *dir;
	int ret;

	*list = NULL;
	if (!tmpc)
		return false;

	/* basedir / tmpc / cgroup \0 */
	len = strlen(basedir) + strlen(tmpc) + strlen(cgroup) + 3;
	dirname = alloca(len);
	snprintf(dirname, len, "%s/%s/%s", basedir, tmpc, cgroup);

	dir = opendir(dirname);
	if (!dir)
		return false;

	while (!readdir_r(dir, &dirent, &direntp)) {
		struct stat mystat;
		int rc;

		if (!direntp)
			break;

		if (!strcmp(direntp->d_name, ".") ||
		    !strcmp(direntp->d_name, ".."))
			continue;

		rc = snprintf(pathname, MAXPATHLEN, "%s/%s", dirname, direntp->d_name);
		if (rc < 0 || rc >= MAXPATHLEN) {
			fprintf(stderr, "%s: pathname too long under %s\n", __func__, dirname);
			continue;
		}

		ret = lstat(pathname, &mystat);
		if (ret) {
			fprintf(stderr, "%s: failed to stat %s: %s\n", __func__, pathname, strerror(errno));
			continue;
		}
		if ((!directories && !S_ISREG(mystat.st_mode)) ||
		    (directories && !S_ISDIR(mystat.st_mode)))
			continue;

		if (sz+2 >= asz) {
			void **tmp;
			asz += BATCH_SIZE;
			do {
				tmp = realloc(*list, asz * typesize);
			} while  (!tmp);
			*list = tmp;
		}
		(*list)[sz] = (*iterator)(controller, cgroup, direntp->d_name);
		(*list)[sz+1] = NULL;
		sz++;
	}
	if (closedir(dir) < 0) {
		fprintf(stderr, "%s: failed closedir for %s: %s\n", __func__, dirname, strerror(errno));
		return false;
	}
	return true;
}

static void *make_children_list_entry(const char *controller, const char *cgroup, const char *dir_entry)
{
	char *dup;
	do {
		dup = strdup(dir_entry);
	} while (!dup);
	return dup;
}

bool cgfs_list_children(const char *controller, const char *cgroup, char ***list)
{
	return cgfs_iterate_cgroup(controller, cgroup, true, (void***)list, sizeof(*list), &make_children_list_entry);
}

void free_key(struct cgfs_files *k)
{
	if (!k)
		return;
	free(k->name);
	free(k);
}

void free_keys(struct cgfs_files **keys)
{
	int i;

	if (!keys)
		return;
	for (i = 0; keys[i]; i++) {
		free_key(keys[i]);
	}
	free(keys);
}

bool cgfs_get_value(const char *controller, const char *cgroup, const char *file, char **value)
{
	size_t len;
	char *fnam, *tmpc = find_mounted_controller(controller);

	if (!tmpc)
		return false;
	/* basedir / tmpc / cgroup / file \0 */
	len = strlen(basedir) + strlen(tmpc) + strlen(cgroup) + strlen(file) + 4;
	fnam = alloca(len);
	snprintf(fnam, len, "%s/%s/%s/%s", basedir, tmpc, cgroup, file);

	*value = slurp_file(fnam);
	return *value != NULL;
}

struct cgfs_files *cgfs_get_key(const char *controller, const char *cgroup, const char *file)
{
	size_t len;
	char *fnam, *tmpc = find_mounted_controller(controller);
	struct stat sb;
	struct cgfs_files *newkey;
	int ret;

	if (!tmpc)
		return false;

	if (file && *file == '/')
		file++;

	if (file && index(file, '/'))
		return NULL;

	/* basedir / tmpc / cgroup / file \0 */
	len = strlen(basedir) + strlen(tmpc) + strlen(cgroup) + 3;
	if (file)
		len += strlen(file) + 1;
	fnam = alloca(len);
	snprintf(fnam, len, "%s/%s/%s%s%s", basedir, tmpc, cgroup,
		file ? "/" : "", file ? file : "");

	ret = stat(fnam, &sb);
	if (ret < 0)
		return NULL;

	do {
		newkey = malloc(sizeof(struct cgfs_files));
	} while (!newkey);
	if (file)
		newkey->name = must_copy_string(file);
	else if (rindex(cgroup, '/'))
		newkey->name = must_copy_string(rindex(cgroup, '/'));
	else
		newkey->name = must_copy_string(cgroup);
	newkey->uid = sb.st_uid;
	newkey->gid = sb.st_gid;
	newkey->mode = sb.st_mode;

	return newkey;
}

static void *make_key_list_entry(const char *controller, const char *cgroup, const char *dir_entry)
{
	struct cgfs_files *entry = cgfs_get_key(controller, cgroup, dir_entry);
	if (!entry) {
		fprintf(stderr, "%s: Error getting files under %s:%s\n",
			__func__, controller, cgroup);
	}
	return entry;
}

bool cgfs_list_keys(const char *controller, const char *cgroup, struct cgfs_files ***keys)
{
	return cgfs_iterate_cgroup(controller, cgroup, false, (void***)keys, sizeof(*keys), &make_key_list_entry);
}

bool is_child_cgroup(const char *controller, const char *cgroup, const char *f)
{      size_t len;
	char *fnam, *tmpc = find_mounted_controller(controller);
	int ret;
	struct stat sb;

	if (!tmpc)
		return false;
	/* basedir / tmpc / cgroup / f \0 */
	len = strlen(basedir) + strlen(tmpc) + strlen(cgroup) + strlen(f) + 4;
	fnam = alloca(len);
	snprintf(fnam, len, "%s/%s/%s/%s", basedir, tmpc, cgroup, f);

	ret = stat(fnam, &sb);
	if (ret < 0 || !S_ISDIR(sb.st_mode))
		return false;
	return true;
}

#define SEND_CREDS_OK 0
#define SEND_CREDS_NOTSK 1
#define SEND_CREDS_FAIL 2
static bool recv_creds(int sock, struct ucred *cred, char *v);
static int wait_for_pid(pid_t pid);
static int send_creds(int sock, struct ucred *cred, char v, bool pingfirst);
static int send_creds_clone_wrapper(void *arg);

/*
 * clone a task which switches to @task's namespace and writes '1'.
 * over a unix sock so we can read the task's reaper's pid in our
 * namespace
 *
 * Note: glibc's fork() does not respect pidns, which can lead to failed
 * assertions inside glibc (and thus failed forks) if the child's pid in
 * the pidns and the parent pid outside are identical. Using clone prevents
 * this issue.
 */
static void write_task_init_pid_exit(int sock, pid_t target)
{
	char fnam[100];
	pid_t pid;
	int fd, ret;
	size_t stack_size = sysconf(_SC_PAGESIZE);
	void *stack = alloca(stack_size);

	ret = snprintf(fnam, sizeof(fnam), "/proc/%d/ns/pid", (int)target);
	if (ret < 0 || ret >= sizeof(fnam))
		_exit(1);

	fd = open(fnam, O_RDONLY);
	if (fd < 0) {
		perror("write_task_init_pid_exit open of ns/pid");
		_exit(1);
	}
	if (setns(fd, 0)) {
		perror("write_task_init_pid_exit setns 1");
		close(fd);
		_exit(1);
	}
	pid = clone(send_creds_clone_wrapper, stack + stack_size, SIGCHLD, &sock);
	if (pid < 0)
		_exit(1);
	if (pid != 0) {
		if (!wait_for_pid(pid))
			_exit(1);
		_exit(0);
	}
}

static int send_creds_clone_wrapper(void *arg) {
	struct ucred cred;
	char v;
	int sock = *(int *)arg;

	/* we are the child */
	cred.uid = 0;
	cred.gid = 0;
	cred.pid = 1;
	v = '1';
	if (send_creds(sock, &cred, v, true) != SEND_CREDS_OK)
		return 1;
	return 0;
}

static pid_t get_init_pid_for_task(pid_t task)
{
	int sock[2];
	pid_t pid;
	pid_t ret = -1;
	char v = '0';
	struct ucred cred;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sock) < 0) {
		perror("socketpair");
		return -1;
	}

	pid = fork();
	if (pid < 0)
		goto out;
	if (!pid) {
		close(sock[1]);
		write_task_init_pid_exit(sock[0], task);
		_exit(0);
	}

	if (!recv_creds(sock[1], &cred, &v))
		goto out;
	ret = cred.pid;

out:
	close(sock[0]);
	close(sock[1]);
	if (pid > 0)
		wait_for_pid(pid);
	return ret;
}

static pid_t lookup_initpid_in_store(pid_t qpid)
{
	pid_t answer = 0;
	struct stat sb;
	struct pidns_init_store *e;
	char fnam[100];

	snprintf(fnam, 100, "/proc/%d/ns/pid", qpid);
	store_lock();
	if (stat(fnam, &sb) < 0)
		goto out;
	e = lookup_verify_initpid(&sb);
	if (e) {
		answer = e->initpid;
		goto out;
	}
	answer = get_init_pid_for_task(qpid);
	if (answer > 0)
		save_initpid(&sb, answer);

out:
	/* we prune at end in case we are returning
	 * the value we were about to return */
	prune_initpid_store();
	store_unlock();
	return answer;
}

static int wait_for_pid(pid_t pid)
{
	int status, ret;

	if (pid <= 0)
		return -1;

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;
		return -1;
	}
	if (ret != pid)
		goto again;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;
	return 0;
}


/*
 * append pid to *src.
 * src: a pointer to a char* in which ot append the pid.
 * sz: the number of characters printed so far, minus trailing \0.
 * asz: the allocated size so far
 * pid: the pid to append
 */
static void must_strcat_pid(char **src, size_t *sz, size_t *asz, pid_t pid)
{
	char tmp[30];

	int tmplen = sprintf(tmp, "%d\n", (int)pid);

	if (!*src || tmplen + *sz + 1 >= *asz) {
		char *tmp;
		do {
			tmp = realloc(*src, *asz + BUF_RESERVE_SIZE);
		} while (!tmp);
		*src = tmp;
		*asz += BUF_RESERVE_SIZE;
	}
	memcpy((*src) +*sz , tmp, tmplen+1); /* include the \0 */
	*sz += tmplen;
}

/*
 * Given a open file * to /proc/pid/{u,g}id_map, and an id
 * valid in the caller's namespace, return the id mapped into
 * pid's namespace.
 * Returns the mapped id, or -1 on error.
 */
unsigned int
convert_id_to_ns(FILE *idfile, unsigned int in_id)
{
	unsigned int nsuid,   // base id for a range in the idfile's namespace
		     hostuid, // base id for a range in the caller's namespace
		     count;   // number of ids in this range
	char line[400];
	int ret;

	fseek(idfile, 0L, SEEK_SET);
	while (fgets(line, 400, idfile)) {
		ret = sscanf(line, "%u %u %u\n", &nsuid, &hostuid, &count);
		if (ret != 3)
			continue;
		if (hostuid + count < hostuid || nsuid + count < nsuid) {
			/*
			 * uids wrapped around - unexpected as this is a procfile,
			 * so just bail.
			 */
			fprintf(stderr, "pid wrapparound at entry %u %u %u in %s\n",
				nsuid, hostuid, count, line);
			return -1;
		}
		if (hostuid <= in_id && hostuid+count > in_id) {
			/*
			 * now since hostuid <= in_id < hostuid+count, and
			 * hostuid+count and nsuid+count do not wrap around,
			 * we know that nsuid+(in_id-hostuid) which must be
			 * less that nsuid+(count) must not wrap around
			 */
			return (in_id - hostuid) + nsuid;
		}
	}

	// no answer found
	return -1;
}

/*
 * for is_privileged_over,
 * specify whether we require the calling uid to be root in his
 * namespace
 */
#define NS_ROOT_REQD true
#define NS_ROOT_OPT false

#define PROCLEN 100

static bool is_privileged_over(pid_t pid, uid_t uid, uid_t victim, bool req_ns_root)
{
	char fpath[PROCLEN];
	int ret;
	bool answer = false;
	uid_t nsuid;

	if (victim == -1 || uid == -1)
		return false;

	/*
	 * If the request is one not requiring root in the namespace,
	 * then having the same uid suffices.  (i.e. uid 1000 has write
	 * access to files owned by uid 1000
	 */
	if (!req_ns_root && uid == victim)
		return true;

	ret = snprintf(fpath, PROCLEN, "/proc/%d/uid_map", pid);
	if (ret < 0 || ret >= PROCLEN)
		return false;
	FILE *f = fopen(fpath, "r");
	if (!f)
		return false;

	/* if caller's not root in his namespace, reject */
	nsuid = convert_id_to_ns(f, uid);
	if (nsuid)
		goto out;

	/*
	 * If victim is not mapped into caller's ns, reject.
	 * XXX I'm not sure this check is needed given that fuse
	 * will be sending requests where the vfs has converted
	 */
	nsuid = convert_id_to_ns(f, victim);
	if (nsuid == -1)
		goto out;

	answer = true;

out:
	fclose(f);
	return answer;
}

static bool perms_include(int fmode, mode_t req_mode)
{
	mode_t r;

	switch (req_mode & O_ACCMODE) {
	case O_RDONLY:
		r = S_IROTH;
		break;
	case O_WRONLY:
		r = S_IWOTH;
		break;
	case O_RDWR:
		r = S_IROTH | S_IWOTH;
		break;
	default:
		return false;
	}
	return ((fmode & r) == r);
}


/*
 * taskcg is  a/b/c
 * querycg is /a/b/c/d/e
 * we return 'd'
 */
static char *get_next_cgroup_dir(const char *taskcg, const char *querycg)
{
	char *start, *end;

	if (strlen(taskcg) <= strlen(querycg)) {
		fprintf(stderr, "%s: I was fed bad input\n", __func__);
		return NULL;
	}

	if (strcmp(querycg, "/") == 0)
		start =  strdup(taskcg + 1);
	else
		start = strdup(taskcg + strlen(querycg) + 1);
	if (!start)
		return NULL;
	end = strchr(start, '/');
	if (end)
		*end = '\0';
	return start;
}

static void stripnewline(char *x)
{
	size_t l = strlen(x);
	if (l && x[l-1] == '\n')
		x[l-1] = '\0';
}

static char *get_pid_cgroup(pid_t pid, const char *contrl)
{
	char fnam[PROCLEN];
	FILE *f;
	char *answer = NULL;
	char *line = NULL;
	size_t len = 0;
	int ret;
	const char *h = find_mounted_controller(contrl);
	if (!h)
		return NULL;

	ret = snprintf(fnam, PROCLEN, "/proc/%d/cgroup", pid);
	if (ret < 0 || ret >= PROCLEN)
		return NULL;
	if (!(f = fopen(fnam, "r")))
		return NULL;

	while (getline(&line, &len, f) != -1) {
		char *c1, *c2;
		if (!line[0])
			continue;
		c1 = strchr(line, ':');
		if (!c1)
			goto out;
		c1++;
		c2 = strchr(c1, ':');
		if (!c2)
			goto out;
		*c2 = '\0';
		if (strcmp(c1, h) != 0)
			continue;
		c2++;
		stripnewline(c2);
		do {
			answer = strdup(c2);
		} while (!answer);
		break;
	}

out:
	fclose(f);
	free(line);
	return answer;
}

/*
 * check whether a fuse context may access a cgroup dir or file
 *
 * If file is not null, it is a cgroup file to check under cg.
 * If file is null, then we are checking perms on cg itself.
 *
 * For files we can check the mode of the list_keys result.
 * For cgroups, we must make assumptions based on the files under the
 * cgroup, because cgmanager doesn't tell us ownership/perms of cgroups
 * yet.
 */
static bool fc_may_access(struct fuse_context *fc, const char *contrl, const char *cg, const char *file, mode_t mode)
{
	struct cgfs_files *k = NULL;
	bool ret = false;

	k = cgfs_get_key(contrl, cg, file);
	if (!k)
		return false;

	if (is_privileged_over(fc->pid, fc->uid, k->uid, NS_ROOT_OPT)) {
		if (perms_include(k->mode >> 6, mode)) {
			ret = true;
			goto out;
		}
	}
	if (fc->gid == k->gid) {
		if (perms_include(k->mode >> 3, mode)) {
			ret = true;
			goto out;
		}
	}
	ret = perms_include(k->mode, mode);

out:
	free_key(k);
	return ret;
}

#define INITSCOPE "/init.scope"
static void prune_init_slice(char *cg)
{
	char *point;
	size_t cg_len = strlen(cg), initscope_len = strlen(INITSCOPE);

	if (cg_len < initscope_len)
		return;

	point = cg + cg_len - initscope_len;
	if (strcmp(point, INITSCOPE) == 0) {
		if (point == cg)
			*(point+1) = '\0';
		else
			*point = '\0';
	}
}

/*
 * If pid is in /a/b/c/d, he may only act on things under cg=/a/b/c/d.
 * If pid is in /a, he may act on /a/b, but not on /b.
 * if the answer is false and nextcg is not NULL, then *nextcg will point
 * to a string containing the next cgroup directory under cg, which must be
 * freed by the caller.
 */
static bool caller_is_in_ancestor(pid_t pid, const char *contrl, const char *cg, char **nextcg)
{
	bool answer = false;
	char *c2 = get_pid_cgroup(pid, contrl);
	char *linecmp;

	if (!c2)
		return false;
	prune_init_slice(c2);

	/*
	 * callers pass in '/' for root cgroup, otherwise they pass
	 * in a cgroup without leading '/'
	 */
	linecmp = *cg == '/' ? c2 : c2+1;
	if (strncmp(linecmp, cg, strlen(linecmp)) != 0) {
		if (nextcg) {
			*nextcg = get_next_cgroup_dir(linecmp, cg);
		}
		goto out;
	}
	answer = true;

out:
	free(c2);
	return answer;
}

/*
 * If pid is in /a/b/c, he may see that /a exists, but not /b or /a/c.
 */
static bool caller_may_see_dir(pid_t pid, const char *contrl, const char *cg)
{
	bool answer = false;
	char *c2, *task_cg;
	size_t target_len, task_len;

	if (strcmp(cg, "/") == 0)
		return true;

	c2 = get_pid_cgroup(pid, contrl);
	if (!c2)
		return false;
	prune_init_slice(c2);

	task_cg = c2 + 1;
	target_len = strlen(cg);
	task_len = strlen(task_cg);
	if (task_len == 0) {
		/* Task is in the root cg, it can see everything. This case is
		 * not handled by the strmcps below, since they test for the
		 * last /, but that is the first / that we've chopped off
		 * above.
		 */
		answer = true;
		goto out;
	}
	if (strcmp(cg, task_cg) == 0) {
		answer = true;
		goto out;
	}
	if (target_len < task_len) {
		/* looking up a parent dir */
		if (strncmp(task_cg, cg, target_len) == 0 && task_cg[target_len] == '/')
			answer = true;
		goto out;
	}
	if (target_len > task_len) {
		/* looking up a child dir */
		if (strncmp(task_cg, cg, task_len) == 0 && cg[task_len] == '/')
			answer = true;
		goto out;
	}

out:
	free(c2);
	return answer;
}

/*
 * given /cgroup/freezer/a/b, return "freezer".
 * the returned char* should NOT be freed.
 */
static char *pick_controller_from_path(struct fuse_context *fc, const char *path)
{
	const char *p1;
	char *contr, *slash;

	if (strlen(path) < 9)
		return NULL;
	if (*(path+7) != '/')
		return NULL;
	p1 = path+8;
	contr = strdupa(p1);
	if (!contr)
		return NULL;
	slash = strstr(contr, "/");
	if (slash)
		*slash = '\0';

	int i;
	for (i = 0;  i < num_hierarchies;  i++) {
		if (hierarchies[i] && strcmp(hierarchies[i], contr) == 0)
			return hierarchies[i];
	}
	return NULL;
}

/*
 * Find the start of cgroup in /cgroup/controller/the/cgroup/path
 * Note that the returned value may include files (keynames) etc
 */
static const char *find_cgroup_in_path(const char *path)
{
	const char *p1;

	if (strlen(path) < 9)
		return NULL;
	p1 = strstr(path+8, "/");
	if (!p1)
		return NULL;
	return p1+1;
}

/*
 * split the last path element from the path in @cg.
 * @dir is newly allocated and should be freed, @last not
*/
static void get_cgdir_and_path(const char *cg, char **dir, char **last)
{
	char *p;

	do {
		*dir = strdup(cg);
	} while (!*dir);
	*last = strrchr(cg, '/');
	if (!*last) {
		*last = NULL;
		return;
	}
	p = strrchr(*dir, '/');
	*p = '\0';
}

/*
 * FUSE ops for /cgroup
 */

int cg_getattr(const char *path, struct stat *sb)
{
	struct timespec now;
	struct fuse_context *fc = fuse_get_context();
	char * cgdir = NULL;
	char *last = NULL, *path1, *path2;
	struct cgfs_files *k = NULL;
	const char *cgroup;
	const char *controller = NULL;
	int ret = -ENOENT;


	if (!fc)
		return -EIO;

	memset(sb, 0, sizeof(struct stat));

	if (clock_gettime(CLOCK_REALTIME, &now) < 0)
		return -EINVAL;

	sb->st_uid = sb->st_gid = 0;
	sb->st_atim = sb->st_mtim = sb->st_ctim = now;
	sb->st_size = 0;

	if (strcmp(path, "/cgroup") == 0) {
		sb->st_mode = S_IFDIR | 00755;
		sb->st_nlink = 2;
		return 0;
	}

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return -EIO;
	cgroup = find_cgroup_in_path(path);
	if (!cgroup) {
		/* this is just /cgroup/controller, return it as a dir */
		sb->st_mode = S_IFDIR | 00755;
		sb->st_nlink = 2;
		return 0;
	}

	get_cgdir_and_path(cgroup, &cgdir, &last);

	if (!last) {
		path1 = "/";
		path2 = cgdir;
	} else {
		path1 = cgdir;
		path2 = last;
	}

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 0)
		initpid = fc->pid;
	/* check that cgcopy is either a child cgroup of cgdir, or listed in its keys.
	 * Then check that caller's cgroup is under path if last is a child
	 * cgroup, or cgdir if last is a file */

	if (is_child_cgroup(controller, path1, path2)) {
		if (!caller_may_see_dir(initpid, controller, cgroup)) {
			ret = -ENOENT;
			goto out;
		}
		if (!caller_is_in_ancestor(initpid, controller, cgroup, NULL)) {
			/* this is just /cgroup/controller, return it as a dir */
			sb->st_mode = S_IFDIR | 00555;
			sb->st_nlink = 2;
			ret = 0;
			goto out;
		}
		if (!fc_may_access(fc, controller, cgroup, NULL, O_RDONLY)) {
			ret = -EACCES;
			goto out;
		}

		// get uid, gid, from '/tasks' file and make up a mode
		// That is a hack, until cgmanager gains a GetCgroupPerms fn.
		sb->st_mode = S_IFDIR | 00755;
		k = cgfs_get_key(controller, cgroup, NULL);
		if (!k) {
			sb->st_uid = sb->st_gid = 0;
		} else {
			sb->st_uid = k->uid;
			sb->st_gid = k->gid;
		}
		free_key(k);
		sb->st_nlink = 2;
		ret = 0;
		goto out;
	}

	if ((k = cgfs_get_key(controller, path1, path2)) != NULL) {
		sb->st_mode = S_IFREG | k->mode;
		sb->st_nlink = 1;
		sb->st_uid = k->uid;
		sb->st_gid = k->gid;
		sb->st_size = 0;
		free_key(k);
		if (!caller_is_in_ancestor(initpid, controller, path1, NULL)) {
			ret = -ENOENT;
			goto out;
		}
		if (!fc_may_access(fc, controller, path1, path2, O_RDONLY)) {
			ret = -EACCES;
			goto out;
		}

		ret = 0;
	}

out:
	free(cgdir);
	return ret;
}

int cg_opendir(const char *path, struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	const char *cgroup;
	struct file_info *dir_info;
	char *controller = NULL;

	if (!fc)
		return -EIO;

	if (strcmp(path, "/cgroup") == 0) {
		cgroup = NULL;
		controller = NULL;
	} else {
		// return list of keys for the controller, and list of child cgroups
		controller = pick_controller_from_path(fc, path);
		if (!controller)
			return -EIO;

		cgroup = find_cgroup_in_path(path);
		if (!cgroup) {
			/* this is just /cgroup/controller, return its contents */
			cgroup = "/";
		}
	}

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 0)
		initpid = fc->pid;
	if (cgroup) {
		if (!caller_may_see_dir(initpid, controller, cgroup))
			return -ENOENT;
		if (!fc_may_access(fc, controller, cgroup, NULL, O_RDONLY))
			return -EACCES;
	}

	/* we'll free this at cg_releasedir */
	dir_info = malloc(sizeof(*dir_info));
	if (!dir_info)
		return -ENOMEM;
	dir_info->controller = must_copy_string(controller);
	dir_info->cgroup = must_copy_string(cgroup);
	dir_info->type = LXC_TYPE_CGDIR;
	dir_info->buf = NULL;
	dir_info->file = NULL;
	dir_info->buflen = 0;

	fi->fh = (unsigned long)dir_info;
	return 0;
}

int cg_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
		struct fuse_file_info *fi)
{
	struct file_info *d = (struct file_info *)fi->fh;
	struct cgfs_files **list = NULL;
	int i, ret;
	char *nextcg = NULL;
	struct fuse_context *fc = fuse_get_context();
	char **clist = NULL;

	if (d->type != LXC_TYPE_CGDIR) {
		fprintf(stderr, "Internal error: file cache info used in readdir\n");
		return -EIO;
	}
	if (!d->cgroup && !d->controller) {
		// ls /var/lib/lxcfs/cgroup - just show list of controllers
		int i;

		for (i = 0;  i < num_hierarchies; i++) {
			if (hierarchies[i] && filler(buf, hierarchies[i], NULL, 0) != 0) {
				return -EIO;
			}
		}
		return 0;
	}

	if (!cgfs_list_keys(d->controller, d->cgroup, &list)) {
		// not a valid cgroup
		ret = -EINVAL;
		goto out;
	}

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 0)
		initpid = fc->pid;
	if (!caller_is_in_ancestor(initpid, d->controller, d->cgroup, &nextcg)) {
		if (nextcg) {
			ret = filler(buf, nextcg,  NULL, 0);
			free(nextcg);
			if (ret != 0) {
				ret = -EIO;
				goto out;
			}
		}
		ret = 0;
		goto out;
	}

	for (i = 0; list[i]; i++) {
		if (filler(buf, list[i]->name, NULL, 0) != 0) {
			ret = -EIO;
			goto out;
		}
	}

	// now get the list of child cgroups

	if (!cgfs_list_children(d->controller, d->cgroup, &clist)) {
		ret = 0;
		goto out;
	}
	if (clist) {
		for (i = 0; clist[i]; i++) {
			if (filler(buf, clist[i], NULL, 0) != 0) {
				ret = -EIO;
				goto out;
			}
		}
	}
	ret = 0;

out:
	free_keys(list);
	if (clist) {
		for (i = 0; clist[i]; i++)
			free(clist[i]);
		free(clist);
	}
	return ret;
}

static void do_release_file_info(struct file_info *f)
{
	if (!f)
		return;
	free(f->controller);
	free(f->cgroup);
	free(f->file);
	free(f->buf);
	free(f);
}

int cg_releasedir(const char *path, struct fuse_file_info *fi)
{
	struct file_info *d = (struct file_info *)fi->fh;

	do_release_file_info(d);
	return 0;
}

int cg_open(const char *path, struct fuse_file_info *fi)
{
	const char *cgroup;
	char *last = NULL, *path1, *path2, * cgdir = NULL, *controller;
	struct cgfs_files *k = NULL;
	struct file_info *file_info;
	struct fuse_context *fc = fuse_get_context();
	int ret;

	if (!fc)
		return -EIO;

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return -EIO;
	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		return -EINVAL;

	get_cgdir_and_path(cgroup, &cgdir, &last);
	if (!last) {
		path1 = "/";
		path2 = cgdir;
	} else {
		path1 = cgdir;
		path2 = last;
	}

	k = cgfs_get_key(controller, path1, path2);
	if (!k) {
		ret = -EINVAL;
		goto out;
	}
	free_key(k);

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 0)
		initpid = fc->pid;
	if (!caller_may_see_dir(initpid, controller, path1)) {
		ret = -ENOENT;
		goto out;
	}
	if (!fc_may_access(fc, controller, path1, path2, fi->flags)) {
		ret = -EACCES;
		goto out;
	}

	/* we'll free this at cg_release */
	file_info = malloc(sizeof(*file_info));
	if (!file_info) {
		ret = -ENOMEM;
		goto out;
	}
	file_info->controller = must_copy_string(controller);
	file_info->cgroup = must_copy_string(path1);
	file_info->file = must_copy_string(path2);
	file_info->type = LXC_TYPE_CGFILE;
	file_info->buf = NULL;
	file_info->buflen = 0;

	fi->fh = (unsigned long)file_info;
	ret = 0;

out:
	free(cgdir);
	return ret;
}

int cg_access(const char *path, int mode)
{
	const char *cgroup;
	char *last = NULL, *path1, *path2, * cgdir = NULL, *controller;
	struct cgfs_files *k = NULL;
	struct fuse_context *fc = fuse_get_context();
	int ret;

	if (!fc)
		return -EIO;

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return -EIO;
	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		return -EINVAL;

	get_cgdir_and_path(cgroup, &cgdir, &last);
	if (!last) {
		path1 = "/";
		path2 = cgdir;
	} else {
		path1 = cgdir;
		path2 = last;
	}

	k = cgfs_get_key(controller, path1, path2);
	if (!k) {
		ret = -EINVAL;
		goto out;
	}
	free_key(k);

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 0)
		initpid = fc->pid;
	if (!caller_may_see_dir(initpid, controller, path1)) {
		ret = -ENOENT;
		goto out;
	}
	if (!fc_may_access(fc, controller, path1, path2, mode)) {
		ret = -EACCES;
		goto out;
	}

	ret = 0;

out:
	free(cgdir);
	return ret;
}

int cg_release(const char *path, struct fuse_file_info *fi)
{
	struct file_info *f = (struct file_info *)fi->fh;

	do_release_file_info(f);
	return 0;
}

#define POLLIN_SET ( EPOLLIN | EPOLLHUP | EPOLLRDHUP )

static bool wait_for_sock(int sock, int timeout)
{
	struct epoll_event ev;
	int epfd, ret, now, starttime, deltatime, saved_errno;

	if ((starttime = time(NULL)) < 0)
		return false;

	if ((epfd = epoll_create(1)) < 0) {
		fprintf(stderr, "Failed to create epoll socket: %m\n");
		return false;
	}

	ev.events = POLLIN_SET;
	ev.data.fd = sock;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev) < 0) {
		fprintf(stderr, "Failed adding socket to epoll: %m\n");
		close(epfd);
		return false;
	}

again:
	if ((now = time(NULL)) < 0) {
		close(epfd);
		return false;
	}

	deltatime = (starttime + timeout) - now;
	if (deltatime < 0) { // timeout
		errno = 0;
		close(epfd);
		return false;
	}
	ret = epoll_wait(epfd, &ev, 1, 1000*deltatime + 1);
	if (ret < 0 && errno == EINTR)
		goto again;
	saved_errno = errno;
	close(epfd);

	if (ret <= 0) {
		errno = saved_errno;
		return false;
	}
	return true;
}

static int msgrecv(int sockfd, void *buf, size_t len)
{
	if (!wait_for_sock(sockfd, 2))
		return -1;
	return recv(sockfd, buf, len, MSG_DONTWAIT);
}

static int send_creds(int sock, struct ucred *cred, char v, bool pingfirst)
{
	struct msghdr msg = { 0 };
	struct iovec iov;
	struct cmsghdr *cmsg;
	char cmsgbuf[CMSG_SPACE(sizeof(*cred))];
	char buf[1];
	buf[0] = 'p';

	if (pingfirst) {
		if (msgrecv(sock, buf, 1) != 1) {
			fprintf(stderr, "%s: Error getting reply from server over socketpair\n",
				  __func__);
			return SEND_CREDS_FAIL;
		}
	}

	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_CREDENTIALS;
	memcpy(CMSG_DATA(cmsg), cred, sizeof(*cred));

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	buf[0] = v;
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(sock, &msg, 0) < 0) {
		fprintf(stderr, "%s: failed at sendmsg: %s\n", __func__,
			  strerror(errno));
		if (errno == 3)
			return SEND_CREDS_NOTSK;
		return SEND_CREDS_FAIL;
	}

	return SEND_CREDS_OK;
}

static bool recv_creds(int sock, struct ucred *cred, char *v)
{
	struct msghdr msg = { 0 };
	struct iovec iov;
	struct cmsghdr *cmsg;
	char cmsgbuf[CMSG_SPACE(sizeof(*cred))];
	char buf[1];
	int ret;
	int optval = 1;

	*v = '1';

	cred->pid = -1;
	cred->uid = -1;
	cred->gid = -1;

	if (setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		fprintf(stderr, "Failed to set passcred: %s\n", strerror(errno));
		return false;
	}
	buf[0] = '1';
	if (write(sock, buf, 1) != 1) {
		fprintf(stderr, "Failed to start write on scm fd: %s\n", strerror(errno));
		return false;
	}

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (!wait_for_sock(sock, 2)) {
		fprintf(stderr, "Timed out waiting for scm_cred: %s\n",
			  strerror(errno));
		return false;
	}
	ret = recvmsg(sock, &msg, MSG_DONTWAIT);
	if (ret < 0) {
		fprintf(stderr, "Failed to receive scm_cred: %s\n",
			  strerror(errno));
		return false;
	}

	cmsg = CMSG_FIRSTHDR(&msg);

	if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred)) &&
			cmsg->cmsg_level == SOL_SOCKET &&
			cmsg->cmsg_type == SCM_CREDENTIALS) {
		memcpy(cred, CMSG_DATA(cmsg), sizeof(*cred));
	}
	*v = buf[0];

	return true;
}

struct pid_ns_clone_args {
	int *cpipe;
	int sock;
	pid_t tpid;
	int (*wrapped) (int, pid_t); // pid_from_ns or pid_to_ns
};

/*
 * pid_ns_clone_wrapper - wraps pid_to_ns or pid_from_ns for usage
 * with clone(). This simply writes '1' as ACK back to the parent
 * before calling the actual wrapped function.
 */
static int pid_ns_clone_wrapper(void *arg) {
	struct pid_ns_clone_args* args = (struct pid_ns_clone_args *) arg;
	char b = '1';

	close(args->cpipe[0]);
	if (write(args->cpipe[1], &b, sizeof(char)) < 0) {
		fprintf(stderr, "%s (child): error on write: %s\n",
			__func__, strerror(errno));
	}
	close(args->cpipe[1]);
	return args->wrapped(args->sock, args->tpid);
}

/*
 * pid_to_ns - reads pids from a ucred over a socket, then writes the
 * int value back over the socket.  This shifts the pid from the
 * sender's pidns into tpid's pidns.
 */
static int pid_to_ns(int sock, pid_t tpid)
{
	char v = '0';
	struct ucred cred;

	while (recv_creds(sock, &cred, &v)) {
		if (v == '1')
			return 0;
		if (write(sock, &cred.pid, sizeof(pid_t)) != sizeof(pid_t))
			return 1;
	}
	return 0;
}


/*
 * pid_to_ns_wrapper: when you setns into a pidns, you yourself remain
 * in your old pidns.  Only children which you clone will be in the target
 * pidns.  So the pid_to_ns_wrapper does the setns, then clones a child to
 * actually convert pids.
 *
 * Note: glibc's fork() does not respect pidns, which can lead to failed
 * assertions inside glibc (and thus failed forks) if the child's pid in
 * the pidns and the parent pid outside are identical. Using clone prevents
 * this issue.
 */
static void pid_to_ns_wrapper(int sock, pid_t tpid)
{
	int newnsfd = -1, ret, cpipe[2];
	char fnam[100];
	pid_t cpid;
	char v;

	ret = snprintf(fnam, sizeof(fnam), "/proc/%d/ns/pid", tpid);
	if (ret < 0 || ret >= sizeof(fnam))
		_exit(1);
	newnsfd = open(fnam, O_RDONLY);
	if (newnsfd < 0)
		_exit(1);
	if (setns(newnsfd, 0) < 0)
		_exit(1);
	close(newnsfd);

	if (pipe(cpipe) < 0)
		_exit(1);

	struct pid_ns_clone_args args = {
		.cpipe = cpipe,
		.sock = sock,
		.tpid = tpid,
		.wrapped = &pid_to_ns
	};
	size_t stack_size = sysconf(_SC_PAGESIZE);
	void *stack = alloca(stack_size);

	cpid = clone(pid_ns_clone_wrapper, stack + stack_size, SIGCHLD, &args);
	if (cpid < 0)
		_exit(1);

	// give the child 1 second to be done forking and
	// write its ack
	if (!wait_for_sock(cpipe[0], 1))
		_exit(1);
	ret = read(cpipe[0], &v, 1);
	if (ret != sizeof(char) || v != '1')
		_exit(1);

	if (!wait_for_pid(cpid))
		_exit(1);
	_exit(0);
}

/*
 * To read cgroup files with a particular pid, we will setns into the child
 * pidns, open a pipe, fork a child - which will be the first to really be in
 * the child ns - which does the cgfs_get_value and writes the data to the pipe.
 */
bool do_read_pids(pid_t tpid, const char *contrl, const char *cg, const char *file, char **d)
{
	int sock[2] = {-1, -1};
	char *tmpdata = NULL;
	int ret;
	pid_t qpid, cpid = -1;
	bool answer = false;
	char v = '0';
	struct ucred cred;
	size_t sz = 0, asz = 0;

	if (!cgfs_get_value(contrl, cg, file, &tmpdata))
		return false;

	/*
	 * Now we read the pids from returned data one by one, pass
	 * them into a child in the target namespace, read back the
	 * translated pids, and put them into our to-return data
	 */

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sock) < 0) {
		perror("socketpair");
		free(tmpdata);
		return false;
	}

	cpid = fork();
	if (cpid == -1)
		goto out;

	if (!cpid) // child - exits when done
		pid_to_ns_wrapper(sock[1], tpid);

	char *ptr = tmpdata;
	cred.uid = 0;
	cred.gid = 0;
	while (sscanf(ptr, "%d\n", &qpid) == 1) {
		cred.pid = qpid;
		ret = send_creds(sock[0], &cred, v, true);

		if (ret == SEND_CREDS_NOTSK)
			goto next;
		if (ret == SEND_CREDS_FAIL)
			goto out;

		// read converted results
		if (!wait_for_sock(sock[0], 2)) {
			fprintf(stderr, "%s: timed out waiting for pid from child: %s\n",
				__func__, strerror(errno));
			goto out;
		}
		if (read(sock[0], &qpid, sizeof(qpid)) != sizeof(qpid)) {
			fprintf(stderr, "%s: error reading pid from child: %s\n",
				__func__, strerror(errno));
			goto out;
		}
		must_strcat_pid(d, &sz, &asz, qpid);
next:
		ptr = strchr(ptr, '\n');
		if (!ptr)
			break;
		ptr++;
	}

	cred.pid = getpid();
	v = '1';
	if (send_creds(sock[0], &cred, v, true) != SEND_CREDS_OK) {
		// failed to ask child to exit
		fprintf(stderr, "%s: failed to ask child to exit: %s\n",
			__func__, strerror(errno));
		goto out;
	}

	answer = true;

out:
	free(tmpdata);
	if (cpid != -1)
		wait_for_pid(cpid);
	if (sock[0] != -1) {
		close(sock[0]);
		close(sock[1]);
	}
	return answer;
}

int cg_read(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	struct file_info *f = (struct file_info *)fi->fh;
	struct cgfs_files *k = NULL;
	char *data = NULL;
	int ret, s;
	bool r;

	if (f->type != LXC_TYPE_CGFILE) {
		fprintf(stderr, "Internal error: directory cache info used in cg_read\n");
		return -EIO;
	}

	if (offset)
		return 0;

	if (!fc)
		return -EIO;

	if (!f->controller)
		return -EINVAL;

	if ((k = cgfs_get_key(f->controller, f->cgroup, f->file)) == NULL) {
		return -EINVAL;
	}
	free_key(k);


	if (!fc_may_access(fc, f->controller, f->cgroup, f->file, O_RDONLY)) {
		ret = -EACCES;
		goto out;
	}

	if (strcmp(f->file, "tasks") == 0 ||
			strcmp(f->file, "/tasks") == 0 ||
			strcmp(f->file, "/cgroup.procs") == 0 ||
			strcmp(f->file, "cgroup.procs") == 0)
		// special case - we have to translate the pids
		r = do_read_pids(fc->pid, f->controller, f->cgroup, f->file, &data);
	else
		r = cgfs_get_value(f->controller, f->cgroup, f->file, &data);

	if (!r) {
		ret = -EINVAL;
		goto out;
	}

	if (!data) {
		ret = 0;
		goto out;
	}
	s = strlen(data);
	if (s > size)
		s = size;
	memcpy(buf, data, s);
	if (s > 0 && s < size && data[s-1] != '\n')
		buf[s++] = '\n';

	ret = s;

out:
	free(data);
	return ret;
}

static int pid_from_ns(int sock, pid_t tpid)
{
	pid_t vpid;
	struct ucred cred;
	char v;
	int ret;

	cred.uid = 0;
	cred.gid = 0;
	while (1) {
		if (!wait_for_sock(sock, 2)) {
			fprintf(stderr, "%s: timeout reading from parent\n", __func__);
			return 1;
		}
		if ((ret = read(sock, &vpid, sizeof(pid_t))) != sizeof(pid_t)) {
			fprintf(stderr, "%s: bad read from parent: %s\n",
				__func__, strerror(errno));
			return 1;
		}
		if (vpid == -1) // done
			break;
		v = '0';
		cred.pid = vpid;
		if (send_creds(sock, &cred, v, true) != SEND_CREDS_OK) {
			v = '1';
			cred.pid = getpid();
			if (send_creds(sock, &cred, v, false) != SEND_CREDS_OK)
				return 1;
		}
	}
	return 0;
}

static void pid_from_ns_wrapper(int sock, pid_t tpid)
{
	int newnsfd = -1, ret, cpipe[2];
	char fnam[100];
	pid_t cpid;
	char v;

	ret = snprintf(fnam, sizeof(fnam), "/proc/%d/ns/pid", tpid);
	if (ret < 0 || ret >= sizeof(fnam))
		_exit(1);
	newnsfd = open(fnam, O_RDONLY);
	if (newnsfd < 0)
		_exit(1);
	if (setns(newnsfd, 0) < 0)
		_exit(1);
	close(newnsfd);

	if (pipe(cpipe) < 0)
		_exit(1);

	struct pid_ns_clone_args args = {
		.cpipe = cpipe,
		.sock = sock,
		.tpid = tpid,
		.wrapped = &pid_from_ns
	};
	size_t stack_size = sysconf(_SC_PAGESIZE);
	void *stack = alloca(stack_size);

	cpid = clone(pid_ns_clone_wrapper, stack + stack_size, SIGCHLD, &args);
	if (cpid < 0)
		_exit(1);

	// give the child 1 second to be done forking and
	// write its ack
	if (!wait_for_sock(cpipe[0], 1))
		_exit(1);
	ret = read(cpipe[0], &v, 1);
	if (ret != sizeof(char) || v != '1')
		_exit(1);

	if (!wait_for_pid(cpid))
		_exit(1);
	_exit(0);
}

/*
 * Given host @uid, return the uid to which it maps in
 * @pid's user namespace, or -1 if none.
 */
bool hostuid_to_ns(uid_t uid, pid_t pid, uid_t *answer)
{
	FILE *f;
	char line[400];

	sprintf(line, "/proc/%d/uid_map", pid);
	if ((f = fopen(line, "r")) == NULL) {
		return false;
	}

	*answer = convert_id_to_ns(f, uid);
	fclose(f);

	if (*answer == -1)
		return false;
	return true;
}

/*
 * get_pid_creds: get the real uid and gid of @pid from
 * /proc/$$/status
 * (XXX should we use euid here?)
 */
void get_pid_creds(pid_t pid, uid_t *uid, gid_t *gid)
{
	char line[400];
	uid_t u;
	gid_t g;
	FILE *f;

	*uid = -1;
	*gid = -1;
	sprintf(line, "/proc/%d/status", pid);
	if ((f = fopen(line, "r")) == NULL) {
		fprintf(stderr, "Error opening %s: %s\n", line, strerror(errno));
		return;
	}
	while (fgets(line, 400, f)) {
		if (strncmp(line, "Uid:", 4) == 0) {
			if (sscanf(line+4, "%u", &u) != 1) {
				fprintf(stderr, "bad uid line for pid %u\n", pid);
				fclose(f);
				return;
			}
			*uid = u;
		} else if (strncmp(line, "Gid:", 4) == 0) {
			if (sscanf(line+4, "%u", &g) != 1) {
				fprintf(stderr, "bad gid line for pid %u\n", pid);
				fclose(f);
				return;
			}
			*gid = g;
		}
	}
	fclose(f);
}

/*
 * May the requestor @r move victim @v to a new cgroup?
 * This is allowed if
 *   . they are the same task
 *   . they are ownedy by the same uid
 *   . @r is root on the host, or
 *   . @v's uid is mapped into @r's where @r is root.
 */
bool may_move_pid(pid_t r, uid_t r_uid, pid_t v)
{
	uid_t v_uid, tmpuid;
	gid_t v_gid;

	if (r == v)
		return true;
	if (r_uid == 0)
		return true;
	get_pid_creds(v, &v_uid, &v_gid);
	if (r_uid == v_uid)
		return true;
	if (hostuid_to_ns(r_uid, r, &tmpuid) && tmpuid == 0
			&& hostuid_to_ns(v_uid, r, &tmpuid))
		return true;
	return false;
}

static bool do_write_pids(pid_t tpid, uid_t tuid, const char *contrl, const char *cg,
		const char *file, const char *buf)
{
	int sock[2] = {-1, -1};
	pid_t qpid, cpid = -1;
	FILE *pids_file = NULL;
	bool answer = false, fail = false;

	pids_file = open_pids_file(contrl, cg);
	if (!pids_file)
		return false;

	/*
	 * write the pids to a socket, have helper in writer's pidns
	 * call movepid for us
	 */
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sock) < 0) {
		perror("socketpair");
		goto out;
	}

	cpid = fork();
	if (cpid == -1)
		goto out;

	if (!cpid) { // child
		fclose(pids_file);
		pid_from_ns_wrapper(sock[1], tpid);
	}

	const char *ptr = buf;
	while (sscanf(ptr, "%d", &qpid) == 1) {
		struct ucred cred;
		char v;

		if (write(sock[0], &qpid, sizeof(qpid)) != sizeof(qpid)) {
			fprintf(stderr, "%s: error writing pid to child: %s\n",
				__func__, strerror(errno));
			goto out;
		}

		if (recv_creds(sock[0], &cred, &v)) {
			if (v == '0') {
				if (!may_move_pid(tpid, tuid, cred.pid)) {
					fail = true;
					break;
				}
				if (fprintf(pids_file, "%d", (int) cred.pid) < 0)
					fail = true;
			}
		}

		ptr = strchr(ptr, '\n');
		if (!ptr)
			break;
		ptr++;
	}

	/* All good, write the value */
	qpid = -1;
	if (write(sock[0], &qpid ,sizeof(qpid)) != sizeof(qpid))
		fprintf(stderr, "Warning: failed to ask child to exit\n");

	if (!fail)
		answer = true;

out:
	if (cpid != -1)
		wait_for_pid(cpid);
	if (sock[0] != -1) {
		close(sock[0]);
		close(sock[1]);
	}
	if (pids_file) {
		if (fclose(pids_file) != 0)
			answer = false;
	}
	return answer;
}

int cg_write(const char *path, const char *buf, size_t size, off_t offset,
	     struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	char *localbuf = NULL;
	struct cgfs_files *k = NULL;
	struct file_info *f = (struct file_info *)fi->fh;
	bool r;

	if (f->type != LXC_TYPE_CGFILE) {
		fprintf(stderr, "Internal error: directory cache info used in cg_write\n");
		return -EIO;
	}

	if (offset)
		return 0;

	if (!fc)
		return -EIO;

	localbuf = alloca(size+1);
	localbuf[size] = '\0';
	memcpy(localbuf, buf, size);

	if ((k = cgfs_get_key(f->controller, f->cgroup, f->file)) == NULL) {
		size = -EINVAL;
		goto out;
	}

	if (!fc_may_access(fc, f->controller, f->cgroup, f->file, O_WRONLY)) {
		size = -EACCES;
		goto out;
	}

	if (strcmp(f->file, "tasks") == 0 ||
			strcmp(f->file, "/tasks") == 0 ||
			strcmp(f->file, "/cgroup.procs") == 0 ||
			strcmp(f->file, "cgroup.procs") == 0)
		// special case - we have to translate the pids
		r = do_write_pids(fc->pid, fc->uid, f->controller, f->cgroup, f->file, localbuf);
	else
		r = cgfs_set_value(f->controller, f->cgroup, f->file, localbuf);

	if (!r)
		size = -EINVAL;

out:
	free_key(k);
	return size;
}

int cg_chown(const char *path, uid_t uid, gid_t gid)
{
	struct fuse_context *fc = fuse_get_context();
	char *cgdir = NULL, *last = NULL, *path1, *path2, *controller;
	struct cgfs_files *k = NULL;
	const char *cgroup;
	int ret;

	if (!fc)
		return -EIO;

	if (strcmp(path, "/cgroup") == 0)
		return -EINVAL;

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return -EINVAL;
	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		/* this is just /cgroup/controller */
		return -EINVAL;

	get_cgdir_and_path(cgroup, &cgdir, &last);

	if (!last) {
		path1 = "/";
		path2 = cgdir;
	} else {
		path1 = cgdir;
		path2 = last;
	}

	if (is_child_cgroup(controller, path1, path2)) {
		// get uid, gid, from '/tasks' file and make up a mode
		// That is a hack, until cgmanager gains a GetCgroupPerms fn.
		k = cgfs_get_key(controller, cgroup, "tasks");

	} else
		k = cgfs_get_key(controller, path1, path2);

	if (!k) {
		ret = -EINVAL;
		goto out;
	}

	/*
	 * This being a fuse request, the uid and gid must be valid
	 * in the caller's namespace.  So we can just check to make
	 * sure that the caller is root in his uid, and privileged
	 * over the file's current owner.
	 */
	if (!is_privileged_over(fc->pid, fc->uid, k->uid, NS_ROOT_REQD)) {
		ret = -EACCES;
		goto out;
	}

	ret = cgfs_chown_file(controller, cgroup, uid, gid);

out:
	free_key(k);
	free(cgdir);

	return ret;
}

int cg_chmod(const char *path, mode_t mode)
{
	struct fuse_context *fc = fuse_get_context();
	char * cgdir = NULL, *last = NULL, *path1, *path2, *controller;
	struct cgfs_files *k = NULL;
	const char *cgroup;
	int ret;

	if (!fc)
		return -EIO;

	if (strcmp(path, "/cgroup") == 0)
		return -EINVAL;

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return -EINVAL;
	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		/* this is just /cgroup/controller */
		return -EINVAL;

	get_cgdir_and_path(cgroup, &cgdir, &last);

	if (!last) {
		path1 = "/";
		path2 = cgdir;
	} else {
		path1 = cgdir;
		path2 = last;
	}

	if (is_child_cgroup(controller, path1, path2)) {
		// get uid, gid, from '/tasks' file and make up a mode
		// That is a hack, until cgmanager gains a GetCgroupPerms fn.
		k = cgfs_get_key(controller, cgroup, "tasks");

	} else
		k = cgfs_get_key(controller, path1, path2);

	if (!k) {
		ret = -EINVAL;
		goto out;
	}

	/*
	 * This being a fuse request, the uid and gid must be valid
	 * in the caller's namespace.  So we can just check to make
	 * sure that the caller is root in his uid, and privileged
	 * over the file's current owner.
	 */
	if (!is_privileged_over(fc->pid, fc->uid, k->uid, NS_ROOT_OPT)) {
		ret = -EPERM;
		goto out;
	}

	if (!cgfs_chmod_file(controller, cgroup, mode)) {
		ret = -EINVAL;
		goto out;
	}

	ret = 0;
out:
	free_key(k);
	free(cgdir);
	return ret;
}

int cg_mkdir(const char *path, mode_t mode)
{
	struct fuse_context *fc = fuse_get_context();
	char *last = NULL, *path1, *cgdir = NULL, *controller, *next = NULL;
	const char *cgroup;
	int ret;

	if (!fc)
		return -EIO;


	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return -EINVAL;

	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		return -EINVAL;

	get_cgdir_and_path(cgroup, &cgdir, &last);
	if (!last)
		path1 = "/";
	else
		path1 = cgdir;

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 0)
		initpid = fc->pid;
	if (!caller_is_in_ancestor(initpid, controller, path1, &next)) {
		if (!next)
			ret = -EINVAL;
		else if (last && strcmp(next, last) == 0)
			ret = -EEXIST;
		else
			ret = -ENOENT;
		goto out;
	}

	if (!fc_may_access(fc, controller, path1, NULL, O_RDWR)) {
		ret = -EACCES;
		goto out;
	}
	if (!caller_is_in_ancestor(initpid, controller, path1, NULL)) {
		ret = -EACCES;
		goto out;
	}

	ret = cgfs_create(controller, cgroup, fc->uid, fc->gid);

out:
	free(cgdir);
	free(next);
	return ret;
}

int cg_rmdir(const char *path)
{
	struct fuse_context *fc = fuse_get_context();
	char *last = NULL, *cgdir = NULL, *controller, *next = NULL;
	const char *cgroup;
	int ret;

	if (!fc)
		return -EIO;

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return -EINVAL;

	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		return -EINVAL;

	get_cgdir_and_path(cgroup, &cgdir, &last);
	if (!last) {
		ret = -EINVAL;
		goto out;
	}

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 0)
		initpid = fc->pid;
	if (!caller_is_in_ancestor(initpid, controller, cgroup, &next)) {
		if (!last || strcmp(next, last) == 0)
			ret = -EBUSY;
		else
			ret = -ENOENT;
		goto out;
	}

	if (!fc_may_access(fc, controller, cgdir, NULL, O_WRONLY)) {
		ret = -EACCES;
		goto out;
	}
	if (!caller_is_in_ancestor(initpid, controller, cgroup, NULL)) {
		ret = -EACCES;
		goto out;
	}

	if (!cgfs_remove(controller, cgroup)) {
		ret = -EINVAL;
		goto out;
	}

	ret = 0;

out:
	free(cgdir);
	free(next);
	return ret;
}

static bool startswith(const char *line, const char *pref)
{
	if (strncmp(line, pref, strlen(pref)) == 0)
		return true;
	return false;
}

static void get_mem_cached(char *memstat, unsigned long *v)
{
	char *eol;

	*v = 0;
	while (*memstat) {
		if (startswith(memstat, "total_cache")) {
			sscanf(memstat + 11, "%lu", v);
			*v /= 1024;
			return;
		}
		eol = strchr(memstat, '\n');
		if (!eol)
			return;
		memstat = eol+1;
	}
}

static void get_blkio_io_value(char *str, unsigned major, unsigned minor, char *iotype, unsigned long *v)
{
	char *eol;
	char key[32];

	memset(key, 0, 32);
	snprintf(key, 32, "%u:%u %s", major, minor, iotype);

	size_t len = strlen(key);
	*v = 0;

	while (*str) {
		if (startswith(str, key)) {
			sscanf(str + len, "%lu", v);
			return;
		}
		eol = strchr(str, '\n');
		if (!eol)
			return;
		str = eol+1;
	}
}

static int read_file(const char *path, char *buf, size_t size,
		     struct file_info *d)
{
	size_t linelen = 0, total_len = 0, rv = 0;
	char *line = NULL;
	char *cache = d->buf;
	size_t cache_size = d->buflen;
	FILE *f = fopen(path, "r");
	if (!f)
		return 0;

	while (getline(&line, &linelen, f) != -1) {
		size_t l = snprintf(cache, cache_size, "%s", line);
		if (l < 0) {
			perror("Error writing to cache");
			rv = 0;
			goto err;
		}
		if (l >= cache_size) {
			fprintf(stderr, "Internal error: truncated write to cache\n");
			rv = 0;
			goto err;
		}
		cache += l;
		cache_size -= l;
		total_len += l;
	}

	d->size = total_len;
	if (total_len > size ) total_len = size;

	/* read from off 0 */
	memcpy(buf, d->buf, total_len);
	rv = total_len;
  err:
	fclose(f);
	free(line);
	return rv;
}

/*
 * FUSE ops for /proc
 */

static unsigned long get_memlimit(const char *cgroup)
{
	char *memlimit_str = NULL;
	unsigned long memlimit = -1;

	if (cgfs_get_value("memory", cgroup, "memory.limit_in_bytes", &memlimit_str))
		memlimit = strtoul(memlimit_str, NULL, 10);

	free(memlimit_str);

	return memlimit;
}

static unsigned long get_min_memlimit(const char *cgroup)
{
	char *copy = strdupa(cgroup);
	unsigned long memlimit = 0, retlimit;

	retlimit = get_memlimit(copy);

	while (strcmp(copy, "/") != 0) {
		copy = dirname(copy);
		memlimit = get_memlimit(copy);
		if (memlimit != -1 && memlimit < retlimit)
			retlimit = memlimit;
	};

	return retlimit;
}

static int proc_meminfo_read(char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = (struct file_info *)fi->fh;
	char *cg;
	char *memusage_str = NULL, *memstat_str = NULL,
		*memswlimit_str = NULL, *memswusage_str = NULL,
		*memswlimit_default_str = NULL, *memswusage_default_str = NULL;
	unsigned long memlimit = 0, memusage = 0, memswlimit = 0, memswusage = 0,
		cached = 0, hosttotal = 0;
	char *line = NULL;
	size_t linelen = 0, total_len = 0, rv = 0;
	char *cache = d->buf;
	size_t cache_size = d->buflen;
	FILE *f = NULL;

	if (offset){
		if (offset > d->size)
			return -EINVAL;
		if (!d->cached)
			return 0;
		int left = d->size - offset;
		total_len = left > size ? size: left;
		memcpy(buf, cache + offset, total_len);
		return total_len;
	}

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 0)
		initpid = fc->pid;
	cg = get_pid_cgroup(initpid, "memory");
	if (!cg)
		return read_file("/proc/meminfo", buf, size, d);
	prune_init_slice(cg);

	memlimit = get_min_memlimit(cg);
	if (!cgfs_get_value("memory", cg, "memory.usage_in_bytes", &memusage_str))
		goto err;
	if (!cgfs_get_value("memory", cg, "memory.stat", &memstat_str))
		goto err;

	// Following values are allowed to fail, because swapaccount might be turned
	// off for current kernel
	if(cgfs_get_value("memory", cg, "memory.memsw.limit_in_bytes", &memswlimit_str) &&
		cgfs_get_value("memory", cg, "memory.memsw.usage_in_bytes", &memswusage_str))
	{
		/* If swapaccounting is turned on, then default value is assumed to be that of cgroup / */
		if (!cgfs_get_value("memory", "/", "memory.memsw.limit_in_bytes", &memswlimit_default_str))
			goto err;
		if (!cgfs_get_value("memory", "/", "memory.memsw.usage_in_bytes", &memswusage_default_str))
			goto err;

		memswlimit = strtoul(memswlimit_str, NULL, 10);
		memswusage = strtoul(memswusage_str, NULL, 10);

		if (!strcmp(memswlimit_str, memswlimit_default_str))
			memswlimit = 0;
		if (!strcmp(memswusage_str, memswusage_default_str))
			memswusage = 0;

		memswlimit = memswlimit / 1024;
		memswusage = memswusage / 1024;
	}

	memusage = strtoul(memusage_str, NULL, 10);
	memlimit /= 1024;
	memusage /= 1024;

	get_mem_cached(memstat_str, &cached);

	f = fopen("/proc/meminfo", "r");
	if (!f)
		goto err;

	while (getline(&line, &linelen, f) != -1) {
		size_t l;
		char *printme, lbuf[100];

		memset(lbuf, 0, 100);
		if (startswith(line, "MemTotal:")) {
			sscanf(line+14, "%lu", &hosttotal);
			if (hosttotal < memlimit)
				memlimit = hosttotal;
			snprintf(lbuf, 100, "MemTotal:       %8lu kB\n", memlimit);
			printme = lbuf;
		} else if (startswith(line, "MemFree:")) {
			snprintf(lbuf, 100, "MemFree:        %8lu kB\n", memlimit - memusage);
			printme = lbuf;
		} else if (startswith(line, "MemAvailable:")) {
			snprintf(lbuf, 100, "MemAvailable:   %8lu kB\n", memlimit - memusage);
			printme = lbuf;
		} else if (startswith(line, "SwapTotal:") && memswlimit > 0) {
			snprintf(lbuf, 100, "SwapTotal:      %8lu kB\n", memswlimit - memlimit);
			printme = lbuf;
		} else if (startswith(line, "SwapFree:") && memswlimit > 0 && memswusage > 0) {
			snprintf(lbuf, 100, "SwapFree:       %8lu kB\n", 
				(memswlimit - memlimit) - (memswusage - memusage));
			printme = lbuf;
		} else if (startswith(line, "Slab:")) {
			snprintf(lbuf, 100, "Slab:        %8lu kB\n", 0UL);
			printme = lbuf;
		} else if (startswith(line, "Buffers:")) {
			snprintf(lbuf, 100, "Buffers:        %8lu kB\n", 0UL);
			printme = lbuf;
		} else if (startswith(line, "Cached:")) {
			snprintf(lbuf, 100, "Cached:         %8lu kB\n", cached);
			printme = lbuf;
		} else if (startswith(line, "SwapCached:")) {
			snprintf(lbuf, 100, "SwapCached:     %8lu kB\n", 0UL);
			printme = lbuf;
		} else
			printme = line;

		l = snprintf(cache, cache_size, "%s", printme);
		if (l < 0) {
			perror("Error writing to cache");
			rv = 0;
			goto err;

		}
		if (l >= cache_size) {
			fprintf(stderr, "Internal error: truncated write to cache\n");
			rv = 0;
			goto err;
		}

		cache += l;
		cache_size -= l;
		total_len += l;
	}

	d->cached = 1;
	d->size = total_len;
	if (total_len > size ) total_len = size;
	memcpy(buf, d->buf, total_len);

	rv = total_len;
err:
	if (f)
		fclose(f);
	free(line);
	free(cg);
	free(memusage_str);
	free(memswlimit_str);
	free(memswusage_str);
	free(memstat_str);
	free(memswlimit_default_str);
	free(memswusage_default_str);
	return rv;
}

/*
 * Read the cpuset.cpus for cg
 * Return the answer in a newly allocated string which must be freed
 */
static char *get_cpuset(const char *cg)
{
	char *answer;

	if (!cgfs_get_value("cpuset", cg, "cpuset.cpus", &answer))
		return NULL;
	return answer;
}

bool cpu_in_cpuset(int cpu, const char *cpuset);

static bool cpuline_in_cpuset(const char *line, const char *cpuset)
{
	int cpu;

	if (sscanf(line, "processor       : %d", &cpu) != 1)
		return false;
	return cpu_in_cpuset(cpu, cpuset);
}

/*
 * check whether this is a '^processor" line in /proc/cpuinfo
 */
static bool is_processor_line(const char *line)
{
	int cpu;

	if (sscanf(line, "processor       : %d", &cpu) == 1)
		return true;
	return false;
}

static int proc_cpuinfo_read(char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = (struct file_info *)fi->fh;
	char *cg;
	char *cpuset = NULL;
	char *line = NULL;
	size_t linelen = 0, total_len = 0, rv = 0;
	bool am_printing = false;
	int curcpu = -1;
	char *cache = d->buf;
	size_t cache_size = d->buflen;
	FILE *f = NULL;

	if (offset){
		if (offset > d->size)
			return -EINVAL;
		if (!d->cached)
			return 0;
		int left = d->size - offset;
		total_len = left > size ? size: left;
		memcpy(buf, cache + offset, total_len);
		return total_len;
	}

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 0)
		initpid = fc->pid;
	cg = get_pid_cgroup(initpid, "cpuset");
	if (!cg)
		return read_file("proc/cpuinfo", buf, size, d);
	prune_init_slice(cg);

	cpuset = get_cpuset(cg);
	if (!cpuset)
		goto err;

	f = fopen("/proc/cpuinfo", "r");
	if (!f)
		goto err;

	while (getline(&line, &linelen, f) != -1) {
		size_t l;
		if (is_processor_line(line)) {
			am_printing = cpuline_in_cpuset(line, cpuset);
			if (am_printing) {
				curcpu ++;
				l = snprintf(cache, cache_size, "processor	: %d\n", curcpu);
				if (l < 0) {
					perror("Error writing to cache");
					rv = 0;
					goto err;
				}
				if (l >= cache_size) {
					fprintf(stderr, "Internal error: truncated write to cache\n");
					rv = 0;
					goto err;
				}
				cache += l;
				cache_size -= l;
				total_len += l;
			}
			continue;
		}
		if (am_printing) {
			l = snprintf(cache, cache_size, "%s", line);
			if (l < 0) {
				perror("Error writing to cache");
				rv = 0;
				goto err;
			}
			if (l >= cache_size) {
				fprintf(stderr, "Internal error: truncated write to cache\n");
				rv = 0;
				goto err;
			}
			cache += l;
			cache_size -= l;
			total_len += l;
		}
	}

	d->cached = 1;
	d->size = total_len;
	if (total_len > size ) total_len = size;

	/* read from off 0 */
	memcpy(buf, d->buf, total_len);
	rv = total_len;
err:
	if (f)
		fclose(f);
	free(line);
	free(cpuset);
	free(cg);
	return rv;
}

static int proc_stat_read(char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = (struct file_info *)fi->fh;
	char *cg;
	char *cpuset = NULL;
	char *line = NULL;
	size_t linelen = 0, total_len = 0, rv = 0;
	int curcpu = -1; /* cpu numbering starts at 0 */
	unsigned long user = 0, nice = 0, system = 0, idle = 0, iowait = 0, irq = 0, softirq = 0, steal = 0, guest = 0;
	unsigned long user_sum = 0, nice_sum = 0, system_sum = 0, idle_sum = 0, iowait_sum = 0,
					irq_sum = 0, softirq_sum = 0, steal_sum = 0, guest_sum = 0;
#define CPUALL_MAX_SIZE BUF_RESERVE_SIZE
	char cpuall[CPUALL_MAX_SIZE];
	/* reserve for cpu all */
	char *cache = d->buf + CPUALL_MAX_SIZE;
	size_t cache_size = d->buflen - CPUALL_MAX_SIZE;
	FILE *f = NULL;

	if (offset){
		if (offset > d->size)
			return -EINVAL;
		if (!d->cached)
			return 0;
		int left = d->size - offset;
		total_len = left > size ? size: left;
		memcpy(buf, d->buf + offset, total_len);
		return total_len;
	}

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 0)
		initpid = fc->pid;
	cg = get_pid_cgroup(initpid, "cpuset");
	if (!cg)
		return read_file("/proc/stat", buf, size, d);
	prune_init_slice(cg);

	cpuset = get_cpuset(cg);
	if (!cpuset)
		goto err;

	f = fopen("/proc/stat", "r");
	if (!f)
		goto err;

	//skip first line
	if (getline(&line, &linelen, f) < 0) {
		fprintf(stderr, "proc_stat_read read first line failed\n");
		goto err;
	}

	while (getline(&line, &linelen, f) != -1) {
		size_t l;
		int cpu;
		char cpu_char[10]; /* That's a lot of cores */
		char *c;

		if (sscanf(line, "cpu%9[^ ]", cpu_char) != 1) {
			/* not a ^cpuN line containing a number N, just print it */
			l = snprintf(cache, cache_size, "%s", line);
			if (l < 0) {
				perror("Error writing to cache");
				rv = 0;
				goto err;
			}
			if (l >= cache_size) {
				fprintf(stderr, "Internal error: truncated write to cache\n");
				rv = 0;
				goto err;
			}
			cache += l;
			cache_size -= l;
			total_len += l;
			continue;
		}

		if (sscanf(cpu_char, "%d", &cpu) != 1)
			continue;
		if (!cpu_in_cpuset(cpu, cpuset))
			continue;
		curcpu ++;

		c = strchr(line, ' ');
		if (!c)
			continue;
		l = snprintf(cache, cache_size, "cpu%d%s", curcpu, c);
		if (l < 0) {
			perror("Error writing to cache");
			rv = 0;
			goto err;

		}
		if (l >= cache_size) {
			fprintf(stderr, "Internal error: truncated write to cache\n");
			rv = 0;
			goto err;
		}

		cache += l;
		cache_size -= l;
		total_len += l;

		if (sscanf(line, "%*s %lu %lu %lu %lu %lu %lu %lu %lu %lu", &user, &nice, &system, &idle, &iowait, &irq,
			&softirq, &steal, &guest) != 9)
			continue;
		user_sum += user;
		nice_sum += nice;
		system_sum += system;
		idle_sum += idle;
		iowait_sum += iowait;
		irq_sum += irq;
		softirq_sum += softirq;
		steal_sum += steal;
		guest_sum += guest;
	}

	cache = d->buf;

	int cpuall_len = snprintf(cpuall, CPUALL_MAX_SIZE, "%s %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
		"cpu ", user_sum, nice_sum, system_sum, idle_sum, iowait_sum, irq_sum, softirq_sum, steal_sum, guest_sum);
	if (cpuall_len > 0 && cpuall_len < CPUALL_MAX_SIZE){
		memcpy(cache, cpuall, cpuall_len);
		cache += cpuall_len;
	} else{
		/* shouldn't happen */
		fprintf(stderr, "proc_stat_read copy cpuall failed, cpuall_len=%d\n", cpuall_len);
		cpuall_len = 0;
	}

	memmove(cache, d->buf + CPUALL_MAX_SIZE, total_len);
	total_len += cpuall_len;
	d->cached = 1;
	d->size = total_len;
	if (total_len > size ) total_len = size;

	memcpy(buf, d->buf, total_len);
	rv = total_len;

err:
	if (f)
		fclose(f);
	free(line);
	free(cpuset);
	free(cg);
	return rv;
}

static long int getreaperage(pid_t pid)
{
	char fnam[100];
	struct stat sb;
	int ret;
	pid_t qpid;

	qpid = lookup_initpid_in_store(pid);
	if (qpid <= 0)
		return 0;

	ret = snprintf(fnam, 100, "/proc/%d", qpid);
	if (ret < 0 || ret >= 100)
		return 0;

	if (lstat(fnam, &sb) < 0)
		return 0;

	return time(NULL) - sb.st_ctime;
}

static unsigned long get_reaper_busy(pid_t task)
{
	pid_t initpid = lookup_initpid_in_store(task);
	char *cgroup = NULL, *usage_str = NULL;
	unsigned long usage = 0;

	if (initpid <= 0)
		return 0;

	cgroup = get_pid_cgroup(initpid, "cpuacct");
	if (!cgroup)
		goto out;
	prune_init_slice(cgroup);
	if (!cgfs_get_value("cpuacct", cgroup, "cpuacct.usage", &usage_str))
		goto out;
	usage = strtoul(usage_str, NULL, 10);
	usage /= 1000000000;

out:
	free(cgroup);
	free(usage_str);
	return usage;
}

#if RELOADTEST
void iwashere(void)
{
	char *name, *cwd = get_current_dir_name();
	size_t len;
	int fd;

	if (!cwd)
		exit(1);
	len = strlen(cwd) + strlen("/iwashere") + 1;
	name = alloca(len);
	snprintf(name, len, "%s/iwashere", cwd);
	free(cwd);
	fd = creat(name, 0755);
	if (fd >= 0)
		close(fd);
}
#endif

/*
 * We read /proc/uptime and reuse its second field.
 * For the first field, we use the mtime for the reaper for
 * the calling pid as returned by getreaperage
 */
static int proc_uptime_read(char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = (struct file_info *)fi->fh;
	long int reaperage = getreaperage(fc->pid);
	unsigned long int busytime = get_reaper_busy(fc->pid), idletime;
	char *cache = d->buf;
	size_t total_len = 0;

#if RELOADTEST
	iwashere();
#endif

	if (offset){
		if (offset > d->size)
			return -EINVAL;
		if (!d->cached)
			return 0;
		int left = d->size - offset;
		total_len = left > size ? size: left;
		memcpy(buf, cache + offset, total_len);
		return total_len;
	}

	idletime = reaperage - busytime;
	if (idletime > reaperage)
		idletime = reaperage;

	total_len = snprintf(d->buf, d->size, "%ld.0 %lu.0\n", reaperage, idletime);
	if (total_len < 0){
		perror("Error writing to cache");
		return 0;
	}

	d->size = (int)total_len;
	d->cached = 1;

	if (total_len > size) total_len = size;

	memcpy(buf, d->buf, total_len);
	return total_len;
}

static int proc_diskstats_read(char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	char dev_name[72];
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = (struct file_info *)fi->fh;
	char *cg;
	char *io_serviced_str = NULL, *io_merged_str = NULL, *io_service_bytes_str = NULL,
			*io_wait_time_str = NULL, *io_service_time_str = NULL;
	unsigned long read = 0, write = 0;
	unsigned long read_merged = 0, write_merged = 0;
	unsigned long read_sectors = 0, write_sectors = 0;
	unsigned long read_ticks = 0, write_ticks = 0;
	unsigned long ios_pgr = 0, tot_ticks = 0, rq_ticks = 0;
	unsigned long rd_svctm = 0, wr_svctm = 0, rd_wait = 0, wr_wait = 0;
	char *cache = d->buf;
	size_t cache_size = d->buflen;
	char *line = NULL;
	size_t linelen = 0, total_len = 0, rv = 0;
	unsigned int major = 0, minor = 0;
	int i = 0;
	FILE *f = NULL;

	if (offset){
		if (offset > d->size)
			return -EINVAL;
		if (!d->cached)
			return 0;
		int left = d->size - offset;
		total_len = left > size ? size: left;
		memcpy(buf, cache + offset, total_len);
		return total_len;
	}

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 0)
		initpid = fc->pid;
	cg = get_pid_cgroup(initpid, "blkio");
	if (!cg)
		return read_file("/proc/diskstats", buf, size, d);
	prune_init_slice(cg);

	if (!cgfs_get_value("blkio", cg, "blkio.io_serviced", &io_serviced_str))
		goto err;
	if (!cgfs_get_value("blkio", cg, "blkio.io_merged", &io_merged_str))
		goto err;
	if (!cgfs_get_value("blkio", cg, "blkio.io_service_bytes", &io_service_bytes_str))
		goto err;
	if (!cgfs_get_value("blkio", cg, "blkio.io_wait_time", &io_wait_time_str))
		goto err;
	if (!cgfs_get_value("blkio", cg, "blkio.io_service_time", &io_service_time_str))
		goto err;


	f = fopen("/proc/diskstats", "r");
	if (!f)
		goto err;

	while (getline(&line, &linelen, f) != -1) {
		size_t l;
		char *printme, lbuf[256];

		i = sscanf(line, "%u %u %71s", &major, &minor, dev_name);
		if(i == 3){
			get_blkio_io_value(io_serviced_str, major, minor, "Read", &read);
			get_blkio_io_value(io_serviced_str, major, minor, "Write", &write);
			get_blkio_io_value(io_merged_str, major, minor, "Read", &read_merged);
			get_blkio_io_value(io_merged_str, major, minor, "Write", &write_merged);
			get_blkio_io_value(io_service_bytes_str, major, minor, "Read", &read_sectors);
			read_sectors = read_sectors/512;
			get_blkio_io_value(io_service_bytes_str, major, minor, "Write", &write_sectors);
			write_sectors = write_sectors/512;

			get_blkio_io_value(io_service_time_str, major, minor, "Read", &rd_svctm);
			rd_svctm = rd_svctm/1000000;
			get_blkio_io_value(io_wait_time_str, major, minor, "Read", &rd_wait);
			rd_wait = rd_wait/1000000;
			read_ticks = rd_svctm + rd_wait;

			get_blkio_io_value(io_service_time_str, major, minor, "Write", &wr_svctm);
			wr_svctm =  wr_svctm/1000000;
			get_blkio_io_value(io_wait_time_str, major, minor, "Write", &wr_wait);
			wr_wait =  wr_wait/1000000;
			write_ticks = wr_svctm + wr_wait;

			get_blkio_io_value(io_service_time_str, major, minor, "Total", &tot_ticks);
			tot_ticks =  tot_ticks/1000000;
		}else{
			continue;
		}

		memset(lbuf, 0, 256);
		if (read || write || read_merged || write_merged || read_sectors || write_sectors || read_ticks || write_ticks) {
			snprintf(lbuf, 256, "%u       %u %s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
				major, minor, dev_name, read, read_merged, read_sectors, read_ticks,
				write, write_merged, write_sectors, write_ticks, ios_pgr, tot_ticks, rq_ticks);
			printme = lbuf;
		} else
			continue;

		l = snprintf(cache, cache_size, "%s", printme);
		if (l < 0) {
			perror("Error writing to fuse buf");
			rv = 0;
			goto err;
		}
		if (l >= cache_size) {
			fprintf(stderr, "Internal error: truncated write to cache\n");
			rv = 0;
			goto err;
		}
		cache += l;
		cache_size -= l;
		total_len += l;
	}

	d->cached = 1;
	d->size = total_len;
	if (total_len > size ) total_len = size;
	memcpy(buf, d->buf, total_len);

	rv = total_len;
err:
	free(cg);
	if (f)
		fclose(f);
	free(line);
	free(io_serviced_str);
	free(io_merged_str);
	free(io_service_bytes_str);
	free(io_wait_time_str);
	free(io_service_time_str);
	return rv;
}

static int proc_swaps_read(char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = (struct file_info *)fi->fh;
	char *cg = NULL;
	char *memswlimit_str = NULL, *memlimit_str = NULL, *memusage_str = NULL, *memswusage_str = NULL,
             *memswlimit_default_str = NULL, *memswusage_default_str = NULL;
	unsigned long memswlimit = 0, memlimit = 0, memusage = 0, memswusage = 0, swap_total = 0, swap_free = 0;
	size_t total_len = 0, rv = 0;
	char *cache = d->buf;

	if (offset) {
		if (offset > d->size)
			return -EINVAL;
		if (!d->cached)
			return 0;
		int left = d->size - offset;
		total_len = left > size ? size: left;
		memcpy(buf, cache + offset, total_len);
		return total_len;
	}

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 0)
		initpid = fc->pid;
	cg = get_pid_cgroup(initpid, "memory");
	if (!cg)
		return read_file("/proc/swaps", buf, size, d);
	prune_init_slice(cg);

	if (!cgfs_get_value("memory", cg, "memory.limit_in_bytes", &memlimit_str))
		goto err;

	if (!cgfs_get_value("memory", cg, "memory.usage_in_bytes", &memusage_str))
		goto err;

	memlimit = strtoul(memlimit_str, NULL, 10);
	memusage = strtoul(memusage_str, NULL, 10);

	if (cgfs_get_value("memory", cg, "memory.memsw.usage_in_bytes", &memswusage_str) &&
	    cgfs_get_value("memory", cg, "memory.memsw.limit_in_bytes", &memswlimit_str)) {

                /* If swap accounting is turned on, then default value is assumed to be that of cgroup / */
                if (!cgfs_get_value("memory", "/", "memory.memsw.limit_in_bytes", &memswlimit_default_str))
                    goto err;
                if (!cgfs_get_value("memory", "/", "memory.memsw.usage_in_bytes", &memswusage_default_str))
                    goto err;

		memswlimit = strtoul(memswlimit_str, NULL, 10);
		memswusage = strtoul(memswusage_str, NULL, 10);

                if (!strcmp(memswlimit_str, memswlimit_default_str))
                    memswlimit = 0;
                if (!strcmp(memswusage_str, memswusage_default_str))
                    memswusage = 0;

		swap_total = (memswlimit - memlimit) / 1024;
		swap_free = (memswusage - memusage) / 1024;
	}

	total_len = snprintf(d->buf, d->size, "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n");

	/* When no mem + swap limit is specified or swapaccount=0*/
	if (!memswlimit) {
		char *line = NULL;
		size_t linelen = 0;
		FILE *f = fopen("/proc/meminfo", "r");

		if (!f)
			goto err;

		while (getline(&line, &linelen, f) != -1) {
			if (startswith(line, "SwapTotal:")) {
				sscanf(line, "SwapTotal:      %8lu kB", &swap_total);
			} else if (startswith(line, "SwapFree:")) {
				sscanf(line, "SwapFree:      %8lu kB", &swap_free);
			}
		}

		free(line);
		fclose(f);
	}

	if (swap_total > 0) {
		total_len += snprintf(d->buf + total_len, d->size - total_len,
				 "none%*svirtual\t\t%lu\t%lu\t0\n", 36, " ",
				 swap_total, swap_free);
	}

	if (total_len < 0) {
		perror("Error writing to cache");
		rv = 0;
		goto err;
	}

	d->cached = 1;
	d->size = (int)total_len;

	if (total_len > size) total_len = size;
	memcpy(buf, d->buf, total_len);
	rv = total_len;

err:
	free(cg);
	free(memswlimit_str);
	free(memlimit_str);
	free(memusage_str);
	free(memswusage_str);
	free(memswusage_default_str);
	free(memswlimit_default_str);
	return rv;
}

static off_t get_procfile_size(const char *which)
{
	FILE *f = fopen(which, "r");
	char *line = NULL;
	size_t len = 0;
	ssize_t sz, answer = 0;
	if (!f)
		return 0;

	while ((sz = getline(&line, &len, f)) != -1)
		answer += sz;
	fclose (f);
	free(line);

	return answer;
}

int proc_getattr(const char *path, struct stat *sb)
{
	struct timespec now;

	memset(sb, 0, sizeof(struct stat));
	if (clock_gettime(CLOCK_REALTIME, &now) < 0)
		return -EINVAL;
	sb->st_uid = sb->st_gid = 0;
	sb->st_atim = sb->st_mtim = sb->st_ctim = now;
	if (strcmp(path, "/proc") == 0) {
		sb->st_mode = S_IFDIR | 00555;
		sb->st_nlink = 2;
		return 0;
	}
	if (strcmp(path, "/proc/meminfo") == 0 ||
			strcmp(path, "/proc/cpuinfo") == 0 ||
			strcmp(path, "/proc/uptime") == 0 ||
			strcmp(path, "/proc/stat") == 0 ||
			strcmp(path, "/proc/diskstats") == 0 ||
			strcmp(path, "/proc/swaps") == 0) {
		sb->st_size = 0;
		sb->st_mode = S_IFREG | 00444;
		sb->st_nlink = 1;
		return 0;
	}

	return -ENOENT;
}

int proc_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
		struct fuse_file_info *fi)
{
	if (filler(buf, "cpuinfo", NULL, 0) != 0 ||
				filler(buf, "meminfo", NULL, 0) != 0 ||
				filler(buf, "stat", NULL, 0) != 0 ||
				filler(buf, "uptime", NULL, 0) != 0 ||
				filler(buf, "diskstats", NULL, 0) != 0 ||
				filler(buf, "swaps", NULL, 0) != 0)
		return -EINVAL;
	return 0;
}

int proc_open(const char *path, struct fuse_file_info *fi)
{
	int type = -1;
	struct file_info *info;

	if (strcmp(path, "/proc/meminfo") == 0)
		type = LXC_TYPE_PROC_MEMINFO;
	else if (strcmp(path, "/proc/cpuinfo") == 0)
		type = LXC_TYPE_PROC_CPUINFO;
	else if (strcmp(path, "/proc/uptime") == 0)
		type = LXC_TYPE_PROC_UPTIME;
	else if (strcmp(path, "/proc/stat") == 0)
		type = LXC_TYPE_PROC_STAT;
	else if (strcmp(path, "/proc/diskstats") == 0)
		type = LXC_TYPE_PROC_DISKSTATS;
	else if (strcmp(path, "/proc/swaps") == 0)
		type = LXC_TYPE_PROC_SWAPS;
	if (type == -1)
		return -ENOENT;

	info = malloc(sizeof(*info));
	if (!info)
		return -ENOMEM;

	memset(info, 0, sizeof(*info));
	info->type = type;

	info->buflen = get_procfile_size(path) + BUF_RESERVE_SIZE;
	do {
		info->buf = malloc(info->buflen);
	} while (!info->buf);
	memset(info->buf, 0, info->buflen);
	/* set actual size to buffer size */
	info->size = info->buflen;

	fi->fh = (unsigned long)info;
	return 0;
}

int proc_access(const char *path, int mask)
{
	/* these are all read-only */
	if ((mask & ~R_OK) != 0)
		return -EPERM;
	return 0;
}

int proc_release(const char *path, struct fuse_file_info *fi)
{
	struct file_info *f = (struct file_info *)fi->fh;

	do_release_file_info(f);
	return 0;
}

int proc_read(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	struct file_info *f = (struct file_info *) fi->fh;

	switch (f->type) {
	case LXC_TYPE_PROC_MEMINFO:
		return proc_meminfo_read(buf, size, offset, fi);
	case LXC_TYPE_PROC_CPUINFO:
		return proc_cpuinfo_read(buf, size, offset, fi);
	case LXC_TYPE_PROC_UPTIME:
		return proc_uptime_read(buf, size, offset, fi);
	case LXC_TYPE_PROC_STAT:
		return proc_stat_read(buf, size, offset, fi);
	case LXC_TYPE_PROC_DISKSTATS:
		return proc_diskstats_read(buf, size, offset, fi);
	case LXC_TYPE_PROC_SWAPS:
		return proc_swaps_read(buf, size, offset, fi);
	default:
		return -EINVAL;
	}
}

static void __attribute__((constructor)) collect_subsystems(void)
{
	FILE *f;
	char *line = NULL;
	size_t len = 0;

	if ((f = fopen("/proc/self/cgroup", "r")) == NULL) {
		fprintf(stderr, "Error opening /proc/self/cgroup: %s\n", strerror(errno));
		return;
	}
	while (getline(&line, &len, f) != -1) {
		char *p, *p2;

		p = strchr(line, ':');
		if (!p)
			goto out;
		*(p++) = '\0';

		p2 = strrchr(p, ':');
		if (!p2)
			goto out;
		*p2 = '\0';

		if (!store_hierarchy(line, p))
			goto out;
	}

	print_subsystems();

out:
	free(line);
	fclose(f);
}

static void __attribute__((destructor)) free_subsystems(void)
{
	int i;

	for (i = 0; i < num_hierarchies; i++)
		if (hierarchies[i])
			free(hierarchies[i]);
	free(hierarchies);
}
