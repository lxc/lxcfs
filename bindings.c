/* lxcfs
 *
 * Copyright © 2014-2016 Canonical, Inc
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
 *
 * See COPYING file for details.
 */

#define FUSE_USE_VERSION 26

#define __STDC_FORMAT_MACROS
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <inttypes.h>
#include <libgen.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wait.h>
#include <linux/magic.h>
#include <linux/sched.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/vfs.h>

#include "bindings.h"
#include "memory_utils.h"
#include "config.h"

/* Define pivot_root() if missing from the C library */
#ifndef HAVE_PIVOT_ROOT
static int pivot_root(const char * new_root, const char * put_old)
{
#ifdef __NR_pivot_root
return syscall(__NR_pivot_root, new_root, put_old);
#else
errno = ENOSYS;
return -1;
#endif
}
#else
extern int pivot_root(const char * new_root, const char * put_old);
#endif

struct cpuacct_usage {
	uint64_t user;
	uint64_t system;
	uint64_t idle;
	bool online;
};

struct memory_stat {
	unsigned long long hierarchical_memory_limit;
	unsigned long long hierarchical_memsw_limit;
	unsigned long long total_cache;
	unsigned long long total_rss;
	unsigned long long total_rss_huge;
	unsigned long long total_shmem;
	unsigned long long total_mapped_file;
	unsigned long long total_dirty;
	unsigned long long total_writeback;
	unsigned long long total_swap;
	unsigned long long total_pgpgin;
	unsigned long long total_pgpgout;
	unsigned long long total_pgfault;
	unsigned long long total_pgmajfault;
	unsigned long long total_inactive_anon;                                                                                     
	unsigned long long total_active_anon;
	unsigned long long total_inactive_file;
	unsigned long long total_active_file;
	unsigned long long total_unevictable;
};

/* The function of hash table.*/
#define LOAD_SIZE 100 /*the size of hash_table */
#define FLUSH_TIME 5  /*the flush rate */
#define DEPTH_DIR 3   /*the depth of per cgroup */
/* The function of calculate loadavg .*/
#define FSHIFT		11		/* nr of bits of precision */
#define FIXED_1		(1<<FSHIFT)	/* 1.0 as fixed-point */
#define EXP_1		1884		/* 1/exp(5sec/1min) as fixed-point */
#define EXP_5		2014		/* 1/exp(5sec/5min) */
#define EXP_15		2037		/* 1/exp(5sec/15min) */
#define LOAD_INT(x) ((x) >> FSHIFT)
#define LOAD_FRAC(x) LOAD_INT(((x) & (FIXED_1-1)) * 100)
/*
 * This parameter is used for proc_loadavg_read().
 * 1 means use loadavg, 0 means not use.
 */
static int loadavg = 0;
static volatile sig_atomic_t loadavg_stop = 0;
static int calc_hash(const char *name)
{
	unsigned int hash = 0;
	unsigned int x = 0;
	/* ELFHash algorithm. */
	while (*name) {
		hash = (hash << 4) + *name++;
		x = hash & 0xf0000000;
		if (x != 0)
			hash ^= (x >> 24);
		hash &= ~x;
	}
	return (hash & 0x7fffffff);
}

struct load_node {
	char *cg;  /*cg */
	unsigned long avenrun[3];		/* Load averages */
	unsigned int run_pid;
	unsigned int total_pid;
	unsigned int last_pid;
	int cfd; /* The file descriptor of the mounted cgroup */
	struct  load_node *next;
	struct  load_node **pre;
};

struct load_head {
	/*
	 * The lock is about insert load_node and refresh load_node.To the first
	 * load_node of each hash bucket, insert and refresh in this hash bucket is
	 * mutually exclusive.
	 */
	pthread_mutex_t lock;
	/*
	 * The rdlock is about read loadavg and delete load_node.To each hash
	 * bucket, read and delete is mutually exclusive. But at the same time, we
	 * allow paratactic read operation. This rdlock is at list level.
	 */
	pthread_rwlock_t rdlock;
	/*
	 * The rilock is about read loadavg and insert load_node.To the first
	 * load_node of each hash bucket, read and insert is mutually exclusive.
	 * But at the same time, we allow paratactic read operation.
	 */
	pthread_rwlock_t rilock;
	struct load_node *next;
};

static struct load_head load_hash[LOAD_SIZE]; /* hash table */
/*
 * init_load initialize the hash table.
 * Return 0 on success, return -1 on failure.
 */
static int init_load(void)
{
	int i;
	int ret;

	for (i = 0; i < LOAD_SIZE; i++) {
		load_hash[i].next = NULL;
		ret = pthread_mutex_init(&load_hash[i].lock, NULL);
		if (ret != 0) {
			lxcfs_error("%s\n", "Failed to initialize lock");
			goto out3;
		}
		ret = pthread_rwlock_init(&load_hash[i].rdlock, NULL);
		if (ret != 0) {
			lxcfs_error("%s\n", "Failed to initialize rdlock");
			goto out2;
		}
		ret = pthread_rwlock_init(&load_hash[i].rilock, NULL);
		if (ret != 0) {
			lxcfs_error("%s\n", "Failed to initialize rilock");
			goto out1;
		}
	}
	return 0;
out1:
	pthread_rwlock_destroy(&load_hash[i].rdlock);
out2:
	pthread_mutex_destroy(&load_hash[i].lock);
out3:
	while (i > 0) {
		i--;
		pthread_mutex_destroy(&load_hash[i].lock);
		pthread_rwlock_destroy(&load_hash[i].rdlock);
		pthread_rwlock_destroy(&load_hash[i].rilock);
	}
	return -1;
}

static void insert_node(struct load_node **n, int locate)
{
	struct load_node *f;

	pthread_mutex_lock(&load_hash[locate].lock);
	pthread_rwlock_wrlock(&load_hash[locate].rilock);
	f = load_hash[locate].next;
	load_hash[locate].next = *n;

	(*n)->pre = &(load_hash[locate].next);
	if (f)
		f->pre = &((*n)->next);
	(*n)->next = f;
	pthread_mutex_unlock(&load_hash[locate].lock);
	pthread_rwlock_unlock(&load_hash[locate].rilock);
}
/*
 * locate_node() finds special node. Not return NULL means success.
 * It should be noted that rdlock isn't unlocked at the end of code
 * because this function is used to read special node. Delete is not
 * allowed before read has ended.
 * unlock rdlock only in proc_loadavg_read().
 */
static struct load_node *locate_node(char *cg, int locate)
{
	struct load_node *f = NULL;
	int i = 0;

	pthread_rwlock_rdlock(&load_hash[locate].rilock);
	pthread_rwlock_rdlock(&load_hash[locate].rdlock);
	if (load_hash[locate].next == NULL) {
		pthread_rwlock_unlock(&load_hash[locate].rilock);
		return f;
	}
	f = load_hash[locate].next;
	pthread_rwlock_unlock(&load_hash[locate].rilock);
	while (f && ((i = strcmp(f->cg, cg)) != 0))
		f = f->next;
	return f;
}
/* Delete the load_node n and return the next node of it. */
static struct load_node *del_node(struct load_node *n, int locate)
{
	struct load_node *g;

	pthread_rwlock_wrlock(&load_hash[locate].rdlock);
	if (n->next == NULL) {
		*(n->pre) = NULL;
	} else {
		*(n->pre) = n->next;
		n->next->pre = n->pre;
	}
	g = n->next;
	free(n->cg);
	free(n);
	pthread_rwlock_unlock(&load_hash[locate].rdlock);
	return g;
}

static void load_free(void)
{
	int i;
	struct load_node *f, *p;

	for (i = 0; i < LOAD_SIZE; i++) {
		pthread_mutex_lock(&load_hash[i].lock);
		pthread_rwlock_wrlock(&load_hash[i].rilock);
		pthread_rwlock_wrlock(&load_hash[i].rdlock);
		if (load_hash[i].next == NULL) {
			pthread_mutex_unlock(&load_hash[i].lock);
			pthread_mutex_destroy(&load_hash[i].lock);
			pthread_rwlock_unlock(&load_hash[i].rilock);
			pthread_rwlock_destroy(&load_hash[i].rilock);
			pthread_rwlock_unlock(&load_hash[i].rdlock);
			pthread_rwlock_destroy(&load_hash[i].rdlock);
			continue;
		}
		for (f = load_hash[i].next; f; ) {
			free(f->cg);
			p = f->next;
			free(f);
			f = p;
		}
		pthread_mutex_unlock(&load_hash[i].lock);
		pthread_mutex_destroy(&load_hash[i].lock);
		pthread_rwlock_unlock(&load_hash[i].rilock);
		pthread_rwlock_destroy(&load_hash[i].rilock);
		pthread_rwlock_unlock(&load_hash[i].rdlock);
		pthread_rwlock_destroy(&load_hash[i].rdlock);
	}
}

/* Data for CPU view */
struct cg_proc_stat {
	char *cg;
	struct cpuacct_usage *usage; // Real usage as read from the host's /proc/stat
	struct cpuacct_usage *view; // Usage stats reported to the container
	int cpu_count;
	pthread_mutex_t lock; // For node manipulation
	struct cg_proc_stat *next;
};

struct cg_proc_stat_head {
	struct cg_proc_stat *next;
	time_t lastcheck;

	/*
	 * For access to the list. Reading can be parallel, pruning is exclusive.
	 */
	pthread_rwlock_t lock;
};

#define CPUVIEW_HASH_SIZE 100
static struct cg_proc_stat_head *proc_stat_history[CPUVIEW_HASH_SIZE];

static bool cpuview_init_head(struct cg_proc_stat_head **head)
{
	*head = malloc(sizeof(struct cg_proc_stat_head));
	if (!(*head)) {
		lxcfs_error("%s\n", strerror(errno));
		return false;
	}

	(*head)->lastcheck = time(NULL);
	(*head)->next = NULL;

	if (pthread_rwlock_init(&(*head)->lock, NULL) != 0) {
		lxcfs_error("%s\n", "Failed to initialize list lock");
		free(*head);
		return false;
	}

	return true;
}

static bool init_cpuview()
{
	int i;

	for (i = 0; i < CPUVIEW_HASH_SIZE; i++)
		proc_stat_history[i] = NULL;

	for (i = 0; i < CPUVIEW_HASH_SIZE; i++) {
		if (!cpuview_init_head(&proc_stat_history[i]))
			goto err;
	}

	return true;

err:
	for (i = 0; i < CPUVIEW_HASH_SIZE; i++) {
		if (proc_stat_history[i]) {
			free(proc_stat_history[i]);
			proc_stat_history[i] = NULL;
		}
	}

	return false;
}

static void free_proc_stat_node(struct cg_proc_stat *node)
{
	pthread_mutex_destroy(&node->lock);
	free(node->cg);
	free(node->usage);
	free(node->view);
	free(node);
}

static void cpuview_free_head(struct cg_proc_stat_head *head)
{
	struct cg_proc_stat *node, *tmp;

	if (head->next) {
		node = head->next;

		for (;;) {
			tmp = node;
			node = node->next;
			free_proc_stat_node(tmp);

			if (!node)
				break;
		}
	}

	pthread_rwlock_destroy(&head->lock);
	free(head);
}

static void free_cpuview()
{
	int i;

	for (i = 0; i < CPUVIEW_HASH_SIZE; i++) {
		if (proc_stat_history[i])
			cpuview_free_head(proc_stat_history[i]);
	}
}

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
		lxcfs_error("returned:%d %s\n", ret, strerror(ret));
		exit(1);
	}
}

/* READ-ONLY after __constructor__ collect_and_mount_subsystems() has run.
 * Number of hierarchies mounted. */
static int num_hierarchies;

/* READ-ONLY after __constructor__ collect_and_mount_subsystems() has run.
 * Hierachies mounted {cpuset, blkio, ...}:
 * Initialized via __constructor__ collect_and_mount_subsystems(). */
static char **hierarchies;

/* READ-ONLY after __constructor__ collect_and_mount_subsystems() has run.
 * Open file descriptors:
 * @fd_hierarchies[i] refers to cgroup @hierarchies[i]. They are mounted in a
 * private mount namespace.
 * Initialized via __constructor__ collect_and_mount_subsystems().
 * @fd_hierarchies[i] can be used to perform file operations on the cgroup
 * mounts and respective files in the private namespace even when located in
 * another namespace using the *at() family of functions
 * {openat(), fchownat(), ...}. */
static int *fd_hierarchies;
static int cgroup_mount_ns_fd = -1;

static void unlock_mutex(pthread_mutex_t *l)
{
	int ret;

	if ((ret = pthread_mutex_unlock(l)) != 0) {
		lxcfs_error("returned:%d %s\n", ret, strerror(ret));
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

	lxcfs_debug("Comparing ctime %ld == %ld for pid %d.\n", e->ctime,
		    initsb.st_ctime, e->initpid);

	if (e->ctime != initsb.st_ctime)
		return false;
	return true;
}

/* Must be called under store_lock */
static void remove_initpid(struct pidns_init_store *e)
{
	struct pidns_init_store *tmp;
	int h;

	lxcfs_debug("Remove_initpid: removing entry for %d.\n", e->initpid);

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

	lxcfs_debug("%s\n", "Pruning.");

	last_prune = now;
	threshold = now - 2 * PURGE_SECS;

	for (i = 0; i < PIDNS_HASH_SIZE; i++) {
		for (prev = NULL, e = pidns_hash_table[i]; e; ) {
			if (e->lastcheck < threshold) {

				lxcfs_debug("Removing cached entry for %d.\n", e->initpid);

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

	lxcfs_debug("Save_initpid: adding entry for %d.\n", pid);

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

static int is_dir(const char *path, int fd)
{
	struct stat statbuf;
	int ret = fstatat(fd, path, &statbuf, fd);
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

static char *slurp_file(const char *from, int fd)
{
	char *line = NULL;
	char *contents = NULL;
	FILE *f = fdopen(fd, "r");
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

static int preserve_ns(const int pid, const char *ns)
{
	int ret;
/* 5 /proc + 21 /int_as_str + 3 /ns + 20 /NS_NAME + 1 \0 */
#define __NS_PATH_LEN 50
	char path[__NS_PATH_LEN];

	/* This way we can use this function to also check whether namespaces
	 * are supported by the kernel by passing in the NULL or the empty
	 * string.
	 */
	ret = snprintf(path, __NS_PATH_LEN, "/proc/%d/ns%s%s", pid,
		       !ns || strcmp(ns, "") == 0 ? "" : "/",
		       !ns || strcmp(ns, "") == 0 ? "" : ns);
	if (ret < 0 || (size_t)ret >= __NS_PATH_LEN) {
		errno = EFBIG;
		return -1;
	}

	return open(path, O_RDONLY | O_CLOEXEC);
}

/**
 * in_same_namespace - Check whether two processes are in the same namespace.
 * @pid1 - PID of the first process.
 * @pid2 - PID of the second process.
 * @ns   - Name of the namespace to check. Must correspond to one of the names
 *         for the namespaces as shown in /proc/<pid/ns/
 *
 * If the two processes are not in the same namespace returns an fd to the
 * namespace of the second process identified by @pid2. If the two processes are
 * in the same namespace returns -EINVAL, -1 if an error occurred.
 */
static int in_same_namespace(pid_t pid1, pid_t pid2, const char *ns)
{
	__do_close_prot_errno int ns_fd1 = -1, ns_fd2 = -1;
	int ret = -1;
	struct stat ns_st1, ns_st2;

	ns_fd1 = preserve_ns(pid1, ns);
	if (ns_fd1 < 0) {
		/* The kernel does not support this namespace. This is not an
		 * error.
		 */
		if (errno == ENOENT)
			return -EINVAL;

		return -1;
	}

	ns_fd2 = preserve_ns(pid2, ns);
	if (ns_fd2 < 0)
		return -1;

	ret = fstat(ns_fd1, &ns_st1);
	if (ret < 0)
		return -1;

	ret = fstat(ns_fd2, &ns_st2);
	if (ret < 0)
		return -1;

	/* processes are in the same namespace */
	if ((ns_st1.st_dev == ns_st2.st_dev) && (ns_st1.st_ino == ns_st2.st_ino))
		return -EINVAL;

	/* processes are in different namespaces */
	return move_fd(ns_fd2);
}

static bool is_shared_pidns(pid_t pid)
{
	if (pid != 1)
		return false;

	if (in_same_namespace(pid, getpid(), "pid") == -EINVAL)
		return true;

	return false;
}

static bool write_string(const char *fnam, const char *string, int fd)
{
	FILE *f;
	size_t len, ret;

	f = fdopen(fd, "w");
	if (!f)
		return false;

	len = strlen(string);
	ret = fwrite(string, 1, len, f);
	if (ret != len) {
		lxcfs_error("%s - Error writing \"%s\" to \"%s\"\n",
			    strerror(errno), string, fnam);
		fclose(f);
		return false;
	}

	if (fclose(f) < 0) {
		lxcfs_error("%s - Failed to close \"%s\"\n", strerror(errno), fnam);
		return false;
	}

	return true;
}

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
			lxcfs_error("%s\n", strerror(errno));
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

	fprintf(stderr, "mount namespace: %d\n", cgroup_mount_ns_fd);
	fprintf(stderr, "hierarchies:\n");
	for (i = 0; i < num_hierarchies; i++) {
		if (hierarchies[i])
			fprintf(stderr, " %2d: fd: %3d: %s\n", i,
				fd_hierarchies[i], hierarchies[i]);
	}
}

static bool in_comma_list(const char *needle, const char *haystack)
{
	const char *s = haystack, *e;
	size_t nlen = strlen(needle);

	while (*s && (e = strchr(s, ','))) {
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
/* Return the mounted controller and store the corresponding open file descriptor
 * referring to the controller mountpoint in the private lxcfs namespace in
 * @cfd.
 */
static char *find_mounted_controller(const char *controller, int *cfd)
{
	int i;

	for (i = 0; i < num_hierarchies; i++) {
		if (!hierarchies[i])
			continue;
		if (strcmp(hierarchies[i], controller) == 0) {
			*cfd = fd_hierarchies[i];
			return hierarchies[i];
		}
		if (in_comma_list(controller, hierarchies[i])) {
			*cfd = fd_hierarchies[i];
			return hierarchies[i];
		}
	}

	return NULL;
}

bool cgfs_set_value(const char *controller, const char *cgroup, const char *file,
		const char *value)
{
	int ret, fd, cfd;
	size_t len;
	char *fnam, *tmpc;

	tmpc = find_mounted_controller(controller, &cfd);
	if (!tmpc)
		return false;

	/* Make sure we pass a relative path to *at() family of functions.
	 * . + /cgroup + / + file + \0
	 */
	len = strlen(cgroup) + strlen(file) + 3;
	fnam = alloca(len);
	ret = snprintf(fnam, len, "%s%s/%s", *cgroup == '/' ? "." : "", cgroup, file);
	if (ret < 0 || (size_t)ret >= len)
		return false;

	fd = openat(cfd, fnam, O_WRONLY);
	if (fd < 0)
		return false;

	return write_string(fnam, value, fd);
}

// Chown all the files in the cgroup directory.  We do this when we create
// a cgroup on behalf of a user.
static void chown_all_cgroup_files(const char *dirname, uid_t uid, gid_t gid, int fd)
{
	struct dirent *direntp;
	char path[MAXPATHLEN];
	size_t len;
	DIR *d;
	int fd1, ret;

	len = strlen(dirname);
	if (len >= MAXPATHLEN) {
		lxcfs_error("Pathname too long: %s\n", dirname);
		return;
	}

	fd1 = openat(fd, dirname, O_DIRECTORY);
	if (fd1 < 0)
		return;

	d = fdopendir(fd1);
	if (!d) {
		lxcfs_error("Failed to open %s\n", dirname);
		return;
	}

	while ((direntp = readdir(d))) {
		if (!strcmp(direntp->d_name, ".") || !strcmp(direntp->d_name, ".."))
			continue;
		ret = snprintf(path, MAXPATHLEN, "%s/%s", dirname, direntp->d_name);
		if (ret < 0 || ret >= MAXPATHLEN) {
			lxcfs_error("Pathname too long under %s\n", dirname);
			continue;
		}
		if (fchownat(fd, path, uid, gid, 0) < 0)
			lxcfs_error("Failed to chown file %s to %u:%u", path, uid, gid);
	}
	closedir(d);
}

int cgfs_create(const char *controller, const char *cg, uid_t uid, gid_t gid)
{
	int cfd;
	size_t len;
	char *dirnam, *tmpc;

	tmpc = find_mounted_controller(controller, &cfd);
	if (!tmpc)
		return -EINVAL;

	/* Make sure we pass a relative path to *at() family of functions.
	 * . + /cg + \0
	 */
	len = strlen(cg) + 2;
	dirnam = alloca(len);
	snprintf(dirnam, len, "%s%s", *cg == '/' ? "." : "", cg);

	if (mkdirat(cfd, dirnam, 0755) < 0)
		return -errno;

	if (uid == 0 && gid == 0)
		return 0;

	if (fchownat(cfd, dirnam, uid, gid, 0) < 0)
		return -errno;

	chown_all_cgroup_files(dirnam, uid, gid, cfd);

	return 0;
}

static bool recursive_rmdir(const char *dirname, int fd, const int cfd)
{
	struct dirent *direntp;
	DIR *dir;
	bool ret = false;
	char pathname[MAXPATHLEN];
	int dupfd;

	dupfd = dup(fd); // fdopendir() does bad things once it uses an fd.
	if (dupfd < 0)
		return false;

	dir = fdopendir(dupfd);
	if (!dir) {
		lxcfs_debug("Failed to open %s: %s.\n", dirname, strerror(errno));
		close(dupfd);
		return false;
	}

	while ((direntp = readdir(dir))) {
		struct stat mystat;
		int rc;

		if (!strcmp(direntp->d_name, ".") ||
		    !strcmp(direntp->d_name, ".."))
			continue;

		rc = snprintf(pathname, MAXPATHLEN, "%s/%s", dirname, direntp->d_name);
		if (rc < 0 || rc >= MAXPATHLEN) {
			lxcfs_error("%s\n", "Pathname too long.");
			continue;
		}

		rc = fstatat(cfd, pathname, &mystat, AT_SYMLINK_NOFOLLOW);
		if (rc) {
			lxcfs_debug("Failed to stat %s: %s.\n", pathname, strerror(errno));
			continue;
		}
		if (S_ISDIR(mystat.st_mode))
			if (!recursive_rmdir(pathname, fd, cfd))
				lxcfs_debug("Error removing %s.\n", pathname);
	}

	ret = true;
	if (closedir(dir) < 0) {
		lxcfs_error("Failed to close directory %s: %s\n", dirname, strerror(errno));
		ret = false;
	}

	if (unlinkat(cfd, dirname, AT_REMOVEDIR) < 0) {
		lxcfs_debug("Failed to delete %s: %s.\n", dirname, strerror(errno));
		ret = false;
	}

	close(dupfd);

	return ret;
}

bool cgfs_remove(const char *controller, const char *cg)
{
	int fd, cfd;
	size_t len;
	char *dirnam, *tmpc;
	bool bret;

	tmpc = find_mounted_controller(controller, &cfd);
	if (!tmpc)
		return false;

	/* Make sure we pass a relative path to *at() family of functions.
	 * . +  /cg + \0
	 */
	len = strlen(cg) + 2;
	dirnam = alloca(len);
	snprintf(dirnam, len, "%s%s", *cg == '/' ? "." : "", cg);

	fd = openat(cfd, dirnam, O_DIRECTORY);
	if (fd < 0)
		return false;

	bret = recursive_rmdir(dirnam, fd, cfd);
	close(fd);
	return bret;
}

bool cgfs_chmod_file(const char *controller, const char *file, mode_t mode)
{
	int cfd;
	size_t len;
	char *pathname, *tmpc;

	tmpc = find_mounted_controller(controller, &cfd);
	if (!tmpc)
		return false;

	/* Make sure we pass a relative path to *at() family of functions.
	 * . + /file + \0
	 */
	len = strlen(file) + 2;
	pathname = alloca(len);
	snprintf(pathname, len, "%s%s", *file == '/' ? "." : "", file);
	if (fchmodat(cfd, pathname, mode, 0) < 0)
		return false;
	return true;
}

static int chown_tasks_files(const char *dirname, uid_t uid, gid_t gid, int fd)
{
	size_t len;
	char *fname;

	len = strlen(dirname) + strlen("/cgroup.procs") + 1;
	fname = alloca(len);
	snprintf(fname, len, "%s/tasks", dirname);
	if (fchownat(fd, fname, uid, gid, 0) != 0)
		return -errno;
	snprintf(fname, len, "%s/cgroup.procs", dirname);
	if (fchownat(fd, fname, uid, gid, 0) != 0)
		return -errno;
	return 0;
}

int cgfs_chown_file(const char *controller, const char *file, uid_t uid, gid_t gid)
{
	int cfd;
	size_t len;
	char *pathname, *tmpc;

	tmpc = find_mounted_controller(controller, &cfd);
	if (!tmpc)
		return -EINVAL;

	/* Make sure we pass a relative path to *at() family of functions.
	 * . + /file + \0
	 */
	len = strlen(file) + 2;
	pathname = alloca(len);
	snprintf(pathname, len, "%s%s", *file == '/' ? "." : "", file);
	if (fchownat(cfd, pathname, uid, gid, 0) < 0)
		return -errno;

	if (is_dir(pathname, cfd))
		// like cgmanager did, we want to chown the tasks file as well
		return chown_tasks_files(pathname, uid, gid, cfd);

	return 0;
}

FILE *open_pids_file(const char *controller, const char *cgroup)
{
	int fd, cfd;
	size_t len;
	char *pathname, *tmpc;

	tmpc = find_mounted_controller(controller, &cfd);
	if (!tmpc)
		return NULL;

	/* Make sure we pass a relative path to *at() family of functions.
	 * . + /cgroup + / "cgroup.procs" + \0
	 */
	len = strlen(cgroup) + strlen("cgroup.procs") + 3;
	pathname = alloca(len);
	snprintf(pathname, len, "%s%s/cgroup.procs", *cgroup == '/' ? "." : "", cgroup);

	fd = openat(cfd, pathname, O_WRONLY);
	if (fd < 0)
		return NULL;

	return fdopen(fd, "w");
}

static bool cgfs_iterate_cgroup(const char *controller, const char *cgroup, bool directories,
                                void ***list, size_t typesize,
                                void* (*iterator)(const char*, const char*, const char*))
{
	int cfd, fd, ret;
	size_t len;
	char *cg, *tmpc;
	char pathname[MAXPATHLEN];
	size_t sz = 0, asz = 0;
	struct dirent *dirent;
	DIR *dir;

	tmpc = find_mounted_controller(controller, &cfd);
	*list = NULL;
	if (!tmpc)
		return false;

	/* Make sure we pass a relative path to *at() family of functions. */
	len = strlen(cgroup) + 1 /* . */ + 1 /* \0 */;
	cg = alloca(len);
	ret = snprintf(cg, len, "%s%s", *cgroup == '/' ? "." : "", cgroup);
	if (ret < 0 || (size_t)ret >= len) {
		lxcfs_error("Pathname too long under %s\n", cgroup);
		return false;
	}

	fd = openat(cfd, cg, O_DIRECTORY);
	if (fd < 0)
		return false;

	dir = fdopendir(fd);
	if (!dir)
		return false;

	while ((dirent = readdir(dir))) {
		struct stat mystat;

		if (!strcmp(dirent->d_name, ".") ||
		    !strcmp(dirent->d_name, ".."))
			continue;

		ret = snprintf(pathname, MAXPATHLEN, "%s/%s", cg, dirent->d_name);
		if (ret < 0 || ret >= MAXPATHLEN) {
			lxcfs_error("Pathname too long under %s\n", cg);
			continue;
		}

		ret = fstatat(cfd, pathname, &mystat, AT_SYMLINK_NOFOLLOW);
		if (ret) {
			lxcfs_error("Failed to stat %s: %s\n", pathname, strerror(errno));
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
		(*list)[sz] = (*iterator)(controller, cg, dirent->d_name);
		(*list)[sz+1] = NULL;
		sz++;
	}
	if (closedir(dir) < 0) {
		lxcfs_error("Failed closedir for %s: %s\n", cgroup, strerror(errno));
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

bool cgfs_get_mstat(const char *controller, const char *cgroup,
                     const char *file, struct memory_stat *mstat)
{
	int ret, fd, cfd;
	size_t len = 0;
	char *fnam, *tmpc;

	tmpc = find_mounted_controller(controller, &cfd);
	if (!tmpc)
		return false;

	/* Make sure we pass a relative path to *at() family of functions.
	 * . + /cgroup + / + file + \0
	 */
	len = strlen(cgroup) + strlen(file) + 3;
	fnam = alloca(len);
	ret = snprintf(fnam, len, "%s%s/%s", *cgroup == '/' ? "." : "", cgroup, file);
	if (ret < 0 || (size_t)ret >= len)
		return false;

	fd = openat(cfd, fnam, O_RDONLY);
	if (fd < 0)
		return false;

	FILE *f = fdopen(fd, "r");
	len = 0;
	char *line = NULL;
	ssize_t linelen;

	if (!f)
		return NULL;

	while ((linelen = getline(&line, &len, f)) != -1) {
        if (strncmp(line, "hierarchical_memory_limit", 25) == 0) {
            sscanf(line, "hierarchical_memory_limit %llu", &(mstat->hierarchical_memory_limit));
        } else if (strncmp(line, "hierarchical_memsw_limit", 24) == 0) {
            sscanf(line, "hierarchical_memsw_limit %llu", &(mstat->hierarchical_memsw_limit));
        } else if (strncmp(line, "total_cache", 11) == 0) {
            sscanf(line, "total_cache %llu", &(mstat->total_cache));
        } else if (strncmp(line, "total_rss", 9) == 0) {
            sscanf(line, "total_rss %llu", &(mstat->total_rss));
        } else if (strncmp(line, "total_rss_huge", 14) == 0) {
            sscanf(line, "total_rss_huge %llu", &(mstat->total_rss_huge));
        } else if (strncmp(line, "total_shmem", 11) == 0) {
            sscanf(line, "total_shmem %llu", &(mstat->total_shmem));
        } else if (strncmp(line, "total_mapped_file", 17) == 0) {
            sscanf(line, "total_mapped_file %llu", &(mstat->total_mapped_file));
        } else if (strncmp(line, "total_dirty", 11) == 0) {
            sscanf(line, "total_dirty %llu", &(mstat->total_dirty));
        } else if (strncmp(line, "total_writeback", 15) == 0) {
            sscanf(line, "total_writeback %llu", &(mstat->total_writeback));
        } else if (strncmp(line, "total_swap", 10) == 0) {
            sscanf(line, "total_swap %llu", &(mstat->total_swap));
        } else if (strncmp(line, "total_pgpgin", 12) == 0) {
            sscanf(line, "total_pgpgin %llu", &(mstat->total_pgpgin));
        } else if (strncmp(line, "total_pgpgout", 13) == 0) {
            sscanf(line, "total_pgpgout %llu", &(mstat->total_pgpgout));
        } else if (strncmp(line, "total_pgfault", 13) == 0) {
            sscanf(line, "total_pgfault %llu", &(mstat->total_pgfault));
        } else if (strncmp(line, "total_pgmajfault", 16) == 0) {
            sscanf(line, "total_pgmajfault %llu", &(mstat->total_pgmajfault));
        } else if (strncmp(line, "total_inactive_anon", 19) == 0) {
            sscanf(line, "total_inactive_anon %llu", &(mstat->total_inactive_anon));
        } else if (strncmp(line, "total_active_anon", 17) == 0) {
            sscanf(line, "total_active_anon %llu", &(mstat->total_active_anon));
        } else if (strncmp(line, "total_inactive_file", 19) == 0) {
            sscanf(line, "total_inactive_file %llu", &(mstat->total_inactive_file));
        } else if (strncmp(line, "total_active_file", 17) == 0) {
            sscanf(line, "total_active_file %llu", &(mstat->total_active_file));
        } else if (strncmp(line, "total_unevictable", 17) == 0) {
            sscanf(line, "total_unevictable %llu", &(mstat->total_unevictable));
        }
	}
    return true;
}

bool cgfs_get_value(const char *controller, const char *cgroup, const char *file, char **value)
{
	int ret, fd, cfd;
	size_t len;
	char *fnam, *tmpc;

	tmpc = find_mounted_controller(controller, &cfd);
	if (!tmpc)
		return false;

	/* Make sure we pass a relative path to *at() family of functions.
	 * . + /cgroup + / + file + \0
	 */
	len = strlen(cgroup) + strlen(file) + 3;
	fnam = alloca(len);
	ret = snprintf(fnam, len, "%s%s/%s", *cgroup == '/' ? "." : "", cgroup, file);
	if (ret < 0 || (size_t)ret >= len)
		return false;

	fd = openat(cfd, fnam, O_RDONLY);
	if (fd < 0)
		return false;

	*value = slurp_file(fnam, fd);
	return *value != NULL;
}

bool cgfs_param_exist(const char *controller, const char *cgroup, const char *file)
{
	int ret, cfd;
	size_t len;
	char *fnam, *tmpc;

	tmpc = find_mounted_controller(controller, &cfd);
	if (!tmpc)
		return false;

	/* Make sure we pass a relative path to *at() family of functions.
	 * . + /cgroup + / + file + \0
	 */
	len = strlen(cgroup) + strlen(file) + 3;
	fnam = alloca(len);
	ret = snprintf(fnam, len, "%s%s/%s", *cgroup == '/' ? "." : "", cgroup, file);
	if (ret < 0 || (size_t)ret >= len)
		return false;

	return (faccessat(cfd, fnam, F_OK, 0) == 0);
}

struct cgfs_files *cgfs_get_key(const char *controller, const char *cgroup, const char *file)
{
	int ret, cfd;
	size_t len;
	char *fnam, *tmpc;
	struct stat sb;
	struct cgfs_files *newkey;

	tmpc = find_mounted_controller(controller, &cfd);
	if (!tmpc)
		return false;

	if (file && *file == '/')
		file++;

	if (file && strchr(file, '/'))
		return NULL;

	/* Make sure we pass a relative path to *at() family of functions.
	 * . + /cgroup + / + file + \0
	 */
	len = strlen(cgroup) + 3;
	if (file)
		len += strlen(file) + 1;
	fnam = alloca(len);
	snprintf(fnam, len, "%s%s%s%s", *cgroup == '/' ? "." : "", cgroup,
		 file ? "/" : "", file ? file : "");

	ret = fstatat(cfd, fnam, &sb, 0);
	if (ret < 0)
		return NULL;

	do {
		newkey = malloc(sizeof(struct cgfs_files));
	} while (!newkey);
	if (file)
		newkey->name = must_copy_string(file);
	else if (strrchr(cgroup, '/'))
		newkey->name = must_copy_string(strrchr(cgroup, '/'));
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
		lxcfs_error("Error getting files under %s:%s\n", controller,
			     cgroup);
	}
	return entry;
}

bool cgfs_list_keys(const char *controller, const char *cgroup, struct cgfs_files ***keys)
{
	return cgfs_iterate_cgroup(controller, cgroup, false, (void***)keys, sizeof(*keys), &make_key_list_entry);
}

bool is_child_cgroup(const char *controller, const char *cgroup, const char *f)
{
	int cfd;
	size_t len;
	char *fnam, *tmpc;
	int ret;
	struct stat sb;

	tmpc = find_mounted_controller(controller, &cfd);
	if (!tmpc)
		return false;

	/* Make sure we pass a relative path to *at() family of functions.
	 * . + /cgroup + / + f + \0
	 */
	len = strlen(cgroup) + strlen(f) + 3;
	fnam = alloca(len);
	ret = snprintf(fnam, len, "%s%s/%s", *cgroup == '/' ? "." : "", cgroup, f);
	if (ret < 0 || (size_t)ret >= len)
		return false;

	ret = fstatat(cfd, fnam, &sb, 0);
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

pid_t lookup_initpid_in_store(pid_t qpid)
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
 * append the given formatted string to *src.
 * src: a pointer to a char* in which to append the formatted string.
 * sz: the number of characters printed so far, minus trailing \0.
 * asz: the allocated size so far
 * format: string format. See printf for details.
 * ...: varargs. See printf for details.
 */
static void must_strcat(char **src, size_t *sz, size_t *asz, const char *format, ...)
{
	char tmp[BUF_RESERVE_SIZE];
	va_list		args;

	va_start (args, format);
	int tmplen = vsnprintf(tmp, BUF_RESERVE_SIZE, format, args);
	va_end(args);

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
 * append pid to *src.
 * src: a pointer to a char* in which ot append the pid.
 * sz: the number of characters printed so far, minus trailing \0.
 * asz: the allocated size so far
 * pid: the pid to append
 */
static void must_strcat_pid(char **src, size_t *sz, size_t *asz, pid_t pid)
{
	must_strcat(src, sz, asz, "%d\n", (int)pid);
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
			lxcfs_error("pid wrapparound at entry %u %u %u in %s\n",
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
		lxcfs_error("%s\n", "I was fed bad input.");
		return NULL;
	}

	if ((strcmp(querycg, "/") == 0) || (strcmp(querycg, "./") == 0))
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

char *get_pid_cgroup(pid_t pid, const char *contrl)
{
	int cfd;
	char fnam[PROCLEN];
	FILE *f;
	char *answer = NULL;
	char *line = NULL;
	size_t len = 0;
	int ret;
	const char *h = find_mounted_controller(contrl, &cfd);
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
void prune_init_slice(char *cg)
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
	 * callers pass in '/' or './' (openat()) for root cgroup, otherwise
	 * they pass in a cgroup without leading '/'
	 *
	 * The original line here was:
	 *	linecmp = *cg == '/' ? c2 : c2+1;
	 * TODO: I'm not sure why you'd want to increment when *cg != '/'?
	 *       Serge, do you know?
	 */
	if (*cg == '/' || !strncmp(cg, "./", 2))
		linecmp = c2;
	else
		linecmp = c2 + 1;
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

	if (strcmp(cg, "/") == 0 || strcmp(cg, "./") == 0)
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

	if (strlen(path) < 9) {
		errno = EACCES;
		return NULL;
	}
	if (*(path + 7) != '/') {
		errno = EINVAL;
		return NULL;
	}
	p1 = path + 8;
	contr = strdupa(p1);
	if (!contr) {
		errno = ENOMEM;
		return NULL;
	}
	slash = strstr(contr, "/");
	if (slash)
		*slash = '\0';

	int i;
	for (i = 0; i < num_hierarchies; i++) {
		if (hierarchies[i] && strcmp(hierarchies[i], contr) == 0)
			return hierarchies[i];
	}
	errno = ENOENT;
	return NULL;
}

/*
 * Find the start of cgroup in /cgroup/controller/the/cgroup/path
 * Note that the returned value may include files (keynames) etc
 */
static const char *find_cgroup_in_path(const char *path)
{
	const char *p1;

	if (strlen(path) < 9) {
		errno = EACCES;
		return NULL;
	}
	p1 = strstr(path + 8, "/");
	if (!p1) {
		errno = EINVAL;
		return NULL;
	}
	errno = 0;
	return p1 + 1;
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
		return -errno;
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
	if (initpid <= 1 || is_shared_pidns(initpid))
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
			return -errno;

		cgroup = find_cgroup_in_path(path);
		if (!cgroup) {
			/* this is just /cgroup/controller, return its contents */
			cgroup = "/";
		}
	}

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 1 || is_shared_pidns(initpid))
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

	if (filler(buf, ".", NULL, 0) != 0 || filler(buf, "..", NULL, 0) != 0)
		return -EIO;

	if (d->type != LXC_TYPE_CGDIR) {
		lxcfs_error("%s\n", "Internal error: file cache info used in readdir.");
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
	if (initpid <= 1 || is_shared_pidns(initpid))
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

	for (i = 0; list && list[i]; i++) {
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

void do_release_file_info(struct fuse_file_info *fi)
{
	struct file_info *f = (struct file_info *)fi->fh;

	if (!f)
		return;

	fi->fh = 0;

	free(f->controller);
	f->controller = NULL;
	free(f->cgroup);
	f->cgroup = NULL;
	free(f->file);
	f->file = NULL;
	free(f->buf);
	f->buf = NULL;
	free(f);
	f = NULL;
}

int cg_releasedir(const char *path, struct fuse_file_info *fi)
{
	do_release_file_info(fi);
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
		return -errno;
	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		return -errno;

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
	if (initpid <= 1 || is_shared_pidns(initpid))
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
	int ret;
	const char *cgroup;
	char *path1, *path2, *controller;
	char *last = NULL, *cgdir = NULL;
	struct cgfs_files *k = NULL;
	struct fuse_context *fc = fuse_get_context();

	if (strcmp(path, "/cgroup") == 0)
		return 0;

	if (!fc)
		return -EIO;

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return -errno;
	cgroup = find_cgroup_in_path(path);
	if (!cgroup) {
		// access("/sys/fs/cgroup/systemd", mode) - rx allowed, w not
		if ((mode & W_OK) == 0)
			return 0;
		return -EACCES;
	}

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
		if ((mode & W_OK) == 0)
			ret = 0;
		else
			ret = -EACCES;
		goto out;
	}
	free_key(k);

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 1 || is_shared_pidns(initpid))
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
	do_release_file_info(fi);
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
		lxcfs_error("%s\n", "Failed to create epoll socket: %m.");
		return false;
	}

	ev.events = POLLIN_SET;
	ev.data.fd = sock;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev) < 0) {
		lxcfs_error("%s\n", "Failed adding socket to epoll: %m.");
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
			lxcfs_error("%s\n", "Error getting reply from server over socketpair.");
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
		lxcfs_error("Failed at sendmsg: %s.\n",strerror(errno));
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
		lxcfs_error("Failed to set passcred: %s\n", strerror(errno));
		return false;
	}
	buf[0] = '1';
	if (write(sock, buf, 1) != 1) {
		lxcfs_error("Failed to start write on scm fd: %s\n", strerror(errno));
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
		lxcfs_error("Timed out waiting for scm_cred: %s\n", strerror(errno));
		return false;
	}
	ret = recvmsg(sock, &msg, MSG_DONTWAIT);
	if (ret < 0) {
		lxcfs_error("Failed to receive scm_cred: %s\n", strerror(errno));
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
	if (write(args->cpipe[1], &b, sizeof(char)) < 0)
		lxcfs_error("(child): error on write: %s.\n", strerror(errno));
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
			lxcfs_error("Timed out waiting for pid from child: %s.\n", strerror(errno));
			goto out;
		}
		if (read(sock[0], &qpid, sizeof(qpid)) != sizeof(qpid)) {
			lxcfs_error("Error reading pid from child: %s.\n", strerror(errno));
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
		lxcfs_error("Failed to ask child to exit: %s.\n", strerror(errno));
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
		lxcfs_error("%s\n", "Internal error: directory cache info used in cg_read.");
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
			lxcfs_error("%s\n", "Timeout reading from parent.");
			return 1;
		}
		if ((ret = read(sock, &vpid, sizeof(pid_t))) != sizeof(pid_t)) {
			lxcfs_error("Bad read from parent: %s.\n", strerror(errno));
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
		lxcfs_error("Error opening %s: %s\n", line, strerror(errno));
		return;
	}
	while (fgets(line, 400, f)) {
		if (strncmp(line, "Uid:", 4) == 0) {
			if (sscanf(line+4, "%u", &u) != 1) {
				lxcfs_error("bad uid line for pid %u\n", pid);
				fclose(f);
				return;
			}
			*uid = u;
		} else if (strncmp(line, "Gid:", 4) == 0) {
			if (sscanf(line+4, "%u", &g) != 1) {
				lxcfs_error("bad gid line for pid %u\n", pid);
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
			lxcfs_error("Error writing pid to child: %s.\n", strerror(errno));
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
		lxcfs_error("%s\n", "Warning: failed to ask child to exit.");

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
		lxcfs_error("%s\n", "Internal error: directory cache info used in cg_write.");
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
		return -EPERM;

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return errno == ENOENT ? -EPERM : -errno;

	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		/* this is just /cgroup/controller */
		return -EPERM;

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
		return -EPERM;

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return errno == ENOENT ? -EPERM : -errno;

	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		/* this is just /cgroup/controller */
		return -EPERM;

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
		return errno == ENOENT ? -EPERM : -errno;

	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		return -errno;

	get_cgdir_and_path(cgroup, &cgdir, &last);
	if (!last)
		path1 = "/";
	else
		path1 = cgdir;

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;
	if (!caller_is_in_ancestor(initpid, controller, path1, &next)) {
		if (!next)
			ret = -EINVAL;
		else if (last && strcmp(next, last) == 0)
			ret = -EEXIST;
		else
			ret = -EPERM;
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
	if (!controller) /* Someone's trying to delete "/cgroup". */
		return -EPERM;

	cgroup = find_cgroup_in_path(path);
	if (!cgroup) /* Someone's trying to delete a controller e.g. "/blkio". */
		return -EPERM;

	get_cgdir_and_path(cgroup, &cgdir, &last);
	if (!last) {
		/* Someone's trying to delete a cgroup on the same level as the
		 * "/lxc" cgroup e.g. rmdir "/cgroup/blkio/lxc" or
		 * rmdir "/cgroup/blkio/init.slice".
		 */
		ret = -EPERM;
		goto out;
	}

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;
	if (!caller_is_in_ancestor(initpid, controller, cgroup, &next)) {
		if (!last || (next && (strcmp(next, last) == 0)))
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

int read_file(const char *path, char *buf, size_t size, struct file_info *d)
{
	size_t linelen = 0, total_len = 0, rv = 0;
	char *line = NULL;
	char *cache = d->buf;
	size_t cache_size = d->buflen;
	FILE *f = fopen(path, "r");
	if (!f)
		return 0;

	while (getline(&line, &linelen, f) != -1) {
		ssize_t l = snprintf(cache, cache_size, "%s", line);
		if (l < 0) {
			perror("Error writing to cache");
			rv = 0;
			goto err;
		}
		if (l >= cache_size) {
			lxcfs_error("%s\n", "Internal error: truncated write to cache.");
			rv = 0;
			goto err;
		}
		cache += l;
		cache_size -= l;
		total_len += l;
	}

	d->size = total_len;
	if (total_len > size)
		total_len = size;

	/* read from off 0 */
	memcpy(buf, d->buf, total_len);
	rv = total_len;
  err:
	fclose(f);
	free(line);
	if (d->size > rv)
		d->cached = d->size - rv;
	return rv;
}

/*
 * FUSE ops for /proc
 */

static unsigned long get_memlimit(const char *cgroup, const char *file)
{
	char *memlimit_str = NULL;
	unsigned long memlimit = -1;

	if (cgfs_get_value("memory", cgroup, file, &memlimit_str))
		memlimit = strtoul(memlimit_str, NULL, 10);

	free(memlimit_str);

	return memlimit;
}

static unsigned long get_min_memlimit(const char *cgroup, const char *file)
{
	char *copy = strdupa(cgroup);
	unsigned long memlimit = 0, retlimit;

	retlimit = get_memlimit(copy, file);

	while (strcmp(copy, "/") != 0) {
		copy = dirname(copy);
		memlimit = get_memlimit(copy, file);
		if (memlimit != -1 && memlimit < retlimit)
			retlimit = memlimit;
	};

	return retlimit;
}

static int proc_meminfo_read(char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	struct lxcfs_opts *opts = (struct lxcfs_opts *) fuse_get_context()->private_data;
	struct file_info *d = (struct file_info *)fi->fh;
	char *cg;
	char *memusage_str = NULL, *memstat_str = NULL,
		*memswlimit_str = NULL, *memswusage_str = NULL;
	unsigned long long memlimit = 0, memusage = 0, memswlimit = 0, memswusage = 0,
		hosttotal=0;
	struct memory_stat *mstat = NULL;
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
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;
	cg = get_pid_cgroup(initpid, "memory");
	if (!cg)
		return read_file("/proc/meminfo", buf, size, d);
	prune_init_slice(cg);

	memlimit = get_min_memlimit(cg, "memory.limit_in_bytes");
	if (!cgfs_get_value("memory", cg, "memory.usage_in_bytes", &memusage_str))
		goto err;

	mstat = malloc(sizeof(struct memory_stat));
	if (!cgfs_get_mstat("memory", cg, "memory.stat", mstat))
		goto err;

	// Following values are allowed to fail, because swapaccount might be turned
	// off for current kernel
	if(cgfs_get_value("memory", cg, "memory.memsw.limit_in_bytes", &memswlimit_str) &&
		cgfs_get_value("memory", cg, "memory.memsw.usage_in_bytes", &memswusage_str))
	{
		memswlimit = get_min_memlimit(cg, "memory.memsw.limit_in_bytes");
		memswusage = strtoul(memswusage_str, NULL, 10);

		memswlimit = memswlimit / 1024;
		memswusage = memswusage / 1024;
	}

	memusage = strtoul(memusage_str, NULL, 10);
	memlimit /= 1024;
	memusage /= 1024;

	f = fopen("/proc/meminfo", "r");
	if (!f)
		goto err;

	while (getline(&line, &linelen, f) != -1) {
		ssize_t l;
		char *printme, lbuf[100];

		memset(lbuf, 0, 100);
		if (startswith(line, "MemTotal:")) {
			sscanf(line+sizeof("MemTotal:")-1, "%llu", &hosttotal);
			if (hosttotal < memlimit)
				memlimit = hosttotal;
			snprintf(lbuf, 100, "MemTotal:       %8llu kB\n", memlimit);
			printme = lbuf;
		} else if (startswith(line, "MemFree:")) {
			snprintf(lbuf, 100, "MemFree:        %8llu kB\n", memlimit - memusage);
			printme = lbuf;
		} else if (startswith(line, "MemAvailable:")) {
			snprintf(lbuf, 100, "MemAvailable:   %8llu kB\n", memlimit - memusage +
								   	(mstat->total_cache)/1024);
			printme = lbuf;
		} else if (startswith(line, "SwapTotal:") && memswlimit > 0 && opts && opts->swap_off == false) {
			memswlimit -= memlimit;
			snprintf(lbuf, 100, "SwapTotal:      %8llu kB\n", memswlimit);
			printme = lbuf;
		} else if (startswith(line, "SwapTotal:") && opts && opts->swap_off == true) {
			snprintf(lbuf, 100, "SwapTotal:      %8llu kB\n", 0ULL);
			printme = lbuf;
		} else if (startswith(line, "SwapFree:") && memswlimit > 0 && memswusage > 0 && opts && opts->swap_off == false) {
			unsigned long long swaptotal = memswlimit,
					swapusage = memusage > memswusage ? 0 : memswusage - memusage,
					swapfree = swapusage < swaptotal ? swaptotal - swapusage : 0;
			snprintf(lbuf, 100, "SwapFree:       %8llu kB\n", swapfree);
			printme = lbuf;
		} else if (startswith(line, "SwapFree:") && opts && opts->swap_off == true) {
			snprintf(lbuf, 100, "SwapFree:       %8llu kB\n", 0ULL);
			printme = lbuf;
		} else if (startswith(line, "Slab:")) {
			snprintf(lbuf, 100, "Slab:           %8llu kB\n", 0ULL);
			printme = lbuf;
		} else if (startswith(line, "Buffers:")) {
			snprintf(lbuf, 100, "Buffers:        %8llu kB\n", 0ULL);
			printme = lbuf;
		} else if (startswith(line, "Cached:")) {
			snprintf(lbuf, 100, "Cached:         %8llu kB\n",
                                    (mstat->total_cache)/1024);
			printme = lbuf;
		} else if (startswith(line, "SwapCached:")) {
			snprintf(lbuf, 100, "SwapCached:     %8llu kB\n", 0ULL);
			printme = lbuf;
		} else if (startswith(line, "Active:")) {
			snprintf(lbuf, 100, "Active:         %8llu kB\n",
					(mstat->total_active_anon + mstat->total_active_file)/1024);
			printme = lbuf;
		} else if (startswith(line, "Inactive:")) {
			snprintf(lbuf, 100, "Inactive:       %8llu kB\n",
					(mstat->total_inactive_anon + mstat->total_inactive_file)/1024);
			printme = lbuf;
		} else if (startswith(line, "Active(anon)")) {
			snprintf(lbuf, 100, "Active(anon):   %8llu kB\n", 
                                    (mstat->total_active_anon)/1024);
			printme = lbuf;
		} else if (startswith(line, "Inactive(anon)")) {
			snprintf(lbuf, 100, "Inactive(anon): %8llu kB\n",
                                    (mstat->total_inactive_anon)/1024);
			printme = lbuf;
		} else if (startswith(line, "Active(file)")) {
			snprintf(lbuf, 100, "Active(file):   %8llu kB\n",
                                    (mstat->total_active_file)/1024);
			printme = lbuf;
		} else if (startswith(line, "Inactive(file)")) {
			snprintf(lbuf, 100, "Inactive(file): %8llu kB\n",
                                    (mstat->total_inactive_file)/1024);
			printme = lbuf;
		} else if (startswith(line, "Unevictable")) {
			snprintf(lbuf, 100, "Unevictable:    %8llu kB\n",
                                    (mstat->total_unevictable)/1024);
			printme = lbuf;
		} else if (startswith(line, "Dirty")) {
			snprintf(lbuf, 100, "Dirty:          %8llu kB\n",
                                    (mstat->total_dirty)/1024);
			printme = lbuf;
		} else if (startswith(line, "Writeback")) {
			snprintf(lbuf, 100, "Writeback:      %8llu kB\n",
                                    (mstat->total_writeback)/1024);
			printme = lbuf;
		} else if (startswith(line, "AnonPages")) {
			snprintf(lbuf, 100, "AnonPages:      %8llu kB\n",
                                    (mstat->total_active_anon
                                     + mstat->total_inactive_anon
                                     - mstat->total_shmem)/1024);
			printme = lbuf;
		} else if (startswith(line, "Mapped")) {
			snprintf(lbuf, 100, "Mapped:         %8llu kB\n",
                                    (mstat->total_mapped_file)/1024);
			printme = lbuf;
		} else if (startswith(line, "SReclaimable")) {
			snprintf(lbuf, 100, "SReclaimable:   %8llu kB\n", 0ULL);
			printme = lbuf;
		} else if (startswith(line, "SUnreclaim")) {
			snprintf(lbuf, 100, "SUnreclaim:     %8llu kB\n", 0ULL);
			printme = lbuf;
		} else if (startswith(line, "Shmem:")) {
			snprintf(lbuf, 100, "Shmem:          %8llu kB\n",
                                    (mstat->total_shmem)/1024);
			printme = lbuf;
		} else if (startswith(line, "ShmemHugePages")) {
			snprintf(lbuf, 100, "ShmemHugePages: %8llu kB\n", 0ULL);
			printme = lbuf;
		} else if (startswith(line, "ShmemPmdMapped")) {
			snprintf(lbuf, 100, "ShmemPmdMapped: %8llu kB\n", 0ULL);
			printme = lbuf;
		} else if (startswith(line, "AnonHugePages")) {
			snprintf(lbuf, 100, "AnonHugePages:  %8llu kB\n",
                                    (mstat->total_rss_huge)/1024);
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
			lxcfs_error("%s\n", "Internal error: truncated write to cache.");
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
	free(mstat);
	return rv;
}

/*
 * Read the cpuset.cpus for cg
 * Return the answer in a newly allocated string which must be freed
 */
char *get_cpuset(const char *cg)
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
 * Read cgroup CPU quota parameters from `cpu.cfs_quota_us` or `cpu.cfs_period_us`,
 * depending on `param`. Parameter value is returned throuh `value`.
 */
static bool read_cpu_cfs_param(const char *cg, const char *param, int64_t *value)
{
	bool rv = false;
	char file[11 + 6 + 1]; // cpu.cfs__us + quota/period + \0
	char *str = NULL;

	sprintf(file, "cpu.cfs_%s_us", param);

	if (!cgfs_get_value("cpu", cg, file, &str))
		goto err;

	if (sscanf(str, "%ld", value) != 1)
		goto err;

	rv = true;

err:
	if (str)
		free(str);
	return rv;
}

/*
 * Return the maximum number of visible CPUs based on CPU quotas.
 * If there is no quota set, zero is returned.
 */
int max_cpu_count(const char *cg)
{
	int rv, nprocs;
	int64_t cfs_quota, cfs_period;
	int nr_cpus_in_cpuset = 0;
	char *cpuset = NULL;

	if (!read_cpu_cfs_param(cg, "quota", &cfs_quota))
		return 0;

	if (!read_cpu_cfs_param(cg, "period", &cfs_period))
		return 0;

	cpuset = get_cpuset(cg);
	if (cpuset)
		nr_cpus_in_cpuset = cpu_number_in_cpuset(cpuset);

	if (cfs_quota <= 0 || cfs_period <= 0){
		if (nr_cpus_in_cpuset > 0)
			return nr_cpus_in_cpuset;

		return 0;
	}

	rv = cfs_quota / cfs_period;

	/* In case quota/period does not yield a whole number, add one CPU for
	 * the remainder.
	 */
	if ((cfs_quota % cfs_period) > 0)
		rv += 1;

	nprocs = get_nprocs();

	if (rv > nprocs)
		rv = nprocs;

	/* use min value in cpu quota and cpuset */
	if (nr_cpus_in_cpuset > 0 && nr_cpus_in_cpuset < rv)
		rv = nr_cpus_in_cpuset;

	return rv;
}

/*
 * Return the exact number of visible CPUs based on CPU quotas.
 * If there is no quota set, zero is returned.
 */
static double exact_cpu_count(const char *cg)
{
	double rv;
	int nprocs;
	int64_t cfs_quota, cfs_period;

	if (!read_cpu_cfs_param(cg, "quota", &cfs_quota))
		return 0;

	if (!read_cpu_cfs_param(cg, "period", &cfs_period))
		return 0;

	if (cfs_quota <= 0 || cfs_period <= 0)
		return 0;

	rv = (double)cfs_quota / (double)cfs_period;

	nprocs = get_nprocs();

	if (rv > nprocs)
		rv = nprocs;

	return rv;
}

/*
 * Determine whether CPU views should be used or not.
 */
bool use_cpuview(const char *cg)
{
	int cfd;
	char *tmpc;

	tmpc = find_mounted_controller("cpu", &cfd);
	if (!tmpc)
		return false;

	tmpc = find_mounted_controller("cpuacct", &cfd);
	if (!tmpc)
		return false;

	return true;
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
	bool am_printing = false, firstline = true, is_s390x = false;
	int curcpu = -1, cpu, max_cpus = 0;
	bool use_view;
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
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;
	cg = get_pid_cgroup(initpid, "cpuset");
	if (!cg)
		return read_file("proc/cpuinfo", buf, size, d);
	prune_init_slice(cg);

	cpuset = get_cpuset(cg);
	if (!cpuset)
		goto err;

	use_view = use_cpuview(cg);

	if (use_view)
		max_cpus = max_cpu_count(cg);

	f = fopen("/proc/cpuinfo", "r");
	if (!f)
		goto err;

	while (getline(&line, &linelen, f) != -1) {
		ssize_t l;
		if (firstline) {
			firstline = false;
			if (strstr(line, "IBM/S390") != NULL) {
				is_s390x = true;
				am_printing = true;
				continue;
			}
		}
		if (strncmp(line, "# processors:", 12) == 0)
			continue;
		if (is_processor_line(line)) {
			if (use_view && max_cpus > 0 && (curcpu+1) == max_cpus)
				break;
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
					lxcfs_error("%s\n", "Internal error: truncated write to cache.");
					rv = 0;
					goto err;
				}
				cache += l;
				cache_size -= l;
				total_len += l;
			}
			continue;
		} else if (is_s390x && sscanf(line, "processor %d:", &cpu) == 1) {
			char *p;
			if (use_view && max_cpus > 0 && (curcpu+1) == max_cpus)
				break;
			if (!cpu_in_cpuset(cpu, cpuset))
				continue;
			curcpu ++;
			p = strchr(line, ':');
			if (!p || !*p)
				goto err;
			p++;
			l = snprintf(cache, cache_size, "processor %d:%s", curcpu, p);
			if (l < 0) {
				perror("Error writing to cache");
				rv = 0;
				goto err;
			}
			if (l >= cache_size) {
				lxcfs_error("%s\n", "Internal error: truncated write to cache.");
				rv = 0;
				goto err;
			}
			cache += l;
			cache_size -= l;
			total_len += l;
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
				lxcfs_error("%s\n", "Internal error: truncated write to cache.");
				rv = 0;
				goto err;
			}
			cache += l;
			cache_size -= l;
			total_len += l;
		}
	}

	if (is_s390x) {
		char *origcache = d->buf;
		ssize_t l;
		do {
			d->buf = malloc(d->buflen);
		} while (!d->buf);
		cache = d->buf;
		cache_size = d->buflen;
		total_len = 0;
		l = snprintf(cache, cache_size, "vendor_id       : IBM/S390\n");
		if (l < 0 || l >= cache_size) {
			free(origcache);
			goto err;
		}
		cache_size -= l;
		cache += l;
		total_len += l;
		l = snprintf(cache, cache_size, "# processors    : %d\n", curcpu + 1);
		if (l < 0 || l >= cache_size) {
			free(origcache);
			goto err;
		}
		cache_size -= l;
		cache += l;
		total_len += l;
		l = snprintf(cache, cache_size, "%s", origcache);
		free(origcache);
		if (l < 0 || l >= cache_size)
			goto err;
		total_len += l;
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

static uint64_t get_reaper_start_time(pid_t pid)
{
	int ret;
	FILE *f;
	uint64_t starttime;
	/* strlen("/proc/") = 6
	 * +
	 * LXCFS_NUMSTRLEN64
	 * +
	 * strlen("/stat") = 5
	 * +
	 * \0 = 1
	 * */
#define __PROC_PID_STAT_LEN (6 + LXCFS_NUMSTRLEN64 + 5 + 1)
	char path[__PROC_PID_STAT_LEN];
	pid_t qpid;

	qpid = lookup_initpid_in_store(pid);
	if (qpid <= 0) {
		/* Caller can check for EINVAL on 0. */
		errno = EINVAL;
		return 0;
	}

	ret = snprintf(path, __PROC_PID_STAT_LEN, "/proc/%d/stat", qpid);
	if (ret < 0 || ret >= __PROC_PID_STAT_LEN) {
		/* Caller can check for EINVAL on 0. */
		errno = EINVAL;
		return 0;
	}

	f = fopen(path, "r");
	if (!f) {
		/* Caller can check for EINVAL on 0. */
		errno = EINVAL;
		return 0;
	}

	/* Note that the *scanf() argument supression requires that length
	 * modifiers such as "l" are omitted. Otherwise some compilers will yell
	 * at us. It's like telling someone you're not married and then asking
	 * if you can bring your wife to the party.
	 */
	ret = fscanf(f, "%*d "      /* (1)  pid         %d   */
			"%*s "      /* (2)  comm        %s   */
			"%*c "      /* (3)  state       %c   */
			"%*d "      /* (4)  ppid        %d   */
			"%*d "      /* (5)  pgrp        %d   */
			"%*d "      /* (6)  session     %d   */
			"%*d "      /* (7)  tty_nr      %d   */
			"%*d "      /* (8)  tpgid       %d   */
			"%*u "      /* (9)  flags       %u   */
			"%*u "      /* (10) minflt      %lu  */
			"%*u "      /* (11) cminflt     %lu  */
			"%*u "      /* (12) majflt      %lu  */
			"%*u "      /* (13) cmajflt     %lu  */
			"%*u "      /* (14) utime       %lu  */
			"%*u "      /* (15) stime       %lu  */
			"%*d "      /* (16) cutime      %ld  */
			"%*d "      /* (17) cstime      %ld  */
			"%*d "      /* (18) priority    %ld  */
			"%*d "      /* (19) nice        %ld  */
			"%*d "      /* (20) num_threads %ld  */
			"%*d "      /* (21) itrealvalue %ld  */
			"%" PRIu64, /* (22) starttime   %llu */
		     &starttime);
	if (ret != 1) {
		fclose(f);
		/* Caller can check for EINVAL on 0. */
		errno = EINVAL;
		return 0;
	}

	fclose(f);

	errno = 0;
	return starttime;
}

static double get_reaper_start_time_in_sec(pid_t pid)
{
	uint64_t clockticks, ticks_per_sec;
	int64_t ret;
	double res = 0;

	clockticks = get_reaper_start_time(pid);
	if (clockticks == 0 && errno == EINVAL) {
		lxcfs_debug("failed to retrieve start time of pid %d\n", pid);
		return 0;
	}

	ret = sysconf(_SC_CLK_TCK);
	if (ret < 0 && errno == EINVAL) {
		lxcfs_debug(
		    "%s\n",
		    "failed to determine number of clock ticks in a second");
		return 0;
	}

	ticks_per_sec = (uint64_t)ret;
	res = (double)clockticks / ticks_per_sec;
	return res;
}

static double get_reaper_age(pid_t pid)
{
	uint64_t uptime_ms;
	double procstart, procage;

	/* We need to substract the time the process has started since system
	 * boot minus the time when the system has started to get the actual
	 * reaper age.
	 */
	procstart = get_reaper_start_time_in_sec(pid);
	procage = procstart;
	if (procstart > 0) {
		int ret;
		struct timespec spec;

		ret = clock_gettime(CLOCK_BOOTTIME, &spec);
		if (ret < 0)
			return 0;

		/* We could make this more precise here by using the tv_nsec
		 * field in the timespec struct and convert it to milliseconds
		 * and then create a double for the seconds and milliseconds but
		 * that seems more work than it is worth.
		 */
		uptime_ms = (spec.tv_sec * 1000) + (spec.tv_nsec * 1e-6);
		procage = (uptime_ms - (procstart * 1000)) / 1000;
	}

	return procage;
}

/*
 * Returns 0 on success.
 * It is the caller's responsibility to free `return_usage`, unless this
 * function returns an error.
 */
static int read_cpuacct_usage_all(char *cg, char *cpuset, struct cpuacct_usage **return_usage, int *size)
{
	int cpucount = get_nprocs_conf();
	struct cpuacct_usage *cpu_usage;
	int rv = 0, i, j, ret;
	int cg_cpu;
	uint64_t cg_user, cg_system;
	int64_t ticks_per_sec;
	char *usage_str = NULL;

	ticks_per_sec = sysconf(_SC_CLK_TCK);

	if (ticks_per_sec < 0 && errno == EINVAL) {
		lxcfs_v(
			"%s\n",
			"read_cpuacct_usage_all failed to determine number of clock ticks "
			"in a second");
		return -1;
	}

	cpu_usage = malloc(sizeof(struct cpuacct_usage) * cpucount);
	if (!cpu_usage)
		return -ENOMEM;

	memset(cpu_usage, 0, sizeof(struct cpuacct_usage) * cpucount);
	if (!cgfs_get_value("cpuacct", cg, "cpuacct.usage_all", &usage_str)) {
		// read cpuacct.usage_percpu instead
		lxcfs_v("failed to read cpuacct.usage_all. reading cpuacct.usage_percpu instead\n%s", "");
		if (!cgfs_get_value("cpuacct", cg, "cpuacct.usage_percpu", &usage_str)) {
			rv = -1;
			goto err;
		}
		lxcfs_v("usage_str: %s\n", usage_str);

		// convert cpuacct.usage_percpu into cpuacct.usage_all
		lxcfs_v("converting cpuacct.usage_percpu into cpuacct.usage_all\n%s", "");

		char *data = NULL;
		size_t sz = 0, asz = 0;

		must_strcat(&data, &sz, &asz, "cpu user system\n");

		int i = 0, read_pos = 0, read_cnt=0;
		while (sscanf(usage_str + read_pos, "%lu %n", &cg_user, &read_cnt) > 0) {
			lxcfs_debug("i: %d, cg_user: %lu, read_pos: %d, read_cnt: %d\n", i, cg_user, read_pos, read_cnt);
			must_strcat(&data, &sz, &asz, "%d %lu 0\n", i, cg_user);
			i++;
			read_pos += read_cnt;
		}

		free(usage_str);
		usage_str = data;

		lxcfs_v("usage_str: %s\n", usage_str);
	}

	int read_pos = 0, read_cnt=0;
	if (sscanf(usage_str, "cpu user system\n%n", &read_cnt) != 0) {
		lxcfs_error("read_cpuacct_usage_all reading first line from "
				"%s/cpuacct.usage_all failed.\n", cg);
		rv = -1;
		goto err;
	}

	read_pos += read_cnt;

	for (i = 0, j = 0; i < cpucount; i++) {
		ret = sscanf(usage_str + read_pos, "%d %lu %lu\n%n", &cg_cpu, &cg_user,
				&cg_system, &read_cnt);

		if (ret == EOF)
			break;

		if (ret != 3) {
			lxcfs_error("read_cpuacct_usage_all reading from %s/cpuacct.usage_all "
					"failed.\n", cg);
			rv = -1;
			goto err;
		}

		read_pos += read_cnt;

		/* Convert the time from nanoseconds to USER_HZ */
		cpu_usage[j].user = cg_user / 1000.0 / 1000 / 1000 * ticks_per_sec;
		cpu_usage[j].system = cg_system / 1000.0 / 1000 / 1000 * ticks_per_sec;
		j++;
	}

	rv = 0;
	*return_usage = cpu_usage;
	*size = cpucount;

err:
	if (usage_str)
		free(usage_str);

	if (rv != 0) {
		free(cpu_usage);
		*return_usage = NULL;
	}

	return rv;
}

static unsigned long diff_cpu_usage(struct cpuacct_usage *older, struct cpuacct_usage *newer, struct cpuacct_usage *diff, int cpu_count)
{
	int i;
	unsigned long sum = 0;

	for (i = 0; i < cpu_count; i++) {
		if (!newer[i].online)
			continue;

		/* When cpuset is changed on the fly, the CPUs might get reordered.
		 * We could either reset all counters, or check that the substractions
		 * below will return expected results.
		 */
		if (newer[i].user > older[i].user)
			diff[i].user = newer[i].user - older[i].user;
		else
			diff[i].user = 0;

		if (newer[i].system > older[i].system)
			diff[i].system = newer[i].system - older[i].system;
		else
			diff[i].system = 0;

		if (newer[i].idle > older[i].idle)
			diff[i].idle = newer[i].idle - older[i].idle;
		else
			diff[i].idle = 0;

		sum += diff[i].user;
		sum += diff[i].system;
		sum += diff[i].idle;
	}

	return sum;
}

static void add_cpu_usage(unsigned long *surplus, struct cpuacct_usage *usage, unsigned long *counter, unsigned long threshold)
{
	unsigned long free_space, to_add;

	free_space = threshold - usage->user - usage->system;

	if (free_space > usage->idle)
		free_space = usage->idle;

	to_add = free_space > *surplus ? *surplus : free_space;

	*counter += to_add;
	usage->idle -= to_add;
	*surplus -= to_add;
}

static struct cg_proc_stat *prune_proc_stat_list(struct cg_proc_stat *node)
{
	struct cg_proc_stat *first = NULL, *prev, *tmp;

	for (prev = NULL; node; ) {
		if (!cgfs_param_exist("cpu", node->cg, "cpu.shares")) {
			tmp = node;
			lxcfs_debug("Removing stat node for %s\n", node->cg);

			if (prev)
				prev->next = node->next;
			else
				first = node->next;

			node = node->next;
			free_proc_stat_node(tmp);
		} else {
			if (!first)
				first = node;
			prev = node;
			node = node->next;
		}
	}

	return first;
}

#define PROC_STAT_PRUNE_INTERVAL 10
static void prune_proc_stat_history(void)
{
	int i;
	time_t now = time(NULL);

	for (i = 0; i < CPUVIEW_HASH_SIZE; i++) {
		pthread_rwlock_wrlock(&proc_stat_history[i]->lock);

		if ((proc_stat_history[i]->lastcheck + PROC_STAT_PRUNE_INTERVAL) > now) {
			pthread_rwlock_unlock(&proc_stat_history[i]->lock);
			return;
		}

		if (proc_stat_history[i]->next) {
			proc_stat_history[i]->next = prune_proc_stat_list(proc_stat_history[i]->next);
			proc_stat_history[i]->lastcheck = now;
		}

		pthread_rwlock_unlock(&proc_stat_history[i]->lock);
	}
}

static struct cg_proc_stat *find_proc_stat_node(struct cg_proc_stat_head *head, const char *cg)
{
	struct cg_proc_stat *node;

	pthread_rwlock_rdlock(&head->lock);

	if (!head->next) {
		pthread_rwlock_unlock(&head->lock);
		return NULL;
	}

	node = head->next;

	do {
		if (strcmp(cg, node->cg) == 0)
			goto out;
	} while ((node = node->next));

	node = NULL;

out:
	pthread_rwlock_unlock(&head->lock);
	prune_proc_stat_history();
	return node;
}

static struct cg_proc_stat *new_proc_stat_node(struct cpuacct_usage *usage, int cpu_count, const char *cg)
{
	struct cg_proc_stat *node;
	int i;

	node = malloc(sizeof(struct cg_proc_stat));
	if (!node)
		goto err;

	node->cg = NULL;
	node->usage = NULL;
	node->view = NULL;

	node->cg = malloc(strlen(cg) + 1);
	if (!node->cg)
		goto err;

	strcpy(node->cg, cg);

	node->usage = malloc(sizeof(struct cpuacct_usage) * cpu_count);
	if (!node->usage)
		goto err;

	memcpy(node->usage, usage, sizeof(struct cpuacct_usage) * cpu_count);

	node->view = malloc(sizeof(struct cpuacct_usage) * cpu_count);
	if (!node->view)
		goto err;

	node->cpu_count = cpu_count;
	node->next = NULL;

	if (pthread_mutex_init(&node->lock, NULL) != 0) {
		lxcfs_error("%s\n", "Failed to initialize node lock");
		goto err;
	}

	for (i = 0; i < cpu_count; i++) {
		node->view[i].user = 0;
		node->view[i].system = 0;
		node->view[i].idle = 0;
	}

	return node;

err:
	if (node && node->cg)
		free(node->cg);
	if (node && node->usage)
		free(node->usage);
	if (node && node->view)
		free(node->view);
	if (node)
		free(node);

	return NULL;
}

static struct cg_proc_stat *add_proc_stat_node(struct cg_proc_stat *new_node)
{
	int hash = calc_hash(new_node->cg) % CPUVIEW_HASH_SIZE;
	struct cg_proc_stat_head *head = proc_stat_history[hash];
	struct cg_proc_stat *node, *rv = new_node;

	pthread_rwlock_wrlock(&head->lock);

	if (!head->next) {
		head->next = new_node;
		goto out;
	}

	node = head->next;

	for (;;) {
		if (strcmp(node->cg, new_node->cg) == 0) {
			/* The node is already present, return it */
			free_proc_stat_node(new_node);
			rv = node;
			goto out;
		}

		if (node->next) {
			node = node->next;
			continue;
		}

		node->next = new_node;
		goto out;
	}

out:
	pthread_rwlock_unlock(&head->lock);
	return rv;
}

static bool expand_proc_stat_node(struct cg_proc_stat *node, int cpu_count)
{
	struct cpuacct_usage *new_usage, *new_view;
	int i;

	/* Allocate new memory */
	new_usage = malloc(sizeof(struct cpuacct_usage) * cpu_count);
	if (!new_usage)
		return false;

	new_view = malloc(sizeof(struct cpuacct_usage) * cpu_count);
	if (!new_view) {
		free(new_usage);
		return false;
	}

	/* Copy existing data & initialize new elements */
	for (i = 0; i < cpu_count; i++) {
		if (i < node->cpu_count) {
			new_usage[i].user = node->usage[i].user;
			new_usage[i].system = node->usage[i].system;
			new_usage[i].idle = node->usage[i].idle;

			new_view[i].user = node->view[i].user;
			new_view[i].system = node->view[i].system;
			new_view[i].idle = node->view[i].idle;
		} else {
			new_usage[i].user = 0;
			new_usage[i].system = 0;
			new_usage[i].idle = 0;

			new_view[i].user = 0;
			new_view[i].system = 0;
			new_view[i].idle = 0;
		}
	}

	free(node->usage);
	free(node->view);

	node->usage = new_usage;
	node->view = new_view;
	node->cpu_count = cpu_count;

	return true;
}

static struct cg_proc_stat *find_or_create_proc_stat_node(struct cpuacct_usage *usage, int cpu_count, const char *cg)
{
	int hash = calc_hash(cg) % CPUVIEW_HASH_SIZE;
	struct cg_proc_stat_head *head = proc_stat_history[hash];
	struct cg_proc_stat *node;

	node = find_proc_stat_node(head, cg);

	if (!node) {
		node = new_proc_stat_node(usage, cpu_count, cg);
		if (!node)
			return NULL;

		node = add_proc_stat_node(node);
		lxcfs_debug("New stat node (%d) for %s\n", cpu_count, cg);
	}

	pthread_mutex_lock(&node->lock);

	/* If additional CPUs on the host have been enabled, CPU usage counter
	 * arrays have to be expanded */
	if (node->cpu_count < cpu_count) {
		lxcfs_debug("Expanding stat node %d->%d for %s\n",
				node->cpu_count, cpu_count, cg);

		if (!expand_proc_stat_node(node, cpu_count)) {
			pthread_mutex_unlock(&node->lock);
			lxcfs_debug("Unable to expand stat node %d->%d for %s\n",
					node->cpu_count, cpu_count, cg);
			return NULL;
		}
	}

	return node;
}

static void reset_proc_stat_node(struct cg_proc_stat *node, struct cpuacct_usage *usage, int cpu_count)
{
	int i;

	lxcfs_debug("Resetting stat node for %s\n", node->cg);
	memcpy(node->usage, usage, sizeof(struct cpuacct_usage) * cpu_count);

	for (i = 0; i < cpu_count; i++) {
		node->view[i].user = 0;
		node->view[i].system = 0;
		node->view[i].idle = 0;
	}

	node->cpu_count = cpu_count;
}

static int cpuview_proc_stat(const char *cg, const char *cpuset, struct cpuacct_usage *cg_cpu_usage, int cg_cpu_usage_size, FILE *f, char *buf, size_t buf_size)
{
	char *line = NULL;
	size_t linelen = 0, total_len = 0, rv = 0, l;
	int curcpu = -1; /* cpu numbering starts at 0 */
	int physcpu, i;
	int max_cpus = max_cpu_count(cg), cpu_cnt = 0;
	unsigned long user = 0, nice = 0, system = 0, idle = 0, iowait = 0, irq = 0, softirq = 0, steal = 0, guest = 0, guest_nice = 0;
	unsigned long user_sum = 0, system_sum = 0, idle_sum = 0;
	unsigned long user_surplus = 0, system_surplus = 0;
	unsigned long total_sum, threshold;
	struct cg_proc_stat *stat_node;
	struct cpuacct_usage *diff = NULL;
	int nprocs = get_nprocs_conf();

	if (cg_cpu_usage_size < nprocs)
		nprocs = cg_cpu_usage_size;

	/* Read all CPU stats and stop when we've encountered other lines */
	while (getline(&line, &linelen, f) != -1) {
		int ret;
		char cpu_char[10]; /* That's a lot of cores */
		uint64_t all_used, cg_used;

		if (strlen(line) == 0)
			continue;
		if (sscanf(line, "cpu%9[^ ]", cpu_char) != 1) {
			/* not a ^cpuN line containing a number N */
			break;
		}

		if (sscanf(cpu_char, "%d", &physcpu) != 1)
			continue;

		if (physcpu >= cg_cpu_usage_size)
			continue;

		curcpu ++;
		cpu_cnt ++;

		if (!cpu_in_cpuset(physcpu, cpuset)) {
			for (i = curcpu; i <= physcpu; i++) {
				cg_cpu_usage[i].online = false;
			}
			continue;
		}

		if (curcpu < physcpu) {
			/* Some CPUs may be disabled */
			for (i = curcpu; i < physcpu; i++)
				cg_cpu_usage[i].online = false;

			curcpu = physcpu;
		}

		cg_cpu_usage[curcpu].online = true;

		ret = sscanf(line, "%*s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
			   &user,
			   &nice,
			   &system,
			   &idle,
			   &iowait,
			   &irq,
			   &softirq,
			   &steal,
			   &guest,
			   &guest_nice);

		if (ret != 10)
			continue;

		all_used = user + nice + system + iowait + irq + softirq + steal + guest + guest_nice;
		cg_used = cg_cpu_usage[curcpu].user + cg_cpu_usage[curcpu].system;

		if (all_used >= cg_used) {
			cg_cpu_usage[curcpu].idle = idle + (all_used - cg_used);

		} else {
			lxcfs_error("cpu%d from %s has unexpected cpu time: %lu in /proc/stat, "
					"%lu in cpuacct.usage_all; unable to determine idle time\n",
					curcpu, cg, all_used, cg_used);
			cg_cpu_usage[curcpu].idle = idle;
		}
	}

	/* Cannot use more CPUs than is available due to cpuset */
	if (max_cpus > cpu_cnt)
		max_cpus = cpu_cnt;

	stat_node = find_or_create_proc_stat_node(cg_cpu_usage, nprocs, cg);

	if (!stat_node) {
		lxcfs_error("unable to find/create stat node for %s\n", cg);
		rv = 0;
		goto err;
	}

	diff = malloc(sizeof(struct cpuacct_usage) * nprocs);
	if (!diff) {
		rv = 0;
		goto err;
	}

	/*
	 * If the new values are LOWER than values stored in memory, it means
	 * the cgroup has been reset/recreated and we should reset too.
	 */
	for (curcpu = 0; curcpu < nprocs; curcpu++) {
		if (!cg_cpu_usage[curcpu].online)
			continue;

		if (cg_cpu_usage[curcpu].user < stat_node->usage[curcpu].user)
			reset_proc_stat_node(stat_node, cg_cpu_usage, nprocs);

		break;
	}

	total_sum = diff_cpu_usage(stat_node->usage, cg_cpu_usage, diff, nprocs);

	for (curcpu = 0, i = -1; curcpu < nprocs; curcpu++) {
		stat_node->usage[curcpu].online = cg_cpu_usage[curcpu].online;

		if (!stat_node->usage[curcpu].online)
			continue;

		i++;

		stat_node->usage[curcpu].user += diff[curcpu].user;
		stat_node->usage[curcpu].system += diff[curcpu].system;
		stat_node->usage[curcpu].idle += diff[curcpu].idle;

		if (max_cpus > 0 && i >= max_cpus) {
			user_surplus += diff[curcpu].user;
			system_surplus += diff[curcpu].system;
		}
	}

	/* Calculate usage counters of visible CPUs */
	if (max_cpus > 0) {
		/* threshold = maximum usage per cpu, including idle */
		threshold = total_sum / cpu_cnt * max_cpus;

		for (curcpu = 0, i = -1; curcpu < nprocs; curcpu++) {
			if (!stat_node->usage[curcpu].online)
				continue;

			i++;

			if (i == max_cpus)
				break;

			if (diff[curcpu].user + diff[curcpu].system >= threshold)
				continue;

			/* Add user */
			add_cpu_usage(
					&user_surplus,
					&diff[curcpu],
					&diff[curcpu].user,
					threshold);

			if (diff[curcpu].user + diff[curcpu].system >= threshold)
				continue;

			/* If there is still room, add system */
			add_cpu_usage(
					&system_surplus,
					&diff[curcpu],
					&diff[curcpu].system,
					threshold);
		}

		if (user_surplus > 0)
			lxcfs_debug("leftover user: %lu for %s\n", user_surplus, cg);
		if (system_surplus > 0)
			lxcfs_debug("leftover system: %lu for %s\n", system_surplus, cg);

		unsigned long diff_user = 0;
		unsigned long diff_system = 0;
		unsigned long diff_idle = 0;
		unsigned long max_diff_idle = 0;
		unsigned long max_diff_idle_index = 0;
		for (curcpu = 0, i = -1; curcpu < nprocs; curcpu++) {
			if (!stat_node->usage[curcpu].online)
				continue;

			i++;

			if (i == max_cpus)
				break;

			stat_node->view[curcpu].user += diff[curcpu].user;
			stat_node->view[curcpu].system += diff[curcpu].system;
			stat_node->view[curcpu].idle += diff[curcpu].idle;

			user_sum += stat_node->view[curcpu].user;
			system_sum += stat_node->view[curcpu].system;
			idle_sum += stat_node->view[curcpu].idle;

			diff_user += diff[curcpu].user;
			diff_system += diff[curcpu].system;
			diff_idle += diff[curcpu].idle;
			if (diff[curcpu].idle > max_diff_idle) {
				max_diff_idle = diff[curcpu].idle;
				max_diff_idle_index = curcpu;
			}

			lxcfs_v("curcpu: %d, diff_user: %lu, diff_system: %lu, diff_idle: %lu\n", curcpu, diff[curcpu].user, diff[curcpu].system, diff[curcpu].idle);
		}
		lxcfs_v("total. diff_user: %lu, diff_system: %lu, diff_idle: %lu\n", diff_user, diff_system, diff_idle);

		// revise cpu usage view to support partial cpu case
		double exact_cpus = exact_cpu_count(cg);
		if (exact_cpus < (double)max_cpus){
			lxcfs_v("revising cpu usage view to match the exact cpu count [%f]\n", exact_cpus);
			unsigned long delta = (unsigned long)((double)(diff_user + diff_system + diff_idle) * (1 - exact_cpus / (double)max_cpus));
			lxcfs_v("delta: %lu\n", delta);
			lxcfs_v("idle_sum before: %lu\n", idle_sum);
			idle_sum = idle_sum > delta ? idle_sum - delta : 0;
			lxcfs_v("idle_sum after: %lu\n", idle_sum);

			curcpu = max_diff_idle_index;
			lxcfs_v("curcpu: %d, idle before: %lu\n", curcpu, stat_node->view[curcpu].idle);
			stat_node->view[curcpu].idle = stat_node->view[curcpu].idle > delta ? stat_node->view[curcpu].idle - delta : 0;
			lxcfs_v("curcpu: %d, idle after: %lu\n", curcpu, stat_node->view[curcpu].idle);
		}
	} else {
		for (curcpu = 0; curcpu < nprocs; curcpu++) {
			if (!stat_node->usage[curcpu].online)
				continue;

			stat_node->view[curcpu].user = stat_node->usage[curcpu].user;
			stat_node->view[curcpu].system = stat_node->usage[curcpu].system;
			stat_node->view[curcpu].idle = stat_node->usage[curcpu].idle;

			user_sum += stat_node->view[curcpu].user;
			system_sum += stat_node->view[curcpu].system;
			idle_sum += stat_node->view[curcpu].idle;
		}
	}

	/* Render the file */
	/* cpu-all */
	l = snprintf(buf, buf_size, "cpu  %lu 0 %lu %lu 0 0 0 0 0 0\n",
			user_sum,
			system_sum,
			idle_sum);
	lxcfs_v("cpu-all: %s\n", buf);

	if (l < 0) {
		perror("Error writing to cache");
		rv = 0;
		goto err;
	}
	if (l >= buf_size) {
		lxcfs_error("%s\n", "Internal error: truncated write to cache.");
		rv = 0;
		goto err;
	}

	buf += l;
	buf_size -= l;
	total_len += l;

	/* Render visible CPUs */
	for (curcpu = 0, i = -1; curcpu < nprocs; curcpu++) {
		if (!stat_node->usage[curcpu].online)
			continue;

		i++;

		if (max_cpus > 0 && i == max_cpus)
			break;

		l = snprintf(buf, buf_size, "cpu%d %lu 0 %lu %lu 0 0 0 0 0 0\n",
				i,
				stat_node->view[curcpu].user,
				stat_node->view[curcpu].system,
				stat_node->view[curcpu].idle);
		lxcfs_v("cpu: %s\n", buf);

		if (l < 0) {
			perror("Error writing to cache");
			rv = 0;
			goto err;

		}
		if (l >= buf_size) {
			lxcfs_error("%s\n", "Internal error: truncated write to cache.");
			rv = 0;
			goto err;
		}

		buf += l;
		buf_size -= l;
		total_len += l;
	}

	/* Pass the rest of /proc/stat, start with the last line read */
	l = snprintf(buf, buf_size, "%s", line);

	if (l < 0) {
		perror("Error writing to cache");
		rv = 0;
		goto err;

	}
	if (l >= buf_size) {
		lxcfs_error("%s\n", "Internal error: truncated write to cache.");
		rv = 0;
		goto err;
	}

	buf += l;
	buf_size -= l;
	total_len += l;

	/* Pass the rest of the host's /proc/stat */
	while (getline(&line, &linelen, f) != -1) {
		l = snprintf(buf, buf_size, "%s", line);
		if (l < 0) {
			perror("Error writing to cache");
			rv = 0;
			goto err;
		}
		if (l >= buf_size) {
			lxcfs_error("%s\n", "Internal error: truncated write to cache.");
			rv = 0;
			goto err;
		}
		buf += l;
		buf_size -= l;
		total_len += l;
	}

	rv = total_len;

err:
	if (stat_node)
		pthread_mutex_unlock(&stat_node->lock);
	if (line)
		free(line);
	if (diff)
		free(diff);
	return rv;
}

#define CPUALL_MAX_SIZE (BUF_RESERVE_SIZE / 2)
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
	int physcpu = 0;
	unsigned long user = 0, nice = 0, system = 0, idle = 0, iowait = 0, irq = 0, softirq = 0, steal = 0, guest = 0, guest_nice = 0;
	unsigned long user_sum = 0, nice_sum = 0, system_sum = 0, idle_sum = 0, iowait_sum = 0,
					irq_sum = 0, softirq_sum = 0, steal_sum = 0, guest_sum = 0, guest_nice_sum = 0;
	char cpuall[CPUALL_MAX_SIZE];
	/* reserve for cpu all */
	char *cache = d->buf + CPUALL_MAX_SIZE;
	size_t cache_size = d->buflen - CPUALL_MAX_SIZE;
	FILE *f = NULL;
	struct cpuacct_usage *cg_cpu_usage = NULL;
	int cg_cpu_usage_size = 0;

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
	lxcfs_v("initpid: %d\n", initpid);
	if (initpid <= 0)
		initpid = fc->pid;

	/*
	 * when container run with host pid namespace initpid == 1, cgroup will "/"
	 * we should return host os's /proc contents.
	 * in some case cpuacct_usage.all in "/" will larger then /proc/stat
	 */
	if (initpid == 1) {
	    return read_file("/proc/stat", buf, size, d);
	}

	cg = get_pid_cgroup(initpid, "cpuset");
	lxcfs_v("cg: %s\n", cg);
	if (!cg)
		return read_file("/proc/stat", buf, size, d);
	prune_init_slice(cg);

	cpuset = get_cpuset(cg);
	if (!cpuset)
		goto err;

	/*
	 * Read cpuacct.usage_all for all CPUs.
	 * If the cpuacct cgroup is present, it is used to calculate the container's
	 * CPU usage. If not, values from the host's /proc/stat are used.
	 */
	if (read_cpuacct_usage_all(cg, cpuset, &cg_cpu_usage, &cg_cpu_usage_size) != 0) {
		lxcfs_v("%s\n", "proc_stat_read failed to read from cpuacct, "
				"falling back to the host's /proc/stat");
	}

	f = fopen("/proc/stat", "r");
	if (!f)
		goto err;

	//skip first line
	if (getline(&line, &linelen, f) < 0) {
		lxcfs_error("%s\n", "proc_stat_read read first line failed.");
		goto err;
	}

	if (use_cpuview(cg) && cg_cpu_usage) {
		total_len = cpuview_proc_stat(cg, cpuset, cg_cpu_usage, cg_cpu_usage_size,
				f, d->buf, d->buflen);
		goto out;
	}

	while (getline(&line, &linelen, f) != -1) {
		ssize_t l;
		char cpu_char[10]; /* That's a lot of cores */
		char *c;
		uint64_t all_used, cg_used, new_idle;
		int ret;

		if (strlen(line) == 0)
			continue;
		if (sscanf(line, "cpu%9[^ ]", cpu_char) != 1) {
			/* not a ^cpuN line containing a number N, just print it */
			l = snprintf(cache, cache_size, "%s", line);
			if (l < 0) {
				perror("Error writing to cache");
				rv = 0;
				goto err;
			}
			if (l >= cache_size) {
				lxcfs_error("%s\n", "Internal error: truncated write to cache.");
				rv = 0;
				goto err;
			}
			cache += l;
			cache_size -= l;
			total_len += l;
			continue;
		}

		if (sscanf(cpu_char, "%d", &physcpu) != 1)
			continue;
		if (!cpu_in_cpuset(physcpu, cpuset))
			continue;
		curcpu ++;

		ret = sscanf(line, "%*s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
			   &user,
			   &nice,
			   &system,
			   &idle,
			   &iowait,
			   &irq,
			   &softirq,
			   &steal,
			   &guest,
			   &guest_nice);

		if (ret != 10 || !cg_cpu_usage) {
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
				lxcfs_error("%s\n", "Internal error: truncated write to cache.");
				rv = 0;
				goto err;
			}

			cache += l;
			cache_size -= l;
			total_len += l;

			if (ret != 10)
				continue;
		}

		if (cg_cpu_usage) {
			if (physcpu >= cg_cpu_usage_size)
				break;

			all_used = user + nice + system + iowait + irq + softirq + steal + guest + guest_nice;
			cg_used = cg_cpu_usage[physcpu].user + cg_cpu_usage[physcpu].system;

			if (all_used >= cg_used) {
				new_idle = idle + (all_used - cg_used);

			} else {
				lxcfs_error("cpu%d from %s has unexpected cpu time: %lu in /proc/stat, "
						"%lu in cpuacct.usage_all; unable to determine idle time\n",
						curcpu, cg, all_used, cg_used);
				new_idle = idle;
			}

			l = snprintf(cache, cache_size, "cpu%d %lu 0 %lu %lu 0 0 0 0 0 0\n",
					curcpu, cg_cpu_usage[physcpu].user, cg_cpu_usage[physcpu].system,
					new_idle);

			if (l < 0) {
				perror("Error writing to cache");
				rv = 0;
				goto err;

			}
			if (l >= cache_size) {
				lxcfs_error("%s\n", "Internal error: truncated write to cache.");
				rv = 0;
				goto err;
			}

			cache += l;
			cache_size -= l;
			total_len += l;

			user_sum += cg_cpu_usage[physcpu].user;
			system_sum += cg_cpu_usage[physcpu].system;
			idle_sum += new_idle;

		} else {
			user_sum += user;
			nice_sum += nice;
			system_sum += system;
			idle_sum += idle;
			iowait_sum += iowait;
			irq_sum += irq;
			softirq_sum += softirq;
			steal_sum += steal;
			guest_sum += guest;
			guest_nice_sum += guest_nice;
		}
	}

	cache = d->buf;

	int cpuall_len = snprintf(cpuall, CPUALL_MAX_SIZE, "cpu  %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
			user_sum,
			nice_sum,
			system_sum,
			idle_sum,
			iowait_sum,
			irq_sum,
			softirq_sum,
			steal_sum,
			guest_sum,
			guest_nice_sum);
	if (cpuall_len > 0 && cpuall_len < CPUALL_MAX_SIZE) {
		memcpy(cache, cpuall, cpuall_len);
		cache += cpuall_len;
	} else {
		/* shouldn't happen */
		lxcfs_error("proc_stat_read copy cpuall failed, cpuall_len=%d.", cpuall_len);
		cpuall_len = 0;
	}

	memmove(cache, d->buf + CPUALL_MAX_SIZE, total_len);
	total_len += cpuall_len;

out:
	d->cached = 1;
	d->size = total_len;
	if (total_len > size)
		total_len = size;

	memcpy(buf, d->buf, total_len);
	rv = total_len;

err:
	if (f)
		fclose(f);
	if (cg_cpu_usage)
		free(cg_cpu_usage);
	free(line);
	free(cpuset);
	free(cg);
	return rv;
}

/* This function retrieves the busy time of a group of tasks by looking at
 * cpuacct.usage. Unfortunately, this only makes sense when the container has
 * been given it's own cpuacct cgroup. If not, this function will take the busy
 * time of all other taks that do not actually belong to the container into
 * account as well. If someone has a clever solution for this please send a
 * patch!
 */
static double get_reaper_busy(pid_t task)
{
	pid_t initpid = lookup_initpid_in_store(task);
	char *cgroup = NULL, *usage_str = NULL;
	unsigned long usage = 0;
	double res = 0;

	if (initpid <= 0)
		return 0;

	cgroup = get_pid_cgroup(initpid, "cpuacct");
	if (!cgroup)
		goto out;
	prune_init_slice(cgroup);
	if (!cgfs_get_value("cpuacct", cgroup, "cpuacct.usage", &usage_str))
		goto out;
	usage = strtoul(usage_str, NULL, 10);
	res = (double)usage / 1000000000;

out:
	free(cgroup);
	free(usage_str);
	return res;
}

#if RELOADTEST
void iwashere(void)
{
	int fd;

	fd = creat("/tmp/lxcfs-iwashere", 0644);
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
	double busytime = get_reaper_busy(fc->pid);
	char *cache = d->buf;
	ssize_t total_len = 0;
	double idletime, reaperage;

#if RELOADTEST
	iwashere();
#endif

	if (offset){
		if (!d->cached)
			return 0;
		if (offset > d->size)
			return -EINVAL;
		int left = d->size - offset;
		total_len = left > size ? size: left;
		memcpy(buf, cache + offset, total_len);
		return total_len;
	}

	reaperage = get_reaper_age(fc->pid);
	/* To understand why this is done, please read the comment to the
	 * get_reaper_busy() function.
	 */
	idletime = reaperage;
	if (reaperage >= busytime)
		idletime = reaperage - busytime;

	total_len = snprintf(d->buf, d->buflen, "%.2lf %.2lf\n", reaperage, idletime);
	if (total_len < 0 || total_len >=  d->buflen){
		lxcfs_error("%s\n", "failed to write to cache");
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
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;
	cg = get_pid_cgroup(initpid, "blkio");
	if (!cg)
		return read_file("/proc/diskstats", buf, size, d);
	prune_init_slice(cg);

	if (!cgfs_get_value("blkio", cg, "blkio.io_serviced_recursive", &io_serviced_str))
		goto err;
	if (!cgfs_get_value("blkio", cg, "blkio.io_merged_recursive", &io_merged_str))
		goto err;
	if (!cgfs_get_value("blkio", cg, "blkio.io_service_bytes_recursive", &io_service_bytes_str))
		goto err;
	if (!cgfs_get_value("blkio", cg, "blkio.io_wait_time_recursive", &io_wait_time_str))
		goto err;
	if (!cgfs_get_value("blkio", cg, "blkio.io_service_time_recursive", &io_service_time_str))
		goto err;


	f = fopen("/proc/diskstats", "r");
	if (!f)
		goto err;

	while (getline(&line, &linelen, f) != -1) {
		ssize_t l;
		char lbuf[256];

		i = sscanf(line, "%u %u %71s", &major, &minor, dev_name);
		if (i != 3)
			continue;

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

		memset(lbuf, 0, 256);
		if (read || write || read_merged || write_merged || read_sectors || write_sectors || read_ticks || write_ticks)
			snprintf(lbuf, 256, "%u       %u %s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
				major, minor, dev_name, read, read_merged, read_sectors, read_ticks,
				write, write_merged, write_sectors, write_ticks, ios_pgr, tot_ticks, rq_ticks);
		else
			continue;

		l = snprintf(cache, cache_size, "%s", lbuf);
		if (l < 0) {
			perror("Error writing to fuse buf");
			rv = 0;
			goto err;
		}
		if (l >= cache_size) {
			lxcfs_error("%s\n", "Internal error: truncated write to cache.");
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
	char *memswlimit_str = NULL, *memlimit_str = NULL, *memusage_str = NULL, *memswusage_str = NULL;
	unsigned long memswlimit = 0, memlimit = 0, memusage = 0, memswusage = 0, swap_total = 0, swap_free = 0;
	ssize_t total_len = 0, rv = 0;
	ssize_t l = 0;
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
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;
	cg = get_pid_cgroup(initpid, "memory");
	if (!cg)
		return read_file("/proc/swaps", buf, size, d);
	prune_init_slice(cg);

	memlimit = get_min_memlimit(cg, "memory.limit_in_bytes");

	if (!cgfs_get_value("memory", cg, "memory.usage_in_bytes", &memusage_str))
		goto err;

	memusage = strtoul(memusage_str, NULL, 10);

	if (cgfs_get_value("memory", cg, "memory.memsw.usage_in_bytes", &memswusage_str) &&
	    cgfs_get_value("memory", cg, "memory.memsw.limit_in_bytes", &memswlimit_str)) {

		memswlimit = get_min_memlimit(cg, "memory.memsw.limit_in_bytes");
		memswusage = strtoul(memswusage_str, NULL, 10);

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
		l = snprintf(d->buf + total_len, d->size - total_len,
				"none%*svirtual\t\t%lu\t%lu\t0\n", 36, " ",
				swap_total, swap_free);
		total_len += l;
	}

	if (total_len < 0 || l < 0) {
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
	return rv;
}
/*
 * Find the process pid from cgroup path.
 * eg:from /sys/fs/cgroup/cpu/docker/containerid/cgroup.procs to find the process pid.
 * @pid_buf : put pid to pid_buf.
 * @dpath : the path of cgroup. eg: /docker/containerid or /docker/containerid/child-cgroup ...
 * @depth : the depth of cgroup in container.
 * @sum : return the number of pid.
 * @cfd : the file descriptor of the mounted cgroup. eg: /sys/fs/cgroup/cpu
 */
static int calc_pid(char ***pid_buf, char *dpath, int depth, int sum, int cfd)
{
	DIR *dir;
	int fd;
	struct dirent *file;
	FILE *f = NULL;
	size_t linelen = 0;
	char *line = NULL;
	int pd;
	char *path_dir, *path;
	char **pid;

	/* path = dpath + "/cgroup.procs" + /0 */
	do {
		path = malloc(strlen(dpath) + 20);
	} while (!path);

	strcpy(path, dpath);
	fd = openat(cfd, path, O_RDONLY);
	if (fd < 0)
		goto out;

	dir = fdopendir(fd);
	if (dir == NULL) {
		close(fd);
		goto out;
	}

	while (((file = readdir(dir)) != NULL) && depth > 0) {
		if (strncmp(file->d_name, ".", 1) == 0)
			continue;
		if (strncmp(file->d_name, "..", 1) == 0)
			continue;
		if (file->d_type == DT_DIR) {
			/* path + '/' + d_name +/0 */
			do {
				path_dir = malloc(strlen(path) + 2 + sizeof(file->d_name));
			} while (!path_dir);
			strcpy(path_dir, path);
			strcat(path_dir, "/");
			strcat(path_dir, file->d_name);
			pd = depth - 1;
			sum = calc_pid(pid_buf, path_dir, pd, sum, cfd);
			free(path_dir);
		}
	}
	closedir(dir);

	strcat(path, "/cgroup.procs");
	fd = openat(cfd, path, O_RDONLY);
	if (fd < 0)
		goto out;

	f = fdopen(fd, "r");
	if (!f) {
		close(fd);
		goto out;
	}

	while (getline(&line, &linelen, f) != -1) {
		do {
			pid = realloc(*pid_buf, sizeof(char *) * (sum + 1));
		} while (!pid);
		*pid_buf = pid;
		do {
			*(*pid_buf + sum) = malloc(strlen(line) + 1);
		} while (*(*pid_buf + sum) == NULL);
		strcpy(*(*pid_buf + sum), line);
		sum++;
	}
	fclose(f);
out:
	if (line)
		free(line);
	free(path);
	return sum;
}
/*
 * calc_load calculates the load according to the following formula:
 * load1 = load0 * exp + active * (1 - exp)
 *
 * @load1: the new loadavg.
 * @load0: the former loadavg.
 * @active: the total number of running pid at this moment.
 * @exp: the fixed-point defined in the beginning.
 */
static unsigned long
calc_load(unsigned long load, unsigned long exp, unsigned long active)
{
	unsigned long newload;

	active = active > 0 ? active * FIXED_1 : 0;
	newload = load * exp + active * (FIXED_1 - exp);
	if (active >= load)
		newload += FIXED_1 - 1;

	return newload / FIXED_1;
}

/*
 * Return 0 means that container p->cg is closed.
 * Return -1 means that error occurred in refresh.
 * Positive num equals the total number of pid.
 */
static int refresh_load(struct load_node *p, char *path)
{
	FILE *f = NULL;
	char **idbuf;
	char proc_path[256];
	int i, ret, run_pid = 0, total_pid = 0, last_pid = 0;
	char *line = NULL;
	size_t linelen = 0;
	int sum, length;
	DIR *dp;
	struct dirent *file;

	do {
		idbuf = malloc(sizeof(char *));
	} while (!idbuf);
	sum = calc_pid(&idbuf, path, DEPTH_DIR, 0, p->cfd);
	/*  normal exit  */
	if (sum == 0)
		goto out;

	for (i = 0; i < sum; i++) {
		/*clean up '\n' */
		length = strlen(idbuf[i])-1;
		idbuf[i][length] = '\0';
		ret = snprintf(proc_path, 256, "/proc/%s/task", idbuf[i]);
		if (ret < 0 || ret > 255) {
			lxcfs_error("%s\n", "snprintf() failed in refresh_load.");
			i = sum;
			sum = -1;
			goto err_out;
		}

		dp = opendir(proc_path);
		if (!dp) {
			lxcfs_error("%s\n", "Open proc_path failed in refresh_load.");
			continue;
		}
		while ((file = readdir(dp)) != NULL) {
			if (strncmp(file->d_name, ".", 1) == 0)
				continue;
			if (strncmp(file->d_name, "..", 1) == 0)
				continue;
			total_pid++;
			/* We make the biggest pid become last_pid.*/
			ret = atof(file->d_name);
			last_pid = (ret > last_pid) ? ret : last_pid;

			ret = snprintf(proc_path, 256, "/proc/%s/task/%s/status", idbuf[i], file->d_name);
			if (ret < 0 || ret > 255) {
				lxcfs_error("%s\n", "snprintf() failed in refresh_load.");
				i = sum;
				sum = -1;
				closedir(dp);
				goto err_out;
			}
			f = fopen(proc_path, "r");
			if (f != NULL) {
				while (getline(&line, &linelen, f) != -1) {
					/* Find State */
					if (strncmp(line, "State", 5) == 0) {
					    if (strncmp(line, "State R", 7) == 0 ||
                                     strncmp(line, "State D", 7) == 0) {
				            run_pid++;
                        }
                        break;
                    }
				}
			    fclose(f);
			}
		}
		closedir(dp);
	}
	/*Calculate the loadavg.*/
	p->avenrun[0] = calc_load(p->avenrun[0], EXP_1, run_pid);
	p->avenrun[1] = calc_load(p->avenrun[1], EXP_5, run_pid);
	p->avenrun[2] = calc_load(p->avenrun[2], EXP_15, run_pid);
	p->run_pid = run_pid;
	p->total_pid = total_pid;
	p->last_pid = last_pid;

	free(line);
err_out:
	for (; i > 0; i--)
		free(idbuf[i-1]);
out:
	free(idbuf);
	return sum;
}
/*
 * Traverse the hash table and update it.
 */
void *load_begin(void *arg)
{

	char *path = NULL;
	int i, sum, length, ret;
	struct load_node *f;
	int first_node;
	clock_t time1, time2;

	while (1) {
		if (loadavg_stop == 1)
			return NULL;

		time1 = clock();
		for (i = 0; i < LOAD_SIZE; i++) {
			pthread_mutex_lock(&load_hash[i].lock);
			if (load_hash[i].next == NULL) {
				pthread_mutex_unlock(&load_hash[i].lock);
				continue;
			}
			f = load_hash[i].next;
			first_node = 1;
			while (f) {
				length = strlen(f->cg) + 2;
				do {
					/* strlen(f->cg) + '.' or '' + \0 */
					path = malloc(length);
				} while (!path);

				ret = snprintf(path, length, "%s%s", *(f->cg) == '/' ? "." : "", f->cg);
				if (ret < 0 || ret > length - 1) {
					/* snprintf failed, ignore the node.*/
					lxcfs_error("Refresh node %s failed for snprintf().\n", f->cg);
					goto out;
				}
				sum = refresh_load(f, path);
				if (sum == 0) {
					f = del_node(f, i);
				} else {
out:					f = f->next;
				}
				free(path);
				/* load_hash[i].lock locks only on the first node.*/
				if (first_node == 1) {
					first_node = 0;
					pthread_mutex_unlock(&load_hash[i].lock);
				}
			}
		}

		if (loadavg_stop == 1)
			return NULL;

		time2 = clock();
		usleep(FLUSH_TIME * 1000000 - (int)((time2 - time1) * 1000000 / CLOCKS_PER_SEC));
	}
}

static int proc_loadavg_read(char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = (struct file_info *)fi->fh;
	pid_t initpid;
	char *cg;
	size_t total_len = 0;
	char *cache = d->buf;
	struct load_node *n;
	int hash;
	int cfd, rv = 0;
	unsigned long a, b, c;

	if (offset) {
		if (offset > d->size)
			return -EINVAL;
		if (!d->cached)
			return 0;
		int left = d->size - offset;
		total_len = left > size ? size : left;
		memcpy(buf, cache + offset, total_len);
		return total_len;
	}
	if (!loadavg)
		return read_file("/proc/loadavg", buf, size, d);

	initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;
	cg = get_pid_cgroup(initpid, "cpu");
	if (!cg)
		return read_file("/proc/loadavg", buf, size, d);

	prune_init_slice(cg);
	hash = calc_hash(cg) % LOAD_SIZE;
	n = locate_node(cg, hash);

	/* First time */
	if (n == NULL) {
		if (!find_mounted_controller("cpu", &cfd)) {
			/*
			 * In locate_node() above, pthread_rwlock_unlock() isn't used
			 * because delete is not allowed before read has ended.
			 */
			pthread_rwlock_unlock(&load_hash[hash].rdlock);
			rv = 0;
			goto err;
		}
		do {
			n = malloc(sizeof(struct load_node));
		} while (!n);

		do {
			n->cg = malloc(strlen(cg)+1);
		} while (!n->cg);
		strcpy(n->cg, cg);
		n->avenrun[0] = 0;
		n->avenrun[1] = 0;
		n->avenrun[2] = 0;
		n->run_pid = 0;
		n->total_pid = 1;
		n->last_pid = initpid;
		n->cfd = cfd;
		insert_node(&n, hash);
	}
	a = n->avenrun[0] + (FIXED_1/200);
	b = n->avenrun[1] + (FIXED_1/200);
	c = n->avenrun[2] + (FIXED_1/200);
	total_len = snprintf(d->buf, d->buflen, "%lu.%02lu %lu.%02lu %lu.%02lu %d/%d %d\n",
		LOAD_INT(a), LOAD_FRAC(a),
		LOAD_INT(b), LOAD_FRAC(b),
		LOAD_INT(c), LOAD_FRAC(c),
		n->run_pid, n->total_pid, n->last_pid);
	pthread_rwlock_unlock(&load_hash[hash].rdlock);
	if (total_len < 0 || total_len >=  d->buflen) {
		lxcfs_error("%s\n", "Failed to write to cache");
		rv = 0;
		goto err;
	}
	d->size = (int)total_len;
	d->cached = 1;

	if (total_len > size)
		total_len = size;
	memcpy(buf, d->buf, total_len);
	rv = total_len;

err:
	free(cg);
	return rv;
}
/* Return a positive number on success, return 0 on failure.*/
pthread_t load_daemon(int load_use)
{
	int ret;
	pthread_t pid;

	ret = init_load();
	if (ret == -1) {
		lxcfs_error("%s\n", "Initialize hash_table fails in load_daemon!");
		return 0;
	}
	ret = pthread_create(&pid, NULL, load_begin, NULL);
	if (ret != 0) {
		lxcfs_error("%s\n", "Create pthread fails in load_daemon!");
		load_free();
		return 0;
	}
	/* use loadavg, here loadavg = 1*/
	loadavg = load_use;
	return pid;
}

/* Returns 0 on success. */
int stop_load_daemon(pthread_t pid)
{
	int s;

	/* Signal the thread to gracefully stop */
	loadavg_stop = 1;

	s = pthread_join(pid, NULL); /* Make sure sub thread has been canceled. */
	if (s != 0) {
		lxcfs_error("%s\n", "stop_load_daemon error: failed to join");
		return -1;
	}

	load_free();
	loadavg_stop = 0;

	return 0;
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
			strcmp(path, "/proc/swaps") == 0 ||
			strcmp(path, "/proc/loadavg") == 0) {
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
	if (filler(buf, ".", NULL, 0) != 0 ||
	    filler(buf, "..", NULL, 0) != 0 ||
	    filler(buf, "cpuinfo", NULL, 0) != 0 ||
	    filler(buf, "meminfo", NULL, 0) != 0 ||
	    filler(buf, "stat", NULL, 0) != 0 ||
	    filler(buf, "uptime", NULL, 0) != 0 ||
	    filler(buf, "diskstats", NULL, 0) != 0 ||
	    filler(buf, "swaps", NULL, 0) != 0   ||
	    filler(buf, "loadavg", NULL, 0) != 0)
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
	else if (strcmp(path, "/proc/loadavg") == 0)
		type = LXC_TYPE_PROC_LOADAVG;
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
	if (strcmp(path, "/proc") == 0 && access(path, R_OK) == 0)
		return 0;

	/* these are all read-only */
	if ((mask & ~R_OK) != 0)
		return -EACCES;
	return 0;
}

int proc_release(const char *path, struct fuse_file_info *fi)
{
	do_release_file_info(fi);
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
	case LXC_TYPE_PROC_LOADAVG:
		return proc_loadavg_read(buf, size, offset, fi);
	default:
		return -EINVAL;
	}
}

/*
 * Functions needed to setup cgroups in the __constructor__.
 */

static bool mkdir_p(const char *dir, mode_t mode)
{
	const char *tmp = dir;
	const char *orig = dir;
	char *makeme;

	do {
		dir = tmp + strspn(tmp, "/");
		tmp = dir + strcspn(dir, "/");
		makeme = strndup(orig, dir - orig);
		if (!makeme)
			return false;
		if (mkdir(makeme, mode) && errno != EEXIST) {
			lxcfs_error("Failed to create directory '%s': %s.\n",
				makeme, strerror(errno));
			free(makeme);
			return false;
		}
		free(makeme);
	} while(tmp != dir);

	return true;
}

static bool umount_if_mounted(void)
{
	if (umount2(BASEDIR, MNT_DETACH) < 0 && errno != EINVAL) {
		lxcfs_error("Failed to unmount %s: %s.\n", BASEDIR, strerror(errno));
		return false;
	}
	return true;
}

/* __typeof__ should be safe to use with all compilers. */
typedef __typeof__(((struct statfs *)NULL)->f_type) fs_type_magic;
static bool has_fs_type(const struct statfs *fs, fs_type_magic magic_val)
{
	return (fs->f_type == (fs_type_magic)magic_val);
}

/*
 * looking at fs/proc_namespace.c, it appears we can
 * actually expect the rootfs entry to very specifically contain
 * " - rootfs rootfs "
 * IIUC, so long as we've chrooted so that rootfs is not our root,
 * the rootfs entry should always be skipped in mountinfo contents.
 */
static bool is_on_ramfs(void)
{
	FILE *f;
	char *p, *p2;
	char *line = NULL;
	size_t len = 0;
	int i;

	f = fopen("/proc/self/mountinfo", "r");
	if (!f)
		return false;

	while (getline(&line, &len, f) != -1) {
		for (p = line, i = 0; p && i < 4; i++)
			p = strchr(p + 1, ' ');
		if (!p)
			continue;
		p2 = strchr(p + 1, ' ');
		if (!p2)
			continue;
		*p2 = '\0';
		if (strcmp(p + 1, "/") == 0) {
			// this is '/'.  is it the ramfs?
			p = strchr(p2 + 1, '-');
			if (p && strncmp(p, "- rootfs rootfs ", 16) == 0) {
				free(line);
				fclose(f);
				return true;
			}
		}
	}
	free(line);
	fclose(f);
	return false;
}

static int pivot_enter()
{
	int ret = -1, oldroot = -1, newroot = -1;

	oldroot = open("/", O_DIRECTORY | O_RDONLY);
	if (oldroot < 0) {
		lxcfs_error("%s\n", "Failed to open old root for fchdir.");
		return ret;
	}

	newroot = open(ROOTDIR, O_DIRECTORY | O_RDONLY);
	if (newroot < 0) {
		lxcfs_error("%s\n", "Failed to open new root for fchdir.");
		goto err;
	}

	/* change into new root fs */
	if (fchdir(newroot) < 0) {
		lxcfs_error("Failed to change directory to new rootfs: %s.\n", ROOTDIR);
		goto err;
	}

	/* pivot_root into our new root fs */
	if (pivot_root(".", ".") < 0) {
		lxcfs_error("pivot_root() syscall failed: %s.\n", strerror(errno));
		goto err;
	}

	/*
	 * At this point the old-root is mounted on top of our new-root.
	 * To unmounted it we must not be chdir'd into it, so escape back
	 * to the old-root.
	 */
	if (fchdir(oldroot) < 0) {
		lxcfs_error("%s\n", "Failed to enter old root.");
		goto err;
	}

	if (umount2(".", MNT_DETACH) < 0) {
		lxcfs_error("%s\n", "Failed to detach old root.");
		goto err;
	}

	if (fchdir(newroot) < 0) {
		lxcfs_error("%s\n", "Failed to re-enter new root.");
		goto err;
	}

	ret = 0;

err:
	if (oldroot > 0)
		close(oldroot);
	if (newroot > 0)
		close(newroot);

	return ret;
}

static int chroot_enter()
{
	if (mount(ROOTDIR, "/", NULL, MS_REC | MS_BIND, NULL)) {
		lxcfs_error("Failed to recursively bind-mount %s into /.", ROOTDIR);
		return -1;
	}

	if (chroot(".") < 0) {
		lxcfs_error("Call to chroot() failed: %s.\n", strerror(errno));
		return -1;
	}

	if (chdir("/") < 0) {
		lxcfs_error("Failed to change directory: %s.\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int permute_and_enter(void)
{
	struct statfs sb;

	if (statfs("/", &sb) < 0) {
		lxcfs_error("%s\n", "Could not stat / mountpoint.");
		return -1;
	}

	/* has_fs_type() is not reliable. When the ramfs is a tmpfs it will
	 * likely report TMPFS_MAGIC. Hence, when it reports no we still check
	 * /proc/1/mountinfo. */
	if (has_fs_type(&sb, RAMFS_MAGIC) || is_on_ramfs())
		return chroot_enter();

	if (pivot_enter() < 0) {
		lxcfs_error("%s\n", "Could not perform pivot root.");
		return -1;
	}

	return 0;
}

/* Prepare our new clean root. */
static int permute_prepare(void)
{
	if (mkdir(ROOTDIR, 0700) < 0 && errno != EEXIST) {
		lxcfs_error("%s\n", "Failed to create directory for new root.");
		return -1;
	}

	if (mount("/", ROOTDIR, NULL, MS_BIND, 0) < 0) {
		lxcfs_error("Failed to bind-mount / for new root: %s.\n", strerror(errno));
		return -1;
	}

	if (mount(RUNTIME_PATH, ROOTDIR RUNTIME_PATH, NULL, MS_BIND, 0) < 0) {
		lxcfs_error("Failed to bind-mount /run into new root: %s.\n", strerror(errno));
		return -1;
	}

	if (mount(BASEDIR, ROOTDIR BASEDIR, NULL, MS_REC | MS_MOVE, 0) < 0) {
		printf("Failed to move " BASEDIR " into new root: %s.\n", strerror(errno));
		return -1;
	}

	return 0;
}

/* Calls chroot() on ramfs, pivot_root() in all other cases. */
static bool permute_root(void)
{
	/* Prepare new root. */
	if (permute_prepare() < 0)
		return false;

	/* Pivot into new root. */
	if (permute_and_enter() < 0)
		return false;

	return true;
}

static int preserve_mnt_ns(int pid)
{
	int ret;
	size_t len = sizeof("/proc/") + 21 + sizeof("/ns/mnt");
	char path[len];

	ret = snprintf(path, len, "/proc/%d/ns/mnt", pid);
	if (ret < 0 || (size_t)ret >= len)
		return -1;

	return open(path, O_RDONLY | O_CLOEXEC);
}

static bool cgfs_prepare_mounts(void)
{
	if (!mkdir_p(BASEDIR, 0700)) {
		lxcfs_error("%s\n", "Failed to create lxcfs cgroup mountpoint.");
		return false;
	}

	if (!umount_if_mounted()) {
		lxcfs_error("%s\n", "Failed to clean up old lxcfs cgroup mountpoint.");
		return false;
	}

	if (unshare(CLONE_NEWNS) < 0) {
		lxcfs_error("Failed to unshare mount namespace: %s.\n", strerror(errno));
		return false;
	}

	cgroup_mount_ns_fd = preserve_mnt_ns(getpid());
	if (cgroup_mount_ns_fd < 0) {
		lxcfs_error("Failed to preserve mount namespace: %s.\n", strerror(errno));
		return false;
	}

	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, 0) < 0) {
		lxcfs_error("Failed to remount / private: %s.\n", strerror(errno));
		return false;
	}

	if (mount("tmpfs", BASEDIR, "tmpfs", 0, "size=100000,mode=700") < 0) {
		lxcfs_error("%s\n", "Failed to mount tmpfs over lxcfs cgroup mountpoint.");
		return false;
	}

	return true;
}

static bool cgfs_mount_hierarchies(void)
{
	char *target;
	size_t clen, len;
	int i, ret;

	for (i = 0; i < num_hierarchies; i++) {
		char *controller = hierarchies[i];

		clen = strlen(controller);
		len = strlen(BASEDIR) + clen + 2;
		target = malloc(len);
		if (!target)
			return false;

		ret = snprintf(target, len, "%s/%s", BASEDIR, controller);
		if (ret < 0 || ret >= len) {
			free(target);
			return false;
		}
		if (mkdir(target, 0755) < 0 && errno != EEXIST) {
			free(target);
			return false;
		}
		if (!strcmp(controller, "unified"))
			ret = mount("none", target, "cgroup2", 0, NULL);
		else
			ret = mount(controller, target, "cgroup", 0, controller);
		if (ret < 0) {
			lxcfs_error("Failed mounting cgroup %s: %s\n", controller, strerror(errno));
			free(target);
			return false;
		}

		fd_hierarchies[i] = open(target, O_DIRECTORY);
		if (fd_hierarchies[i] < 0) {
			free(target);
			return false;
		}
		free(target);
	}
	return true;
}

static bool cgfs_setup_controllers(void)
{
	if (!cgfs_prepare_mounts())
		return false;

	if (!cgfs_mount_hierarchies()) {
		lxcfs_error("%s\n", "Failed to set up private lxcfs cgroup mounts.");
		return false;
	}

	if (!permute_root())
		return false;

	return true;
}

static void __attribute__((constructor)) collect_and_mount_subsystems(void)
{
	FILE *f;
	char *cret, *line = NULL;
	char cwd[MAXPATHLEN];
	size_t len = 0;
	int i, init_ns = -1;
	bool found_unified = false;

	if ((f = fopen("/proc/self/cgroup", "r")) == NULL) {
		lxcfs_error("Error opening /proc/self/cgroup: %s\n", strerror(errno));
		return;
	}

	while (getline(&line, &len, f) != -1) {
		char *idx, *p, *p2;

		p = strchr(line, ':');
		if (!p)
			goto out;
		idx = line;
		*(p++) = '\0';

		p2 = strrchr(p, ':');
		if (!p2)
			goto out;
		*p2 = '\0';

		/* With cgroupv2 /proc/self/cgroup can contain entries of the
		 * form: 0::/ This will cause lxcfs to fail the cgroup mounts
		 * because it parses out the empty string "" and later on passes
		 * it to mount(). Let's skip such entries.
		 */
		if (!strcmp(p, "") && !strcmp(idx, "0") && !found_unified) {
			found_unified = true;
			p = "unified";
		}

		if (!store_hierarchy(line, p))
			goto out;
	}

	/* Preserve initial namespace. */
	init_ns = preserve_mnt_ns(getpid());
	if (init_ns < 0) {
		lxcfs_error("%s\n", "Failed to preserve initial mount namespace.");
		goto out;
	}

	fd_hierarchies = malloc(sizeof(int) * num_hierarchies);
	if (!fd_hierarchies) {
		lxcfs_error("%s\n", strerror(errno));
		goto out;
	}

	for (i = 0; i < num_hierarchies; i++)
		fd_hierarchies[i] = -1;

	cret = getcwd(cwd, MAXPATHLEN);
	if (!cret)
		lxcfs_debug("Could not retrieve current working directory: %s.\n", strerror(errno));

	/* This function calls unshare(CLONE_NEWNS) our initial mount namespace
	 * to privately mount lxcfs cgroups. */
	if (!cgfs_setup_controllers()) {
		lxcfs_error("%s\n", "Failed to setup private cgroup mounts for lxcfs.");
		goto out;
	}

	if (setns(init_ns, 0) < 0) {
		lxcfs_error("Failed to switch back to initial mount namespace: %s.\n", strerror(errno));
		goto out;
	}

	if (!cret || chdir(cwd) < 0)
		lxcfs_debug("Could not change back to original working directory: %s.\n", strerror(errno));

	if (!init_cpuview()) {
		lxcfs_error("%s\n", "failed to init CPU view");
		goto out;
	}

	print_subsystems();

out:
	free(line);
	fclose(f);
	if (init_ns >= 0)
		close(init_ns);
}

static void __attribute__((destructor)) free_subsystems(void)
{
	int i;

	lxcfs_debug("%s\n", "Running destructor for liblxcfs.");

	for (i = 0; i < num_hierarchies; i++) {
		if (hierarchies[i])
			free(hierarchies[i]);
		if (fd_hierarchies && fd_hierarchies[i] >= 0)
			close(fd_hierarchies[i]);
	}
	free(hierarchies);
	free(fd_hierarchies);
	free_cpuview();

	if (cgroup_mount_ns_fd >= 0)
		close(cgroup_mount_ns_fd);
}
