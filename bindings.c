/* lxcfs
 *
 * Copyright © 2014-2016 Canonical, Inc
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
 *
 * See COPYING file for details.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 26
#endif

#define _FILE_OFFSET_BITS 64

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
#include "config.h"
#include "cgroup_fuse.h"
#include "cgroups/cgroup.h"
#include "cgroups/cgroup_utils.h"
#include "memory_utils.h"
#include "proc_cpuview.h"
#include "utils.h"

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

struct cgroup_ops *cgroup_ops;

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
		free_disarm(e);
		return;
	}

	tmp = pidns_hash_table[h];
	while (tmp) {
		if (tmp->next == e) {
			tmp->next = e->next;
			free_disarm(e);
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
				free_disarm(delme);
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

struct cgfs_files {
	char *name;
	uint32_t uid, gid;
	uint32_t mode;
};

static void print_subsystems(void)
{
	int i = 0;

	fprintf(stderr, "mount namespace: %d\n", cgroup_ops->mntns_fd);
	fprintf(stderr, "hierarchies:\n");
	for (struct hierarchy **h = cgroup_ops->hierarchies; h && *h; h++, i++) {
		__do_free char *controllers = lxc_string_join(",", (const char **)(*h)->controllers, false);
		fprintf(stderr, " %2d: fd: %3d: %s\n", i, (*h)->fd, controllers ?: "");
	}
}

bool cgfs_param_exist(const char *controller, const char *cgroup, const char *file)
{
	int ret, cfd;
	size_t len;
	char *fnam;

	cfd = get_cgroup_fd(controller);
	if (cfd < 0)
		return false;

	/* Make sure we pass a relative path to *at() family of functions.
	 * . + /cgroup + / + file + \0
	 */
	len = strlen(cgroup) + strlen(file) + 3;
	fnam = alloca(len);
	ret = snprintf(fnam, len, "%s%s/%s", dot_or_empty(cgroup), cgroup, file);
	if (ret < 0 || (size_t)ret >= len)
		return false;

	return (faccessat(cfd, fnam, F_OK, 0) == 0);
}

#define SEND_CREDS_OK 0
#define SEND_CREDS_NOTSK 1
#define SEND_CREDS_FAIL 2
static int wait_for_pid(pid_t pid);
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

struct pid_ns_clone_args {
	int *cpipe;
	int sock;
	pid_t tpid;
	int (*wrapped) (int, pid_t); // pid_from_ns or pid_to_ns
};

/*
 * Functions needed to setup cgroups in the __constructor__.
 */

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

	cgroup_ops->mntns_fd = preserve_ns(getpid(), "mnt");
	if (cgroup_ops->mntns_fd < 0) {
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
	if (!mkdir_p(BASEDIR DEFAULT_CGROUP_MOUNTPOINT, 0755))
		return false;

	if (!cgroup_ops->mount(cgroup_ops, BASEDIR))
		return false;

	for (struct hierarchy **h = cgroup_ops->hierarchies; h && *h; h++) {
		__do_free char *path = must_make_path(BASEDIR, (*h)->mountpoint, NULL);
		(*h)->fd = open(path, O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
		if ((*h)->fd < 0)
			return false;
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

static void __attribute__((constructor)) lxcfs_init(void)
{
	__do_close_prot_errno int init_ns = -EBADF;
	char *cret;
	char cwd[MAXPATHLEN];

	cgroup_ops = cgroup_init();
	if (!cgroup_ops)
		log_exit("Failed to initialize cgroup support");

	/* Preserve initial namespace. */
	init_ns = preserve_ns(getpid(), "mnt");
	if (init_ns < 0)
		log_exit("Failed to preserve initial mount namespace");

	cret = getcwd(cwd, MAXPATHLEN);
		log_exit("%s - Could not retrieve current working directory", strerror(errno));

	/* This function calls unshare(CLONE_NEWNS) our initial mount namespace
	 * to privately mount lxcfs cgroups. */
	if (!cgfs_setup_controllers())
		log_exit("Failed to setup private cgroup mounts for lxcfs");

	if (setns(init_ns, 0) < 0)
		log_exit("%s - Failed to switch back to initial mount namespace", strerror(errno));

	if (!cret || chdir(cwd) < 0)
		log_exit("%s - Could not change back to original working directory", strerror(errno));

	if (!init_cpuview())
		log_exit("Failed to init CPU view");

	print_subsystems();
}

static void __attribute__((destructor)) lxcfs_exit(void)
{
	lxcfs_debug("%s\n", "Running destructor for liblxcfs");
	free_cpuview();
	cgroup_exit(cgroup_ops);
}
