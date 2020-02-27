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
#include <signal.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/vfs.h>

#include "api_extensions.h"
#include "bindings.h"
#include "config.h"
#include "cgroup_fuse.h"
#include "cgroups/cgroup.h"
#include "cgroups/cgroup_utils.h"
#include "memory_utils.h"
#include "proc_cpuview.h"
#include "utils.h"

static bool can_use_pidfd;

/* Define pivot_root() if missing from the C library */
#ifndef HAVE_PIVOT_ROOT
static int pivot_root(const char *new_root, const char *put_old)
{
#ifdef __NR_pivot_root
	return syscall(__NR_pivot_root, new_root, put_old);
#else
	errno = ENOSYS;
	return -1;
#endif
}
#else
extern int pivot_root(const char *new_root, const char *put_old);
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
	ino_t ino;     /* inode number for /proc/$pid/ns/pid */
	pid_t initpid; /* the pid of nit in that ns */
	int init_pidfd;
	long int ctime; /* the time at which /proc/$initpid was created */
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

	ret = pthread_mutex_lock(l);
	if (ret)
		log_exit("%s - returned %d\n", strerror(ret), ret);
}

struct cgroup_ops *cgroup_ops;

static void unlock_mutex(pthread_mutex_t *l)
{
	int ret;

	ret = pthread_mutex_unlock(l);
	if (ret)
		log_exit("%s - returned %d\n", strerror(ret), ret);
}

static void store_lock(void)
{
	lock_mutex(&pidns_store_mutex);
}

static void store_unlock(void)
{
	unlock_mutex(&pidns_store_mutex);
}

/* /proc/       =    6
 *                +
 * <pid-as-str> =   INTTYPE_TO_STRLEN(pid_t)
 *                +
 * \0           =    1
 */
#define LXCFS_PROC_PID_LEN \
	(STRLITERALLEN("/proc/") + INTTYPE_TO_STRLEN(uint64_t) + +1)

/* Must be called under store_lock */
static bool initpid_still_valid(struct pidns_init_store *entry)
{
	bool valid = true;

	if (entry->init_pidfd >= 0) {
		if (pidfd_send_signal(entry->init_pidfd, 0, NULL, 0))
			valid = false;
	} else {
		struct stat st;
		char path[LXCFS_PROC_PID_LEN];

		snprintf(path, sizeof(path), "/proc/%d", entry->initpid);

		if (stat(path, &st) || entry->ctime != st.st_ctime)
			valid = false;
	}

	return valid;
}

/* Must be called under store_lock */
static void remove_initpid(struct pidns_init_store *entry)
{
	struct pidns_init_store *it;
	int ino_hash;

	lxcfs_debug("Removing cached entry for pid %d from init pid cache",
		    entry->initpid);

	ino_hash = HASH(entry->ino);
	if (pidns_hash_table[ino_hash] == entry) {
		pidns_hash_table[ino_hash] = entry->next;
		close_prot_errno_disarm(entry->init_pidfd);
		free_disarm(entry);
		return;
	}

	it = pidns_hash_table[ino_hash];
	while (it) {
		if (it->next == entry) {
			it->next = entry->next;
			close_prot_errno_disarm(entry->init_pidfd);
			free_disarm(entry);
			return;
		}
		it = it->next;
	}
}

#define PURGE_SECS 5
/* Must be called under store_lock */
static void prune_initpid_store(void)
{
	static long int last_prune = 0;
	long int now, threshold;

	if (!last_prune) {
		last_prune = time(NULL);
		return;
	}

	now = time(NULL);
	if (now < last_prune + PURGE_SECS)
		return;

	lxcfs_debug("Pruning init pid cache");

	last_prune = now;
	threshold = now - 2 * PURGE_SECS;

	for (int i = 0; i < PIDNS_HASH_SIZE; i++) {
		for (struct pidns_init_store *entry = pidns_hash_table[i], *prev = NULL; entry;) {
			if (entry->lastcheck < threshold) {
				struct pidns_init_store *cur = entry;

				lxcfs_debug("Removed cache entry for pid %d to init pid cache", cur->initpid);

				if (prev)
					prev->next = entry->next;
				else
					pidns_hash_table[i] = entry->next;
				entry = entry->next;
				close_prot_errno_disarm(cur->init_pidfd);
				free_disarm(cur);
			} else {
				prev = entry;
				entry = entry->next;
			}
		}
	}
}

/* Must be called under store_lock */
static void save_initpid(struct stat *sb, pid_t pid)
{
	__do_free struct pidns_init_store *entry = NULL;
	__do_close_prot_errno int pidfd = -EBADF;
	char path[LXCFS_PROC_PID_LEN];
	struct lxcfs_opts *opts = fuse_get_context()->private_data;
	struct stat st;
	int ino_hash;

	if (opts->use_pidfd && can_use_pidfd) {
		pidfd = pidfd_open(pid, 0);
		if (pidfd < 0)
			return;
	}

	snprintf(path, sizeof(path), "/proc/%d", pid);
	if (stat(path, &st))
		return;

	entry = malloc(sizeof(*entry));
	if (entry)
		return;

	ino_hash = HASH(entry->ino);
	*entry = (struct pidns_init_store){
		.ino		= sb->st_ino,
		.initpid	= pid,
		.ctime		= st.st_ctime,
		.next		= pidns_hash_table[ino_hash],
		.lastcheck	= time(NULL),
		.init_pidfd	= move_fd(pidfd),
	};
	pidns_hash_table[ino_hash] = move_ptr(entry);

	lxcfs_debug("Added cache entry %d for pid %d to init pid cache", ino_hash, pid);
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
	struct pidns_init_store *entry = pidns_hash_table[HASH(sb->st_ino)];

	while (entry) {
		if (entry->ino == sb->st_ino) {
			if (initpid_still_valid(entry)) {
				entry->lastcheck = time(NULL);
				return entry;
			}

			remove_initpid(entry);
			return NULL;
		}
		entry = entry->next;
	}

	return NULL;
}

static int send_creds_clone_wrapper(void *arg)
{
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

/*
 * Let's use the "standard stack limit" (i.e. glibc thread size default) for
 * stack sizes: 8MB.
 */
#define __LXCFS_STACK_SIZE (8 * 1024 * 1024)
static pid_t lxcfs_clone(int (*fn)(void *), void *arg, int flags)
{
	pid_t ret;
	void *stack;

	stack = malloc(__LXCFS_STACK_SIZE);
	if (!stack)
		return ret_errno(ENOMEM);

#ifdef __ia64__
	ret = __clone2(fn, stack, __LXCFS_STACK_SIZE, flags | SIGCHLD, arg, NULL);
#else
	ret = clone(fn, stack + __LXCFS_STACK_SIZE, flags | SIGCHLD, arg, NULL);
#endif
	return ret;
}

#define LXCFS_PROC_PID_NS_LEN                                    \
	(STRLITERALLEN("/proc/") + INTTYPE_TO_STRLEN(uint64_t) + \
	 STRLITERALLEN("/ns/pid") + 1)

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
	__do_close_prot_errno int fd = -EBADF;
	char path[LXCFS_PROC_PID_NS_LEN];
	pid_t pid;

	snprintf(path, sizeof(path), "/proc/%d/ns/pid", (int)target);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		log_exit("write_task_init_pid_exit open of ns/pid");

	if (setns(fd, 0))
		log_exit("Failed to setns to pid namespace of process %d", target);

	pid = lxcfs_clone(send_creds_clone_wrapper, &sock, 0);
	if (pid < 0)
		_exit(EXIT_FAILURE);

	if (pid != 0) {
		if (!wait_for_pid(pid))
			_exit(EXIT_FAILURE);

		_exit(EXIT_SUCCESS);
	}
}

static pid_t get_init_pid_for_task(pid_t task)
{
	char v = '0';
	pid_t pid_ret = -1;
	pid_t pid;
	int sock[2];
	struct ucred cred;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sock) < 0)
		return -1;

	pid = fork();
	if (pid < 0)
		goto out;

	if (pid == 0) {
		close(sock[1]);
		write_task_init_pid_exit(sock[0], task);
		_exit(EXIT_SUCCESS);
	}

	if (!recv_creds(sock[1], &cred, &v))
		goto out;

	pid_ret = cred.pid;

out:
	close(sock[0]);
	close(sock[1]);
	if (pid > 0)
		wait_for_pid(pid);

	return pid_ret;
}

pid_t lookup_initpid_in_store(pid_t pid)
{
	pid_t answer = 0;
	char path[LXCFS_PROC_PID_NS_LEN];
	struct stat st;
	struct pidns_init_store *entry;

	snprintf(path, sizeof(path), "/proc/%d/ns/pid", pid);

	store_lock();
	if (stat(path, &st))
		goto out;

	entry = lookup_verify_initpid(&st);
	if (entry) {
		answer = entry->initpid;
		goto out;
	}

	answer = get_init_pid_for_task(pid);
	if (answer > 0)
		save_initpid(&st, answer);

out:
	/*
	 * Prune at the end in case we're returning the value we were about to
	 * return.
	 */
	prune_initpid_store();

	store_unlock();

	return answer;
}

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
	__do_free char *line = NULL;
	__do_fclose FILE *f = NULL;
	size_t len = 0;

	f = fopen("/proc/self/mountinfo", "re");
	if (!f)
		return false;

	while (getline(&line, &len, f) != -1) {
		int i;
		char *p, *p2;

		for (p = line, i = 0; p && i < 4; i++)
			p = strchr(p + 1, ' ');
		if (!p)
			continue;

		p2 = strchr(p + 1, ' ');
		if (!p2)
			continue;
		*p2 = '\0';
		if (strcmp(p + 1, "/") == 0) {
			/* This is '/'. Is it the ramfs? */
			p = strchr(p2 + 1, '-');
			if (p && strncmp(p, "- rootfs rootfs ", 16) == 0)
				return true;
		}
	}

	return false;
}

static int pivot_enter()
{
	__do_close_prot_errno int oldroot = -EBADF, newroot = -EBADF;

	oldroot = open("/", O_DIRECTORY | O_RDONLY);
	if (oldroot < 0)
		return log_error_errno(-1, errno,
				       "Failed to open old root for fchdir");

	newroot = open(ROOTDIR, O_DIRECTORY | O_RDONLY);
	if (newroot < 0)
		return log_error_errno(-1, errno,
				       "Failed to open new root for fchdir");

	/* change into new root fs */
	if (fchdir(newroot) < 0)
		return log_error_errno(-1,
				       errno, "Failed to change directory to new rootfs: %s",
				       ROOTDIR);

	/* pivot_root into our new root fs */
	if (pivot_root(".", ".") < 0)
		return log_error_errno(-1, errno,
				       "pivot_root() syscall failed: %s",
				       strerror(errno));

	/*
	 * At this point the old-root is mounted on top of our new-root.
	 * To unmounted it we must not be chdir'd into it, so escape back
	 * to the old-root.
	 */
	if (fchdir(oldroot) < 0)
		return log_error_errno(-1, errno, "Failed to enter old root");

	if (umount2(".", MNT_DETACH) < 0)
		return log_error_errno(-1, errno, "Failed to detach old root");

	if (fchdir(newroot) < 0)
		return log_error_errno(-1, errno, "Failed to re-enter new root");

	return 0;
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

	if (!cgfs_mount_hierarchies())
		return log_error_errno(false, errno, "Failed to set up private lxcfs cgroup mounts");

	if (!permute_root())
		return false;

	return true;
}

static void __attribute__((constructor)) lxcfs_init(void)
{
	__do_close_prot_errno int init_ns = -EBADF, pidfd = -EBADF;
	int i = 0;
	pid_t pid;
	char *cret;
	char cwd[MAXPATHLEN];

	cgroup_ops = cgroup_init();
	if (!cgroup_ops)
		log_exit("Failed to initialize cgroup support");

	/* Preserve initial namespace. */
	pid = getpid();
	init_ns = preserve_ns(pid, "mnt");
	if (init_ns < 0)
		log_exit("Failed to preserve initial mount namespace");

	cret = getcwd(cwd, MAXPATHLEN);
	if (!cret)
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

	fprintf(stderr, "mount namespace: %d\n", cgroup_ops->mntns_fd);
	fprintf(stderr, "hierarchies:\n");

	for (struct hierarchy **h = cgroup_ops->hierarchies; h && *h; h++, i++) {
		__do_free char *controllers = lxc_string_join(",", (const char **)(*h)->controllers, false);
		fprintf(stderr, " %2d: fd: %3d: %s\n", i, (*h)->fd, controllers ?: "");
	}

	pidfd = pidfd_open(pid, 0);
	if (pidfd >= 0 && pidfd_send_signal(pidfd, 0, NULL, 0) == 0) {
		can_use_pidfd = true;
		fprintf(stderr, "Kernel supports pidfds\n");
	}

	fprintf(stderr, "api_extensions:\n");
	for (i = 0; i < nr_api_extensions; i++)
		fprintf(stderr, "- %s\n", api_extensions[i]);
}

static void __attribute__((destructor)) lxcfs_exit(void)
{
	lxcfs_debug("%s\n", "Running destructor for liblxcfs");
	free_cpuview();
	cgroup_exit(cgroup_ops);
}
