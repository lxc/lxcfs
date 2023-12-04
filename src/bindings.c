/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <linux/limits.h>
#include <linux/magic.h>
#include <linux/sched.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>
#include <wait.h>

#include "bindings.h"

#include "api_extensions.h"
#include "cgroup_fuse.h"
#include "cgroups/cgroup.h"
#include "cgroups/cgroup_utils.h"
#include "memory_utils.h"
#include "proc_cpuview.h"
#include "syscall_numbers.h"
#include "utils.h"

/* directory under which we mount the controllers - /run/lxcfs/controllers */
#define BASEDIR "/lxcfs/controllers"
#define ROOTDIR "/lxcfs/root"

static bool can_use_pidfd;
static bool can_use_swap;
static bool can_use_sys_cpu;
static bool has_versioned_opts;
static bool memory_is_cgroupv2;
static __u32 host_personality;
static char runtime_path[PATH_MAX] = DEFAULT_RUNTIME_PATH;


static volatile sig_atomic_t reload_successful;


static char* get_base_dir(void) {
        return must_make_path(runtime_path, BASEDIR, NULL);
}

static char *get_root_dir(void) {
        return must_make_path(runtime_path, ROOTDIR, NULL);
}

bool liblxcfs_functional(void)
{
	return reload_successful != 0;
}

bool liblxcfs_can_use_swap(void)
{
	return can_use_swap;
}

bool liblxcfs_can_use_sys_cpu(void)
{
	return can_use_sys_cpu;
}

bool liblxcfs_has_versioned_opts(void)
{
	return has_versioned_opts;
}

bool liblxcfs_memory_is_cgroupv2(void)
{
	return memory_is_cgroupv2;
}

__u32 liblxcfs_personality(void)
{
	return host_personality;
}

/* Define pivot_root() if missing from the C library */
#ifndef HAVE_PIVOT_ROOT
static int pivot_root(const char *new_root, const char *put_old)
{
	return syscall(__NR_pivot_root, new_root, put_old);
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
	int64_t ctime; /* the time at which /proc/$initpid was created */
	struct pidns_init_store *next;
	int64_t lastcheck;
};

/* lol - look at how they are allocated in the kernel */
#define PIDNS_HASH_SIZE 4096
#define HASH(x) ((x) % PIDNS_HASH_SIZE)

static struct pidns_init_store *pidns_hash_table[PIDNS_HASH_SIZE];
static pthread_mutex_t pidns_store_mutex = PTHREAD_MUTEX_INITIALIZER;

static void mutex_lock(pthread_mutex_t *l)
{
	int ret;

	ret = pthread_mutex_lock(l);
	if (ret)
		log_exit("%s - returned %d\n", strerror(ret), ret);
}

struct cgroup_ops *cgroup_ops;

static void mutex_unlock(pthread_mutex_t *l)
{
	int ret;

	ret = pthread_mutex_unlock(l);
	if (ret)
		log_exit("%s - returned %d\n", strerror(ret), ret);
}

static inline void store_lock(void)
{
	mutex_lock(&pidns_store_mutex);
}

static inline void store_unlock(void)
{
	mutex_unlock(&pidns_store_mutex);
}

#define define_interruptible_lock(type, lockname, lockfn)           \
        int lockname##_interruptible(type *l)                       \
        {                                                           \
                int ret = ETIMEDOUT;                                \
                while (!fuse_interrupted() && (ret == ETIMEDOUT)) { \
                        struct timespec deadline;                   \
                        clock_gettime(CLOCK_REALTIME, &deadline);   \
                        deadline.tv_sec += 1;                       \
                        ret = lockfn(l, &deadline);                 \
                }                                                   \
                return -ret;                                        \
        }

define_interruptible_lock(pthread_mutex_t, mutex_lock, pthread_mutex_timedlock)
define_interruptible_lock(pthread_rwlock_t, rwlock_rdlock, pthread_rwlock_timedrdlock)
define_interruptible_lock(pthread_rwlock_t, rwlock_wrlock, pthread_rwlock_timedwrlock)

#undef define_interruptible_lock

/* /proc/       =    6
 *                +
 * <pid-as-str> =   INTTYPE_TO_STRLEN(pid_t)
 *                +
 * \0           =    1
 */
#define LXCFS_PROC_PID_LEN \
	(STRLITERALLEN("/proc/") + INTTYPE_TO_STRLEN(uint64_t) + +1)

static int initpid_still_valid_pidfd(struct pidns_init_store *entry)
{
	int ret;

	if (entry->init_pidfd < 0)
		return ret_errno(ENOSYS);

	ret = pidfd_send_signal(entry->init_pidfd, 0, NULL, 0);
	if (ret < 0) {
		if (errno == ENOSYS)
			return ret_errno(ENOSYS);

		return 0;
	}

	return 1;
}

static int initpid_still_valid_stat(struct pidns_init_store *entry)
{
	struct stat st;
	char path[LXCFS_PROC_PID_LEN];

	snprintf(path, sizeof(path), "/proc/%d", entry->initpid);
	if (stat(path, &st) || entry->ctime != st.st_ctime)
		return 0;

	return 1;
}

/* Must be called under store_lock */
static bool initpid_still_valid(struct pidns_init_store *entry)
{
	int ret;

	ret = initpid_still_valid_pidfd(entry);
	if (ret < 0)
		ret = initpid_still_valid_stat(entry);

	return ret == 1;
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
	static int64_t last_prune = 0;
	int64_t now, threshold;

	if (!last_prune) {
		last_prune = time(NULL);
		return;
	}

	now = time(NULL);
	if (now < (last_prune + PURGE_SECS))
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

static void clear_initpid_store(void)
{
	store_lock();
	for (int i = 0; i < PIDNS_HASH_SIZE; i++) {
		for (struct pidns_init_store *entry = pidns_hash_table[i]; entry;) {
			struct pidns_init_store *cur = entry;

			lxcfs_debug("Removed cache entry for pid %d to init pid cache", cur->initpid);

			pidns_hash_table[i] = entry->next;
			entry = entry->next;
			close_prot_errno_disarm(cur->init_pidfd);
			free_disarm(cur);
		}
	}
	store_unlock();
}

/* Must be called under store_lock */
static void save_initpid(ino_t pidns_inode, pid_t pid)
{
	__do_free struct pidns_init_store *entry = NULL;
	__do_close int pidfd = -EBADF;
	const struct lxcfs_opts *opts = fuse_get_context()->private_data;
	char path[LXCFS_PROC_PID_LEN];
	struct stat st;
	int ino_hash;

	if (opts && opts->use_pidfd && can_use_pidfd) {
		pidfd = pidfd_open(pid, 0);
		if (pidfd < 0)
			return;
	}

	snprintf(path, sizeof(path), "/proc/%d", pid);
	if (stat(path, &st))
		return;

	entry = zalloc(sizeof(*entry));
	if (!entry)
		return;

	ino_hash = HASH(pidns_inode);
	*entry = (struct pidns_init_store){
		.ino		= pidns_inode,
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
static pid_t lookup_verify_initpid(ino_t pidns_inode)
{
	struct pidns_init_store *entry = pidns_hash_table[HASH(pidns_inode)];

	while (entry) {
		if (entry->ino == pidns_inode) {
			if (initpid_still_valid(entry)) {
				entry->lastcheck = time(NULL);
				return entry->initpid;
			}

			remove_initpid(entry);
			return ret_errno(ESRCH);
		}
		entry = entry->next;
	}

	return ret_errno(ESRCH);
}

static bool send_creds_ok(int sock_fd)
{
	char v = '1'; /* we are the child */
	struct ucred cred = {
	    .uid = 0,
	    .gid = 0,
	    .pid = 1,
	};

	return send_creds(sock_fd, &cred, v, true) == SEND_CREDS_OK;
}

__returns_twice pid_t lxcfs_raw_clone(unsigned long flags, int *pidfd)
{
	/*
	 * These flags don't interest at all so we don't jump through any hoops
	 * of retrieving them and passing them to the kernel.
	 */
	errno = EINVAL;
	if ((flags & (CLONE_VM | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID |
		      CLONE_CHILD_CLEARTID | CLONE_SETTLS)))
		return -EINVAL;

#if defined(__s390x__) || defined(__s390__) || defined(__CRIS__)
	/* On s390/s390x and cris the order of the first and second arguments
	 * of the system call is reversed.
	 */
	return syscall(__NR_clone, NULL, flags | SIGCHLD, pidfd);
#elif defined(__sparc__) && defined(__arch64__)
	{
		/*
		 * sparc64 always returns the other process id in %o0, and a
		 * boolean flag whether this is the child or the parent in %o1.
		 * Inline assembly is needed to get the flag returned in %o1.
		 */
		register long g1 asm("g1") = __NR_clone;
		register long o0 asm("o0") = flags | SIGCHLD;
		register long o1 asm("o1") = 0; /* is parent/child indicator */
		register long o2 asm("o2") = (unsigned long)pidfd;
		long is_error, retval, in_child;
		pid_t child_pid;

		asm volatile(
#if defined(__arch64__)
		    "t 0x6d\n\t" /* 64-bit trap */
#else
		    "t 0x10\n\t" /* 32-bit trap */
#endif
		    /*
		     * catch errors: On sparc, the carry bit (csr) in the
		     * processor status register (psr) is used instead of a
		     * full register.
		     */
		    "addx %%g0, 0, %%g1"
		    : "=r"(g1), "=r"(o0), "=r"(o1), "=r"(o2) /* outputs */
		    : "r"(g1), "r"(o0), "r"(o1), "r"(o2)     /* inputs */
		    : "%cc");				     /* clobbers */

		is_error = g1;
		retval = o0;
		in_child = o1;

		if (is_error) {
			errno = retval;
			return -1;
		}

		if (in_child)
			return 0;

		child_pid = retval;
		return child_pid;
	}
#elif defined(__ia64__)
	/* On ia64 the stack and stack size are passed as separate arguments. */
	return syscall(__NR_clone, flags | SIGCHLD, NULL, 0, pidfd);
#else
	return syscall(__NR_clone, flags | SIGCHLD, NULL, pidfd);
#endif
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
	__do_close int fd = -EBADF;
	char path[LXCFS_PROC_PID_NS_LEN];
	pid_t pid;

	snprintf(path, sizeof(path), "/proc/%d/ns/pid", (int)target);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		log_exit("write_task_init_pid_exit open of ns/pid");

	if (setns(fd, 0))
		log_exit("Failed to setns to pid namespace of process %d", target);

	pid = lxcfs_raw_clone(0, NULL);
	if (pid < 0)
		_exit(EXIT_FAILURE);

	if (pid == 0) {
		if (!send_creds_ok(sock))
			_exit(EXIT_FAILURE);

		_exit(EXIT_SUCCESS);
	}

	if (!wait_for_pid(pid))
		_exit(EXIT_FAILURE);

	_exit(EXIT_SUCCESS);
}

static pid_t scm_init_pid(pid_t task)
{
	char v = '0';
	pid_t pid_ret = -1;
	struct ucred cred = {
		.pid = -1,
		.uid = -1,
		.gid = -1,
	};
	pid_t pid;
	int sock[2];

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
	pid_t hashed_pid = 0;
	char path[LXCFS_PROC_PID_NS_LEN];
	struct stat st;

	snprintf(path, sizeof(path), "/proc/%d/ns/pid", pid);
	if (stat(path, &st))
		return ret_errno(ESRCH);

	store_lock();

	hashed_pid = lookup_verify_initpid(st.st_ino);
	if (hashed_pid < 0) {
		/* release the mutex as the following call is expensive */
		store_unlock();

		hashed_pid = scm_init_pid(pid);

		store_lock();

		if (hashed_pid > 0)
			save_initpid(st.st_ino, hashed_pid);
	}

	/*
	 * Prune at the end in case we're pruning the value
	 * we were about to return.
	 */
	prune_initpid_store();
	store_unlock();

	return hashed_pid;
}

/*
 * Functions needed to setup cgroups in the __constructor__.
 */

static bool umount_if_mounted(void)
{
        __do_free char *base_dir = get_base_dir();
	if (umount2(base_dir, MNT_DETACH) < 0 && errno != EINVAL) {
		lxcfs_error("Failed to unmount %s: %s.\n", base_dir, strerror(errno));
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
	__do_free void *fopen_cache = NULL;
	__do_fclose FILE *f = NULL;
	size_t len = 0;

	f = fopen_cached("/proc/self/mountinfo", "re", &fopen_cache);
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

static int pivot_enter(void)
{
	__do_close int oldroot = -EBADF, newroot = -EBADF;
        __do_free char *root_dir = get_root_dir();

	oldroot = open("/", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (oldroot < 0)
		return log_error_errno(-1, errno,
				       "Failed to open old root for fchdir");

	newroot = open(root_dir, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (newroot < 0)
		return log_error_errno(-1, errno,
				       "Failed to open new root for fchdir");

	/* change into new root fs */
	if (fchdir(newroot) < 0)
		return log_error_errno(-1,
				       errno, "Failed to change directory to new rootfs: %s",
				       root_dir);

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

static int chroot_enter(void)
{
        __do_free char *root_dir = get_root_dir();

	if (mount(root_dir, "/", NULL, MS_REC | MS_BIND, NULL)) {
		lxcfs_error("Failed to recursively bind-mount %s into /.", root_dir);
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
        __do_free char *base_dir = get_base_dir();
        __do_free char *root_dir = get_root_dir();
        __do_free char *new_runtime = must_make_path(root_dir, runtime_path, NULL);
        __do_free char *new_base_dir = must_make_path(root_dir, base_dir, NULL);

	if (mkdir(root_dir, 0700) < 0 && errno != EEXIST) {
		lxcfs_error("%s\n", "Failed to create directory for new root.");
		return -1;
	}

	if (mount("/", root_dir, NULL, MS_BIND, 0) < 0) {
		lxcfs_error("Failed to bind-mount / for new root: %s.\n", strerror(errno));
		return -1;
	}

        if (!mkdir_p(new_runtime, 0755)) {
		lxcfs_error("Failed to create dir %s\n", new_runtime);
		return -1;
        }

	if (mount(runtime_path, new_runtime, NULL, MS_BIND, 0) < 0) {
		lxcfs_error("Failed to bind-mount %s into new root: %s.\n", runtime_path, strerror(errno));
		return -1;
	}

	if (mount(base_dir, new_base_dir, NULL, MS_REC | MS_MOVE, 0) < 0) {
		printf("Failed to move %s into new root: %s.\n", base_dir, strerror(errno));
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
        __do_free char *base_dir = get_base_dir();

	if (!mkdir_p(base_dir, 0700)) {
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

	if (mount("tmpfs", base_dir, "tmpfs", 0, "size=100000,mode=700") < 0) {
		lxcfs_error("%s\n", "Failed to mount tmpfs over lxcfs cgroup mountpoint.");
		return false;
	}

	return true;
}

static bool cgfs_mount_hierarchies(void)
{
        __do_free char *base_dir = get_base_dir();
        __do_free char *base_dir_cgroup_mount = must_make_path(base_dir, DEFAULT_CGROUP_MOUNTPOINT, NULL);

	if (!mkdir_p(base_dir_cgroup_mount, 0755))
		return false;

	if (!cgroup_ops->mount(cgroup_ops, base_dir))
		return false;

	for (struct hierarchy **h = cgroup_ops->hierarchies; h && *h; h++) {
		__do_free char *path = must_make_path(base_dir, (*h)->mountpoint, NULL);
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

static void sigusr2_toggle_virtualization(int signo, siginfo_t *info, void *extra)
{
	int ret;

	if (reload_successful) {
		reload_successful = 0;

		/* write() is async signal safe */
		ret = write(STDERR_FILENO,
			    "Switched into non-virtualization mode\n",
			    STRLITERALLEN("Switched into non-virtualization mode\n"));
		if (ret < 0)
			goto please_compiler;
	} else {
		reload_successful = 1;

		/* write() is async signal safe */
		ret = write(STDERR_FILENO, "Switched into virtualization mode\n",
			    STRLITERALLEN("Switched into virtualization mode\n"));
		if (ret < 0)
			goto please_compiler;
	}

please_compiler:
	/*
	 * The write() syscall is a function whose return value needs to be
	 * checked. Otherwise the compiler will warn.Another one could be to
	 * use syscall(__NR_write, ...) directly but whatever.
	 */
	return;
}

void lxcfslib_init(void)
{
	__do_close int init_ns = -EBADF, root_fd = -EBADF,
				  pidfd = -EBADF;
	int i = 0;
	pid_t pid;
	struct hierarchy *hierarchy;

	lxcfs_info("Running constructor %s to reload liblxcfs", __func__);

	cgroup_ops = cgroup_init();
	if (!cgroup_ops) {
		lxcfs_info("Failed to initialize cgroup support");
		goto broken_upgrade;
	}

	/* Preserve initial namespace. */
	pid = getpid();
	init_ns = preserve_ns(pid, "mnt");
	if (init_ns < 0) {
		lxcfs_info("Failed to preserve initial mount namespace");
		goto broken_upgrade;
	}

	/* This function calls unshare(CLONE_NEWNS) our initial mount namespace
	 * to privately mount lxcfs cgroups. */
	if (!cgfs_setup_controllers()) {
		log_exit("Failed to setup private cgroup mounts for lxcfs");
		goto broken_upgrade;
	}

	if (setns(init_ns, 0) < 0) {
		log_exit("%s - Failed to switch back to initial mount namespace", strerror(errno));
		goto broken_upgrade;
	}

	if (!init_cpuview()) {
		log_exit("Failed to init CPU view");
		goto broken_upgrade;
	}

	lxcfs_info("mount namespace: %d", cgroup_ops->mntns_fd);
	lxcfs_info("hierarchies:");

	for (struct hierarchy **h = cgroup_ops->hierarchies; h && *h; h++, i++) {
		char **controller_list = (*h)->controllers;
		__do_free char *controllers = NULL;
		if (controller_list && *controller_list)
			controllers = lxc_string_join(",", (const char **)controller_list, false);
		lxcfs_info(" %2d: fd: %3d: %s", i, (*h)->fd, controllers ?: "");
	}

	pidfd = pidfd_open(pid, 0);
	if (pidfd >= 0 && pidfd_send_signal(pidfd, 0, NULL, 0) == 0) {
		can_use_pidfd = true;
		lxcfs_info("Kernel supports pidfds");
	}

	can_use_swap = cgroup_ops->can_use_swap(cgroup_ops);
	if (can_use_swap)
		lxcfs_info("Kernel supports swap accounting");
	else
		lxcfs_info("Kernel does not support swap accounting");

	hierarchy = cgroup_ops->get_hierarchy(cgroup_ops, "memory");
	memory_is_cgroupv2 = hierarchy && is_unified_hierarchy(hierarchy);

	lxcfs_info("api_extensions:");
	for (size_t nr = 0; nr < nr_api_extensions; nr++)
		lxcfs_info("- %s", api_extensions[nr]);

	root_fd = open("/", O_PATH | O_CLOEXEC);
	if (root_fd < 0)
		lxcfs_info("%s - Failed to open root directory", strerror(errno));
	else if (fchdir(root_fd) < 0)
		lxcfs_info("%s - Failed to change to root directory", strerror(errno));

	if (install_signal_handler(SIGUSR2, sigusr2_toggle_virtualization)) {
		lxcfs_info("%s - Failed to install SIGUSR2 signal handler", strerror(errno));
		goto broken_upgrade;
	}

	if (get_task_personality(getpid(), &host_personality) < 0) {
		lxcfs_info("Failed to retrieve host personality");
		goto broken_upgrade;
	}

	reload_successful = 1;
	return;

broken_upgrade:
	reload_successful = 0;
	lxcfs_info("Failed to run constructor %s to reload liblxcfs", __func__);
}

static void __attribute__((destructor)) lxcfs_exit(void)
{
	lxcfs_info("Running destructor %s", __func__);

	clear_initpid_store();
	free_cpuview();
	cgroup_exit(cgroup_ops);
}

void *lxcfs_fuse_init(struct fuse_conn_info *conn, void *data)
{
	struct fuse_context *fc = fuse_get_context();
#if HAVE_FUSE_RETURNS_DT_TYPE
	can_use_sys_cpu = true;
#endif
	has_versioned_opts = true;
        return fc ? fc->private_data : NULL;
}

bool set_runtime_path(const char* new_path)
{
        int pathlen;

        if (new_path && strlen(new_path) < PATH_MAX) {
                pathlen = strlen(new_path);
                memcpy(runtime_path, new_path, pathlen);
                runtime_path[pathlen] = '\0';
                lxcfs_info("Using runtime path %s", runtime_path);
                return true;
        } else {
		lxcfs_error("%s\n", "Failed to overwrite the runtime path");
                return false;
        }
}
