/* lxcfs
 *
 * Copyright © 2014-2016 Canonical, Inc
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
 *
 * See COPYING file for details.
 */

#define FUSE_USE_VERSION 26

#include <alloca.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <libgen.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wait.h>
#include <linux/sched.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include "bindings.h"
#include "config.h" // for VERSION

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

void *dlopen_handle;

/* Functions to keep track of number of threads using the library */

static int users_count;
static pthread_mutex_t user_count_mutex = PTHREAD_MUTEX_INITIALIZER;
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

static void users_lock(void)
{
	lock_mutex(&user_count_mutex);
}

static void users_unlock(void)
{
	unlock_mutex(&user_count_mutex);
}

static volatile sig_atomic_t need_reload;

/* do_reload - reload the dynamic library.  Done under
 * lock and when we know the user_count was 0 */
static void do_reload(void)
{
	if (dlopen_handle)
		dlclose(dlopen_handle);

	/* First try loading using ld.so */
	dlopen_handle = dlopen("liblxcfs.so", RTLD_LAZY);
	if (dlopen_handle)
		goto good;

	dlopen_handle = dlopen("/usr/lib/lxcfs/liblxcfs.so", RTLD_LAZY);
	if (!dlopen_handle) {
		fprintf(stderr, "Failed to open liblxcfs\n");
		_exit(1);
	}

good:
	if (need_reload)
		fprintf(stderr, "lxcfs: reloaded\n");
	need_reload = 0;
}

static void up_users(void)
{
	users_lock();
	if (users_count == 0 && need_reload)
		do_reload();
	users_count++;
	users_unlock();
}

static void down_users(void)
{
	users_lock();
	users_count--;
	users_unlock();
}

static void reload_handler(int sig)
{
	need_reload = 1;
}

/*
 * Functions and types to ease the use of clone()/__clone2()
 */
pid_t lxcfs_clone(int (*fn)(void *), void *arg, int flags)
{
	size_t stack_size = sysconf(_SC_PAGESIZE);
	void *stack = alloca(stack_size);
	pid_t ret;

#ifdef __ia64__
	ret = __clone2(do_clone, stack,
		       stack_size, flags | SIGCHLD, &clone_arg);
#else
	ret = clone(fn, stack  + stack_size, flags | SIGCHLD, &arg);
#endif
	if (ret < 0)
		fprintf(stderr, "failed to clone (%#x): %s", flags, strerror(errno));

	return ret;
}

/* Functions to run the library methods */
static int do_cg_getattr(const char *path, struct stat *sb)
{
	int (*cg_getattr)(const char *path, struct stat *sb);
	char *error;
	dlerror();    /* Clear any existing error */
	cg_getattr = (int (*)(const char *, struct stat *)) dlsym(dlopen_handle, "cg_getattr");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "cg_getattr: %s\n", error);
		return -1;
	}

	return cg_getattr(path, sb);
}

static int do_proc_getattr(const char *path, struct stat *sb)
{
	int (*proc_getattr)(const char *path, struct stat *sb);
	char *error;
	dlerror();    /* Clear any existing error */
	proc_getattr = (int (*)(const char *, struct stat *)) dlsym(dlopen_handle, "proc_getattr");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "proc_getattr: %s\n", error);
		return -1;
	}

	return proc_getattr(path, sb);
}

static int do_cg_read(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	int (*cg_read)(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi);
	char *error;

	dlerror();    /* Clear any existing error */
	cg_read = (int (*)(const char *, char *, size_t, off_t, struct fuse_file_info *)) dlsym(dlopen_handle, "cg_read");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "cg_read: %s\n", error);
		return -1;
	}

	return cg_read(path, buf, size, offset, fi);
}

static int do_proc_read(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	int (*proc_read)(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi);
	char *error;

	dlerror();    /* Clear any existing error */
	proc_read = (int (*)(const char *, char *, size_t, off_t, struct fuse_file_info *)) dlsym(dlopen_handle, "proc_read");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "proc_read: %s\n", error);
		return -1;
	}

	return proc_read(path, buf, size, offset, fi);
}

static int do_cg_write(const char *path, const char *buf, size_t size, off_t offset,
	     struct fuse_file_info *fi)
{
	int (*cg_write)(const char *path, const char *buf, size_t size, off_t offset,
	     struct fuse_file_info *fi);
	char *error;
	dlerror();    /* Clear any existing error */
	cg_write = (int (*)(const char *, const char *, size_t, off_t, struct fuse_file_info *)) dlsym(dlopen_handle, "cg_write");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "cg_write: %s\n", error);
		return -1;
	}

	return cg_write(path, buf, size, offset, fi);
}

static int do_cg_mkdir(const char *path, mode_t mode)
{
	int (*cg_mkdir)(const char *path, mode_t mode);
	char *error;
	dlerror();    /* Clear any existing error */
	cg_mkdir = (int (*)(const char *, mode_t)) dlsym(dlopen_handle, "cg_mkdir");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "cg_mkdir: %s\n", error);
		return -1;
	}

	return cg_mkdir(path, mode);
}

static int do_cg_chown(const char *path, uid_t uid, gid_t gid)
{
	int (*cg_chown)(const char *path, uid_t uid, gid_t gid);
	char *error;
	dlerror();    /* Clear any existing error */
	cg_chown = (int (*)(const char *, uid_t, gid_t)) dlsym(dlopen_handle, "cg_chown");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "cg_chown: %s\n", error);
		return -1;
	}

	return cg_chown(path, uid, gid);
}

static int do_cg_rmdir(const char *path)
{
	int (*cg_rmdir)(const char *path);
	char *error;
	dlerror();    /* Clear any existing error */
	cg_rmdir = (int (*)(const char *path)) dlsym(dlopen_handle, "cg_rmdir");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "cg_rmdir: %s\n", error);
		return -1;
	}

	return cg_rmdir(path);
}

static int do_cg_chmod(const char *path, mode_t mode)
{
	int (*cg_chmod)(const char *path, mode_t mode);
	char *error;
	dlerror();    /* Clear any existing error */
	cg_chmod = (int (*)(const char *, mode_t)) dlsym(dlopen_handle, "cg_chmod");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "cg_chmod: %s\n", error);
		return -1;
	}

	return cg_chmod(path, mode);
}

static int do_cg_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
		struct fuse_file_info *fi)
{
	int (*cg_readdir)(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
		struct fuse_file_info *fi);
	char *error;

	dlerror();    /* Clear any existing error */
	cg_readdir = (int (*)(const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *)) dlsym(dlopen_handle, "cg_readdir");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "cg_readdir: %s\n", error);
		return -1;
	}

	return cg_readdir(path, buf, filler, offset, fi);
}

static int do_proc_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
		struct fuse_file_info *fi)
{
	int (*proc_readdir)(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
		struct fuse_file_info *fi);
	char *error;

	dlerror();    /* Clear any existing error */
	proc_readdir = (int (*)(const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *)) dlsym(dlopen_handle, "proc_readdir");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "proc_readdir: %s\n", error);
		return -1;
	}

	return proc_readdir(path, buf, filler, offset, fi);
}

static int do_cg_open(const char *path, struct fuse_file_info *fi)
{
	int (*cg_open)(const char *path, struct fuse_file_info *fi);
	char *error;
	dlerror();    /* Clear any existing error */
	cg_open = (int (*)(const char *, struct fuse_file_info *)) dlsym(dlopen_handle, "cg_open");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "cg_open: %s\n", error);
		return -1;
	}

	return cg_open(path, fi);
}

static int do_cg_access(const char *path, int mode)
{
	int (*cg_access)(const char *path, int mode);
	char *error;
	dlerror();    /* Clear any existing error */
	cg_access = (int (*)(const char *, int mode)) dlsym(dlopen_handle, "cg_access");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "cg_access: %s\n", error);
		return -1;
	}

	return cg_access(path, mode);
}

static int do_proc_open(const char *path, struct fuse_file_info *fi)
{
	int (*proc_open)(const char *path, struct fuse_file_info *fi);
	char *error;
	dlerror();    /* Clear any existing error */
	proc_open = (int (*)(const char *path, struct fuse_file_info *fi)) dlsym(dlopen_handle, "proc_open");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "proc_open: %s\n", error);
		return -1;
	}

	return proc_open(path, fi);
}

static int do_proc_access(const char *path, int mode)
{
	int (*proc_access)(const char *path, int mode);
	char *error;
	dlerror();    /* Clear any existing error */
	proc_access = (int (*)(const char *, int mode)) dlsym(dlopen_handle, "proc_access");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "proc_access: %s\n", error);
		return -1;
	}

	return proc_access(path, mode);
}

static int do_cg_release(const char *path, struct fuse_file_info *fi)
{
	int (*cg_release)(const char *path, struct fuse_file_info *fi);
	char *error;
	dlerror();    /* Clear any existing error */
	cg_release = (int (*)(const char *path, struct fuse_file_info *)) dlsym(dlopen_handle, "cg_release");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "cg_release: %s\n", error);
		return -1;
	}

	return cg_release(path, fi);
}

static int do_proc_release(const char *path, struct fuse_file_info *fi)
{
	int (*proc_release)(const char *path, struct fuse_file_info *fi);
	char *error;
	dlerror();    /* Clear any existing error */
	proc_release = (int (*)(const char *path, struct fuse_file_info *)) dlsym(dlopen_handle, "proc_release");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "proc_release: %s\n", error);
		return -1;
	}

	return proc_release(path, fi);
}

static int do_cg_opendir(const char *path, struct fuse_file_info *fi)
{
	int (*cg_opendir)(const char *path, struct fuse_file_info *fi);
	char *error;
	dlerror();    /* Clear any existing error */
	cg_opendir = (int (*)(const char *path, struct fuse_file_info *fi)) dlsym(dlopen_handle, "cg_opendir");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "cg_opendir: %s\n", error);
		return -1;
	}

	return cg_opendir(path, fi);
}

static int do_cg_releasedir(const char *path, struct fuse_file_info *fi)
{
	int (*cg_releasedir)(const char *path, struct fuse_file_info *fi);
	char *error;
	dlerror();    /* Clear any existing error */
	cg_releasedir = (int (*)(const char *path, struct fuse_file_info *)) dlsym(dlopen_handle, "cg_releasedir");
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "cg_releasedir: %s\n", error);
		return -1;
	}

	return cg_releasedir(path, fi);
}

/*
 * FUSE ops for /
 * these just delegate to the /proc and /cgroup ops as
 * needed
 */

static int lxcfs_getattr(const char *path, struct stat *sb)
{
	int ret;
	if (strcmp(path, "/") == 0) {
		sb->st_mode = S_IFDIR | 00755;
		sb->st_nlink = 2;
		return 0;
	}
	if (strncmp(path, "/cgroup", 7) == 0) {
		up_users();
		ret = do_cg_getattr(path, sb);
		down_users();
		return ret;
	}
	if (strncmp(path, "/proc", 5) == 0) {
		up_users();
		ret = do_proc_getattr(path, sb);
		down_users();
		return ret;
	}
	return -EINVAL;
}

static int lxcfs_opendir(const char *path, struct fuse_file_info *fi)
{
	int ret;
	if (strcmp(path, "/") == 0)
		return 0;

	if (strncmp(path, "/cgroup", 7) == 0) {
		up_users();
		ret = do_cg_opendir(path, fi);
		down_users();
		return ret;
	}
	if (strcmp(path, "/proc") == 0)
		return 0;
	return -ENOENT;
}

static int lxcfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
		struct fuse_file_info *fi)
{
	int ret;
	if (strcmp(path, "/") == 0) {
		if (filler(buf, "proc", NULL, 0) != 0 ||
				filler(buf, "cgroup", NULL, 0) != 0)
			return -EINVAL;
		return 0;
	}
	if (strncmp(path, "/cgroup", 7) == 0) {
		up_users();
		ret = do_cg_readdir(path, buf, filler, offset, fi);
		down_users();
		return ret;
	}
	if (strcmp(path, "/proc") == 0) {
		up_users();
		ret = do_proc_readdir(path, buf, filler, offset, fi);
		down_users();
		return ret;
	}
	return -EINVAL;
}

static int lxcfs_access(const char *path, int mode)
{
	int ret;
	if (strncmp(path, "/cgroup", 7) == 0) {
		up_users();
		ret = do_cg_access(path, mode);
		down_users();
		return ret;
	}
	if (strncmp(path, "/proc", 5) == 0) {
		up_users();
		ret = do_proc_access(path, mode);
		down_users();
		return ret;
	}

	return -EINVAL;
}

static int lxcfs_releasedir(const char *path, struct fuse_file_info *fi)
{
	int ret;
	if (strcmp(path, "/") == 0)
		return 0;
	if (strncmp(path, "/cgroup", 7) == 0) {
		up_users();
		ret = do_cg_releasedir(path, fi);
		down_users();
		return ret;
	}
	if (strcmp(path, "/proc") == 0)
		return 0;
	return -EINVAL;
}

static int lxcfs_open(const char *path, struct fuse_file_info *fi)
{
	int ret;
	if (strncmp(path, "/cgroup", 7) == 0) {
		up_users();
		ret = do_cg_open(path, fi);
		down_users();
		return ret;
	}
	if (strncmp(path, "/proc", 5) == 0) {
		up_users();
		ret = do_proc_open(path, fi);
		down_users();
		return ret;
	}

	return -EINVAL;
}

static int lxcfs_read(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	int ret;
	if (strncmp(path, "/cgroup", 7) == 0) {
		up_users();
		ret = do_cg_read(path, buf, size, offset, fi);
		down_users();
		return ret;
	}
	if (strncmp(path, "/proc", 5) == 0) {
		up_users();
		ret = do_proc_read(path, buf, size, offset, fi);
		down_users();
		return ret;
	}

	return -EINVAL;
}

int lxcfs_write(const char *path, const char *buf, size_t size, off_t offset,
	     struct fuse_file_info *fi)
{
	int ret;
	if (strncmp(path, "/cgroup", 7) == 0) {
		up_users();
		ret = do_cg_write(path, buf, size, offset, fi);
		down_users();
		return ret;
	}

	return -EINVAL;
}

static int lxcfs_flush(const char *path, struct fuse_file_info *fi)
{
	return 0;
}

static int lxcfs_release(const char *path, struct fuse_file_info *fi)
{
	int ret;
	if (strncmp(path, "/cgroup", 7) == 0) {
		up_users();
		ret = do_cg_release(path, fi);
		down_users();
		return ret;
	}
	if (strncmp(path, "/proc", 5) == 0) {
		up_users();
		ret = do_proc_release(path, fi);
		down_users();
		return ret;
	}

	return -EINVAL;
}

static int lxcfs_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
	return 0;
}

int lxcfs_mkdir(const char *path, mode_t mode)
{
	int ret;
	if (strncmp(path, "/cgroup", 7) == 0) {
		up_users();
		ret = do_cg_mkdir(path, mode);
		down_users();
		return ret;
	}

	return -EINVAL;
}

int lxcfs_chown(const char *path, uid_t uid, gid_t gid)
{
	int ret;
	if (strncmp(path, "/cgroup", 7) == 0) {
		up_users();
		ret = do_cg_chown(path, uid, gid);
		down_users();
		return ret;
	}

	return -EINVAL;
}

/*
 * cat first does a truncate before doing ops->write.  This doesn't
 * really make sense for cgroups.  So just return 0 always but do
 * nothing.
 */
int lxcfs_truncate(const char *path, off_t newsize)
{
	if (strncmp(path, "/cgroup", 7) == 0)
		return 0;
	return -EINVAL;
}

int lxcfs_rmdir(const char *path)
{
	int ret;
	if (strncmp(path, "/cgroup", 7) == 0) {
		up_users();
		ret = do_cg_rmdir(path);
		down_users();
		return ret;
	}
	return -EINVAL;
}

int lxcfs_chmod(const char *path, mode_t mode)
{
	int ret;
	if (strncmp(path, "/cgroup", 7) == 0) {
		up_users();
		ret = do_cg_chmod(path, mode);
		down_users();
		return ret;
	}
	return -EINVAL;
}

const struct fuse_operations lxcfs_ops = {
	.getattr = lxcfs_getattr,
	.readlink = NULL,
	.getdir = NULL,
	.mknod = NULL,
	.mkdir = lxcfs_mkdir,
	.unlink = NULL,
	.rmdir = lxcfs_rmdir,
	.symlink = NULL,
	.rename = NULL,
	.link = NULL,
	.chmod = lxcfs_chmod,
	.chown = lxcfs_chown,
	.truncate = lxcfs_truncate,
	.utime = NULL,

	.open = lxcfs_open,
	.read = lxcfs_read,
	.release = lxcfs_release,
	.write = lxcfs_write,

	.statfs = NULL,
	.flush = lxcfs_flush,
	.fsync = lxcfs_fsync,

	.setxattr = NULL,
	.getxattr = NULL,
	.listxattr = NULL,
	.removexattr = NULL,

	.opendir = lxcfs_opendir,
	.readdir = lxcfs_readdir,
	.releasedir = lxcfs_releasedir,

	.fsyncdir = NULL,
	.init = NULL,
	.destroy = NULL,
	.access = lxcfs_access,
	.create = NULL,
	.ftruncate = NULL,
	.fgetattr = NULL,
};

static void usage(const char *me)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "%s [-p pidfile] mountpoint\n", me);
	fprintf(stderr, "  Default pidfile is %s/lxcfs.pid\n", RUNTIME_PATH);
	fprintf(stderr, "%s -h\n", me);
	exit(1);
}

static bool is_help(char *w)
{
	if (strcmp(w, "-h") == 0 ||
			strcmp(w, "--help") == 0 ||
			strcmp(w, "-help") == 0 ||
			strcmp(w, "help") == 0)
		return true;
	return false;
}

void swallow_arg(int *argcp, char *argv[], char *which)
{
	int i;

	for (i = 1; argv[i]; i++) {
		if (strcmp(argv[i], which) != 0)
			continue;
		for (; argv[i]; i++) {
			argv[i] = argv[i+1];
		}
		(*argcp)--;
		return;
	}
}

bool swallow_option(int *argcp, char *argv[], char *opt, char **v)
{
	int i;

	for (i = 1; argv[i]; i++) {
		if (!argv[i+1])
			continue;
		if (strcmp(argv[i], opt) != 0)
			continue;
		do {
			*v = strdup(argv[i+1]);
		} while (!*v);
		for (; argv[i+1]; i++) {
			argv[i] = argv[i+2];
		}
		(*argcp) -= 2;
		return true;
	}
	return false;
}

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
			fprintf(stderr, "failed to create directory '%s': %s",
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
		fprintf(stderr, "failed to umount %s: %s\n", BASEDIR,
			strerror(errno));
		return false;
	}
	return true;
}

static int pivot_enter(void)
{
	int ret = -1, oldroot = -1, newroot = -1;

	oldroot = open("/", O_DIRECTORY | O_RDONLY);
	if (oldroot < 0) {
		fprintf(stderr, "%s: Failed to open old root for fchdir.\n", __func__);
		return ret;
	}

	newroot = open(ROOTDIR, O_DIRECTORY | O_RDONLY);
	if (newroot < 0) {
		fprintf(stderr, "%s: Failed to open new root for fchdir.\n", __func__);
		goto err;
	}

	/* change into new root fs */
	if (fchdir(newroot) < 0) {
		fprintf(stderr, "%s: Failed to change directory to new rootfs: %s.\n", __func__, ROOTDIR);
		goto err;
	}

	/* pivot_root into our new root fs */
	if (pivot_root(".", ".") < 0) {
		fprintf(stderr, "%s: pivot_root() syscall failed: %s.\n", __func__, strerror(errno));
		goto err;
	}

	/*
	 * At this point the old-root is mounted on top of our new-root.
	 * To unmounted it we must not be chdir'd into it, so escape back
	 * to the old-root.
	 */
	if (fchdir(oldroot) < 0) {
		fprintf(stderr, "%s: Failed to enter old root.\n", __func__);
		goto err;
	}
	if (umount2(".", MNT_DETACH) < 0) {
		fprintf(stderr, "%s: Failed to detach old root.\n", __func__);
		goto err;
	}

	if (fchdir(newroot) < 0) {
		fprintf(stderr, "%s: Failed to re-enter new root.\n", __func__);
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

/* Prepare our new clean root. */
static int pivot_prepare(void)
{
	if (mkdir(ROOTDIR, 0700) < 0 && errno != EEXIST) {
		fprintf(stderr, "%s: Failed to create directory for new root.\n", __func__);
		return -1;
	}

	if (mount("/", ROOTDIR, NULL, MS_BIND, 0) < 0) {
		fprintf(stderr, "%s: Failed to bind-mount / for new root: %s.\n", __func__, strerror(errno));
		return -1;
	}

	if (mount(RUNTIME_PATH, ROOTDIR RUNTIME_PATH, NULL, MS_BIND, 0) < 0) {
		fprintf(stderr, "%s: Failed to bind-mount /run into new root: %s.\n", __func__, strerror(errno));
		return -1;
	}

	if (mount(BASEDIR, ROOTDIR BASEDIR, NULL, MS_REC | MS_MOVE, 0) < 0) {
		printf("%s: failed to move " BASEDIR " into new root: %s.\n", __func__, strerror(errno));
		return -1;
	}

	return 0;
}

static bool pivot_new_root(void)
{
	/* Prepare new root. */
	if (pivot_prepare() < 0)
		return false;

	/* Pivot into new root. */
	if (pivot_enter() < 0)
		return false;

	return true;
}

static bool setup_cgfs_dir(void)
{
	if (!mkdir_p(BASEDIR, 0700)) {
		fprintf(stderr, "Failed to create lxcfs cgdir\n");
		return false;
	}
	if (!umount_if_mounted()) {
		fprintf(stderr, "Failed to clean up old lxcfs cgdir\n");
		return false;
	}
	if (mount("tmpfs", BASEDIR, "tmpfs", 0, "size=100000,mode=700") < 0) {
		fprintf(stderr, "Failed to mount tmpfs for private controllers\n");
		return false;
	}
	return true;
}

static bool do_mount_cgroups(void)
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
		if (mount(controller, target, "cgroup", 0, controller) < 0) {
			fprintf(stderr, "Failed mounting cgroup %s\n", controller);
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

static int cgfs_setup_controllers(void *data)
{
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, 0) < 0) {
		fprintf(stderr, "%s: Failed to re-mount / private: %s.\n", __func__, strerror(errno));
		return -1;
	}

	if (!setup_cgfs_dir()) {
		return false;
	}

	if (!do_mount_cgroups()) {
		fprintf(stderr, "Failed to set up cgroup mounts\n");
		return false;
	}

	if (!pivot_new_root())
		return false;

	return true;
}

static int set_pidfile(char *pidfile)
{
	int fd;
	char buf[50];
	struct flock fl;

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	fd = open(pidfile, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		fprintf(stderr, "Could not open pidfile %s: %m", pidfile);
		return -1;
	}

	if (fcntl(fd, F_SETLK, &fl) == -1) {
		if (errno  == EAGAIN || errno == EACCES) {
			fprintf(stderr, "PID file '%s' is already locked.\n", pidfile);
			close(fd);
			return -1;
		}
		fprintf(stderr, "Warning; unable to lock PID file, proceeding.\n");
	}

	if (ftruncate(fd, 0) == -1) {
		fprintf(stderr, "Error truncating PID file '%s': %m", pidfile);
		close(fd);
		return -1;
	}

	snprintf(buf, 50, "%ld\n", (long) getpid());
	if (write(fd, buf, strlen(buf)) != strlen(buf)) {
		fprintf(stderr, "Error writing to PID file '%s': %m", pidfile);
		close(fd);
		return -1;
	}

	return fd;
}

static void close_fd_hierarchies(void)
{
	int i;
	for (i = 0; i < num_hierarchies; i++)
		if (fd_hierarchies[i] > 0)
			close(fd_hierarchies[i]);
}

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	int pidfd = -1;
	char *pidfile = NULL, *v = NULL;
	size_t pidfile_len, mmap_len = 0;
	/*
	 * what we pass to fuse_main is:
	 * argv[0] -s -f -o allow_other,directio argv[1] NULL
	 */
	int nargs = 5, cnt = 0;
	char *newargv[6];

	/* accomodate older init scripts */
	swallow_arg(&argc, argv, "-s");
	swallow_arg(&argc, argv, "-f");
	if (swallow_option(&argc, argv, "-o", &v)) {
		if (strcmp(v, "allow_other") != 0) {
			fprintf(stderr, "Warning: unexpected fuse option %s\n", v);
			exit(EXIT_FAILURE);
		}
		free(v);
		v = NULL;
	}
	if (swallow_option(&argc, argv, "-p", &v))
		pidfile = v;

	if (argc == 2  && strcmp(argv[1], "--version") == 0) {
		fprintf(stderr, "%s\n", VERSION);
		exit(EXIT_SUCCESS);
	}
	if (argc != 2 || is_help(argv[1]))
		usage(argv[0]);

	do_reload();
	if (signal(SIGUSR1, reload_handler) == SIG_ERR) {
		fprintf(stderr, "Error setting USR1 signal handler: %m\n");
		goto out;
	}

	newargv[cnt++] = argv[0];
	newargv[cnt++] = "-f";
	newargv[cnt++] = "-o";
	newargv[cnt++] = "allow_other,direct_io,entry_timeout=0.5,attr_timeout=0.5";
	newargv[cnt++] = argv[1];
	newargv[cnt++] = NULL;

	/* Share memory with our clone(). */
	mmap_len = sizeof(int *) * num_hierarchies;
	fd_hierarchies = mmap(NULL, mmap_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!fd_hierarchies)
		goto out;

	/* Mount cgroups in private mount namespace while sharing open file
	 * desciptores between clone() and parent. */
	pid_t pid = lxcfs_clone(cgfs_setup_controllers, NULL, CLONE_NEWNS | CLONE_FILES);
	if (pid < 0) {
		fprintf(stderr, "%s: Error cloning new mount namespace: %s\n", __func__, strerror(errno));
		goto out;
	}
	if (waitpid(pid, NULL, 0) < 0) {
		fprintf(stderr, "%s: Error waiting on cloned child: %s\n", __func__, strerror(errno));
		goto out;
	}

	if (!pidfile) {
		pidfile_len = strlen(RUNTIME_PATH) + strlen("/lxcfs.pid") + 1;
		pidfile = alloca(pidfile_len);
		snprintf(pidfile, pidfile_len, "%s/lxcfs.pid", RUNTIME_PATH);
	}
	if ((pidfd = set_pidfile(pidfile)) < 0)
		goto out;

	if (!fuse_main(nargs, newargv, &lxcfs_ops, NULL))
		ret = EXIT_SUCCESS;

out:
	if (dlopen_handle)
		dlclose(dlopen_handle);
	if (pidfile)
		unlink(pidfile);
	if (pidfd > 0)
		close(pidfd);
	close_fd_hierarchies();
	if (fd_hierarchies)
		munmap(fd_hierarchies, mmap_len);
	exit(ret);
}
