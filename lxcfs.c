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
#include <sys/mount.h>
#include <sys/socket.h>
#include <linux/limits.h>

#include "bindings.h"
#include "config.h" // for VERSION

void *dlopen_handle;

/* Functions to keep track of number of threads using the library */

static int users_count;
static pthread_mutex_t user_count_mutex = PTHREAD_MUTEX_INITIALIZER;
static void lock_mutex(pthread_mutex_t *l)
{
	int ret;

	if ((ret = pthread_mutex_lock(l)) != 0) {
		lxcfs_error("returned:%d %s\n", ret, strerror(ret));
		exit(1);
	}
}

static void unlock_mutex(pthread_mutex_t *l)
{
	int ret;

	if ((ret = pthread_mutex_unlock(l)) != 0) {
		lxcfs_error("returned:%d %s\n", ret, strerror(ret));
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
	char lxcfs_lib_path[PATH_MAX];
	if (dlopen_handle) {
		lxcfs_debug("%s\n", "Closing liblxcfs.so handle.");
		dlclose(dlopen_handle);
	}

	/* First try loading using ld.so */
	dlopen_handle = dlopen("liblxcfs.so", RTLD_LAZY);
	if (dlopen_handle) {
		lxcfs_debug("%s\n", "Successfully called dlopen() on liblxcfs.so.");
		goto good;
	}

#ifdef LIBDIR
	/* LIBDIR: autoconf will setup this MACRO. Default value is $PREFIX/lib */
        snprintf(lxcfs_lib_path, PATH_MAX, "%s/lxcfs/liblxcfs.so", LIBDIR);
#else
        snprintf(lxcfs_lib_path, PATH_MAX, "/usr/local/lib/lxcfs/liblxcfs.so");
#endif
        dlopen_handle = dlopen(lxcfs_lib_path, RTLD_LAZY);
	if (!dlopen_handle) {
		lxcfs_error("Failed to open liblxcfs.so: %s.\n", dlerror());
		_exit(1);
	}

good:
	if (need_reload)
		lxcfs_error("%s\n", "lxcfs: reloaded");
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

/* Functions to run the library methods */
static int do_cg_getattr(const char *path, struct stat *sb)
{
	int (*cg_getattr)(const char *path, struct stat *sb);
	char *error;
	dlerror();    /* Clear any existing error */
	cg_getattr = (int (*)(const char *, struct stat *)) dlsym(dlopen_handle, "cg_getattr");
	error = dlerror();
	if (error != NULL) {
		lxcfs_error("%s\n", error);
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
		lxcfs_error("%s\n", error);
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
		lxcfs_error("%s\n", error);
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
		lxcfs_error("%s\n", error);
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
		lxcfs_error("%s\n", error);
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
		lxcfs_error("%s\n", error);
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
		lxcfs_error("%s\n", error);
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
		lxcfs_error("%s\n", error);
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
		lxcfs_error("%s\n", error);
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
		lxcfs_error("%s\n", error);
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
		lxcfs_error("%s\n", error);
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
		lxcfs_error("%s\n", error);
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
		lxcfs_error("%s\n", error);
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
		lxcfs_error("%s\n", error);
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
		lxcfs_error("%s\n", error);
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
		lxcfs_error("%s\n", error);
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
		lxcfs_error("%s\n", error);
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
		lxcfs_error("%s\n", error);
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
		lxcfs_error("%s\n", error);
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
	struct timespec now;

	if (strcmp(path, "/") == 0) {
		if (clock_gettime(CLOCK_REALTIME, &now) < 0)
			return -EINVAL;
		sb->st_uid = sb->st_gid = 0;
		sb->st_atim = sb->st_mtim = sb->st_ctim = now;
		sb->st_size = 0;
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
	return -ENOENT;
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
		if (filler(buf, ".", NULL, 0) != 0 ||
		    filler(buf, "..", NULL, 0) != 0 ||
		    filler(buf, "proc", NULL, 0) != 0 ||
		    filler(buf, "cgroup", NULL, 0) != 0)
			return -ENOMEM;
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
	return -ENOENT;
}

static int lxcfs_access(const char *path, int mode)
{
	int ret;

	if (strcmp(path, "/") == 0 && (mode & W_OK) == 0)
		return 0;

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

	return -EACCES;
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

	return -EACCES;
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

	return -EPERM;
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

	if (strncmp(path, "/proc", 5) == 0)
		return -EPERM;

	return -ENOENT;
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
	return -EPERM;
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
	return -EPERM;
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

	if (strncmp(path, "/proc", 5) == 0)
		return -EPERM;

	return -ENOENT;
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

static void usage()
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "lxcfs [-f|-d] [-p pidfile] mountpoint\n");
	fprintf(stderr, "  -f running foreground by default; -d enable debug output \n");
	fprintf(stderr, "  Default pidfile is %s/lxcfs.pid\n", RUNTIME_PATH);
	fprintf(stderr, "lxcfs -h\n");
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

bool swallow_arg(int *argcp, char *argv[], char *which)
{
	int i;

	for (i = 1; argv[i]; i++) {
		if (strcmp(argv[i], which) != 0)
			continue;
		for (; argv[i]; i++) {
			argv[i] = argv[i+1];
		}
		(*argcp)--;
		return true;
	}
	return false;
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
		fprintf(stderr, "Could not open pidfile %s: %m\n", pidfile);
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

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	int pidfd = -1;
	char *pidfile = NULL, *saveptr = NULL, *token = NULL, *v = NULL;
	size_t pidfile_len;
	bool debug = false, nonempty = false;
	/*
	 * what we pass to fuse_main is:
	 * argv[0] -s [-f|-d] -o allow_other,directio argv[1] NULL
	 */
	int nargs = 5, cnt = 0;
	char *newargv[6];

	/* accomodate older init scripts */
	swallow_arg(&argc, argv, "-s");
	swallow_arg(&argc, argv, "-f");
	debug = swallow_arg(&argc, argv, "-d");
	if (swallow_option(&argc, argv, "-o", &v)) {
		/* Parse multiple values */
		for (; (token = strtok_r(v, ",", &saveptr)); v = NULL) {
			if (strcmp(token, "allow_other") == 0) {
				/* Noop. this is the default. Always enabled. */
			} else if (strcmp(token, "nonempty") == 0) {
				nonempty = true;
			} else {
				free(v);
				fprintf(stderr, "Warning: unexpected fuse option %s\n", v);
				exit(EXIT_FAILURE);
			}
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
		usage();

	do_reload();
	if (signal(SIGUSR1, reload_handler) == SIG_ERR) {
		fprintf(stderr, "Error setting USR1 signal handler: %m\n");
		goto out;
	}

	newargv[cnt++] = argv[0];
	if (debug)
		newargv[cnt++] = "-d";
	else
		newargv[cnt++] = "-f";
	newargv[cnt++] = "-o";
	if (nonempty)
		newargv[cnt++] = "allow_other,direct_io,entry_timeout=0.5,attr_timeout=0.5,nonempty";
	else
		newargv[cnt++] = "allow_other,direct_io,entry_timeout=0.5,attr_timeout=0.5";
	newargv[cnt++] = argv[1];
	newargv[cnt++] = NULL;

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
	exit(ret);
}
