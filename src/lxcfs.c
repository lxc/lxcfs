/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "config.h"

#ifdef HAVE_FUSE3
#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 30
#endif
#else
#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 26
#endif
#endif

#define _FILE_OFFSET_BITS 64

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
#include "lxcfs_fuse_compat.h"
#include "macro.h"
#include "memory_utils.h"

void *dlopen_handle;

/* Functions to keep track of number of threads using the library */

static int users_count;
static pthread_mutex_t user_count_mutex = PTHREAD_MUTEX_INITIALIZER;
static void lock_mutex(pthread_mutex_t *l)
{
	int ret;

	ret = pthread_mutex_lock(l);
	if (ret)
		log_exit("%s - returned: %d\n", strerror(ret), ret);
}

static void unlock_mutex(pthread_mutex_t *l)
{
	int ret;

	ret = pthread_mutex_unlock(l);
	if (ret)
		log_exit("%s - returned: %d\n", strerror(ret), ret);
}

static inline void users_lock(void)
{
	lock_mutex(&user_count_mutex);
}

static inline void users_unlock(void)
{
	unlock_mutex(&user_count_mutex);
}

static pthread_t loadavg_pid = 0;

/* Returns zero on success */
static int start_loadavg(void)
{
	char *error;
	pthread_t (*__load_daemon)(int);

	dlerror();
	__load_daemon = (pthread_t(*)(int))dlsym(dlopen_handle, "load_daemon");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to start loadavg daemon", error);

	loadavg_pid = __load_daemon(1);
	if (!loadavg_pid)
		return -1;

	return 0;
}

/* Returns zero on success */
static int stop_loadavg(void)
{
	char *error;
	int (*__stop_load_daemon)(pthread_t);

	__stop_load_daemon = (int (*)(pthread_t))dlsym(dlopen_handle, "stop_load_daemon");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to stop loadavg daemon", error);

	if (__stop_load_daemon(loadavg_pid))
		return -1;

	return 0;
}

static volatile sig_atomic_t need_reload;

/* do_reload - reload the dynamic library.  Done under
 * lock and when we know the user_count was 0 */
static void do_reload(void)
{
	int ret;
	char lxcfs_lib_path[PATH_MAX];

	if (loadavg_pid > 0)
		stop_loadavg();

	if (dlopen_handle) {
		lxcfs_info("Closed liblxcfs.so");
		dlclose(dlopen_handle);
	}

	/* First try loading using ld.so */
#ifdef RESOLVE_NOW
	dlopen_handle = dlopen("liblxcfs.so", RTLD_NOW);
#else
	dlopen_handle = dlopen("liblxcfs.so", RTLD_LAZY);
#endif
	if (dlopen_handle) {
		lxcfs_debug("Opened liblxcfs.so");
		goto good;
	}

#ifdef LIBDIR
	/* LIBDIR: autoconf will setup this MACRO. Default value is $PREFIX/lib */
        ret = snprintf(lxcfs_lib_path, sizeof(lxcfs_lib_path), "%s/lxcfs/liblxcfs.so", LIBDIR);
#else
        ret = snprintf(lxcfs_lib_path, sizeof(lxcfs_lib_path), "/usr/local/lib/lxcfs/liblxcfs.so");
#endif
	if (ret < 0 || ret >= sizeof(lxcfs_lib_path))
		log_exit("Failed to create path to open liblxcfs");

        dlopen_handle = dlopen(lxcfs_lib_path, RTLD_LAZY);
	if (!dlopen_handle)
		log_exit("%s - Failed to open liblxcfs.so", dlerror());
	else
		lxcfs_debug("Opened %s", lxcfs_lib_path);

good:
	if (loadavg_pid > 0)
		start_loadavg();

	if (need_reload)
		lxcfs_info("Reloaded LXCFS");
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

static void sigusr1_reload(int signo, siginfo_t *info, void *extra)
{
	need_reload = 1;
}

/* Functions to run the library methods */
static int do_cg_getattr(const char *path, struct stat *sb)
{
	char *error;
	int (*__cg_getattr)(const char *path, struct stat *sb);

	dlerror();
	__cg_getattr = (int (*)(const char *, struct stat *))dlsym(dlopen_handle, "cg_getattr");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find cg_getattr()", error);

	return __cg_getattr(path, sb);
}

static int do_proc_getattr(const char *path, struct stat *sb)
{
	char *error;
	int (*__proc_getattr)(const char *path, struct stat *sb);

	dlerror();
	__proc_getattr = (int (*)(const char *, struct stat *)) dlsym(dlopen_handle, "proc_getattr");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find proc_getattr()", error);

	return __proc_getattr(path, sb);
}

static int do_sys_getattr(const char *path, struct stat *sb)
{
	char *error;
	int (*__sys_getattr)(const char *path, struct stat *sb);

	dlerror();
	__sys_getattr = (int (*)(const char *, struct stat *)) dlsym(dlopen_handle, "sys_getattr");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find sys_getattr()", error);

	return __sys_getattr(path, sb);
}

static int do_cg_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	char *error;
	int (*__cg_read)(const char *path, char *buf, size_t size, off_t offset,
			 struct fuse_file_info *fi);

	dlerror();
	__cg_read = (int (*)(const char *, char *, size_t, off_t, struct fuse_file_info *))dlsym(dlopen_handle, "cg_read");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find cg_read()", error);

	return __cg_read(path, buf, size, offset, fi);
}

static int do_proc_read(const char *path, char *buf, size_t size, off_t offset,
			struct fuse_file_info *fi)
{
	char *error;
	int (*__proc_read)(const char *path, char *buf, size_t size,
			   off_t offset, struct fuse_file_info *fi);

	dlerror();
	__proc_read = (int (*)(const char *, char *, size_t, off_t, struct fuse_file_info *))dlsym(dlopen_handle, "proc_read");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find proc_read()", error);

	return __proc_read(path, buf, size, offset, fi);
}

static int do_sys_read(const char *path, char *buf, size_t size, off_t offset,
		       struct fuse_file_info *fi)
{
	char *error;
	int (*__sys_read)(const char *path, char *buf, size_t size,
			  off_t offset, struct fuse_file_info *fi);

	dlerror();
	__sys_read = (int (*)(const char *, char *, size_t, off_t, struct fuse_file_info *))dlsym(dlopen_handle, "sys_read");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find sys_read()", error);

	return __sys_read(path, buf, size, offset, fi);
}

static int do_cg_write(const char *path, const char *buf, size_t size,
		       off_t offset, struct fuse_file_info *fi)
{
	char *error;
	int (*__cg_write)(const char *path, const char *buf, size_t size,
			  off_t offset, struct fuse_file_info *fi);

	dlerror();
	__cg_write = (int (*)(const char *, const char *, size_t, off_t, struct fuse_file_info *))dlsym(dlopen_handle, "cg_write");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find cg_write()", error);

	return __cg_write(path, buf, size, offset, fi);
}

static int do_cg_mkdir(const char *path, mode_t mode)
{
	char *error;
	int (*__cg_mkdir)(const char *path, mode_t mode);

	dlerror();
	__cg_mkdir = (int (*)(const char *, mode_t))dlsym(dlopen_handle, "cg_mkdir");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find cg_mkdir()", error);

	return __cg_mkdir(path, mode);
}

static int do_cg_chown(const char *path, uid_t uid, gid_t gid)
{
	char *error;
	int (*__cg_chown)(const char *path, uid_t uid, gid_t gid);

	dlerror();
	__cg_chown = (int (*)(const char *, uid_t, gid_t))dlsym(dlopen_handle, "cg_chown");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find cg_chown()", error);

	return __cg_chown(path, uid, gid);
}

static int do_cg_rmdir(const char *path)
{
	char *error;
	int (*__cg_rmdir)(const char *path);

	dlerror();
	__cg_rmdir = (int (*)(const char *path))dlsym(dlopen_handle, "cg_rmdir");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find cg_rmdir()", error);

	return __cg_rmdir(path);
}

static int do_cg_chmod(const char *path, mode_t mode)
{
	char *error;
	int (*__cg_chmod)(const char *path, mode_t mode);

	dlerror();
	__cg_chmod = (int (*)(const char *, mode_t))dlsym(dlopen_handle, "cg_chmod");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find cg_chmod()", error);

	return __cg_chmod(path, mode);
}

static int do_cg_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	char *error;
	int (*__cg_readdir)(const char *path, void *buf, fuse_fill_dir_t filler,
			    off_t offset, struct fuse_file_info *fi);

	dlerror();
	__cg_readdir = (int (*)(const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *))dlsym(dlopen_handle, "cg_readdir");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find cg_readdir()", error);

	return __cg_readdir(path, buf, filler, offset, fi);
}

static int do_proc_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			   off_t offset, struct fuse_file_info *fi)
{
	char *error;
	int (*__proc_readdir)(const char *path, void *buf, fuse_fill_dir_t filler,
			      off_t offset, struct fuse_file_info *fi);

	dlerror();
	__proc_readdir = (int (*)(const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *))dlsym(dlopen_handle, "proc_readdir");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find proc_readdir()", error);

	return __proc_readdir(path, buf, filler, offset, fi);
}

static int do_sys_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			  off_t offset, struct fuse_file_info *fi)
{
	char *error;
	int (*__sys_readdir)(const char *path, void *buf, fuse_fill_dir_t filler,
			     off_t offset, struct fuse_file_info *fi);

	dlerror();
	__sys_readdir = (int (*)(const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *))dlsym(dlopen_handle, "sys_readdir");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find sys_readdir()", error);

	return __sys_readdir(path, buf, filler, offset, fi);
}


static int do_cg_open(const char *path, struct fuse_file_info *fi)
{
	char *error;
	int (*__cg_open)(const char *path, struct fuse_file_info *fi);

	dlerror();
	__cg_open = (int (*)(const char *, struct fuse_file_info *))dlsym(dlopen_handle, "cg_open");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find cg_open()", error);

	return __cg_open(path, fi);
}

static int do_cg_access(const char *path, int mode)
{
	char *error;
	int (*__cg_access)(const char *path, int mode);

	dlerror();
	__cg_access = (int (*)(const char *, int mode))dlsym(dlopen_handle, "cg_access");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find cg_access()", error);

	return __cg_access(path, mode);
}

static int do_proc_open(const char *path, struct fuse_file_info *fi)
{
	char *error;
	int (*__proc_open)(const char *path, struct fuse_file_info *fi);

	dlerror();
	__proc_open = (int (*)(const char *path, struct fuse_file_info *fi))dlsym(dlopen_handle, "proc_open");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find proc_open()", error);

	return __proc_open(path, fi);
}

static int do_proc_access(const char *path, int mode)
{
	char *error;
	int (*__proc_access)(const char *path, int mode);

	dlerror();
	__proc_access = (int (*)(const char *, int mode))dlsym(dlopen_handle, "proc_access");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find proc_access()", error);

	return __proc_access(path, mode);
}

static int do_sys_open(const char *path, struct fuse_file_info *fi)
{
	char *error;
	int (*__sys_open)(const char *path, struct fuse_file_info *fi);

	dlerror();
	__sys_open = (int (*)(const char *path, struct fuse_file_info *fi))dlsym(dlopen_handle, "sys_open");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find sys_open()", error);

	return __sys_open(path, fi);
}

static int do_sys_access(const char *path, int mode)
{
	char *error;
	int (*__sys_access)(const char *path, int mode);

	dlerror();
	__sys_access = (int (*)(const char *, int mode))dlsym(dlopen_handle, "sys_access");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find sys_access()", error);

	return __sys_access(path, mode);
}

static int do_cg_release(const char *path, struct fuse_file_info *fi)
{
	char *error;
	int (*__cg_release)(const char *path, struct fuse_file_info *fi);

	dlerror();
	__cg_release = (int (*)(const char *path, struct fuse_file_info *))dlsym(dlopen_handle, "cg_release");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find cg_release()", error);

	return __cg_release(path, fi);
}

static int do_proc_release(const char *path, struct fuse_file_info *fi)
{
	char *error;
	int (*__proc_release)(const char *path, struct fuse_file_info *fi);

	dlerror();
	__proc_release = (int (*)(const char *path, struct fuse_file_info *)) dlsym(dlopen_handle, "proc_release");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find proc_release()", error);

	return __proc_release(path, fi);
}

static int do_sys_release(const char *path, struct fuse_file_info *fi)
{
	char *error;
	int (*__sys_release)(const char *path, struct fuse_file_info *fi);

	dlerror();
	__sys_release = (int (*)(const char *path, struct fuse_file_info *))dlsym(dlopen_handle, "sys_release");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find sys_release()", error);

	return __sys_release(path, fi);
}

static int do_cg_opendir(const char *path, struct fuse_file_info *fi)
{
	char *error;
	int (*__cg_opendir)(const char *path, struct fuse_file_info *fi);

	dlerror();
	__cg_opendir = (int (*)(const char *path, struct fuse_file_info *fi))dlsym(dlopen_handle, "cg_opendir");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find cg_opendir()", error);

	return __cg_opendir(path, fi);
}

static int do_cg_releasedir(const char *path, struct fuse_file_info *fi)
{
	char *error;
	int (*__cg_releasedir)(const char *path, struct fuse_file_info *fi);

	dlerror();
	__cg_releasedir = (int (*)(const char *path, struct fuse_file_info *))dlsym(dlopen_handle, "cg_releasedir");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find cg_releasedir()", error);

	return __cg_releasedir(path, fi);
}

static int do_sys_releasedir(const char *path, struct fuse_file_info *fi)
{
	char *error;
	int (*__sys_releasedir)(const char *path, struct fuse_file_info *fi);

	dlerror();
	__sys_releasedir = (int (*)(const char *path, struct fuse_file_info *))dlsym(dlopen_handle, "sys_releasedir");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find sys_releasedir()", error);

	return __sys_releasedir(path, fi);
}

#ifdef HAVE_FUSE3
static int lxcfs_getattr(const char *path, struct stat *sb, struct fuse_file_info *fi)
#else
static int lxcfs_getattr(const char *path, struct stat *sb)
#endif
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

	if (strncmp(path, "/sys", 4) == 0) {
		up_users();
		ret = do_sys_getattr(path, sb);
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

	if (strncmp(path, "/sys", 4) == 0)
		return 0;

	return -ENOENT;
}

#ifdef HAVE_FUSE3
static int lxcfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags)
#else
static int lxcfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
#endif
{
	int ret;

	if (strcmp(path, "/") == 0) {
		if (DIR_FILLER(filler, buf, ".", NULL, 0) != 0 ||
		    DIR_FILLER(filler, buf, "..", NULL, 0) != 0 ||
		    DIR_FILLER(filler, buf, "proc", NULL, 0) != 0 ||
		    DIR_FILLER(filler, buf, "sys", NULL, 0) != 0 ||
		    DIR_FILLER(filler, buf, "cgroup", NULL, 0) != 0)
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

	if (strncmp(path, "/sys", 4) == 0) {
		up_users();
		ret = do_sys_readdir(path, buf, filler, offset, fi);
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

	if (strncmp(path, "/sys", 4) == 0) {
		up_users();
		ret = do_sys_access(path, mode);
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

	if (strncmp(path, "/sys", 4) == 0) {
		up_users();
		ret = do_sys_releasedir(path, fi);
		down_users();
		return ret;
	}

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

	if (strncmp(path, "/sys", 4) == 0) {
		up_users();
		ret = do_sys_open(path, fi);
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

	if (strncmp(path, "/sys", 4) == 0) {
		up_users();
		ret = do_sys_read(path, buf, size, offset, fi);
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

	if (strncmp(path, "/sys", 4) == 0) {
		up_users();
		ret = do_sys_release(path, fi);
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

#ifdef HAVE_FUSE3
int lxcfs_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi)
#else
int lxcfs_chown(const char *path, uid_t uid, gid_t gid)
#endif
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

	if (strncmp(path, "/sys", 4) == 0)
		return -EPERM;

	return -ENOENT;
}

/*
 * cat first does a truncate before doing ops->write.  This doesn't
 * really make sense for cgroups.  So just return 0 always but do
 * nothing.
 */
#ifdef HAVE_FUSE3
int lxcfs_truncate(const char *path, off_t newsize, struct fuse_file_info *fi)
#else
int lxcfs_truncate(const char *path, off_t newsize)
#endif
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

#ifdef HAVE_FUSE3
int lxcfs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi)
#else
int lxcfs_chmod(const char *path, mode_t mode)
#endif
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

	if (strncmp(path, "/sys", 4) == 0)
		return -EPERM;

	return -ENOENT;
}

const struct fuse_operations lxcfs_ops = {
	.access		= lxcfs_access,
	.chmod		= lxcfs_chmod,
	.chown		= lxcfs_chown,
	.flush		= lxcfs_flush,
	.fsync		= lxcfs_fsync,
	.getattr	= lxcfs_getattr,
	.mkdir		= lxcfs_mkdir,
	.open		= lxcfs_open,
	.opendir	= lxcfs_opendir,
	.read		= lxcfs_read,
	.readdir	= lxcfs_readdir,
	.release	= lxcfs_release,
	.releasedir	= lxcfs_releasedir,
	.rmdir		= lxcfs_rmdir,
	.truncate	= lxcfs_truncate,
	.write		= lxcfs_write,

	.create		= NULL,
	.destroy	= NULL,
#ifndef HAVE_FUSE3
	.fgetattr	= NULL,
#endif
	.fsyncdir	= NULL,
#ifndef HAVE_FUSE3
	.ftruncate	= NULL,
	.getdir		= NULL,
#endif
	.getxattr	= NULL,
	.init		= NULL,
	.link		= NULL,
	.listxattr	= NULL,
	.mknod		= NULL,
	.readlink	= NULL,
	.rename		= NULL,
	.removexattr	= NULL,
	.setxattr	= NULL,
	.statfs		= NULL,
	.symlink	= NULL,
	.unlink		= NULL,
#ifndef HAVE_FUSE3
	.utime		= NULL,
#endif
};

static void usage()
{
	lxcfs_info("Usage: lxcfs <directory>\n");
	lxcfs_info("lxcfs is a FUSE-based proc, sys and cgroup virtualizing filesystem\n");
	lxcfs_info("Options :");
	lxcfs_info("  -d, --debug          Run lxcfs with debugging enabled");
	lxcfs_info("  -f, --foreground     Run lxcfs in the foreground");
	lxcfs_info("  -n, --help           Print help");
	lxcfs_info("  -l, --enable-loadavg Enable loadavg virtualization");
	lxcfs_info("  -o                   Options to pass directly through fuse");
	lxcfs_info("  -p, --pidfile=FILE   Path to use for storing lxcfs pid");
	lxcfs_info("                       Default pidfile is %s/lxcfs.pid", RUNTIME_PATH);
	lxcfs_info("  -u, --disable-swap   Disable swap virtualization");
	lxcfs_info("  -v, --version        Print lxcfs version");
	lxcfs_info("  --enable-cfs         Enable CPU virtualization via CPU shares");
	lxcfs_info("  --enable-pidfd       Use pidfd for process tracking");
	exit(EXIT_FAILURE);
}

static inline bool is_help(char *w)
{
	return strcmp(w, "-h") == 0 ||
	       strcmp(w, "--help") == 0 ||
	       strcmp(w, "-help") == 0 ||
	       strcmp(w, "help") == 0;
}

static inline bool is_version(char *w)
{
	return strcmp(w, "-v") == 0 ||
	       strcmp(w, "--version") == 0 ||
	       strcmp(w, "-version") == 0 ||
	       strcmp(w, "version") == 0;
}

static bool swallow_arg(int *argcp, char *argv[], char *which)
{
	for (int i = 1; argv[i]; i++) {
		if (strcmp(argv[i], which) != 0)
			continue;

		for (; argv[i]; i++)
			argv[i] = argv[i + 1];

		(*argcp)--;
		return true;
	}

	return false;
}

static bool swallow_option(int *argcp, char *argv[], char *opt, char **v)
{
	for (int i = 1; argv[i]; i++) {
		if (!argv[i + 1])
			continue;

		if (strcmp(argv[i], opt) != 0)
			continue;

		do {
			*v = strdup(argv[i + 1]);
		} while (!*v);

		for (; argv[i + 1]; i++)
			argv[i] = argv[i + 2];

		(*argcp) -= 2;
		return true;
	}

	return false;
}

static int set_pidfile(char *pidfile)
{
	__do_close int fd = -EBADF;
	char buf[INTTYPE_TO_STRLEN(long)];
	int ret;
	struct flock fl = {
		.l_type		= F_WRLCK,
		.l_whence	= SEEK_SET,
		.l_start	= 0,
		.l_len		= 0,
	};

	fd = open(pidfile, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | O_CLOEXEC);
	if (fd < 0)
		return log_error(-1, "Could not open pidfile %s: %m", pidfile);

	if (fcntl(fd, F_SETLK, &fl) < 0) {
		if (errno == EAGAIN || errno == EACCES)
			return log_error(-1, "PID file '%s' is already locked", pidfile);
		lxcfs_error("Warning; unable to lock PID file, proceeding");
	}

	if (ftruncate(fd, 0))
		return log_error(-1, "Error truncating PID file '%s': %m", pidfile);

	ret = snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
	if (ret < 0 || ret >= sizeof(buf))
		return log_error(-1, "Failed to convert pid to string %m");

	if (write(fd, buf, ret) != ret)
		return log_error(-1, "Error writing to PID file '%s': %m", pidfile);

	return move_fd(fd);
}

int main(int argc, char *argv[])
{
	int pidfile_fd = -EBADF;
	int ret = EXIT_FAILURE;
	char *pidfile = NULL, *saveptr = NULL, *token = NULL, *v = NULL;
	char pidfile_buf[STRLITERALLEN(RUNTIME_PATH) + STRLITERALLEN("/lxcfs.pid") + 1] = {};
	bool debug = false, foreground = false;
#ifndef HAVE_FUSE3
	bool nonempty = false;
#endif
	bool load_use = false;
	/*
	 * what we pass to fuse_main is:
	 * argv[0] -s [-f|-d] -o allow_other,directio argv[1] NULL
	 */
	int nargs = 5, cnt = 0;
	char *newargv[6];
	struct lxcfs_opts *opts;

	opts = malloc(sizeof(struct lxcfs_opts));
	if (opts == NULL) {
		lxcfs_error("Error allocating memory for options");
		goto out;
	}
	opts->swap_off = false;
	opts->use_pidfd = false;
	opts->use_cfs = false;

	/* accomodate older init scripts */
	swallow_arg(&argc, argv, "-s");

	/* -f / --foreground */
	foreground = swallow_arg(&argc, argv, "-f");
	if (swallow_arg(&argc, argv, "--foreground"))
		foreground = true;

	/* -d / --debug */
	debug = swallow_arg(&argc, argv, "-d");
	if (swallow_arg(&argc, argv, "--debug"))
		debug = true;

	if (foreground && debug)
		log_exit("Both --debug and --forgreound specified");

	/* -l / --enable-loadavg */
	load_use = swallow_arg(&argc, argv, "-l");
	if (swallow_arg(&argc, argv, "--enable-loadavg"))
		load_use = true;

	/* -u / --disable-swap */
	opts->swap_off = swallow_arg(&argc, argv, "-u");
	if (swallow_arg(&argc, argv, "--disable-swap"))
		opts->swap_off = true;

	/* --enable-pidfd */
	opts->use_pidfd = swallow_arg(&argc, argv, "--enable-pidfd");

	/* --enable-cfs */
	if (swallow_arg(&argc, argv, "--enable-cfs"))
		opts->use_cfs = true;

	if (swallow_option(&argc, argv, "-o", &v)) {
		/* Parse multiple values */
		for (; (token = strtok_r(v, ",", &saveptr)); v = NULL) {
			if (strcmp(token, "allow_other") == 0) {
				/* Noop. this is the default. Always enabled. */
			} else if (strcmp(token, "nonempty") == 0) {
#ifdef HAVE_FUSE3
				/* FUSE3: Noop. this is the default. */
#else
				nonempty = true;
#endif
			} else {
				lxcfs_error("Warning: unexpected fuse option %s", v);
				free(v);
				exit(EXIT_FAILURE);
			}
		}
		free(v);
		v = NULL;
	}

	/* -p / --pidfile */
	if (swallow_option(&argc, argv, "-p", &v))
		pidfile = v;
	if (!pidfile && swallow_option(&argc, argv, "--pidfile", &v))
		pidfile = v;

	if (argc == 2  && is_version(argv[1])) {
		lxcfs_info("%s", VERSION);
		exit(EXIT_SUCCESS);
	}

	if (argc != 2 || is_help(argv[1]))
		usage();

	do_reload();
	if (install_signal_handler(SIGUSR1, sigusr1_reload)) {
		lxcfs_error("%s - Failed to install SIGUSR1 signal handler", strerror(errno));
		goto out;
	}

	newargv[cnt++] = argv[0];
	if (debug)
		newargv[cnt++] = "-d";
	else
		newargv[cnt++] = "-f";
	newargv[cnt++] = "-o";

	/*
	 * We can't use default_permissions since we still support systems that
	 * don't have kernels with cgroup namespace support. On such kernels
	 * lxcfs will provide a namespaced cgroup view and needs explicit
	 * access helpers to make that work.
	 * Another reason that came to me is that we can't or at least
	 * shouldn't guarantee that we don't need more complicated access
	 * helpers for proc and sys virtualization in the future.
	 */
#ifdef HAVE_FUSE3
	newargv[cnt++] = "allow_other,entry_timeout=0.5,attr_timeout=0.5";
#else
	if (nonempty)
		newargv[cnt++] = "allow_other,direct_io,entry_timeout=0.5,attr_timeout=0.5,nonempty";
	else
		newargv[cnt++] = "allow_other,direct_io,entry_timeout=0.5,attr_timeout=0.5";
#endif
	newargv[cnt++] = argv[1];
	newargv[cnt++] = NULL;

	if (!pidfile) {
		snprintf(pidfile_buf, sizeof(pidfile_buf), "%s/lxcfs.pid", RUNTIME_PATH);
		pidfile = pidfile_buf;
	}

	pidfile_fd = set_pidfile(pidfile);
	if (pidfile_fd < 0)
		goto out;

	if (load_use && start_loadavg() != 0)
		goto out;

	if (!fuse_main(nargs, newargv, &lxcfs_ops, opts))
		ret = EXIT_SUCCESS;

	if (load_use)
		stop_loadavg();

out:
	if (dlopen_handle)
		dlclose(dlopen_handle);
	if (pidfile)
		unlink(pidfile);
	free(opts);
	close_prot_errno_disarm(pidfile_fd);
	exit(ret);
}
