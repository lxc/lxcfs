/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <alloca.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
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

#include "lxcfs_fuse.h"

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

/* Returns file info type of custom type declaration carried
 * in fuse_file_info */
static inline enum lxcfs_virt_t file_info_type(struct fuse_file_info *fi)
{
	struct file_info *f;

	f = INTTYPE_TO_PTR(fi->fh);
	if (!f)
		return -1;

	if (!LXCFS_TYPE_OK(f->type))
		return -1;

	return f->type;
}

static pthread_t loadavg_pid = 0;

/* Returns zero on success */
static int start_loadavg(void)
{
	char *error;
	pthread_t (*__load_daemon)(int);
	int (*__load_daemon_v2)(pthread_t *, int);

	/* try a new load_daemon_v2() API */
	dlerror();
	__load_daemon_v2 = (int (*)(pthread_t *, int))dlsym(dlopen_handle, "load_daemon_v2");
	error = dlerror();
	if (error)
		/* try with an old symbol name */
		goto old_api;

	lxcfs_debug("start_loadavg: using load_daemon_v2");

	if (__load_daemon_v2(&loadavg_pid, 1)) {
		/* we have to NULLify loadavg_pid as in case of error it's contents are undefined */
		loadavg_pid = 0;
		return log_error(-1, "Failed to start loadavg daemon");
	}

	/* we are done */
	return 0;

old_api:
	/* go with an old load_daemon() API */
	dlerror();
	__load_daemon = (pthread_t(*)(int))dlsym(dlopen_handle, "load_daemon");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to start loadavg daemon", error);

	lxcfs_debug("start_loadavg: using load_daemon");

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

static int lxcfs_init_library(void)
{
	char *error;
	void *(*__lxcfs_fuse_init)(struct fuse_conn_info * conn, void * cfg);

	dlerror();
	__lxcfs_fuse_init = (void *(*)(struct fuse_conn_info * conn, void * cfg))dlsym(dlopen_handle, "lxcfs_fuse_init");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find lxcfs_fuse_init()", error);

	__lxcfs_fuse_init(NULL, NULL);

	return 0;
}

/* do_reload - reload the dynamic library.  Done under
 * lock and when we know the user_count was 0 */
static void do_reload(bool reinit)
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
	if (ret < 0 || (size_t)ret >= sizeof(lxcfs_lib_path))
		log_exit("Failed to create path to open liblxcfs");

        dlopen_handle = dlopen(lxcfs_lib_path, RTLD_LAZY);
	if (!dlopen_handle)
		log_exit("%s - Failed to open liblxcfs.so", dlerror());
	else
		lxcfs_debug("Opened %s", lxcfs_lib_path);

good:
	/* initialize the library */
	if (reinit && lxcfs_init_library() < 0) {
		log_exit("Failed to initialize liblxcfs.so");
	}

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
		do_reload(true);
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

static int do_sys_write(const char *path, const char *buf, size_t size,
		       off_t offset, struct fuse_file_info *fi)
{
	char *error;
	int (*__sys_write)(const char *path, const char *buf, size_t size,
			  off_t offset, struct fuse_file_info *fi);

	dlerror();
	__sys_write = (int (*)(const char *, const char *, size_t, off_t, struct fuse_file_info *))dlsym(dlopen_handle, "sys_write");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find sys_write()", error);

	return __sys_write(path, buf, size, offset, fi);
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

static int do_sys_readlink(const char *path, char *buf, size_t size)
{
	char *error;
	int (*__sys_readlink)(const char *path, char *buf, size_t size);

	dlerror();
	__sys_readlink = (int (*)(const char *, char *, size_t))dlsym(dlopen_handle, "sys_readlink");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find sys_readlink()", error);

	return __sys_readlink(path, buf, size);
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

static int do_sys_opendir(const char *path, struct fuse_file_info *fi)
{
	char *error;
	int (*__sys_opendir)(const char *path, struct fuse_file_info *fi);

	dlerror();
	__sys_opendir = (int (*)(const char *path, struct fuse_file_info *fi))dlsym(dlopen_handle, "sys_opendir");
	error = dlerror();
	if (error)
		return log_error(-1, "%s - Failed to find sys_opendir()", error);

	return __sys_opendir(path, fi);
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

#if HAVE_FUSE3
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

	if (strncmp(path, "/sys", 4) == 0) {
		up_users();
		ret = do_sys_opendir(path, fi);
		down_users();
		return ret;
	}

	return -ENOENT;
}

#if HAVE_FUSE3
static int lxcfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags)
#else
static int lxcfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
#endif
{
	int ret;

	if (strcmp(path, "/") == 0) {
		if (dir_filler(filler, buf, ".", 0) != 0 ||
		    dir_filler(filler, buf, "..", 0) != 0 ||
		    dir_filler(filler, buf, "proc", 0) != 0 ||
		    dir_filler(filler, buf, "sys", 0) != 0 ||
		    dir_filler(filler, buf, "cgroup", 0) != 0)
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
	enum lxcfs_virt_t type;

	type = file_info_type(fi);

	if (LXCFS_TYPE_CGROUP(type)) {
		up_users();
		ret = do_cg_releasedir(path, fi);
		down_users();
		return ret;
	}

	if (LXCFS_TYPE_SYS(type)) {
		up_users();
		ret = do_sys_releasedir(path, fi);
		down_users();
		return ret;
	}

	if (path) {
		if (strcmp(path, "/") == 0)
			return 0;
		if (strcmp(path, "/proc") == 0)
			return 0;
	}

	lxcfs_error("unknown file type: path=%s, type=%d, fi->fh=%" PRIu64,
			path, type, fi->fh);

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

	if (strncmp(path, "/sys", 4) == 0) {
		up_users();
		ret = do_sys_write(path, buf, size, offset, fi);
		down_users();
		return ret;
	}

	return -EINVAL;
}

int lxcfs_readlink(const char *path, char *buf, size_t size)
{
	int ret;

	if (strncmp(path, "/sys", 4) == 0) {
		up_users();
		ret = do_sys_readlink(path, buf, size);
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
	enum lxcfs_virt_t type;

	type = file_info_type(fi);

	if (LXCFS_TYPE_CGROUP(type)) {
		up_users();
		ret = do_cg_release(path, fi);
		down_users();
		return ret;
	}

	if (LXCFS_TYPE_PROC(type)) {
		up_users();
		ret = do_proc_release(path, fi);
		down_users();
		return ret;
	}

	if (LXCFS_TYPE_SYS(type)) {
		up_users();
		ret = do_sys_release(path, fi);
		down_users();
		return ret;
	}

	lxcfs_error("unknown file type: path=%s, type=%d, fi->fh=%" PRIu64,
			path, type, fi->fh);

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

#if HAVE_FUSE3
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
#if HAVE_FUSE3
int lxcfs_truncate(const char *path, off_t newsize, struct fuse_file_info *fi)
#else
int lxcfs_truncate(const char *path, off_t newsize)
#endif
{
	if (strncmp(path, "/cgroup", 7) == 0)
		return 0;

	if (strncmp(path, "/sys", 4) == 0)
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

#if HAVE_FUSE3
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

#if HAVE_FUSE3
static void fuse_intr_sighandler(int sig)
{
	(void) sig;
	/* Nothing to do */
}

static int fuse_init_intr_signal(int signum)
{
	struct sigaction old_sa;
	struct sigaction sa;

	if (sigaction(signum, NULL, &old_sa) == -1)
		return log_error(-1, "cannot get old signal handler\n");

	if (old_sa.sa_handler != SIG_DFL)
		return log_error(-1, "%d has non-default handler\n", signum);

	memset(&sa, 0, sizeof(struct sigaction));

	/*
	 * We *must* enable SA_RESTART, otherwise we may accidentally
	 * break some code which is not ready to signals/fuse interrupt.
	 */
	sa.sa_flags = SA_RESTART;

	sa.sa_handler = fuse_intr_sighandler;
	sigemptyset(&sa.sa_mask);

	if (sigaction(signum, &sa, NULL) == -1)
		return log_error(-1, "cannot set interrupt signal handler\n");

	return 0;
}
#endif

#if HAVE_FUSE3
static void *lxcfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
#else
static void *lxcfs_init(struct fuse_conn_info *conn)
#endif
{
	if (lxcfs_init_library() < 0)
		return NULL;

#if HAVE_FUSE3
	cfg->direct_io = 1;
	cfg->intr = 1;
	cfg->intr_signal = LXCFS_INTR_SIGNAL;
#endif

	return fuse_get_context()->private_data;
}

const struct fuse_operations lxcfs_ops = {
	.access		= lxcfs_access,
	.chmod		= lxcfs_chmod,
	.chown		= lxcfs_chown,
	.flush		= lxcfs_flush,
	.fsync		= lxcfs_fsync,
	.getattr	= lxcfs_getattr,
	.init		= lxcfs_init,
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
	.readlink	= lxcfs_readlink,

	.create		= NULL,
	.destroy	= NULL,
#if !HAVE_FUSE3
	.fgetattr	= NULL,
#endif
	.fsyncdir	= NULL,
#if !HAVE_FUSE3
	.ftruncate	= NULL,
	.getdir		= NULL,
#endif
	.getxattr	= NULL,
	.link		= NULL,
	.listxattr	= NULL,
	.mknod		= NULL,
	.rename		= NULL,
	.removexattr	= NULL,
	.setxattr	= NULL,
	.statfs		= NULL,
	.symlink	= NULL,
	.unlink		= NULL,
#if !HAVE_FUSE3
	.utime		= NULL,
#endif
};

static void usage(void)
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
	lxcfs_info("                       Default pidfile is %s/lxcfs.pid", DEFAULT_RUNTIME_PATH);
	lxcfs_info("  -u, --disable-swap   Disable swap virtualization");
	lxcfs_info("  -v, --version        Print lxcfs version");
	lxcfs_info("  --enable-cfs         Enable CPU virtualization via CPU shares");
	lxcfs_info("  --enable-pidfd       Use pidfd for process tracking");
	exit(EXIT_FAILURE);
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
	if (ret < 0 || (size_t)ret >= sizeof(buf))
		return log_error(-1, "Failed to convert pid to string %m");

	if (write(fd, buf, ret) != ret)
		return log_error(-1, "Error writing to PID file '%s': %m", pidfile);

	return move_fd(fd);
}

static const struct option long_options[] = {
	{"debug",		no_argument,		0,	'd'	},
	{"disable-swap",	no_argument,		0,	'u'	},
	{"enable-loadavg",	no_argument,		0,	'l'	},
	{"foreground",		no_argument,		0,	'f'	},
	{"help",		no_argument,		0,	'h'	},
	{"version",		no_argument,		0,	'v'	},

	{"enable-cfs",		no_argument,		0,	  0	},
	{"enable-pidfd",	no_argument,		0,	  0	},

	{"pidfile",		required_argument,	0,	'p'	},
	{								},
};

static int append_comma_separate(char **s, const char *append)
{
	int ret;
	char *news;
	size_t append_len, len;

	if (!append)
		return 0;

	append_len = strlen(append);
	if (!append_len)
		return 0;

	if (*s) {
		len = strlen(*s);
		news = realloc(*s, len + append_len + 2);
	} else {
		len = 0;
		news = realloc(NULL, append_len + 1);
	}
	if (!news)
		return -ENOMEM;

	if (*s)
		ret = snprintf(news + len, append_len + 2, ",%s", append);
	else
		ret = snprintf(news, append_len + 1, "%s", append);
	if (ret < 0)
		return -EIO;

	*s = news;
	return 0;
}

int main(int argc, char *argv[])
{
	int pidfile_fd = -EBADF;
	int ret = EXIT_FAILURE;
	char *pidfile = NULL, *token = NULL;
	char pidfile_buf[STRLITERALLEN(DEFAULT_RUNTIME_PATH) + STRLITERALLEN("/lxcfs.pid") + 1] = {};
	bool debug = false, foreground = false;
#if !HAVE_FUSE3
	bool nonempty = false;
#endif
	bool load_use = false;
	/*
	 * what we pass to fuse_main is:
	 * argv[0] -s [-f|-d] -o allow_other,directio argv[1] NULL
	 */
	int fuse_argc = 0;
	int c, idx, new_argc;
	char *fuse_argv[7];
	const char *fuse_opts = NULL;
	char *new_fuse_opts = NULL;
	char *const *new_argv;
	struct lxcfs_opts *opts;

	opts = malloc(sizeof(struct lxcfs_opts));
	if (opts == NULL) {
		lxcfs_error("Error allocating memory for options");
		goto out;
	}

	opts->swap_off = false;
	opts->use_pidfd = false;
	opts->use_cfs = false;
	opts->version = 1;

	while ((c = getopt_long(argc, argv, "dulfhvso:p:", long_options, &idx)) != -1) {
		switch (c) {
		case 0:
			if (strcmp(long_options[idx].name, "enable-pidfd") == 0)
				opts->use_pidfd = true;
			else if (strcmp(long_options[idx].name, "enable-cfs") == 0)
				opts->use_cfs = true;
			else
				usage();
			break;
		case 'd':
			debug = true;
			break;
		case 'f':
			foreground = true;
			break;
		case 'l':
			load_use = true;
			break;
		case 'o':
			if (fuse_opts) {
				lxcfs_error("Specifying -o multiple times is unsupported");
				usage();
			}

			fuse_opts = optarg;
			break;
		case 'p':
			pidfile = optarg;
			break;
		case 's':
			/* legacy argument: ignore */
			break;
		case 'u':
			opts->swap_off = true;
			break;
		case 'v':
			lxcfs_info("%s", STRINGIFY(PROJECT_VERSION));
			exit(EXIT_SUCCESS);
		default:
			usage();
		}
	}

	if (foreground && debug)
		log_exit("Both --debug and --forgreound specified");

	new_argv = &argv[optind];
	new_argc = argc - optind;

	/* Older LXCFS versions printed help when used without any argument. */
	if (new_argc == 0)
		usage();

	if (new_argc != 1) {
		lxcfs_error("Missing mountpoint");
		goto out;
	}

	fuse_argv[fuse_argc++] = argv[0];
	if (debug)
		fuse_argv[fuse_argc++] = "-d";
	else
		fuse_argv[fuse_argc++] = "-f";
	fuse_argv[fuse_argc++] = "-o";

	/* Parse additional fuse options. */
	if (fuse_opts) {
		char *dup;

		dup = strdup(fuse_opts);
		if (!dup) {
			lxcfs_error("Failed to copy fuse options");
			goto out;
		}

		lxc_iterate_parts(token, dup, ",") {
			/* default */
			if (strcmp(token, "allow_other") == 0)
				continue;

			/* default for LXCFS */
			if (strcmp(token, "direct_io") == 0)
				continue;

			/* default for LXCFS */
			if (strncmp(token, "entry_timeout", STRLITERALLEN("entry_timeout")) == 0)
				continue;

			/* default for LXCFS */
			if (strncmp(token, "attr_timeout", STRLITERALLEN("entry_timeout")) == 0)
				continue;

			/* default for LXCFS */
			if (strncmp(token, "allow_other", STRLITERALLEN("allow_other")) == 0)
				continue;

			/* default with fuse3 */
			if (strcmp(token, "nonempty") == 0) {
				#if !HAVE_FUSE3
				nonempty = true;
				#endif
				continue;
			}

			if (append_comma_separate(&new_fuse_opts, token)) {
				lxcfs_error("Failed to copy fuse argument \"%s\"", token);
				free(dup);
				goto out;
			}
		}
		free(dup);
	}

	if (append_comma_separate(&new_fuse_opts, "allow_other,entry_timeout=0.5,attr_timeout=0.5")) {
		lxcfs_error("Failed to copy fuse argument \"allow_other,entry_timeout=0.5,attr_timeout=0.5\"");
		goto out;
	}

#if !HAVE_FUSE3
	if (nonempty) {
		if (append_comma_separate(&new_fuse_opts, "nonempty")) {
			lxcfs_error("Failed to copy fuse argument \"nonempty\"");
			goto out;
		}
	}

	if (append_comma_separate(&new_fuse_opts, "direct_io")) {
		lxcfs_error("Failed to copy fuse argument \"direct_io\"");
		goto out;
	}
#endif

	/*
	 * We can't use default_permissions since we still support systems that
	 * don't have kernels with cgroup namespace support. On such kernels
	 * lxcfs will provide a namespaced cgroup view and needs explicit
	 * access helpers to make that work.
	 * Another reason that came to me is that we can't or at least
	 * shouldn't guarantee that we don't need more complicated access
	 * helpers for proc and sys virtualization in the future.
	 */

	fuse_argv[fuse_argc++] = new_fuse_opts;
	fuse_argv[fuse_argc++] = new_argv[0];
	fuse_argv[fuse_argc] = NULL;

	lxcfs_info("Starting LXCFS at %s", argv[0]);

	do_reload(false);
	if (install_signal_handler(SIGUSR1, sigusr1_reload)) {
		lxcfs_error("%s - Failed to install SIGUSR1 signal handler", strerror(errno));
		goto out;
	}

#if HAVE_FUSE3
	if (fuse_init_intr_signal(LXCFS_INTR_SIGNAL)) {
		lxcfs_error("Failed to install fuse interrupt signal handler");
		goto out;
	}
#endif

	if (!pidfile) {
		snprintf(pidfile_buf, sizeof(pidfile_buf), "%s/lxcfs.pid", DEFAULT_RUNTIME_PATH);
		pidfile = pidfile_buf;
	}

	pidfile_fd = set_pidfile(pidfile);
	if (pidfile_fd < 0)
		goto out;

	if (load_use && start_loadavg() != 0)
		goto out;

	if (!fuse_main(fuse_argc, fuse_argv, &lxcfs_ops, opts))
		ret = EXIT_SUCCESS;

	if (load_use)
		stop_loadavg();

out:
	if (dlopen_handle)
		dlclose(dlopen_handle);
	if (pidfile)
		unlink(pidfile);
	free(new_fuse_opts);
	free(opts);
	close_prot_errno_disarm(pidfile_fd);
	exit(ret);
}
