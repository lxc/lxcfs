#ifndef __LXCFS_BINDINGS_H
#define __LXCFS_BINDINGS_H

#include "macro.h"
#include "sysfs_fuse.h"

/* directory under which we mount the controllers - /run/lxcfs/controllers */
#define BASEDIR RUNTIME_PATH "/lxcfs/controllers"
#define ROOTDIR RUNTIME_PATH "/lxcfs/root"

/* Maximum number for 64 bit integer is a string with 21 digits: 2^64 - 1 = 21 */
#define LXCFS_NUMSTRLEN64 21

/* Reserve buffer size to account for file size changes. */
#define BUF_RESERVE_SIZE 512

enum lxcfs_virt_t {
	LXC_TYPE_CGDIR,
	LXC_TYPE_CGFILE,
	LXC_TYPE_PROC_MEMINFO,
	LXC_TYPE_PROC_CPUINFO,
	LXC_TYPE_PROC_UPTIME,
	LXC_TYPE_PROC_STAT,
	LXC_TYPE_PROC_DISKSTATS,
	LXC_TYPE_PROC_SWAPS,
	LXC_TYPE_PROC_LOADAVG,
	LXC_TYPE_SYS_DEVICES,
	LXC_TYPE_SYS_DEVICES_SYSTEM,
	LXC_TYPE_SYS_DEVICES_SYSTEM_CPU,
	LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_ONLINE,
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

struct lxcfs_opts {
	bool swap_off;
};

extern int cg_write(const char *path, const char *buf, size_t size, off_t offset,
	     struct fuse_file_info *fi);
extern int cg_mkdir(const char *path, mode_t mode);
extern int cg_chown(const char *path, uid_t uid, gid_t gid);
extern int cg_rmdir(const char *path);
extern int cg_chmod(const char *path, mode_t mode);
extern int cg_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
		struct fuse_file_info *fi);
extern int cg_releasedir(const char *path, struct fuse_file_info *fi);
extern int cg_release(const char *path, struct fuse_file_info *fi);
extern int cg_read(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi);
extern int cg_opendir(const char *path, struct fuse_file_info *fi);
extern int cg_getattr(const char *path, struct stat *sb);
extern int cg_open(const char *path, struct fuse_file_info *fi);
extern int cg_access(const char *path, int mode);

extern int proc_getattr(const char *path, struct stat *sb);
extern int proc_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
		struct fuse_file_info *fi);
extern int proc_release(const char *path, struct fuse_file_info *fi);
extern int proc_open(const char *path, struct fuse_file_info *fi);
extern int proc_read(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi);
extern int proc_access(const char *path, int mask);
extern pthread_t load_daemon(int load_use);
extern int stop_load_daemon(pthread_t pid);

extern pid_t lookup_initpid_in_store(pid_t qpid);
extern char *get_pid_cgroup(pid_t pid, const char *contrl);
extern int read_file(const char *path, char *buf, size_t size,
		     struct file_info *d);
extern void prune_init_slice(char *cg);
extern char *get_cpuset(const char *cg);
extern bool use_cpuview(const char *cg);
extern int max_cpu_count(const char *cg);
extern void do_release_file_info(struct fuse_file_info *fi);

#endif /* __LXCFS_BINDINGS_H */
