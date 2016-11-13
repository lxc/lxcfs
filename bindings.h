#ifndef __LXCFS_BINDINGS_H
#define __LXCFS_BINDINGS_H

#include "macro.h"

/* directory under which we mount the controllers - /run/lxcfs/controllers */
#define BASEDIR RUNTIME_PATH "/lxcfs/controllers"
#define ROOTDIR RUNTIME_PATH "/lxcfs/root"

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

#endif /* __LXCFS_BINDINGS_H */
