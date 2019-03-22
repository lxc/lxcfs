/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __LXCFS_SYSFS_FUSE_H
#define __LXCFS_SYSFS_FUSE_H

extern int sys_getattr(const char *path, struct stat *sb);
extern int sys_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
		struct fuse_file_info *fi);
extern int sys_release(const char *path, struct fuse_file_info *fi);
extern int sys_releasedir(const char *path, struct fuse_file_info *fi);
extern int sys_open(const char *path, struct fuse_file_info *fi);
extern int sys_read(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi);
extern int sys_access(const char *path, int mask);

#endif /* __LXCFS_SYSFS_FUSE_H */
