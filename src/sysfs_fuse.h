/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXCFS_SYSFS_FUSE_H
#define __LXCFS_SYSFS_FUSE_H

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lxcfs_fuse.h"

#include "macro.h"

__visible extern int sys_getattr(const char *path, struct stat *sb);
__visible extern int sys_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
__visible extern int sys_readlink(const char *path, char *buf, size_t size);
__visible extern int sys_release(const char *path, struct fuse_file_info *fi);
__visible extern int sys_releasedir(const char *path, struct fuse_file_info *fi);
__visible extern int sys_open(const char *path, struct fuse_file_info *fi);
__visible extern int sys_opendir(const char *path, struct fuse_file_info *fi);
__visible extern int sys_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
__visible extern int sys_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
__visible extern int sys_access(const char *path, int mask);

#endif /* __LXCFS_SYSFS_FUSE_H */
