/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXCFSCTL_FUSE_H
#define __LXCFSCTL_FUSE_H

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lxcfs_fuse.h"

#include "macro.h"

__visible extern int lxcfsctl_getattr(const char *path, struct stat *sb);
__visible extern int lxcfsctl_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
__visible extern int lxcfsctl_readlink(const char *path, char *buf, size_t size);
__visible extern int lxcfsctl_release(const char *path, struct fuse_file_info *fi);
__visible extern int lxcfsctl_releasedir(const char *path, struct fuse_file_info *fi);
__visible extern int lxcfsctl_open(const char *path, struct fuse_file_info *fi);
__visible extern int lxcfsctl_opendir(const char *path, struct fuse_file_info *fi);
__visible extern int lxcfsctl_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
__visible extern int lxcfsctl_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
__visible extern int lxcfsctl_access(const char *path, int mask);

#endif /* __LXCFSCTL_FUSE_H */
