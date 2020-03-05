/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXCFS_PROC_FUSE_H
#define __LXCFS_PROC_FUSE_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 26
#endif

#define _FILE_OFFSET_BITS 64

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "macro.h"

__visible extern int proc_getattr(const char *path, struct stat *sb);
__visible extern int proc_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
__visible extern int proc_open(const char *path, struct fuse_file_info *fi);
__visible extern int proc_access(const char *path, int mask);
__visible extern int proc_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
__visible extern int proc_release(const char *path, struct fuse_file_info *fi);

#endif /* __LXCFS_PROC_FUSE_H */
