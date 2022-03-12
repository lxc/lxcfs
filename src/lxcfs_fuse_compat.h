/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXCFS_FUSE_COMPAT_H
#define __LXCFS_FUSE_COMPAT_H

#include "config.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "memory_utils.h"

#if HAVE_FUSE3
static inline int dir_filler(fuse_fill_dir_t filler, void *buf,
			     const char *name, off_t off)
{
	return filler(buf, name, NULL, off, FUSE_FILL_DIR_PLUS);
}

static inline int dirent_filler(fuse_fill_dir_t filler, const char *path,
				const char *name, void *buf, off_t off)
{
	return filler(buf, name, NULL, off, FUSE_FILL_DIR_PLUS);
}

static inline int dirent_fillerat(fuse_fill_dir_t filler, DIR *dp,
				  struct dirent *dentry, void *buf, off_t off)
{
	return filler(buf, dentry->d_name, NULL, off, FUSE_FILL_DIR_PLUS);
}
#else
static inline int dir_filler(fuse_fill_dir_t filler, void *buf,
			     const char *name, off_t off)
{
	return filler(buf, name, NULL, off);
}

static inline int dirent_filler(fuse_fill_dir_t filler, const char *path,
				const char *name, void *buf, off_t off)
{
	__do_closedir DIR *dirp = NULL;
	struct stat st;

	dirp = opendir(path);
	if (dirp && !fstatat(dirfd(dirp), name, &st, AT_SYMLINK_NOFOLLOW))
		return filler(buf, name, &st, off);

	return filler(buf, name, NULL, off);
}

static inline int dirent_fillerat(fuse_fill_dir_t filler, DIR *dp,
				  struct dirent *dentry, void *buf, off_t off)
{
	struct stat st;
	int ret;

	ret = fstatat(dirfd(dp), dentry->d_name, &st, AT_SYMLINK_NOFOLLOW);
	if (ret) {
		st = (struct stat){
			.st_ino  = dentry->d_ino,
			.st_mode = dentry->d_type << 12,
		};
	}

	return filler(buf, dentry->d_name, &st, off);
}
#endif

#endif /* __LXCFS_FUSE_COMPAT_H */
