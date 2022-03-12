/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXCFS_FUSE_COMPAT_H
#define __LXCFS_FUSE_COMPAT_H

#include "config.h"

#if HAVE_FUSE3
static inline int dir_filler(fuse_fill_dir_t filler, void *buf,
			     const char *name, off_t off)
{
	return filler(buf, name, NULL, off, FUSE_FILL_DIR_PLUS);
}
#else
static inline int dir_filler(fuse_fill_dir_t filler, void *buf,
			     const char *name, off_t off)
{
	return filler(buf, name, NULL, off);
}
#endif

#endif /* __LXCFS_FUSE_COMPAT_H */
