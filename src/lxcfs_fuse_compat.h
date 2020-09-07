/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXCFS_FUSE_COMPAT_H
#define __LXCFS_FUSE_COMPAT_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_FUSE3
#define DIR_FILLER(F,B,N,S,O) F(B,N,S,O,FUSE_FILL_DIR_PLUS)
#else
#define DIR_FILLER(F,B,N,S,O) F(B,N,S,O)
#endif
#endif /* __LXCFS_FUSE_COMPAT_H */
