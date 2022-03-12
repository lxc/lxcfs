/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXCFS_FUSE_H
#define __LXCFS_FUSE_H

#include "config.h"

#if HAVE_FUSE3
#include <fuse3/fuse.h>
#else
#include <fuse.h>
#endif

#include "lxcfs_fuse_compat.h"

#endif /* __LXCFS_FUSE_H */
