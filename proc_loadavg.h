/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __LXCFS_PROC_LOADAVG_FUSE_H
#define __LXCFS_PROC_LOADAVG_FUSE_H

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

extern int proc_loadavg_read(char *buf, size_t size, off_t offset,
			     struct fuse_file_info *fi);
extern pthread_t load_daemon(int load_use);
extern int stop_load_daemon(pthread_t pid);

#endif /* __LXCFS_PROC_LOADAVG_FUSE_H */

