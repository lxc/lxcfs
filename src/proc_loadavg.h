/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXCFS_PROC_LOADAVG_FUSE_H
#define __LXCFS_PROC_LOADAVG_FUSE_H

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lxcfs_fuse.h"

#include "macro.h"

__visible extern pthread_t load_daemon(int load_use);
__visible extern int stop_load_daemon(pthread_t pid);

extern int proc_loadavg_read(char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
extern int calc_hash(const char *name);

#endif /* __LXCFS_PROC_LOADAVG_FUSE_H */

