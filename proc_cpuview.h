/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __LXCFS_PROC_CPUVIEW_FUSE_H
#define __LXCFS_PROC_CPUVIEW_FUSE_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 26
#endif

#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "macro.h"

struct cpuacct_usage;

extern int cpuview_proc_stat(const char *cg, const char *cpuset,
			     struct cpuacct_usage *cg_cpu_usage,
			     int cg_cpu_usage_size, FILE *f, char *buf,
			     size_t buf_size);
extern int proc_cpuinfo_read(char *buf, size_t size, off_t offset,
			     struct fuse_file_info *fi);
extern int read_cpuacct_usage_all(char *cg, char *cpuset,
				  struct cpuacct_usage **return_usage, int *size);
extern bool init_cpuview();
extern void free_cpuview();

#endif /* __LXCFS_PROC_CPUVIEW_FUSE_H */

