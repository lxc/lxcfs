/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXCFS_PROC_CPUVIEW_FUSE_H
#define __LXCFS_PROC_CPUVIEW_FUSE_H

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "lxcfs_fuse.h"

#include "macro.h"

struct cpuacct_usage {
	uint64_t user;
	uint64_t system;
	uint64_t idle;
	bool online;
};

extern int cpuview_proc_stat(const char *cg, const char *cpuset,
			     struct cpuacct_usage *cg_cpu_usage,
			     int cg_cpu_usage_size, FILE *f, char *buf,
			     size_t buf_size);
extern int proc_cpuinfo_read(char *buf, size_t size, off_t offset,
			     struct fuse_file_info *fi);
extern int read_cpuacct_usage_all(char *cg, char *cpuset,
				  struct cpuacct_usage **return_usage, int *size);
extern bool init_cpuview(void);
extern void free_cpuview(void);
extern int max_cpu_count(const char *cg);

#endif /* __LXCFS_PROC_CPUVIEW_FUSE_H */

