/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXCFS_BINDINGS_H
#define __LXCFS_BINDINGS_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 26
#endif

#define _FILE_OFFSET_BITS 64

#include <fuse.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cgroup_fuse.h"
#include "config.h"
#include "macro.h"
#include "proc_cpuview.h"
#include "proc_fuse.h"
#include "proc_loadavg.h"
#include "sysfs_fuse.h"

/* directory under which we mount the controllers - /run/lxcfs/controllers */
#define BASEDIR RUNTIME_PATH "/lxcfs/controllers"
#define ROOTDIR RUNTIME_PATH "/lxcfs/root"

/* Maximum number for 64 bit integer is a string with 21 digits: 2^64 - 1 = 21 */
#define LXCFS_NUMSTRLEN64 21

enum lxcfs_virt_t {
	LXC_TYPE_CGDIR,
	LXC_TYPE_CGFILE,

	LXC_TYPE_PROC_MEMINFO,
#define LXC_TYPE_PROC_MEMINFO_PATH "/proc/meminfo"

	LXC_TYPE_PROC_CPUINFO,
#define LXC_TYPE_PROC_CPUINFO_PATH "/proc/cpuinfo"

	LXC_TYPE_PROC_UPTIME,
#define LXC_TYPE_PROC_UPTIME_PATH "/proc/uptime"

	LXC_TYPE_PROC_STAT,
#define LXC_TYPE_PROC_STAT_PATH "/proc/stat"

	LXC_TYPE_PROC_DISKSTATS,
#define LXC_TYPE_PROC_DISKSTATS_PATH "/proc/diskstats"

	LXC_TYPE_PROC_SWAPS,
#define LXC_TYPE_PROC_SWAPS_PATH "/proc/swaps"

	LXC_TYPE_PROC_LOADAVG,
#define LXC_TYPE_PROC_LOADAVG_PATH "/proc/loadavg"

	LXC_TYPE_SYS_DEVICES,
	LXC_TYPE_SYS_DEVICES_SYSTEM,
	LXC_TYPE_SYS_DEVICES_SYSTEM_CPU,

	LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_ONLINE,
#define LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_ONLINE_PATH "/sys/devices/system/cpu/online"
};

struct file_info {
	char *controller;
	char *cgroup;
	char *file;
	int type;
	char *buf; /* unused */
	int buflen;
	int size; /*actual data size */
	int cached;
};

struct lxcfs_opts {
	bool swap_off;
	bool use_pidfd;
	bool use_cfs;
};

extern pid_t lookup_initpid_in_store(pid_t qpid);
extern void prune_init_slice(char *cg);
extern bool supports_pidfd(void);
extern bool liblxcfs_functional(void);
extern bool liblxcfs_can_use_swap(void);

static inline int install_signal_handler(int signo,
					 void (*handler)(int, siginfo_t *, void *))
{
	struct sigaction action = {
	    .sa_flags = SA_SIGINFO,
	    .sa_sigaction = handler,
	};

	return sigaction(signo, &action, NULL);
}

extern pid_t lxcfs_clone(int (*fn)(void *), void *arg, int flags);

#endif /* __LXCFS_BINDINGS_H */
