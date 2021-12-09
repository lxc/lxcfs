/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXCFS_BINDINGS_H
#define __LXCFS_BINDINGS_H

#include "config.h"

#include <linux/types.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lxcfs_fuse.h"

#include "cgroup_fuse.h"
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

	LXC_TYPE_PROC_SLABINFO,
#define LXC_TYPE_PROC_SLABINFO_PATH "/proc/slabinfo"

	LXC_TYPE_SYS,
	LXC_TYPE_SYS_DEVICES,
	LXC_TYPE_SYS_DEVICES_SYSTEM,
	LXC_TYPE_SYS_DEVICES_SYSTEM_CPU,
	LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_SUBDIR,
	LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_SUBFILE,

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
	/*
	 * Ideally we'd version by size but because of backwards compatability
	 * and the use of bool instead of explicited __u32 and __u64 we can't.
	 */
	__u32 version;
};

typedef enum lxcfs_opt_t {
	LXCFS_SWAP_ON	= 0,
	LXCFS_PIDFD_ON	= 1,
	LXCFS_CFS_ON	= 2,
	LXCFS_OPTS_MAX	= LXCFS_CFS_ON,
} lxcfs_opt_t;


extern pid_t lookup_initpid_in_store(pid_t qpid);
extern void prune_init_slice(char *cg);
extern bool supports_pidfd(void);
extern bool liblxcfs_functional(void);
extern bool liblxcfs_can_use_swap(void);
extern bool liblxcfs_memory_is_cgroupv2(void);
extern bool liblxcfs_can_use_sys_cpu(void);
extern bool liblxcfs_has_versioned_opts(void);

static inline bool lxcfs_has_opt(struct lxcfs_opts *opts, lxcfs_opt_t opt)
{
	if (!opts)
		return false;

	if (opt > LXCFS_OPTS_MAX)
		return false;

	switch (opt) {
	case LXCFS_SWAP_ON:
		if (!opts->swap_off)
			return liblxcfs_can_use_swap();
		return false;
	case LXCFS_PIDFD_ON:
		return opts->use_pidfd;
	case LXCFS_CFS_ON:
		return opts->use_cfs;
	}

	return false;
}

static inline int install_signal_handler(int signo,
					 void (*handler)(int, siginfo_t *, void *))
{
	struct sigaction action = {
	    .sa_flags = SA_SIGINFO,
	    .sa_sigaction = handler,
	};

	return sigaction(signo, &action, NULL);
}

extern pid_t lxcfs_raw_clone(unsigned long flags, int *pidfd);

static inline pid_t lxcfs_clone(int (*fn)(void *), void *arg, int flags)
{
	pid_t pid;

	pid = lxcfs_raw_clone(flags, NULL);
	if (pid < 0)
		return -1;

	if (pid == 0)
		_exit(fn(arg));

	return pid;
}

__visible extern void *lxcfs_fuse_init(struct fuse_conn_info *conn, void *data);

#endif /* __LXCFS_BINDINGS_H */
