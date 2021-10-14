/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXCFS_API_EXTENSIONS_H
#define __LXCFS_API_EXTENSIONS_H

#include "config.h"

#include <stdio.h>
#include <stdlib.h>

/*
 * api_extensions is the list of all API extensions in the order they were
 * added.
 */
static char *api_extensions[] = {
	"cgroups",
	"sys_cpu_online",
	"proc_cpuinfo",
	"proc_diskstats",
	"proc_loadavg",
	"proc_meminfo",
	"proc_stat",
	"proc_swaps",
	"proc_uptime",
	"proc_slabinfo",
	"shared_pidns",
	"cpuview_daemon",
	"loadavg_daemon",
	"pidfds",
};

static size_t nr_api_extensions = sizeof(api_extensions) / sizeof(*api_extensions);

#endif /* __LXCFS_API_EXTENSIONS_H */
