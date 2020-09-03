/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "config.h"

#ifdef HAVE_FUSE3
#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 30
#endif
#else
#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 26
#endif
#endif

#define _FILE_OFFSET_BITS 64

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include "bindings.h"
#include "cgroups/cgroup.h"
#include "cgroups/cgroup_utils.h"
#include "memory_utils.h"
#include "proc_loadavg.h"
#include "utils.h"

/*
 * Helper functions for cpuset_in-set
 */
static char *cpuset_nexttok(const char *c)
{
	char *r;

	r = strchr(c + 1, ',');
	return r ? (r + 1) : NULL;
}

static int cpuset_getrange(const char *c, int *a, int *b)
{
	int ret;

	ret = sscanf(c, "%d-%d", a, b);
	return ret;
}

/*
 * cpusets are in format "1,2-3,4"
 * iow, comma-delimited ranges
 */
bool cpu_in_cpuset(int cpu, const char *cpuset)
{
	for (const char *c = cpuset; c; c = cpuset_nexttok(c)) {
		int a, b, ret;

		ret = cpuset_getrange(c, &a, &b);
		if (ret == 1 && cpu == a) /* "1" or "1,6" */
			return true;
		else if (ret == 2 && cpu >= a && cpu <= b) /* range match */
			return true;
	}

	return false;
}

/*
 * get cpu number in cpuset
 */
int cpu_number_in_cpuset(const char *cpuset)
{
	int cpu_number = 0;

	for (const char *c = cpuset; c; c = cpuset_nexttok(c)) {
		int a, b, ret;

		ret = cpuset_getrange(c, &a, &b);
		if (ret == 1)
			cpu_number++;
		else if (ret == 2)
			cpu_number += a > b ? a - b + 1 : b - a + 1;
	}

	return cpu_number;
}
