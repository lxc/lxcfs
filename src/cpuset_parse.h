/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXCFS_CPUSET_PARSE_H
#define __LXCFS_CPUSET_PARSE_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 26
#endif

#define _FILE_OFFSET_BITS 64

#include <fuse.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "macro.h"

extern bool cpu_in_cpuset(int cpu, const char *cpuset);
extern int cpu_number_in_cpuset(const char *cpuset);
extern char *get_cpuset(const char *cg);

#endif /* __LXCFS_CPUSET_PARSE_H */


