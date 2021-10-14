/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/magic.h>
#include <linux/sched.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "../macro.h"
#include "../memory_utils.h"
#include "cgroup.h"
#include "cgroup_utils.h"
#include "cgroup2_devices.h"

extern struct cgroup_ops *cgfsng_ops_init(void);

struct cgroup_ops *cgroup_init(void)
{
	struct cgroup_ops *ops;

	ops = cgfsng_ops_init();
	if (!ops)
		return log_error_errno(NULL, errno, "Failed to initialize cgroup driver");

	return ops;
}

void cgroup_exit(struct cgroup_ops *ops)
{
	if (!ops)
		return;

	for (struct hierarchy **it = ops->hierarchies; it && *it; it++) {
		for (char **p = (*it)->controllers; p && *p; p++)
			free(*p);
		free((*it)->controllers);
		free((*it)->__controllers);

		if ((*it)->fd >= 0)
			close((*it)->fd);

		free((*it)->mountpoint);
		free((*it)->base_path);
		free(*it);
	}

	if (ops->mntns_fd >= 0)
		close(ops->mntns_fd);

	if (ops->cgroup2_root_fd >= 0)
		close(ops->cgroup2_root_fd);

	free(ops->hierarchies);

	free(ops);

	return;
}

#define INIT_SCOPE "/init.scope"
void prune_init_scope(char *cg)
{
	char *point;

	if (!cg)
		return;

	point = cg + strlen(cg) - strlen(INIT_SCOPE);
	if (point < cg)
		return;

	if (strcmp(point, INIT_SCOPE) == 0) {
		if (point == cg)
			*(point + 1) = '\0';
		else
			*point = '\0';
	}
}

char *get_pid_cgroup(pid_t pid, const char *contrl)
{
	int cfd;

	cfd = get_cgroup_fd(contrl);
	if (cfd < 0)
		return NULL;

	if (pure_unified_layout(cgroup_ops))
		return cg_unified_get_current_cgroup(pid);

	return cg_legacy_get_current_cgroup(pid, contrl);
}

/*
 * Read the cpuset.cpus for cg
 * Return the answer in a newly allocated string which must be freed
 */
char *get_cpuset(const char *cg)
{
	char *value = NULL;
	int ret;

	ret = cgroup_ops->get_cpuset_cpus(cgroup_ops, cg, &value);
	if (ret < 0)
		return NULL;

	return value;
}
