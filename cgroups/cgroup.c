/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "cgroup.h"
#include "cgroup2_devices.h"

extern struct cgroup_ops *cgfsng_ops_init(void);

struct cgroup_ops *cgroup_init(void)
{
	struct cgroup_ops *cgroup_ops;

	cgroup_ops = cgfsng_ops_init();
	if (!cgroup_ops)
		return log_error_errno(NULL, errno, "Failed to initialize cgroup driver");

	return cgroup_ops;
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
