/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_CGROUP_H
#define __LXC_CGROUP_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "macro.h"

#define DEFAULT_CGROUP_MOUNTPOINT "/sys/fs/cgroup"

typedef enum {
        CGROUP_LAYOUT_UNKNOWN = -1,
        CGROUP_LAYOUT_LEGACY  =  0,
        CGROUP_LAYOUT_HYBRID  =  1,
        CGROUP_LAYOUT_UNIFIED =  2,
} cgroup_layout_t;

/* A descriptor for a mounted hierarchy
 *
 * @controllers
 * - legacy hierarchy
 *   Either NULL, or a null-terminated list of all the co-mounted controllers.
 * - unified hierarchy
 *   Either NULL, or a null-terminated list of all enabled controllers.
 *
 * @mountpoint
 * - The mountpoint we will use.
 * - legacy hierarchy
 *   It will be either /sys/fs/cgroup/controller or
 *   /sys/fs/cgroup/controllerlist.
 * - unified hierarchy
 *   It will either be /sys/fs/cgroup or /sys/fs/cgroup/<mountpoint-name>
 *   depending on whether this is a hybrid cgroup layout (mix of legacy and
 *   unified hierarchies) or a pure unified cgroup layout.
 *
 * @container_base_path
 * - The cgroup under which the container cgroup path
 *   is created. This will be either the caller's cgroup (if not root), or
 *   init's cgroup (if root).
 *
 * @container_full_path
 * - The full path to the containers cgroup.
 *
 * @monitor_full_path
 * - The full path to the monitor's cgroup.
 *
 * @version
 * - legacy hierarchy
 *   If the hierarchy is a legacy hierarchy this will be set to
 *   CGROUP_SUPER_MAGIC.
 * - unified hierarchy
 *   If the hierarchy is a unified hierarchy this will be set to
 *   CGROUP2_SUPER_MAGIC.
 */
struct hierarchy {
	/*
	 * cgroup2 only: what files need to be chowned to delegate a cgroup to
	 * an unprivileged user.
	 */
	char **controllers;
	char *__controllers;
	char *mountpoint;
	char *container_base_path;
	char *container_full_path;
	char *monitor_full_path;
	int version;

	/* cgroup2 only */
	unsigned int bpf_device_controller:1;
	int fd;
};

struct cgroup_ops {
	/* string constant */
	const char *driver;

	/* string constant */
	const char *version;

	/* What controllers is the container supposed to use. */
	char *container_cgroup;
	char *monitor_cgroup;

	/* @hierarchies
	 * - A NULL-terminated array of struct hierarchy, one per legacy
	 *   hierarchy. No duplicates. First sufficient, writeable mounted
	 *   hierarchy wins.
	 */
	struct hierarchy **hierarchies;
	/* Pointer to the unified hierarchy. Do not free! */
	struct hierarchy *unified;

	/*
	 * @cgroup_layout
	 * - What cgroup layout the container is running with.
	 *   - CGROUP_LAYOUT_UNKNOWN
	 *     The cgroup layout could not be determined. This should be treated
	 *     as an error condition.
	 *   - CGROUP_LAYOUT_LEGACY
	 *     The container is running with all controllers mounted into legacy
	 *     cgroup hierarchies.
	 *   - CGROUP_LAYOUT_HYBRID
	 *     The container is running with at least one controller mounted
	 *     into a legacy cgroup hierarchy and a mountpoint for the unified
	 *     hierarchy. The unified hierarchy can be empty (no controllers
	 *     enabled) or non-empty (controllers enabled).
	 *   - CGROUP_LAYOUT_UNIFIED
	 *     The container is running on a pure unified cgroup hierarchy. The
	 *     unified hierarchy can be empty (no controllers enabled) or
	 *     non-empty (controllers enabled).
	 */
	cgroup_layout_t cgroup_layout;

	int (*num_hierarchies)(struct cgroup_ops *ops);
	bool (*get_hierarchies)(struct cgroup_ops *ops, int n, char ***out);
	bool (*mount)(struct cgroup_ops *ops, const char *root);
	int (*nrtasks)(struct cgroup_ops *ops);
	struct hierarchy *(*get_hierarchy)(struct cgroup_ops *ops,
					   const char *controller);
};

extern struct cgroup_ops *cgroup_init(void);
extern void cgroup_exit(struct cgroup_ops *ops);

extern void prune_init_scope(char *cg);

static inline void __auto_cgroup_exit__(struct cgroup_ops **ops)
{
	if (*ops)
		cgroup_exit(*ops);
}

extern int cgroup_attach(const char *name, const char *lxcpath, int64_t pid);

#define __do_cgroup_exit __attribute__((__cleanup__(__auto_cgroup_exit__)))

static inline bool pure_unified_layout(const struct cgroup_ops *ops)
{
	return ops->cgroup_layout == CGROUP_LAYOUT_UNIFIED;
}

static inline bool is_unified_hierarchy(const struct hierarchy *h)
{
	return h->version == CGROUP2_SUPER_MAGIC;
}

#endif
