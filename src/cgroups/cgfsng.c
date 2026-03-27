/* SPDX-License-Identifier: LGPL-2.1+ */

/*
 * cgfs-ng.c: this is a new, simplified implementation of a filesystem
 * cgroup backend.  The original cgfs.c was designed to be as flexible
 * as possible.  It would try to find cgroup filesystems no matter where
 * or how you had them mounted, and deduce the most usable mount for
 * each controller.
 *
 * This new implementation assumes that cgroup filesystems are mounted
 * under /sys/fs/cgroup/clist where clist is either the controller, or
 * a comma-separated list of controllers.
 */

#include "config.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <linux/kdev_t.h>
#include <linux/types.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <unistd.h>

#include "../macro.h"
#include "../memory_utils.h"
#include "../utils.h"
#include "cgroup.h"
#include "cgroup_utils.h"

/* Given a pointer to a null-terminated array of pointers, realloc to add one
 * entry, and point the new entry to NULL. Do not fail. Return the index to the
 * second-to-last entry - that is, the one which is now available for use
 * (keeping the list null-terminated).
 */
static int append_null_to_list(void ***list)
{
	int newentry = 0;

	if (*list)
		for (; (*list)[newentry]; newentry++)
			;

	*list = must_realloc(*list, (newentry + 2) * sizeof(void **));
	(*list)[newentry + 1] = NULL;
	return newentry;
}

/* Given a null-terminated array of strings, check whether @entry is one of the
 * strings.
 */
static bool string_in_list(char **list, const char *entry)
{
	int i;

	if (!list)
		return false;

	for (i = 0; list[i]; i++)
		if (strcmp(list[i], entry) == 0)
			return true;

	return false;
}

/* Given a handler's cgroup data, return the struct hierarchy for the controller
 * @c, or NULL if there is none.
 */
static struct hierarchy *cgfsng_get_hierarchy(struct cgroup_ops *ops,
					      const char *controller)
{
	int i;

	errno = ENOENT;

	if (!ops->hierarchies)
		return NULL;

	for (i = 0; ops->hierarchies[i]; i++) {
		if (!controller) {
			/* This is the empty unified hierarchy. */
			if (ops->hierarchies[i]->controllers &&
			    !ops->hierarchies[i]->controllers[0])
				return ops->hierarchies[i];
			continue;
		} else if (pure_unified_layout(ops) &&
			   strcmp(controller, "devices") == 0) {
			if (ops->unified->bpf_device_controller)
				return ops->unified;
			break;
		}

		if (string_in_list(ops->hierarchies[i]->controllers, controller))
			return ops->hierarchies[i];
	}

	return NULL;
}

static char **cg_unified_make_empty_controller(void)
{
	int newentry;
	char **aret = NULL;

	newentry = append_null_to_list((void ***)&aret);
	aret[newentry] = NULL;
	return aret;
}

static char **cg_unified_get_controllers(const char *file)
{
	__do_free char *buf = NULL;
	char *sep = " \t\n";
	char **aret = NULL;
	char *tok;

	buf = read_file(file);
	if (!buf)
		return NULL;

	lxc_iterate_parts(tok, buf, sep) {
		int newentry;
		char *copy;

		newentry = append_null_to_list((void ***)&aret);
		copy = must_copy_string(tok);
		aret[newentry] = copy;
	}

	return aret;
}

static struct hierarchy *add_hierarchy(struct hierarchy ***h, char **clist, char *mountpoint,
				       char *base_path, int type)
{
	struct hierarchy *new;
	int newentry;

	new = must_realloc(NULL, sizeof(*new));
	memset(new, 0, sizeof(*new));
	new->controllers = clist;
	new->mountpoint = mountpoint;
	new->base_path = base_path;
	new->version = type;

	newentry = append_null_to_list((void ***)h);
	(*h)[newentry] = new;
	return new;
}

/* __cg_mount_direct
 *
 * Mount cgroup hierarchies directly without using bind-mounts. The main
 * uses-cases are mounting cgroup hierarchies in cgroup namespaces and mounting
 * cgroups for the LXC_AUTO_CGROUP_FULL option.
 */
static int __cg_mount_direct(struct hierarchy *h, const char *controllerpath)
{
	__do_free char *controllers = NULL;
	char *fstype = "cgroup2";
	unsigned long flags = 0;
	int ret;

	flags |= MS_NOSUID;
	flags |= MS_NOEXEC;
	flags |= MS_NODEV;
	flags |= MS_RELATIME;

	if (h->version != CGROUP2_SUPER_MAGIC) {
		controllers = lxc_string_join(",", (const char **)h->controllers, false);
		if (!controllers)
			return -ENOMEM;
		fstype = "cgroup";
		ret = mount("cgroup", controllerpath, fstype, flags, controllers);
	} else {
		__do_free const char *sb_opts = NULL;

		/*
		 * Before mounting cgroup2 fs we have to try out best to find
		 * an existing mount and extract mount existing mount options from it.
		 * It is important because otherwise we can change cgroup2 superblock
		 * options. See kernel logic in apply_cgroup_root_flags for more details:
		 * https://github.com/torvalds/linux/blob/18f7fcd5e69a04df57b563360b88be72471d6b62/kernel/cgroup/cgroup.c#L2047
		 *
		 * If we haven't found an existing mount, just mount a new one with
		 * an empty list of options.
		 */
		sb_opts = cgroup2_extract_sb_opts(DEFAULT_CGROUP_MOUNTPOINT);
		ret = mount(fstype, controllerpath, fstype, flags, sb_opts);
	}

	if (ret < 0)
		return -1;

	return 0;
}

static inline int cg_mount_cgroup_full(struct hierarchy *h,
				       const char *controllerpath)
{
	return __cg_mount_direct(h, controllerpath);
}

static bool cgfsng_mount(struct cgroup_ops *ops, const char *root)
{
	__do_free char *cgroup_root = NULL;

	if (!ops)
		return ret_set_errno(false, ENOENT);

	if (!ops->hierarchies)
		return true;

	cgroup_root = must_make_path(root, DEFAULT_CGROUP_MOUNTPOINT, NULL);

	if (ops->cgroup_layout != CGROUP_LAYOUT_UNIFIED)
		return ret_set_errno(false, ENOTSUP);

	return cg_mount_cgroup_full(ops->unified, cgroup_root) == 0;
}

static bool cgfsng_get(struct cgroup_ops *ops, const char *controller,
		       const char *cgroup, const char *file, char **value)
{
	__do_free char *path = NULL;
	struct hierarchy *h;

	h = ops->get_hierarchy(ops, controller);
	if (!h)
		return false;

	path = must_make_path_relative(cgroup, file, NULL);
	*value = readat_file(h->fd, path);
	return *value != NULL;
}

static int cgfsng_get_memory(struct cgroup_ops *ops, const char *cgroup,
			     const char *file, char **value)
{
	__do_free char *path = NULL;
	struct hierarchy *h;
	int ret;

	h = ops->get_hierarchy(ops, "memory");
	if (!h)
		return -1;

	if (!is_unified_hierarchy(h)) {
		lxcfs_error("Only unified hierarchy is supported");
		return -ENOTSUP;
	}

	path = must_make_path_relative(cgroup, NULL);
	ret = cgroup_walkup_to_root(ops->cgroup2_root_fd, h->fd, path, file, value);
	if (ret < 0)
		return ret;
	if (ret == 1) {
		*value = strdup("");
		if (!*value)
			return -ENOMEM;
	}

	return CGROUP2_SUPER_MAGIC;
}

static int cgfsng_get_memory_stats_fd(struct cgroup_ops *ops, const char *cgroup)
{
	__do_free char *path = NULL;
	struct hierarchy *h;

	h = ops->get_hierarchy(ops, "memory");
	if (!h)
		return -1;

	path = must_make_path_relative(cgroup, "memory.stat", NULL);
	return openat(h->fd, path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
}

static int cgfsng_get_memory_current(struct cgroup_ops *ops, const char *cgroup,
				     char **value)
{
	return cgfsng_get_memory(ops, cgroup, "memory.current", value);
}

static int cgfsng_get_memory_swap_current(struct cgroup_ops *ops,
					  const char *cgroup, char **value)
{
	return cgfsng_get_memory(ops, cgroup, "memory.swap.current", value);
}

static int cgfsng_get_memory_max(struct cgroup_ops *ops, const char *cgroup,
				 char **value)
{
	return cgfsng_get_memory(ops, cgroup, "memory.max", value);
}

static int cgfsng_get_memory_swappiness(struct cgroup_ops *ops, const char *cgroup,
				 char **value)
{
	return cgfsng_get_memory(ops, cgroup, "memory.swappiness", value);
}

static int cgfsng_get_memory_swap_max(struct cgroup_ops *ops,
				      const char *cgroup, char **value)
{
	return cgfsng_get_memory(ops, cgroup, "memory.swap.max", value);
}

static int cgfsng_get_memory_slabinfo_fd(struct cgroup_ops *ops, const char *cgroup)
{
	__do_free char *path = NULL;
	struct hierarchy *h;

	h = ops->get_hierarchy(ops, "memory");
	if (!h)
		return -1;

	if (faccessat(h->fd, "memory.kmem.slabinfo", F_OK, 0))
		return -1;

	path = must_make_path_relative(cgroup, "memory.kmem.slabinfo", NULL);
	return openat(h->fd, path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
}

static bool cgfsng_can_use_memory_feature(struct cgroup_ops *ops,
				struct hierarchy *h, const char *cgroup, const char *file)
{
	__do_free char *cgroup_rel = NULL, *junk_value = NULL;
	bool ret;

	cgroup_rel = must_make_path_relative(cgroup, NULL);

	/* For v2, we need to look at the lower levels of the hierarchy because
	 * no 'memory.<feature>.current' file exists at the root. We must search
	 * upwards in the hierarchy in case memory accounting is disabled via
	 * cgroup.subtree_control for the given cgroup itself.
	 */
	if (is_cgroup2_fd(h->fd) && strcmp(cgroup, "/") == 0) {
		/*
		 * It looks like LXCFS sits in the root cgroup,
		 * which means that we have to find *some* cgroup
		 * down the tree and check a (file) presence in there.
		 *
		 * Note, that this only needed for cgroup2.
		 */

		__do_close int fd = -EBADF;
		__do_closedir DIR *dir = NULL;
		struct dirent *dent;

		fd = openat_safe(h->fd, ".");
		if (fd < 0)
			return false;

		dir = fdopendir(fd);
		if (!dir) {
			lxcfs_error("Failed to open memory cgroup hierarchy\n");
			return false;
		}
		/* Transfer ownership to fdopendir(). */
		move_fd(fd);

		ret = false;
		while (((dent = readdir(dir)) != NULL)) {
			if (strcmp(dent->d_name, ".") == 0 ||
			    strcmp(dent->d_name, "..") == 0)
				continue;

			if (dent->d_type == DT_DIR) {
				__do_free char *path = NULL;

				path = must_make_path_relative(dent->d_name, file, NULL);

				if (!faccessat(h->fd, path, F_OK, 0)) {
					/* We found it. Exit. */
					ret = true;
					break;
				}
			}
		}
	} else {
		/*
		 * We can check a (file) presence on the current
		 * level and go up in the cgroup tree if needed.
		 */
		ret = cgroup_walkup_to_root(ops->cgroup2_root_fd, h->fd, cgroup_rel, file, &junk_value) == 0;
	}

	return ret;
}

static bool cgfsng_can_use_swap(struct cgroup_ops *ops, const char *cgroup)
{
	struct hierarchy *h;

	h = ops->get_hierarchy(ops, "memory");
	if (!h)
		return false;

	return cgfsng_can_use_memory_feature(ops, h, cgroup, is_unified_hierarchy(h) ? "memory.swap.current" : "memory.memsw.usage_in_bytes");
}

static bool cgfsng_can_use_zswap(struct cgroup_ops *ops, const char *cgroup)
{
	struct hierarchy *h;

	h = ops->get_hierarchy(ops, "memory");
	if (!h)
		return false;

	/* zswap is only available in cgroupv2 */
	if (!is_unified_hierarchy(h))
		return false;

	return cgfsng_can_use_memory_feature(ops, h, cgroup, "memory.zswap.current");
}

static int cgfsng_get_memory_stats(struct cgroup_ops *ops, const char *cgroup,
				   char **value)
{
	return cgfsng_get_memory(ops, cgroup, "memory.stat", value);
}

static char *readat_cpuset(int cgroup_fd)
{
	__do_free char *val = NULL;

	val = readat_file(cgroup_fd, "cpuset.cpus");
	if (val && strcmp(val, "") != 0)
		return move_ptr(val);

	free_disarm(val);
	val = readat_file(cgroup_fd, "cpuset.cpus.effective");
	if (val && strcmp(val, "") != 0)
		return move_ptr(val);

	return NULL;
}

static int cgfsng_get_cpuset_cpus(struct cgroup_ops *ops, const char *cgroup,
				  char **value)
{
	__do_close int cgroup_fd = -EBADF;
	__do_free char *path = NULL;
	char *v;
	struct hierarchy *h;
	int ret = CGROUP2_SUPER_MAGIC;

	h = ops->get_hierarchy(ops, "cpuset");
	if (!h)
		return -1;

	if (!is_unified_hierarchy(h)) {
		lxcfs_error("Only unified hierarchy is supported");
		return -1;
	}

	*value = NULL;
	path = must_make_path_relative(cgroup, NULL);
	cgroup_fd = openat_safe(h->fd, path);
	if (cgroup_fd < 0)
		return -1;

	v = readat_cpuset(cgroup_fd);
	if (v) {
		*value = v;
		return ret;
	}

	/*
	 * cpuset.cpus and cpuset.cpus.effective are empty so we need to look
	 * the nearest ancestor with a non-empty cpuset.cpus{.effective} file.
	 */
	for (;;) {
		int fd;

		fd = openat_safe(cgroup_fd, "../");
		if (fd < 0 || !is_cgroup2_fd(fd))
			return -1;

		close_prot_errno_replace(cgroup_fd, fd);

		v = readat_cpuset(fd);
		if (v) {
			*value = v;
			return ret;
		}
	}

	return -1;
}

static int cgfsng_get_io(struct cgroup_ops *ops, const char *cgroup,
			 const char *file, char **value)
{
	__do_free char *path = NULL;
	struct hierarchy *h;

	h = ops->get_hierarchy(ops, "blkio");
	if (!h)
		return -1;

	if (!is_unified_hierarchy(h)) {
		lxcfs_error("Only unified hierarchy is supported");
		return -1;
	}

	path = must_make_path_relative(cgroup, file, NULL);
	*value = readat_file(h->fd, path);
	if (!*value) {
		if (errno == ENOENT)
			errno = EOPNOTSUPP;
		return ret_errno(errno);
	}

	return CGROUP2_SUPER_MAGIC;
}

static int cgfsng_get_io_service_bytes(struct cgroup_ops *ops,
				       const char *cgroup, char **value)
{
	return cgfsng_get_io(ops, cgroup, "blkio.io_service_bytes_recursive", value);
}

static int cgfsng_get_io_service_time(struct cgroup_ops *ops,
				      const char *cgroup, char **value)
{
	return cgfsng_get_io(ops, cgroup, "blkio.io_service_time_recursive", value);
}

static int cgfsng_get_io_serviced(struct cgroup_ops *ops, const char *cgroup,
				  char **value)
{
	return cgfsng_get_io(ops, cgroup, "blkio.io_serviced_recursive", value);
}

static int cgfsng_get_io_merged(struct cgroup_ops *ops, const char *cgroup,
				char **value)
{
	return cgfsng_get_io(ops, cgroup, "blkio.io_merged_recursive", value);
}

static int cgfsng_get_io_wait_time(struct cgroup_ops *ops, const char *cgroup,
				   char **value)
{
	return cgfsng_get_io(ops, cgroup, "blkio.io_wait_time_recursive", value);
}

static bool cgfsng_can_use_cpuview(struct cgroup_ops *ops)
{
	struct hierarchy *cpu, *cpuacct;

	if (pure_unified_layout(ops))
		return true;

	cpu = ops->get_hierarchy(ops, "cpu");
	if (!cpu || is_unified_hierarchy(cpu))
		return false;

	cpuacct = ops->get_hierarchy(ops, "cpuacct");
	if (!cpuacct || is_unified_hierarchy(cpuacct))
		return false;

	return true;
}

static int cgfsng_get_pressure_io_fd(struct cgroup_ops *ops, const char *cgroup)
{
	__do_free char *path = NULL;
	struct hierarchy *h;

	h = ops->get_hierarchy(ops, "blkio");
	if (!h)
		return -1;

	if (faccessat(h->fd, "io.pressure", F_OK, 0))
		return -1;

	path = must_make_path_relative(cgroup, "io.pressure", NULL);
	return openat(h->fd, path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
}

static int cgfsng_get_pressure_cpu_fd(struct cgroup_ops *ops, const char *cgroup)
{
	__do_free char *path = NULL;
	struct hierarchy *h;

	h = ops->get_hierarchy(ops, "cpu");
	if (!h)
		return -1;

	if (faccessat(h->fd, "cpu.pressure", F_OK, 0))
		return -1;

	path = must_make_path_relative(cgroup, "cpu.pressure", NULL);
	return openat(h->fd, path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
}

static int cgfsng_get_pressure_memory_fd(struct cgroup_ops *ops, const char *cgroup)
{
	__do_free char *path = NULL;
	struct hierarchy *h;

	h = ops->get_hierarchy(ops, "memory");
	if (!h)
		return -1;

	if (faccessat(h->fd, "memory.pressure", F_OK, 0))
		return -1;

	path = must_make_path_relative(cgroup, "memory.pressure", NULL);
	return openat(h->fd, path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
}

static int cg_unified_init(struct cgroup_ops *ops)
{
	__do_free char *subtree_path = NULL;
	int ret;
	char *mountpoint;
	char **delegatable;
	struct hierarchy *new;
	char *base_cgroup = NULL;

	ret = unified_cgroup_hierarchy();
	if (ret == -ENOMEDIUM)
		return ret_errno(ENOMEDIUM);

	if (ret != CGROUP2_SUPER_MAGIC)
		return 0;

	base_cgroup = cg_unified_get_current_cgroup(1);
	if (!base_cgroup)
		return ret_errno(EINVAL);
	prune_init_scope(base_cgroup);

	/*
	 * We assume that the cgroup we're currently in has been delegated to
	 * us and we are free to further delege all of the controllers listed
	 * in cgroup.controllers further down the hierarchy.
	 */
	mountpoint = must_copy_string(DEFAULT_CGROUP_MOUNTPOINT);
	subtree_path = must_make_path(mountpoint, base_cgroup, "cgroup.controllers", NULL);
	delegatable = cg_unified_get_controllers(subtree_path);
	if (!delegatable)
		delegatable = cg_unified_make_empty_controller();

	/* TODO: If the user requested specific controllers via lxc.cgroup.use
	 * we should verify here. The reason I'm not doing it right is that I'm
	 * not convinced that lxc.cgroup.use will be the future since it is a
	 * global property. I much rather have an option that lets you request
	 * controllers per container.
	 */

	new = add_hierarchy(&ops->hierarchies, delegatable, mountpoint, base_cgroup, CGROUP2_SUPER_MAGIC);

	ops->cgroup_layout = CGROUP_LAYOUT_UNIFIED;
	ops->unified = new;

	ops->cgroup2_root_fd = open(DEFAULT_CGROUP_MOUNTPOINT, O_DIRECTORY | O_PATH | O_CLOEXEC);
	if (ops->cgroup2_root_fd < 0)
		return -errno;

	return CGROUP2_SUPER_MAGIC;
}

static int cg_init(struct cgroup_ops *ops)
{
	int ret;

	ret = cg_unified_init(ops);
	if (ret < 0)
		return -1;

	if (ret == CGROUP2_SUPER_MAGIC)
		return 0;

	return -1;
}

struct cgroup_ops *cgfsng_ops_init(void)
{
	__do_free struct cgroup_ops *cgfsng_ops = NULL;

	cgfsng_ops = zalloc(sizeof(struct cgroup_ops));
	if (!cgfsng_ops)
		return ret_set_errno(NULL, ENOMEM);

	cgfsng_ops->cgroup_layout = CGROUP_LAYOUT_UNKNOWN;
	cgfsng_ops->mntns_fd = -EBADF;
	cgfsng_ops->cgroup2_root_fd = -EBADF;

	if (cg_init(cgfsng_ops))
		return NULL;

	cgfsng_ops->get = cgfsng_get;
	cgfsng_ops->get_hierarchy = cgfsng_get_hierarchy;
	cgfsng_ops->driver = "cgfsng";
	cgfsng_ops->version = "2.0.0";
	cgfsng_ops->mount = cgfsng_mount;

	/* memory */
	cgfsng_ops->get_memory_stats_fd = cgfsng_get_memory_stats_fd;
	cgfsng_ops->get_memory_stats = cgfsng_get_memory_stats;
	cgfsng_ops->get_memory_max = cgfsng_get_memory_max;
	cgfsng_ops->get_memory_swappiness = cgfsng_get_memory_swappiness;
	cgfsng_ops->get_memory_swap_max = cgfsng_get_memory_swap_max;
	cgfsng_ops->get_memory_current = cgfsng_get_memory_current;
	cgfsng_ops->get_memory_swap_current = cgfsng_get_memory_swap_current;
	cgfsng_ops->get_memory_slabinfo_fd = cgfsng_get_memory_slabinfo_fd;
	cgfsng_ops->can_use_swap = cgfsng_can_use_swap;
	cgfsng_ops->can_use_zswap = cgfsng_can_use_zswap;

	/* cpuset */
	cgfsng_ops->get_cpuset_cpus = cgfsng_get_cpuset_cpus;
	cgfsng_ops->can_use_cpuview = cgfsng_can_use_cpuview;

	/* blkio */
	cgfsng_ops->get_io_service_bytes	= cgfsng_get_io_service_bytes;
	cgfsng_ops->get_io_service_time		= cgfsng_get_io_service_time;
	cgfsng_ops->get_io_serviced		= cgfsng_get_io_serviced;
	cgfsng_ops->get_io_merged		= cgfsng_get_io_merged;
	cgfsng_ops->get_io_wait_time		= cgfsng_get_io_wait_time;

	/* psi */
	cgfsng_ops->get_pressure_io_fd = cgfsng_get_pressure_io_fd;
	cgfsng_ops->get_pressure_cpu_fd = cgfsng_get_pressure_cpu_fd;
	cgfsng_ops->get_pressure_memory_fd = cgfsng_get_pressure_memory_fd;

	return move_ptr(cgfsng_ops);
}
