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
#include "cgroup2_devices.h"
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

/* Return a copy of @entry prepending "name=", i.e.  turn "systemd" into
 * "name=systemd". Do not fail.
 */
static char *cg_legacy_must_prefix_named(char *entry)
{
	size_t len;
	char *prefixed;

	len = strlen(entry);
	prefixed = must_realloc(NULL, len + 6);

	memcpy(prefixed, "name=", STRLITERALLEN("name="));
	memcpy(prefixed + STRLITERALLEN("name="), entry, len);
	prefixed[len + 5] = '\0';

	return prefixed;
}

/* Append an entry to the clist. Do not fail. @clist must be NULL the first time
 * we are called.
 *
 * We also handle named subsystems here. Any controller which is not a kernel
 * subsystem, we prefix "name=". Any which is both a kernel and named subsystem,
 * we refuse to use because we're not sure which we have here.
 * (TODO: We could work around this in some cases by just remounting to be
 * unambiguous, or by comparing mountpoint contents with current cgroup.)
 *
 * The last entry will always be NULL.
 */
static void must_append_controller(char **klist, char **nlist, char ***clist,
				   char *entry)
{
	int newentry;
	char *copy;

	if (string_in_list(klist, entry) && string_in_list(nlist, entry))
		return;

	newentry = append_null_to_list((void ***)clist);

	if (strncmp(entry, "name=", 5) == 0)
		copy = must_copy_string(entry);
	else if (string_in_list(klist, entry))
		copy = must_copy_string(entry);
	else
		copy = cg_legacy_must_prefix_named(entry);

	(*clist)[newentry] = copy;
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

/* Given two null-terminated lists of strings, return true if any string is in
 * both.
 */
static bool controller_lists_intersect(char **l1, char **l2)
{
	int i;

	if (!l1 || !l2)
		return false;

	for (i = 0; l1[i]; i++) {
		if (string_in_list(l2, l1[i]))
			return true;
	}

	return false;
}

/* For a null-terminated list of controllers @clist, return true if any of those
 * controllers is already listed the null-terminated list of hierarchies @hlist.
 * Realistically, if one is present, all must be present.
 */
static bool controller_list_is_dup(struct hierarchy **hlist, char **clist)
{
	int i;

	if (!hlist)
		return false;

	for (i = 0; hlist[i]; i++)
		if (controller_lists_intersect(hlist[i]->controllers, clist))
			return true;

	return false;
}

/* Get the controllers from a mountinfo line There are other ways we could get
 * this info. For lxcfs, field 3 is /cgroup/controller-list. For cgroupfs, we
 * could parse the mount options. But we simply assume that the mountpoint must
 * be /sys/fs/cgroup/controller-list
 */
static char **cg_hybrid_get_controllers(char **klist, char **nlist, char *line,
					int type, char **controllers)
{
	/* The fourth field is /sys/fs/cgroup/comma-delimited-controller-list
	 * for legacy hierarchies.
	 */
	int i;
	char *p2, *tok;
	char *p = line, *sep = ",";
	char **aret = NULL;

	for (i = 0; i < 4; i++) {
		p = strchr(p, ' ');
		if (!p)
			return NULL;
		p++;
	}

	/* Note, if we change how mountinfo works, then our caller will need to
	 * verify /sys/fs/cgroup/ in this field.
	 */
	if (strncmp(p, DEFAULT_CGROUP_MOUNTPOINT "/", 15) != 0)
		return NULL;

	p += 15;
	p2 = strchr(p, ' ');
	if (!p2)
		return NULL;
	*p2 = '\0';

	if (type == CGROUP_SUPER_MAGIC) {
		__do_free char *dup = NULL;

		/* strdup() here for v1 hierarchies. Otherwise
		 * lxc_iterate_parts() will destroy mountpoints such as
		 * "/sys/fs/cgroup/cpu,cpuacct".
		 */
		dup = must_copy_string(p);
		if (!dup)
			return NULL;

		lxc_iterate_parts (tok, dup, sep)
			must_append_controller(klist, nlist, &aret, tok);
		*controllers = move_ptr(dup);
	}
	*p2 = ' ';

	return aret;
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

	new = zalloc(sizeof(*new));
	new->controllers = clist;
	new->mountpoint = mountpoint;
	new->base_path = base_path;
	new->version = type;

	newentry = append_null_to_list((void ***)h);
	(*h)[newentry] = new;
	return new;
}

/* Get a copy of the mountpoint from @line, which is a line from
 * /proc/self/mountinfo.
 */
static char *cg_hybrid_get_mountpoint(char *line)
{
	int i;
	size_t len;
	char *p2;
	char *p = line, *sret = NULL;

	for (i = 0; i < 4; i++) {
		p = strchr(p, ' ');
		if (!p)
			return NULL;
		p++;
	}

	if (strncmp(p, DEFAULT_CGROUP_MOUNTPOINT "/", 15) != 0)
		return NULL;

	p2 = strchr(p + 15, ' ');
	if (!p2)
		return NULL;
	*p2 = '\0';

	len = strlen(p);
	sret = must_realloc(NULL, len + 1);
	memcpy(sret, p, len);
	sret[len] = '\0';
	return sret;
}

static void must_append_string(char ***list, char *entry)
{
	int newentry;
	char *copy;

	newentry = append_null_to_list((void ***)list);
	copy = must_copy_string(entry);
	(*list)[newentry] = copy;
}

static int get_existing_subsystems(char ***klist, char ***nlist)
{
	__do_free char *line = NULL;
	__do_fclose FILE *f = NULL;
	size_t len = 0;

	f = fopen("/proc/self/cgroup", "re");
	if (!f)
		return -1;

	while (getline(&line, &len, f) != -1) {
		char *p, *p2, *tok;
		p = strchr(line, ':');
		if (!p)
			continue;
		p++;
		p2 = strchr(p, ':');
		if (!p2)
			continue;
		*p2 = '\0';

		/* If the kernel has cgroup v2 support, then /proc/self/cgroup
		 * contains an entry of the form:
		 *
		 *	0::/some/path
		 *
		 * In this case we use "cgroup2" as controller name.
		 */
		if ((p2 - p) == 0) {
			must_append_string(klist, "cgroup2");
			continue;
		}

		lxc_iterate_parts(tok, p, ",") {
			if (strncmp(tok, "name=", 5) == 0)
				must_append_string(nlist, tok);
			else
				must_append_string(klist, tok);
		}
	}

	return 0;
}

static void trim(char *s)
{
	size_t len;

	len = strlen(s);
	while ((len > 1) && (s[len - 1] == '\n'))
		s[--len] = '\0';
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
	}

	ret = mount("cgroup", controllerpath, fstype, flags, controllers);
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
	int ret;
	bool retval = false;

	if (!ops)
		return ret_set_errno(false, ENOENT);

	if (!ops->hierarchies)
		return true;

	cgroup_root = must_make_path(root, DEFAULT_CGROUP_MOUNTPOINT, NULL);
	if (ops->cgroup_layout == CGROUP_LAYOUT_UNIFIED)
		return cg_mount_cgroup_full(ops->unified, cgroup_root) == 0;

	/* mount tmpfs */
	ret = safe_mount(NULL, cgroup_root, "tmpfs",
			 MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME,
			 "size=10240k,mode=755", root);
	if (ret < 0)
		goto on_error;

	for (int i = 0; ops->hierarchies[i]; i++) {
		__do_free char *controllerpath = NULL;
		struct hierarchy *h = ops->hierarchies[i];
		char *controller = strrchr(h->mountpoint, '/');

		if (!controller)
			continue;
		controller++;

		controllerpath = must_make_path(cgroup_root, controller, NULL);
		if (dir_exists(controllerpath))
			continue;

		ret = mkdir(controllerpath, 0755);
		if (ret < 0)
			log_error_errno(goto on_error, errno,
					"Error creating cgroup path: %s",
					controllerpath);

		ret = cg_mount_cgroup_full(h, controllerpath);
		if (ret < 0)
			goto on_error;
	}
	retval = true;

on_error:
	return retval;
}

static int cgfsng_num_hierarchies(struct cgroup_ops *ops)
{
	int i = 0;

	if (!ops)
		return ret_set_errno(-1, ENOENT);

	if (!ops->hierarchies)
		return 0;

	for (; ops->hierarchies[i]; i++)
		;

	return i;
}

static bool cgfsng_get_hierarchies(struct cgroup_ops *ops, int n, char ***out)
{
	int i;

	if (!ops)
		return ret_set_errno(false, ENOENT);

	if (!ops->hierarchies)
		return false;

	/* sanity check n */
	for (i = 0; i < n; i++)
		if (!ops->hierarchies[i])
			return ret_set_errno(false, ENOENT);

	*out = ops->hierarchies[i]->controllers;

	return true;
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
	int cgroup2_root_fd, layout, ret;

	h = ops->get_hierarchy(ops, "memory");
	if (!h)
		return -1;

	if (!is_unified_hierarchy(h)) {
		if (strcmp(file, "memory.max") == 0)
			file = "memory.limit_in_bytes";
		else if (strcmp(file, "memory.swap.max") == 0)
			file = "memory.memsw.limit_in_bytes";
		else if (strcmp(file, "memory.swap.current") == 0)
			file = "memory.memsw.usage_in_bytes";
		else if (strcmp(file, "memory.current") == 0)
			file = "memory.usage_in_bytes";
		layout = CGROUP_SUPER_MAGIC;
		cgroup2_root_fd = -EBADF;
	} else {
		layout = CGROUP2_SUPER_MAGIC;
		cgroup2_root_fd = ops->cgroup2_root_fd;
	}

	path = must_make_path_relative(cgroup, NULL);
	ret = cgroup_walkup_to_root(cgroup2_root_fd, h->fd, path, file, value);
	if (ret < 0)
		return ret;
	if (ret == 1) {
		*value = strdup("");
		if (!*value)
			return -ENOMEM;
	}

	return layout;
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

static bool cgfsng_can_use_swap(struct cgroup_ops *ops)
{
	bool has_swap = false;
	struct hierarchy *h;

	h = ops->get_hierarchy(ops, "memory");
	if (!h)
		return false;

	if (is_unified_hierarchy(h)) {
		if (faccessat(h->fd, "memory.swap.max", F_OK, 0))
			return false;

		if (faccessat(h->fd, "memory.swap.current", F_OK, 0))
			return false;

		has_swap = true;
	} else {
		if (faccessat(h->fd, "memory.memsw.limit_in_bytes", F_OK, 0))
			return false;

		if (faccessat(h->fd, "memory.memsw.usage_in_bytes", F_OK, 0))
			return false;

		has_swap = true;
	}

	return has_swap;
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
	int ret;

	h = ops->get_hierarchy(ops, "cpuset");
	if (!h)
		return -1;

	if (!is_unified_hierarchy(h))
		ret = CGROUP_SUPER_MAGIC;
	else
		ret = CGROUP2_SUPER_MAGIC;

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
		if (fd < 0 || !is_cgroup_fd(fd))
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
	int ret;

	h = ops->get_hierarchy(ops, "blkio");
	if (!h)
		return -1;

	if (!is_unified_hierarchy(h))
		ret = CGROUP_SUPER_MAGIC;
	else
		ret = CGROUP2_SUPER_MAGIC;

	path = must_make_path_relative(cgroup, file, NULL);
	*value = readat_file(h->fd, path);
	if (!*value) {
		if (errno == ENOENT)
			errno = EOPNOTSUPP;
		return ret_errno(errno);
	}

	return ret;
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

/* At startup, parse_hierarchies finds all the info we need about cgroup
 * mountpoints and current cgroups, and stores it in @d.
 */
static int cg_hybrid_init(struct cgroup_ops *ops)
{
	__do_free char *basecginfo = NULL;
	__do_free char *line = NULL;
	__do_free void *fopen_cache = NULL;
	__do_fclose FILE *f = NULL;
	int ret;
	size_t len = 0;
	char **klist = NULL, **nlist = NULL;

	/* Root spawned containers escape the current cgroup, so use init's
	 * cgroups as our base in that case.
	 */
	basecginfo = read_file("/proc/1/cgroup");
	if (!basecginfo)
		return ret_set_errno(-1, ENOMEM);

	ret = get_existing_subsystems(&klist, &nlist);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to retrieve available legacy cgroup controllers");

	f = fopen_cached("/proc/self/mountinfo", "re", &fopen_cache);
	if (!f)
		return log_error_errno(-1, errno, "Failed to open \"/proc/self/mountinfo\"");

	while (getline(&line, &len, f) != -1) {
		int type;
		struct hierarchy *new;
		char *base_cgroup = NULL, *mountpoint = NULL;
		char **controller_list = NULL;
		__do_free char *controllers = NULL;

		type = get_cgroup_version(line);
		if (type == 0)
			continue;

		if (type == CGROUP2_SUPER_MAGIC && ops->unified)
			continue;

		if (ops->cgroup_layout == CGROUP_LAYOUT_UNKNOWN) {
			if (type == CGROUP2_SUPER_MAGIC)
				ops->cgroup_layout = CGROUP_LAYOUT_UNIFIED;
			else if (type == CGROUP_SUPER_MAGIC)
				ops->cgroup_layout = CGROUP_LAYOUT_LEGACY;
		} else if (ops->cgroup_layout == CGROUP_LAYOUT_UNIFIED) {
			if (type == CGROUP_SUPER_MAGIC)
				ops->cgroup_layout = CGROUP_LAYOUT_HYBRID;
		} else if (ops->cgroup_layout == CGROUP_LAYOUT_LEGACY) {
			if (type == CGROUP2_SUPER_MAGIC)
				ops->cgroup_layout = CGROUP_LAYOUT_HYBRID;
		}

		controller_list = cg_hybrid_get_controllers(klist, nlist, line,
							    type, &controllers);
		if (!controller_list && type == CGROUP_SUPER_MAGIC)
			continue;

		if (type == CGROUP_SUPER_MAGIC)
			if (controller_list_is_dup(ops->hierarchies, controller_list))
				ret_set_errno(goto next, EEXIST);

		mountpoint = cg_hybrid_get_mountpoint(line);
		if (!mountpoint)
			log_error_errno(goto next, EINVAL, "Failed parsing mountpoint from \"%s\"", line);

		if (type == CGROUP_SUPER_MAGIC)
			base_cgroup = cg_hybrid_get_current_cgroup(basecginfo, controller_list[0], CGROUP_SUPER_MAGIC);
		else
			base_cgroup = cg_hybrid_get_current_cgroup(basecginfo, NULL, CGROUP2_SUPER_MAGIC);
		if (!base_cgroup)
			log_error_errno(goto next, EINVAL, "Failed to find current cgroup %s", mountpoint);

		trim(base_cgroup);
		prune_init_scope(base_cgroup);

		if (type == CGROUP2_SUPER_MAGIC) {
			char *cgv2_ctrl_path;

			cgv2_ctrl_path = must_make_path(mountpoint, base_cgroup,
							"cgroup.controllers",
							NULL);

			controller_list = cg_unified_get_controllers(cgv2_ctrl_path);
			free(cgv2_ctrl_path);
			if (!controller_list)
				controller_list = cg_unified_make_empty_controller();
		}

		new = add_hierarchy(&ops->hierarchies, controller_list, mountpoint, base_cgroup, type);
		new->__controllers = move_ptr(controllers);
		if (type == CGROUP2_SUPER_MAGIC && !ops->unified)
			ops->unified = new;

		continue;

	next:
		free_string_list(controller_list);
		free(mountpoint);
		free(base_cgroup);
	}

	free_string_list(klist);
	free_string_list(nlist);

	return 0;
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

	if (bpf_devices_cgroup_supported())
		new->bpf_device_controller = 1;

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

	return cg_hybrid_init(ops);
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

	cgfsng_ops->num_hierarchies = cgfsng_num_hierarchies;
	cgfsng_ops->get = cgfsng_get;
	cgfsng_ops->get_hierarchies = cgfsng_get_hierarchies;
	cgfsng_ops->get_hierarchy = cgfsng_get_hierarchy;
	cgfsng_ops->driver = "cgfsng";
	cgfsng_ops->version = "1.0.0";
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

	/* cpuset */
	cgfsng_ops->get_cpuset_cpus = cgfsng_get_cpuset_cpus;
	cgfsng_ops->can_use_cpuview = cgfsng_can_use_cpuview;

	/* blkio */
	cgfsng_ops->get_io_service_bytes	= cgfsng_get_io_service_bytes;
	cgfsng_ops->get_io_service_time		= cgfsng_get_io_service_time;
	cgfsng_ops->get_io_serviced		= cgfsng_get_io_serviced;
	cgfsng_ops->get_io_merged		= cgfsng_get_io_merged;
	cgfsng_ops->get_io_wait_time		= cgfsng_get_io_wait_time;


	return move_ptr(cgfsng_ops);
}
