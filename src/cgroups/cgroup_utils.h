/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_CGROUP_UTILS_H
#define __LXC_CGROUP_UTILS_H

#include "config.h"

#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "../macro.h"
#include "../memory_utils.h"

/* Retrieve the cgroup version of a given entry from /proc/<pid>/mountinfo. */
extern int get_cgroup_version(char *line);

/* Check if given entry from /proc/<pid>/mountinfo is a cgroupfs v1 mount. */
extern bool is_cgroupfs_v1(char *line);

/* Check if given entry from /proc/<pid>/mountinfo is a cgroupfs v2 mount. */
extern bool is_cgroupfs_v2(char *line);

/* Given a v1 hierarchy @mountpoint and base @path, verify that we can create
 * directories underneath it.
 */
extern bool test_writeable_v1(char *mountpoint, char *path);

/* Given a v2 hierarchy @mountpoint and base @path, verify that we can create
 * directories underneath it and that we have write access to the cgroup's
 * "cgroup.procs" file.
 */
extern bool test_writeable_v2(char *mountpoint, char *path);

extern int unified_cgroup_hierarchy(void);

extern void *must_realloc(void *orig, size_t sz);

extern char *must_make_path(const char *first, ...);

extern char *must_copy_string(const char *entry);

/* __typeof__ should be safe to use with all compilers. */
typedef __typeof__(((struct statfs *)NULL)->f_type) fs_type_magic;
extern bool is_fs_type(const struct statfs *fs, fs_type_magic magic_val);

extern char *lxc_string_join(const char *sep, const char **parts,
			     bool use_as_prefix);
extern int lxc_count_file_lines(const char *fn);

extern bool dir_exists(const char *path);

extern int safe_mount(const char *src, const char *dest, const char *fstype,
		      unsigned long flags, const void *data, const char *rootfs);

#if !HAVE_STRLCPY
extern size_t strlcpy(char *, const char *, size_t);
#endif

#if !HAVE_STRLCAT
extern size_t strlcat(char *d, const char *s, size_t n);
#endif

extern FILE *fopen_cloexec(const char *path, const char *mode);
extern void append_line(char **dest, size_t oldlen, char *new, size_t newlen);
extern char *read_file(const char *fnam);
extern char *readat_file(int fd, const char *path);
extern char *read_file_strip_newline(const char *fnam);
extern char *cg_unified_get_current_cgroup(pid_t pid);
extern char *cg_hybrid_get_current_cgroup(char *basecginfo,
					  const char *controller, int type);
extern char *cg_legacy_get_current_cgroup(pid_t pid, const char *controller);
extern bool mkdir_p(const char *dir, mode_t mode);
extern bool is_cgroup_fd(int fd);

static inline int openat_safe(int fd, const char *path)
{
	return openat(fd, path, O_DIRECTORY | O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
}

extern int cgroup_walkup_to_root(int cgroup2_root_fd, int hierarchy_fd,
				 const char *cgroup, const char *file,
				 char **value);

#define must_make_path_relative(__first__, ...)                                \
	({                                                                     \
		char *__ptr__;                                                 \
		if (*__first__ == '/')                                         \
			__ptr__ = must_make_path(".", __first__, __VA_ARGS__); \
		else                                                           \
			__ptr__ = must_make_path(__first__, __VA_ARGS__);      \
		__ptr__;                                                       \
	})

static inline bool is_empty_string(const char *s)
{
	return !s || strcmp(s, "") == 0;
}

#endif /* __LXC_CGROUP_UTILS_H */
