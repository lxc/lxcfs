/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __LXCFS_UTILS_H
#define __LXCFS_UTILS_H

#define FUSE_USE_VERSION 26

#include <fuse.h>

/* Reserve buffer size to account for file size changes. */
#define BUF_RESERVE_SIZE 512

extern void must_strcat(char **src, size_t *sz, size_t *asz, const char *format, ...);
extern bool is_shared_pidns(pid_t pid);
extern int preserve_ns(const int pid, const char *ns);
extern void do_release_file_info(struct fuse_file_info *fi);

#endif /* __LXCFS_UTILS_H */
