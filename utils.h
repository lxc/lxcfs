/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __LXCFS_UTILS_H
#define __LXCFS_UTILS_H

/* Reserve buffer size to account for file size changes. */
#define BUF_RESERVE_SIZE 512

extern void must_strcat(char **src, size_t *sz, size_t *asz, const char *format, ...);
extern bool is_shared_pidns(pid_t pid);
extern int preserve_ns(const int pid, const char *ns);

#endif /* __LXCFS_UTILS_H */
