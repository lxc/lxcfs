/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __LXCFS_UTILS_H
#define __LXCFS_UTILS_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 26
#endif

#define _FILE_OFFSET_BITS 64

#include <fuse.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "config.h"
#include "macro.h"

/* Reserve buffer size to account for file size changes. */
#define BUF_RESERVE_SIZE 512

#define SEND_CREDS_OK 0
#define SEND_CREDS_NOTSK 1
#define SEND_CREDS_FAIL 2

struct file_info;

extern void must_strcat(char **src, size_t *sz, size_t *asz, const char *format, ...);
extern bool is_shared_pidns(pid_t pid);
extern int preserve_ns(const int pid, const char *ns);
extern void do_release_file_info(struct fuse_file_info *fi);
extern bool recv_creds(int sock, struct ucred *cred, char *v);
extern int send_creds(int sock, struct ucred *cred, char v, bool pingfirst);
extern bool wait_for_sock(int sock, int timeout);
extern int read_file_fuse(const char *path, char *buf, size_t size,
			  struct file_info *d);
extern void prune_init_slice(char *cg);
extern int wait_for_pid(pid_t pid);

#ifndef HAVE_PIDFD_OPEN
static inline int pidfd_open(pid_t pid, unsigned int flags)
{
#ifdef __NR_pidfd_open
	return syscall(__NR_pidfd_open, pid, flags);
#else
	return ret_errno(ENOSYS);
#endif
}
#endif

#ifndef HAVE_PIDFD_SEND_SIGNAL
static inline int pidfd_send_signal(int pidfd, int sig, siginfo_t *info,
				    unsigned int flags)
{
#ifdef __NR_pidfd_send_signal
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
#else
	return ret_errno(ENOSYS);
#endif
}
#endif

#endif /* __LXCFS_UTILS_H */
