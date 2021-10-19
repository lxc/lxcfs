/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXCFS_UTILS_H
#define __LXCFS_UTILS_H

#include "config.h"

#include <signal.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "lxcfs_fuse.h"

#include "macro.h"
#include "syscall_numbers.h"

/* Reserve buffer size to account for file size changes. */
#define BUF_RESERVE_SIZE 512

#define SEND_CREDS_OK 0
#define SEND_CREDS_NOTSK 1
#define SEND_CREDS_FAIL 2

struct file_info;

__attribute__((__format__(__printf__, 4, 5))) extern char *must_strcat(char **src, size_t *sz, size_t *asz, const char *format, ...);
extern bool is_shared_pidns(pid_t pid);
extern int preserve_ns(const int pid, const char *ns);
extern void do_release_file_info(struct fuse_file_info *fi);
extern bool recv_creds(int sock, struct ucred *cred, char *v);
extern int send_creds(int sock, struct ucred *cred, char v, bool pingfirst);
extern bool wait_for_sock(int sock, int timeout);
extern int read_file_fuse(const char *path, char *buf, size_t size,
			  struct file_info *d);
extern int read_file_fuse_with_offset(const char *path, char *buf, size_t size,
				      off_t offset, struct file_info *d);
extern void prune_init_slice(char *cg);
extern int wait_for_pid(pid_t pid);

#if !HAVE_PIDFD_OPEN
static inline int pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}
#endif

#if !HAVE_PIDFD_SEND_SIGNAL
static inline int pidfd_send_signal(int pidfd, int sig, siginfo_t *info,
				    unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}
#endif

extern FILE *fopen_cached(const char *path, const char *mode,
			  void **caller_freed_buffer);
extern FILE *fdopen_cached(int fd, const char *mode, void **caller_freed_buffer);
extern ssize_t write_nointr(int fd, const void *buf, size_t count);
extern int safe_uint64(const char *numstr, uint64_t *converted, int base);
extern char *trim_whitespace_in_place(char *buffer);

static inline bool file_exists(const char *f)
{
	struct stat statbuf;

	return stat(f, &statbuf) == 0;
}

#define PROTECT_OPEN_WITH_TRAILING_SYMLINKS (O_CLOEXEC | O_NOCTTY | O_RDONLY)
#define PROTECT_OPEN (PROTECT_OPEN_WITH_TRAILING_SYMLINKS | O_NOFOLLOW)
extern char *read_file_at(int dfd, const char *fnam, unsigned int o_flags);

#endif /* __LXCFS_UTILS_H */
