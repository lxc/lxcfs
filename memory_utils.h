/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXCFS_MEMORY_UTILS_H
#define __LXCFS_MEMORY_UTILS_H

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "macro.h"

static inline void __auto_free__(void *p)
{
	free(*(void **)p);
}

static inline void __auto_fclose__(FILE **f)
{
	if (*f)
		fclose(*f);
}

static inline void __auto_closedir__(DIR **d)
{
	if (*d)
		closedir(*d);
}

#define close_prot_errno_disarm(fd) \
	if (fd >= 0) {              \
		int _e_ = errno;    \
		close(fd);          \
		errno = _e_;        \
		fd = -EBADF;        \
	}

#define free_disarm(ptr)       \
	({                     \
		free(ptr);     \
		move_ptr(ptr); \
	})

static inline void __auto_close__(int *fd)
{
	close_prot_errno_disarm(*fd);
}

#define __do_close_prot_errno __attribute__((__cleanup__(__auto_close__)))
#define __do_free __attribute__((__cleanup__(__auto_free__)))
#define __do_fclose __attribute__((__cleanup__(__auto_fclose__)))
#define __do_closedir __attribute__((__cleanup__(__auto_closedir__)))

#define move_ptr(ptr)                                 \
	({                                            \
		typeof(ptr) __internal_ptr__ = (ptr); \
		(ptr) = NULL;                         \
		__internal_ptr__;                     \
	})

#define move_fd(fd)                         \
	({                                  \
		int __internal_fd__ = (fd); \
		(fd) = -EBADF;              \
		__internal_fd__;            \
	})

#define zalloc(__size__) (calloc(1, __size__))

#endif /* __LXCFS_MEMORY_UTILS_H */
