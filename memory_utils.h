/* liblxcapi
 *
 * Copyright © 2019 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2019 Canonical Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __LXC_MEMORY_UTILS_H
#define __LXC_MEMORY_UTILS_H

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "macro.h"

static inline void __free_move__(void *p)
{
	free(*(void **)p);
	*(void **)p = NULL;
}

static inline void __fclose_move__(FILE **f)
{
	if (*f) {
		fclose(*f);
		*f = NULL;
	}
}

static inline void __closedir_move__(DIR **d)
{
	if (*d) {
		closedir(*d);
		*d = NULL;
	}
}

#define close_prot_errno_disarm(fd) \
	if (fd >= 0) {              \
		int _e_ = errno;    \
		close(fd);          \
		errno = _e_;        \
		fd = -EBADF;        \
	}

static inline void __close_move__(int *fd)
{
	close_prot_errno_disarm(*fd);
}

#define __do_close_prot_errno __attribute__((__cleanup__(__close_move__)))
#define __do_free __attribute__((__cleanup__(__free_move__)))
#define __do_fclose __attribute__((__cleanup__(__fclose_move__)))
#define __do_closedir __attribute__((__cleanup__(__closedir_move__)))

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

#endif /* __LXC_MEMORY_UTILS_H */
