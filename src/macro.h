/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXCFS_MACRO_H
#define __LXCFS_MACRO_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 26
#endif

#define _FILE_OFFSET_BITS 64

#include <stdio.h>

#include "config.h"

#define BATCH_SIZE 50

/* filesystem magic values */
#ifndef CGROUP_SUPER_MAGIC
#define CGROUP_SUPER_MAGIC 0x27e0eb
#endif

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

#define lxcfs_debug_stream(stream, format, ...)                       \
	do {                                                          \
		fprintf(stream, "%s: %d: %s: " format "\n", __FILE__, \
			__LINE__, __func__, ##__VA_ARGS__);           \
	} while (false)

#define lxcfs_error(format, ...) lxcfs_debug_stream(stderr, format, ##__VA_ARGS__)

#ifdef DEBUG
#define lxcfs_debug(format, ...) lxcfs_error(format, ##__VA_ARGS__)
#else
#define lxcfs_debug(format, ...) \
	do {                     \
	} while (false)
#endif /* DEBUG */

#ifdef VERBOSE
#define lxcfs_v(format, ...) lxcfs_error(format, ##__VA_ARGS__);
#else
#define lxcfs_v(format, ...)
#endif /* VERBOSE */

#define lxcfs_info(format, ...)                              \
	do {                                                 \
		fprintf(stderr, format "\n", ##__VA_ARGS__); \
	} while (false)

#define log_error_errno(__ret__, __errno__, format, ...) \
	({						 \
		errno = __errno__;			 \
		lxcfs_error(format, ##__VA_ARGS__);	 \
		__ret__;				 \
	})

#define log_error(__ret__, format, ...)             \
	({                                          \
		lxcfs_error(format, ##__VA_ARGS__); \
		__ret__;                            \
	})

#define STRLITERALLEN(x) (sizeof(""x"") - 1)

/* Calculate the number of chars needed to represent a given integer as a C
 * string. Include room for '-' to indicate negative numbers and the \0 byte.
 * This is based on systemd.
 */
#define INTTYPE_TO_STRLEN(type)                   \
	(2 + (sizeof(type) <= 1                   \
		  ? 3                             \
		  : sizeof(type) <= 2             \
			? 5                       \
			: sizeof(type) <= 4       \
			      ? 10                \
			      : sizeof(type) <= 8 \
				    ? 20          \
				    : sizeof(int[-2 * (sizeof(type) > 8)])))

#define move_ptr(ptr)                                 \
	({                                            \
		__typeof__(ptr) __internal_ptr__ = (ptr); \
		(ptr) = NULL;                         \
		__internal_ptr__;                     \
	})

#define move_fd(fd)                         \
	({                                  \
		int __internal_fd__ = (fd); \
		(fd) = -EBADF;              \
		__internal_fd__;            \
	})

#define ret_errno(__errno__)       \
	({                         \
		errno = __errno__; \
		-__errno__;        \
	})

#define ret_set_errno(__ret__, __errno__) \
	({                                \
		errno = __errno__;        \
		__ret__;                  \
	})

#define lxc_iterate_parts(__iterator, __splitme, __separators)                  \
	for (char *__p = NULL, *__it = strtok_r(__splitme, __separators, &__p); \
	     (__iterator = __it);                                               \
	     __iterator = __it = strtok_r(NULL, __separators, &__p))

#define log_exit(format, ...)                           \
	({                                              \
		fprintf(stderr, format, ##__VA_ARGS__); \
		_exit(EXIT_FAILURE);                    \
	})

#ifdef DEBUG
#define log_debug(__ret__, format, ...)                            \
	({                                                         \
		lxcfs_debug_stream(stderr, format, ##__VA_ARGS__); \
		__ret__;                                           \
	})
#else
#define log_debug(__ret__, format, ...) ({ __ret__; })
#endif

#define PTR_TO_INT(p) ((int)((intptr_t)(p)))
#define INT_TO_PTR(u) ((void *)((intptr_t)(u)))
#define PTR_TO_UINT64(p) ((uint64_t)((intptr_t)(p)))
#define INTTYPE_TO_PTR(u) ((void *)((intptr_t)(u)))

#define __visible __attribute__((visibility("default")))

#define __lxcfs_fuse_ops

#ifndef __returns_twice
#define __returns_twice __attribute__((returns_twice))
#endif

#endif /* __LXCFS_MACRO_H */
