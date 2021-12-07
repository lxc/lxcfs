/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#ifndef __LXCFS_ATOMIC_UTILS_H
#define __LXCFS_ATOMIC_UTILS_H

#define atomic_load_acquire(ptr)                             \
	({                                                   \
		typeof(*ptr) _val;                           \
		__atomic_load(ptr, &_val, __ATOMIC_ACQUIRE); \
		_val;                                        \
	})

#define atomic_store_release(ptr, i)                        \
	do {                                                \
		__atomic_store_n(ptr, i, __ATOMIC_RELEASE); \
	} while (0)

#define atomic_fetch_inc(ptr)  __atomic_fetch_add(ptr, 1, __ATOMIC_SEQ_CST)
#define atomic_fetch_dec(ptr)  __atomic_fetch_sub(ptr, 1, __ATOMIC_SEQ_CST)

#define atomic_read(ptr) __atomic_load_n(ptr, __ATOMIC_RELAXED)

#define atomic_cmpxchg(ptr, old, new)                                     \
	({                                                                \
		typeof(*ptr) _old = (old);                                \
		(void)__atomic_compare_exchange_n(ptr, &_old, new, false, \
						  __ATOMIC_SEQ_CST,       \
						  __ATOMIC_SEQ_CST);      \
		_old;                                                     \
	})

#endif /* __LXCFS_ATOMIC_UTILS_H */
