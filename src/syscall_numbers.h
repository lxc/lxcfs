/* SPDX-License-Identifier: LGPL-2.1+ */
#ifndef __LXCFS_SYSCALL_NUMBERS_H
#define __LXCFS_SYSCALL_NUMBERS_H

#include "config.h"

#include <asm/unistd.h>
#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef __NR_pivot_root
	#if defined __i386__
		#define __NR_pivot_root 217
	#elif defined __x86_64__
		#define __NR_pivot_root	155
	#elif defined __arm__
		#define __NR_pivot_root 218
	#elif defined __aarch64__
		#define __NR_pivot_root 218
	#elif defined __s390__
		#define __NR_pivot_root 217
	#elif defined __powerpc__
		#define __NR_pivot_root 203
	#elif defined __sparc__
		#define __NR_pivot_root 146
	#elif defined __ia64__
		#define __NR_pivot_root 183
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_pivot_root 4216
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_pivot_root 6151
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_pivot_root 5151
		#endif
	#else
		#define -1
		#warning "__NR_pivot_root not defined for your architecture"
	#endif
#endif

#ifndef __NR_bpf
	#if defined __i386__
		#define __NR_bpf 357
	#elif defined __x86_64__
		#define __NR_bpf 321
	#elif defined __arm__
		#define __NR_bpf 386
	#elif defined __aarch64__
		#define __NR_bpf 386
	#elif defined __s390__
		#define __NR_bpf 351
	#elif defined __powerpc__
		#define __NR_bpf 361
	#elif defined __sparc__
		#define __NR_bpf 349
	#elif defined __ia64__
		#define __NR_bpf 317
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_bpf 4355
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_bpf 6319
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_bpf 5315
		#endif
	#else
		#define -1
		#warning "__NR_bpf not defined for your architecture"
	#endif
#endif

#ifndef __NR_pidfd_send_signal
	#if defined __alpha__
		#define __NR_pidfd_send_signal 534
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_pidfd_send_signal 4424
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_pidfd_send_signal 6424
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_pidfd_send_signal 5424
		#endif
	#else
		#define __NR_pidfd_send_signal 424
	#endif
#endif

#ifndef __NR_pidfd_open
	#if defined __alpha__
		#define __NR_pidfd_open 544
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_pidfd_open 4434
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_pidfd_open 6434
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_pidfd_open 5434
		#endif
	#else
		#define __NR_pidfd_open 434
	#endif
#endif

#endif /* __LXCFS_SYSCALL_NUMBERS_H */
