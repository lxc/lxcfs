/* SPDX-License-Identifier: LGPL-2.1+ */

/* Parts of this taken from systemd's implementation. */

#ifndef __LXC_CGROUP2_DEVICES_H
#define __LXC_CGROUP2_DEVICES_H

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef HAVE_STRUCT_BPF_CGROUP_DEV_CTX
#include <linux/bpf.h>
#include <linux/filter.h>
#endif

#include "../syscall_numbers.h"

#if !HAVE_BPF

union bpf_attr;

enum {
	LXC_BPF_DEVICE_CGROUP_LOCAL_RULE = -1,
	LXC_BPF_DEVICE_CGROUP_ALLOWLIST  =  0,
	LXC_BPF_DEVICE_CGROUP_DENYLIST  =  1,
};

static inline int missing_bpf(int cmd, union bpf_attr *attr, size_t size)
{
	return (int)syscall(__NR_bpf, cmd, attr, size);
}

#define bpf missing_bpf
#endif

struct bpf_program {
	int device_list_type;
	int kernel_fd;
	uint32_t prog_type;

	size_t n_instructions;
#ifdef HAVE_STRUCT_BPF_CGROUP_DEV_CTX
	struct bpf_insn *instructions;
#endif /* HAVE_STRUCT_BPF_CGROUP_DEV_CTX */

	char *attached_path;
	int attached_type;
	uint32_t attached_flags;
};

#ifdef HAVE_STRUCT_BPF_CGROUP_DEV_CTX
struct bpf_program *bpf_program_new(uint32_t prog_type);
int bpf_program_init(struct bpf_program *prog);
int bpf_program_append_device(struct bpf_program *prog,
			      struct device_item *device);
int bpf_program_finalize(struct bpf_program *prog);
int bpf_program_cgroup_attach(struct bpf_program *prog, int type,
			      const char *path, uint32_t flags);
int bpf_program_cgroup_detach(struct bpf_program *prog);
void bpf_program_free(struct bpf_program *prog);
bool bpf_devices_cgroup_supported(void);
static inline void __auto_bpf_program_free__(struct bpf_program **prog)
{
	if (*prog) {
		bpf_program_free(*prog);
		*prog = NULL;
	}
}
#else /* HAVE_STRUCT_BPF_CGROUP_DEV_CTX */
static inline struct bpf_program *bpf_program_new(uint32_t prog_type)
{
	errno = ENOSYS;
	return NULL;
}

static inline int bpf_program_init(struct bpf_program *prog)
{
	errno = ENOSYS;
	return -1;
}

static inline int bpf_program_append_device(struct bpf_program *prog, char type,
					    int major, int minor,
					    const char *access, int allow)
{
	errno = ENOSYS;
	return -1;
}

static inline int bpf_program_finalize(struct bpf_program *prog)
{
	errno = ENOSYS;
	return -1;
}

static inline int bpf_program_cgroup_attach(struct bpf_program *prog, int type,
					    const char *path, uint32_t flags)
{
	errno = ENOSYS;
	return -1;
}

static inline int bpf_program_cgroup_detach(struct bpf_program *prog)
{
	errno = ENOSYS;
	return -1;
}

static inline void bpf_program_free(struct bpf_program *prog)
{
}


static inline bool bpf_devices_cgroup_supported(void)
{
	return false;
}

static inline void __auto_bpf_program_free__(struct bpf_program **prog)
{
}

#endif /* HAVE_BPF */

define_cleanup_function(struct bpf_program *, bpf_program_free);

#endif /* __LXC_CGROUP2_DEVICES_H */
