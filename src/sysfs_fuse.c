/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "config.h"

#ifdef HAVE_FUSE3
#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 30
#endif
#else
#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 26
#endif
#endif

/* Taken over modified from the kernel sources. */
#define NBITS 32 /* bits in uint32_t */
#define DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))
#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, NBITS)

#define _FILE_OFFSET_BITS 64

#define __STDC_FORMAT_MACROS
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <inttypes.h>
#include <libgen.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wait.h>
#include <linux/magic.h>
#include <linux/sched.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/vfs.h>

#include "bindings.h"
#include "memory_utils.h"
#include "cgroups/cgroup.h"
#include "lxcfs_fuse_compat.h"
#include "sysfs_fuse.h"
#include "utils.h"

static size_t get_max_cpus(char *cpulist)
{
	char *c1, *c2;
	char *maxcpus = cpulist;
	size_t cpus = 0;

	c1 = strrchr(maxcpus, ',');
	if (c1)
		c1++;

	c2 = strrchr(maxcpus, '-');
	if (c2)
		c2++;

	if (!c1 && !c2)
		c1 = maxcpus;
	else if (c1 > c2)
		c2 = c1;
	else if (c1 < c2)
		c1 = c2;
	else if (!c1 && c2)
		c1 = c2;

	errno = 0;
	cpus = strtoul(c1, NULL, 0);
	if (errno != 0)
		return -1;

	return cpus;
}

static void set_bit(unsigned bit, uint32_t *bitarr)
{
	bitarr[bit / NBITS] |= (1 << (bit % NBITS));
}

static bool is_set(unsigned bit, uint32_t *bitarr)
{
	return (bitarr[bit / NBITS] & (1 << (bit % NBITS))) != 0;
}

/* Create cpumask from cpulist aka turn:
 *
 *	0,2-3
 *
 * into bit array
 *
 *	1 0 1 1
 */
static uint32_t *lxc_cpumask(char *buf, size_t nbits)
{
	__do_free uint32_t *bitarr = NULL;
	char *token;
	size_t arrlen;

	arrlen = BITS_TO_LONGS(nbits);
	bitarr = calloc(arrlen, sizeof(uint32_t));
	if (!bitarr)
		return ret_set_errno(NULL, ENOMEM);

	lxc_iterate_parts(token, buf, ",") {
		errno = 0;
		unsigned end, start;
		char *range;

		start = strtoul(token, NULL, 0);
		end = start;
		range = strchr(token, '-');
		if (range)
			end = strtoul(range + 1, NULL, 0);

		if (!(start <= end))
			return ret_set_errno(NULL, EINVAL);

		if (end >= nbits)
			return ret_set_errno(NULL, EINVAL);

		while (start <= end)
			set_bit(start++, bitarr);
	}

	return move_ptr(bitarr);
}

static int sys_devices_system_cpu_online_read(char *buf, size_t size,
					off_t offset,
					struct fuse_file_info *fi)
{
	__do_free char *cg = NULL, *cpuset = NULL;
	struct fuse_context *fc = fuse_get_context();
	struct lxcfs_opts *opts = (struct lxcfs_opts *)fc->private_data;
	struct file_info *d = INTTYPE_TO_PTR(fi->fh);
	char *cache = d->buf;
	bool use_view;

	int max_cpus = 0;
	pid_t initpid;
	ssize_t total_len = 0;

	if (offset) {
		int left;

		if (!d->cached)
			return 0;

		if (offset > d->size)
			return -EINVAL;

		left = d->size - offset;
		total_len = left > size ? size : left;
		memcpy(buf, cache + offset, total_len);

		return total_len;
	}

	initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;

	cg = get_pid_cgroup(initpid, "cpuset");
	if (!cg)
		return read_file_fuse("/sys/devices/system/cpu/online", buf, size, d);
	prune_init_slice(cg);

	cpuset = get_cpuset(cg);
	if (!cpuset)
		return 0;

	if (cgroup_ops->can_use_cpuview(cgroup_ops) && opts && opts->use_cfs)
		use_view = true;
	else
		use_view = false;

	if (use_view)
		max_cpus = max_cpu_count(cg);

	if (use_view) {
		if (max_cpus > 1)
			total_len = snprintf(d->buf, d->buflen, "0-%d\n", max_cpus - 1);
		else
			total_len = snprintf(d->buf, d->buflen, "0\n");
	} else {
		total_len = snprintf(d->buf, d->buflen, "%s\n", cpuset);
	}
	if (total_len < 0 || total_len >= d->buflen)
		return log_error(0, "Failed to write to cache");

	d->size = (int)total_len;
	d->cached = 1;

	if (total_len > size)
		total_len = size;

	memcpy(buf, d->buf, total_len);

	return total_len;
}

static int filler_sys_devices_system_cpu(const char *path, void *buf, fuse_fill_dir_t filler)
{
	__do_free char *cg = NULL, *cpuset = NULL;
	__do_closedir DIR *dir = NULL;
	struct dirent *dirent;
	struct fuse_context *fc = fuse_get_context();
	pid_t initpid;
	size_t max_cpus;
	char cpu[100];
	uint32_t * cpumask;
	size_t len;

	initpid = lookup_initpid_in_store(fc->pid);

	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;
	cg = get_pid_cgroup(initpid, "cpuset");
	if (!cg)
		return 0; 

	prune_init_slice(cg);

	cpuset = get_cpuset(cg);
	if (!cpuset)
		return 0; 

	max_cpus = get_max_cpus(cpuset);
	if (max_cpus < 0 || max_cpus >= INT_MAX - 1)
		return -1;
	
	cpumask = lxc_cpumask(cpuset, max_cpus+1);
	if (!cpumask)
		return -errno;
                
	for (size_t i = 0; i <= max_cpus; i++) { 
		if (!is_set(i, cpumask))
			continue;
			
                sprintf(cpu, "cpu%ld", i);
		if (DIR_FILLER(filler, buf, cpu, NULL, 0) != 0)
			return -ENOENT;
        }

	dir = opendir(path);
	if (!dir)
		return -ENOENT;

	while ((dirent = readdir(dir))) {
		len = strlen(dirent->d_name);
		if (strncmp(dirent->d_name, "cpu", 3) == 0 && dirent->d_name[len - 1] >= '0' &&dirent->d_name[len - 1] <= '9')
			continue;

		if (DIR_FILLER(filler, buf, dirent->d_name, NULL, 0) != 0)
			return -ENOENT;
	}

	return 0;
}

static mode_t get_st_mode(const char *path)
{
	struct stat sb;
	int ret;

	ret = lstat(path, &sb);
	if (ret < 0)
		return -ENOENT;

	return sb.st_mode;
}

static off_t get_sysfile_size(const char *which)
{
	__do_fclose FILE *f = NULL;
	__do_free char *line = NULL;
	size_t len = 0;
	ssize_t sz, answer = 0;

	f = fopen(which, "re");
	if (!f)
		return 0;

	while ((sz = getline(&line, &len, f)) != -1)
		answer += sz;

	return answer;
}

__lxcfs_fuse_ops int sys_getattr(const char *path, struct stat *sb)
{
	struct timespec now;
	mode_t st_mode;

	if (!liblxcfs_functional())
		return -EIO;

	memset(sb, 0, sizeof(struct stat));
	if (clock_gettime(CLOCK_REALTIME, &now) < 0)
		return -EINVAL;

	sb->st_uid = sb->st_gid = 0;
	sb->st_atim = sb->st_mtim = sb->st_ctim = now;

	st_mode = get_st_mode(path);
	if (st_mode < 0)
		return -ENOENT;

	if (S_ISDIR(st_mode)) {
		sb->st_mode = st_mode;
		sb->st_nlink = 2;
		return 0;
	}

	if (S_ISREG(st_mode) || S_ISLNK(st_mode)) {
		sb->st_size = get_sysfile_size(path);
		sb->st_mode = st_mode;
		sb->st_nlink = 1;
		return 0;
	}

	return -ENOENT;
}

__lxcfs_fuse_ops int sys_write(const char *path, const char *buf, 
			size_t size, off_t offset, 
			struct fuse_file_info *fi)
{
	__do_close int fd = -EBADF;
	struct file_info *f = INTTYPE_TO_PTR(fi->fh);

	if (!liblxcfs_functional())
		return -EIO;

	if (f->type != LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_SUBFILE)
		return -EINVAL;
	
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd == -1)
		return -errno;
	
	return pwrite(fd, buf, size, offset);
}

__lxcfs_fuse_ops int sys_readdir(const char *path, void *buf,
				fuse_fill_dir_t filler, off_t offset,
				struct fuse_file_info *fi)
{
	__do_closedir DIR *dir = NULL;
	struct dirent *dirent;
	struct file_info *f = INTTYPE_TO_PTR(fi->fh);

	if (!liblxcfs_functional())
		return -EIO;

	switch (f->type) {
	case LXC_TYPE_SYS: {
			if (DIR_FILLER(filler, buf, ".",    NULL, 0) != 0 ||
			    DIR_FILLER(filler, buf, "..",   NULL, 0) != 0 ||
			    DIR_FILLER(filler, buf, "devices",  NULL, 0) != 0)
					return -ENOENT;

			return 0;
		}
	case LXC_TYPE_SYS_DEVICES: {
			if (DIR_FILLER(filler, buf, ".",    NULL, 0) != 0 ||
			    DIR_FILLER(filler, buf, "..",   NULL, 0) != 0 ||
			    DIR_FILLER(filler, buf, "system",  NULL, 0) != 0)
					return -ENOENT;

			return 0;
		}
	case LXC_TYPE_SYS_DEVICES_SYSTEM: {
			if (DIR_FILLER(filler, buf, ".",    NULL, 0) != 0 ||
			    DIR_FILLER(filler, buf, "..",   NULL, 0) != 0 ||
			    DIR_FILLER(filler, buf, "cpu",  NULL, 0) != 0)
					return -ENOENT;

			return 0;
		}
	case LXC_TYPE_SYS_DEVICES_SYSTEM_CPU:
			return filler_sys_devices_system_cpu(path, buf, filler);
	case LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_SUBDIR: {
			dir = opendir(path);
			if (!dir)
				return -ENOENT;

			while ((dirent = readdir(dir))) {
				if (DIR_FILLER(filler, buf, dirent->d_name, NULL, 0) != 0)
					return -ENOENT;
			}

			return 0; 
		}
	}

	return -EINVAL;
}

__lxcfs_fuse_ops int sys_readlink(const char *path, char *buf, size_t size)
{
	int ret = readlink(path, buf, size);

	if (!liblxcfs_functional())
		return -EIO;

	if (ret < 0)
		return -errno;
	if (ret > size)
		return -1;

	buf[ret] = '\0';

	return 0;
}
__lxcfs_fuse_ops int sys_open(const char *path, struct fuse_file_info *fi)
{
	__do_free struct file_info *info = NULL;
	int type = -1;

	if (!liblxcfs_functional())
		return -EIO;

	if (strcmp(path, "/sys/devices/system/cpu/online") == 0)
		type = LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_ONLINE;
	else if (strncmp(path, "/sys/devices/system/cpu/", STRLITERALLEN("/sys/devices/system/cpu/")) == 0 && S_ISREG(get_st_mode(path)))
		type = LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_SUBFILE;
	if (type == -1) 
		return -ENOENT;

	info = malloc(sizeof(*info));
	if (!info)
		return -ENOMEM;

	memset(info, 0, sizeof(*info));
	info->type = type;

	info->buflen = get_sysfile_size(path) + BUF_RESERVE_SIZE;

	info->buf = malloc(info->buflen);
	if (!info->buf)
		return -ENOMEM;

	memset(info->buf, 0, info->buflen);
	/* set actual size to buffer size */
	info->size = info->buflen;

	fi->fh = PTR_TO_UINT64(move_ptr(info));
	return 0;
}

__lxcfs_fuse_ops int sys_opendir(const char *path, struct fuse_file_info *fi)
{
	__do_free struct file_info *dir_info = NULL;
	int type = -1;

	if (!liblxcfs_functional())
		return -EIO;

	if (strcmp(path, "/sys") == 0)
		type = LXC_TYPE_SYS;
	if (strcmp(path, "/sys/devices") == 0)
		type = LXC_TYPE_SYS_DEVICES;
	if (strcmp(path, "/sys/devices/system") == 0)
		type = LXC_TYPE_SYS_DEVICES_SYSTEM;
	if (strcmp(path, "/sys/devices/system/cpu") == 0)
		type = LXC_TYPE_SYS_DEVICES_SYSTEM_CPU;
	if (strncmp(path, "/sys/devices/system/cpu/", STRLITERALLEN("/sys/devices/system/cpu/")) == 0 && S_ISDIR(get_st_mode(path)))  
		type = LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_SUBDIR;
	if (type == -1)
		return -ENOENT;

	dir_info = malloc(sizeof(*dir_info));
	if (!dir_info) 
		return -ENOMEM;

	memset(dir_info, 0, sizeof(*dir_info));
	dir_info->type = type;
	dir_info->buf = NULL;
	dir_info->file = NULL;
	dir_info->buflen = 0;

	fi->fh = PTR_TO_UINT64(move_ptr(dir_info));
	return 0;
}

__lxcfs_fuse_ops int sys_access(const char *path, int mask)
{
	if (!liblxcfs_functional())
		return -EIO;

	return access(path, mask);
}

__lxcfs_fuse_ops int sys_release(const char *path, struct fuse_file_info *fi)
{
	do_release_file_info(fi);
	return 0;
}

__lxcfs_fuse_ops int sys_releasedir(const char *path, struct fuse_file_info *fi)
{
	do_release_file_info(fi);
	return 0;
}

__lxcfs_fuse_ops int sys_read(const char *path, char *buf, size_t size,
			off_t offset, struct fuse_file_info *fi)
{
	struct file_info *f = INTTYPE_TO_PTR(fi->fh);

	if (!liblxcfs_functional())
		return -EIO;

	switch (f->type) {
	case LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_ONLINE:
		return sys_devices_system_cpu_online_read(buf, size, offset, fi);
	case LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_SUBFILE:
		return read_file_fuse_with_offset(path, buf, size, offset, f);
	}

	return -EINVAL;
}
