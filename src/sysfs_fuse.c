/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
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

#include "sysfs_fuse.h"

#include "bindings.h"
#include "memory_utils.h"
#include "cgroups/cgroup.h"
#include "lxcfs_fuse_compat.h"
#include "utils.h"

/* Create cpumask from cpulist aka turn:
 *
 *	0,2-3
 *
 * into bit array
 *
 *	1 0 1 1
 */
static int lxc_cpumask(char *buf, __u32 **bitarr, __u32 *last_set_bit)
{
	__do_free __u32 *arr_u32 = NULL;
	__u32 cur_last_set_bit = 0, nbits = 256;
	__u32 nr_u32;
	char *token;

	nr_u32 = BITS_TO_LONGS(nbits);
	arr_u32 = zalloc(nr_u32 * sizeof(__u32));
	if (!arr_u32)
		return ret_errno(ENOMEM);

	lxc_iterate_parts(token, buf, ",") {
		__u32 last_bit, first_bit;
		char *range;

		errno = 0;
		first_bit = strtoul(token, NULL, 0);
		last_bit = first_bit;
		range = strchr(token, '-');
		if (range)
			last_bit = strtoul(range + 1, NULL, 0);

		if (!(first_bit <= last_bit))
			return ret_errno(EINVAL);

		if (last_bit >= nbits) {
			__u32 add_bits = last_bit - nbits + 32;
			__u32 new_nr_u32;
			__u32 *p;

			new_nr_u32 = BITS_TO_LONGS(nbits + add_bits);
			p = realloc(arr_u32, new_nr_u32 * sizeof(uint32_t));
			if (!p)
				return ret_errno(ENOMEM);
			arr_u32 = move_ptr(p);

			memset(arr_u32 + nr_u32, 0,
			       (new_nr_u32 - nr_u32) * sizeof(uint32_t));
			nbits += add_bits;
		}

		while (first_bit <= last_bit)
			set_bit(first_bit++, arr_u32);

		if (last_bit > cur_last_set_bit)
			cur_last_set_bit = last_bit;
	}

	*last_set_bit = cur_last_set_bit;
	*bitarr = move_ptr(arr_u32);
	return 0;
}

static int lxc_cpumask_update(char *buf, __u32 *bitarr, __u32 last_set_bit,
			      bool clear)
{
	bool flipped = false;
	char *token;

	lxc_iterate_parts(token, buf, ",") {
		__u32 last_bit, first_bit;
		char *range;

		errno = 0;
		first_bit = strtoul(token, NULL, 0);
		last_bit = first_bit;
		range = strchr(token, '-');
		if (range)
			last_bit = strtoul(range + 1, NULL, 0);

		if (!(first_bit <= last_bit)) {
			lxcfs_debug("The cup range seems to be inverted: %u-%u", first_bit, last_bit);
			continue;
		}

		if (last_bit > last_set_bit)
			continue;

		while (first_bit <= last_bit) {
			if (clear && is_set(first_bit, bitarr)) {
				flipped = true;
				clear_bit(first_bit, bitarr);
			} else if (!clear && !is_set(first_bit, bitarr)) {
				flipped = true;
				set_bit(first_bit, bitarr);
			}

			first_bit++;
		}
	}

	if (flipped)
		return 1;

	return 0;
}

#define __ISOL_CPUS "/sys/devices/system/cpu/isolated"
#define __OFFLINE_CPUS "/sys/devices/system/cpu/offline"
static int cpumask(char *posscpus, __u32 **bitarr, __u32 *last_set_bit)
{
	__do_free char *isolcpus = NULL, *offlinecpus = NULL;
	__do_free __u32 *possmask = NULL;
	int ret;
	__u32 poss_last_set_bit = 0;

	if (file_exists(__ISOL_CPUS)) {
		isolcpus = read_file_at(-EBADF, __ISOL_CPUS, PROTECT_OPEN);
		if (!isolcpus)
			return -1;

		if (!isdigit(isolcpus[0]))
			free_disarm(isolcpus);
	} else {
		lxcfs_debug("The path \""__ISOL_CPUS"\" to read isolated cpus from does not exist");
	}

	if (file_exists(__OFFLINE_CPUS)) {
		offlinecpus = read_file_at(-EBADF, __OFFLINE_CPUS, PROTECT_OPEN);
		if (!offlinecpus)
			return -1;

		if (!isdigit(offlinecpus[0]))
			free_disarm(offlinecpus);
	} else {
		lxcfs_debug("The path \""__OFFLINE_CPUS"\" to read offline cpus from does not exist");
	}

	ret = lxc_cpumask(posscpus, &possmask, &poss_last_set_bit);
	if (ret)
		return ret;

	if (isolcpus)
		ret = lxc_cpumask_update(isolcpus, possmask, poss_last_set_bit, true);

	if (offlinecpus)
		ret |= lxc_cpumask_update(offlinecpus, possmask, poss_last_set_bit, true);
	if (ret)
		return ret;

	*bitarr = move_ptr(possmask);
	*last_set_bit = poss_last_set_bit;
	return 0;
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
	pid_t initpid;
	int max_cpus = 0;
	ssize_t total_len = 0;
	bool use_view;

	if (offset) {
		size_t left;

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

	if ((size_t)total_len > size)
		total_len = size;

	memcpy(buf, d->buf, total_len);

	return total_len;
}

static int filler_sys_devices_system_cpu(const char *path, void *buf,
					 fuse_fill_dir_t filler)
{
	__do_free __u32 *bitarr = NULL;
	__do_free char *cg = NULL, *cpuset = NULL;
	__do_closedir DIR *dir = NULL;
	struct fuse_context *fc = fuse_get_context();
	__u32 last_set_bit = 0;
	int ret;
	struct dirent *dirent;
	pid_t initpid;

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

	ret = cpumask(cpuset, &bitarr, &last_set_bit);
	if (ret)
		return ret;

	for (__u32 bit = 0; bit <= last_set_bit; bit++) {
		char cpu[100];

		if (!is_set(bit, bitarr))
			continue;

		ret = snprintf(cpu, sizeof(cpu), "cpu%u", bit);
		if (ret < 0 || (size_t)ret >= sizeof(cpu))
			continue;

		if (DIR_FILLER(filler, buf, cpu, NULL, 0) != 0)
			return -ENOENT;
	}

	dir = opendir(path);
	if (!dir)
		return -ENOENT;

	while ((dirent = readdir(dir))) {
		char *entry = dirent->d_name;

		if (strlen(entry) <= 3)
			continue;
		entry += 3;

		/* Don't emit entries we already filtered above. */
		if (isdigit(*entry))
			continue;

		if (DIR_FILLER(filler, buf, dirent->d_name, NULL, 0) != 0)
			return -ENOENT;
	}

	return 0;
}

static int get_st_mode(const char *path, mode_t *mode)
{
	struct stat sb;
	int ret;

	ret = lstat(path, &sb);
	if (ret < 0)
		return -ENOENT;

	*mode = sb.st_mode;
	return 0;
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

static int sys_getattr_legacy(const char *path, struct stat *sb)
{
	struct timespec now;

	memset(sb, 0, sizeof(struct stat));
	if (clock_gettime(CLOCK_REALTIME, &now) < 0)
		return -EINVAL;

	sb->st_uid = sb->st_gid = 0;
	sb->st_atim = sb->st_mtim = sb->st_ctim = now;
	if (strcmp(path, "/sys") == 0) {
		sb->st_mode = S_IFDIR | 00555;
		sb->st_nlink = 2;
		return 0;
	}

	if (strcmp(path, "/sys/devices") == 0) {
		sb->st_mode = S_IFDIR | 00555;
		sb->st_nlink = 2;
		return 0;
	}

	if (strcmp(path, "/sys/devices/system") == 0) {
		sb->st_mode = S_IFDIR | 00555;
		sb->st_nlink = 2;
		return 0;
	}

	if (strcmp(path, "/sys/devices/system/cpu") == 0) {
		sb->st_mode = S_IFDIR | 00555;
		sb->st_nlink = 2;
		return 0;
	}

	if (strcmp(path, "/sys/devices/system/cpu/online") == 0) {
		sb->st_size = get_sysfile_size (path);
		sb->st_mode = S_IFREG | 00444;
		sb->st_nlink = 1;
		return 0;
	}

	return -ENOENT;
}

__lxcfs_fuse_ops int sys_getattr(const char *path, struct stat *sb)
{
	int ret;
	struct timespec now;
	mode_t st_mode;

	if (!liblxcfs_functional())
		return -EIO;

	if (!liblxcfs_can_use_sys_cpu())
		return sys_getattr_legacy(path, sb);

	memset(sb, 0, sizeof(struct stat));
	if (clock_gettime(CLOCK_REALTIME, &now) < 0)
		return -EINVAL;

	sb->st_uid = sb->st_gid = 0;
	sb->st_atim = sb->st_mtim = sb->st_ctim = now;

	ret = get_st_mode(path, &st_mode);
	if (ret)
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

__lxcfs_fuse_ops int sys_write(const char *path, const char *buf, size_t size,
			       off_t offset, struct fuse_file_info *fi)
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

static int sys_readdir_legacy(const char *path, void *buf, fuse_fill_dir_t filler,
			      off_t offset, struct fuse_file_info *fi)
{
	if (strcmp(path, "/sys") == 0) {
		if (DIR_FILLER(filler, buf, ".",	NULL, 0) != 0 ||
		    DIR_FILLER(filler, buf, "..",	NULL, 0) != 0 ||
		    DIR_FILLER(filler, buf, "devices",	NULL, 0) != 0)
			return -ENOENT;

		return 0;
	}
	if (strcmp(path, "/sys/devices") == 0) {
		if (DIR_FILLER(filler, buf, ".",	NULL, 0) != 0 ||
		    DIR_FILLER(filler, buf, "..",	NULL, 0) != 0 ||
		    DIR_FILLER(filler, buf, "system",	NULL, 0) != 0)
			return -ENOENT;

		return 0;
	}
	if (strcmp(path, "/sys/devices/system") == 0) {
		if (DIR_FILLER(filler, buf, ".",	NULL, 0) != 0 ||
		    DIR_FILLER(filler, buf, "..",	NULL, 0) != 0 ||
		    DIR_FILLER(filler, buf, "cpu",	NULL, 0) != 0)
			return -ENOENT;

		return 0;
	}
	if (strcmp(path, "/sys/devices/system/cpu") == 0) {
		if (DIR_FILLER(filler, buf, ".",	NULL, 0) != 0 ||
		    DIR_FILLER(filler, buf, "..",	NULL, 0) != 0 ||
		    DIR_FILLER(filler, buf, "online",	NULL, 0) != 0)
			return -ENOENT;

		return 0;
	}

	return 0;
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

	if (!liblxcfs_can_use_sys_cpu())
		return sys_readdir_legacy(path, buf, filler, offset, fi);

	/*
	 * When we reload LXCFS and we don't load the lxcfs binary itself
	 * changes to such functions as lxcfs_opendir() aren't reflected so
	 * sys_opendir() doesn't run but sys_readdir() does. We need to account
	 * for that here.
	 */
	if (!f)
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
		if (DIR_FILLER(filler, buf, ".", NULL, 0) != 0 ||
		    DIR_FILLER(filler, buf, "..", NULL, 0) != 0)
			return -ENOENT;

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
	ssize_t ret;

	if (!liblxcfs_functional())
		return -EIO;

	ret = readlink(path, buf, size);
	if (ret < 0)
		return -errno;

	if ((size_t)ret > size)
		return -1;

	buf[ret] = '\0';

	return 0;
}

static int sys_open_legacy(const char *path, struct fuse_file_info *fi)
{
	__do_free struct file_info *info = NULL;
	int type = -1;

	if (strcmp(path, "/sys/devices") == 0)
		type = LXC_TYPE_SYS_DEVICES;
	if (strcmp(path, "/sys/devices/system") == 0)
		type = LXC_TYPE_SYS_DEVICES_SYSTEM;
	if (strcmp(path, "/sys/devices/system/cpu") == 0)
		type = LXC_TYPE_SYS_DEVICES_SYSTEM_CPU;
	if (strcmp(path, "/sys/devices/system/cpu/online") == 0)
		type = LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_ONLINE;
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

__lxcfs_fuse_ops int sys_open(const char *path, struct fuse_file_info *fi)
{
	__do_free struct file_info *info = NULL;
	int type = -1;

	if (!liblxcfs_functional())
		return -EIO;

	if (!liblxcfs_can_use_sys_cpu())
		return sys_open_legacy(path, fi);

	if (strcmp(path, "/sys/devices/system/cpu/online") == 0) {
		type = LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_ONLINE;
	} else if (strncmp(path, "/sys/devices/system/cpu/",
			   STRLITERALLEN("/sys/devices/system/cpu/")) == 0) {
		int ret;
		mode_t st_mode;

		ret = get_st_mode(path, &st_mode);
		if (ret)
			return ret;

		if (S_ISREG(st_mode))
			type = LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_SUBFILE;
	}
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

	if (strcmp(path, "/sys") == 0) {
		type = LXC_TYPE_SYS;
	} else if (strcmp(path, "/sys/devices") == 0) {
		type = LXC_TYPE_SYS_DEVICES;
	} else if (strcmp(path, "/sys/devices/system") == 0) {
		type = LXC_TYPE_SYS_DEVICES_SYSTEM;
	} else if (strcmp(path, "/sys/devices/system/cpu") == 0) {
		type = LXC_TYPE_SYS_DEVICES_SYSTEM_CPU;
	} else if (strncmp(path, "/sys/devices/system/cpu/",
			   STRLITERALLEN("/sys/devices/system/cpu/")) == 0) {
		int ret;
		mode_t st_mode;

		ret = get_st_mode(path, &st_mode);
		if (ret)
			return ret;

		if (S_ISDIR(st_mode))
			type = LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_SUBDIR;
	}
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

static int sys_access_legacy(const char *path, int mask)
{
	if (strcmp(path, "/sys") == 0 && access(path, R_OK) == 0)
		return 0;

	if (strcmp(path, "/sys/devices") == 0 && access(path, R_OK) == 0)
		return 0;

	if (strcmp(path, "/sys/devices/system") == 0 && access(path, R_OK) == 0)
		return 0;

	if (strcmp(path, "/sys/devices/system/cpu") == 0 &&
	    access(path, R_OK) == 0)
		return 0;

	/* these are all read-only */
	if ((mask & ~R_OK) != 0)
		return -EACCES;

	return 0;
}

__lxcfs_fuse_ops int sys_access(const char *path, int mask)
{
	if (!liblxcfs_functional())
		return -EIO;

	if (!liblxcfs_can_use_sys_cpu())
		return sys_access_legacy(path, mask);

	return access(path, mask);
}

static int sys_read_legacy(const char *path, char *buf, size_t size,
			   off_t offset, struct fuse_file_info *fi)
{
	struct file_info *f = INTTYPE_TO_PTR(fi->fh);

	switch (f->type) {
	case LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_ONLINE:
		if (liblxcfs_functional())
			return sys_devices_system_cpu_online_read(buf, size, offset, fi);

		return read_file_fuse_with_offset(LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_ONLINE_PATH,
						  buf, size, offset, f);
	case LXC_TYPE_SYS_DEVICES:
		break;
	case LXC_TYPE_SYS_DEVICES_SYSTEM:
		break;
	case LXC_TYPE_SYS_DEVICES_SYSTEM_CPU:
		break;
	}

	return -EINVAL;
}

__lxcfs_fuse_ops int sys_read(const char *path, char *buf, size_t size,
			      off_t offset, struct fuse_file_info *fi)
{
	struct file_info *f = INTTYPE_TO_PTR(fi->fh);

	if (!liblxcfs_functional())
		return -EIO;

	if (!liblxcfs_can_use_sys_cpu())
		return sys_read_legacy(path, buf, size, offset, fi);

	switch (f->type) {
	case LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_ONLINE:
		return sys_devices_system_cpu_online_read(buf, size, offset, fi);
	case LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_SUBFILE:
		return read_file_fuse_with_offset(path, buf, size, offset, f);
	}

	return -EINVAL;
}
