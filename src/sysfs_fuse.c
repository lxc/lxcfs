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

static off_t get_sysfile_size(const char *which);
static int do_cpuset_read(char *cg, char *cpu_cg, char *buf, size_t buflen)
{
        __do_free char *cpuset = NULL;
        struct fuse_context *fc = fuse_get_context();
        struct lxcfs_opts *opts = (struct lxcfs_opts *)fc->private_data;
        int max_cpus = 0;
        ssize_t total_len = 0;
        bool use_view;

        cpuset = get_cpuset(cg);
        if (!cpuset)
                return 0;

        if (cgroup_ops->can_use_cpuview(cgroup_ops) && opts && opts->use_cfs)
                use_view = true;
        else
                use_view = false;

        if (use_view)
                max_cpus = max_cpu_count(cg, cpu_cg, lxcfs_has_opt(opts, LXCFS_RECURSIVE));

        if (use_view) {
                if (max_cpus > 1)
                        total_len = snprintf(buf, buflen, "0-%d\n", max_cpus - 1);
                else
                        total_len = snprintf(buf, buflen, "0\n");
        } else {
                total_len = snprintf(buf, buflen, "%s\n", cpuset);
        }
        if (total_len < 0 || (size_t)total_len >= buflen)
                return log_error(0, "Failed to write to cache");

        return total_len;
}

static int sys_devices_system_cpu_online_read(char *buf, size_t size,
					      off_t offset,
					      struct fuse_file_info *fi)
{
	__do_free char *cg = NULL, *cpu_cg = NULL;
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = INTTYPE_TO_PTR(fi->fh);
	char *cache = d->buf;
	pid_t initpid;
	ssize_t total_len = 0;

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
	cpu_cg = get_pid_cgroup(initpid, "cpu");
	if (!cpu_cg)
		return read_file_fuse("/sys/devices/system/cpu/online", buf, size, d);
	prune_init_slice(cpu_cg);
	total_len = do_cpuset_read(cg, cpu_cg, d->buf, d->buflen);

	d->size = (int)total_len;
	d->cached = 1;

	if ((size_t)total_len > size)
		total_len = size;

	memcpy(buf, d->buf, total_len);

	return total_len;
}

static int sys_devices_system_cpu_online_getsize(const char *path)
{
        __do_free char *cg = NULL, *cpu_cg = NULL;
        struct fuse_context *fc = fuse_get_context();
        pid_t initpid;
        char buf[BUF_RESERVE_SIZE];
        int buflen = sizeof(buf);

        initpid = lookup_initpid_in_store(fc->pid);
        if (initpid <= 1 || is_shared_pidns(initpid))
                initpid = fc->pid;

        cg = get_pid_cgroup(initpid, "cpuset");
        if (!cg)
                return get_sysfile_size(path);
        cpu_cg = get_pid_cgroup(initpid, "cpu");
        if (!cpu_cg)
                return get_sysfile_size(path);
        prune_init_slice(cg);
        prune_init_slice(cpu_cg);

        return do_cpuset_read(cg, cpu_cg, buf, buflen);
}

static int filler_sys_devices_system_cpu(const char *path, void *buf,
					 fuse_fill_dir_t filler)
{
	__do_closedir DIR *dirp = NULL;
	struct dirent *dirent;

	dirp = opendir(path);
	if (!dirp)
		return -ENOENT;

	while ((dirent = readdir(dirp))) {
		if (dirent_fillerat(filler, dirp, dirent, buf, 0) != 0)
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
		sb->st_size = sys_devices_system_cpu_online_getsize(path);
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
                if (strcmp(path, "/sys/devices/system/cpu/online") == 0)
                        sb->st_size = sys_devices_system_cpu_online_getsize(path);
                else
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

	return -EACCES;
}

static int sys_readdir_legacy(const char *path, void *buf, fuse_fill_dir_t filler,
			      off_t offset, struct fuse_file_info *fi)
{
	if (strcmp(path, "/sys") == 0) {
		if (dir_filler(filler, buf, ".",	0) != 0 ||
		    dir_filler(filler, buf, "..",	0) != 0 ||
		    dirent_filler(filler, path, "devices", buf,  0) != 0)
			return -ENOENT;

		return 0;
	}
	if (strcmp(path, "/sys/devices") == 0) {
		if (dir_filler(filler, buf, ".",	0) != 0 ||
		    dir_filler(filler, buf, "..",	0) != 0 ||
		    dirent_filler(filler, path, "system", buf,  0) != 0)
			return -ENOENT;

		return 0;
	}
	if (strcmp(path, "/sys/devices/system") == 0) {
		if (dir_filler(filler, buf, ".",	0) != 0 ||
		    dir_filler(filler, buf, "..",	0) != 0 ||
		    dirent_filler(filler, path, "cpu", buf,  0) != 0)
			return -ENOENT;

		return 0;
	}
	if (strcmp(path, "/sys/devices/system/cpu") == 0) {
		if (dir_filler(filler, buf, ".",	0) != 0 ||
		    dir_filler(filler, buf, "..",	0) != 0 ||
		    dirent_filler(filler, path, "online", buf,  0) != 0)
			return -ENOENT;

		return 0;
	}

	return 0;
}

__lxcfs_fuse_ops int sys_readdir(const char *path, void *buf,
				 fuse_fill_dir_t filler, off_t offset,
				 struct fuse_file_info *fi)
{
	__do_closedir DIR *dirp = NULL;
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
	case LXC_TYPE_SYS:
		if (dir_filler(filler, buf, ".", 0) != 0 ||
		    dir_filler(filler, buf, "..", 0) != 0 ||
		    dirent_filler(filler, path, "devices", buf, 0) != 0)
			return -ENOENT;
		return 0;
	case LXC_TYPE_SYS_DEVICES:
		if (dir_filler(filler, buf, ".", 0) != 0 ||
		    dir_filler(filler, buf, "..", 0) != 0 ||
		    dirent_filler(filler, path, "system", buf, 0) != 0)
			return -ENOENT;
		return 0;
	case LXC_TYPE_SYS_DEVICES_SYSTEM:
		if (dir_filler(filler, buf, ".", 0) != 0 ||
		    dir_filler(filler, buf, "..", 0) != 0 ||
		    dirent_filler(filler, path, "cpu", buf, 0) != 0)
			return -ENOENT;
		return 0;
	case LXC_TYPE_SYS_DEVICES_SYSTEM_CPU:
		if (dir_filler(filler, buf, ".",	0) != 0 ||
		    dir_filler(filler, buf, "..",	0) != 0 ||
		    dirent_filler(filler, path, "online", buf,  0) != 0)
			return -ENOENT;
		return filler_sys_devices_system_cpu(path, buf, filler);
	case LXC_TYPE_SYS_DEVICES_SYSTEM_CPU_SUBDIR:
		dirp = opendir_flags(path, O_CLOEXEC | O_NOFOLLOW);
		if (!dirp)
			return -errno;

		while ((dirent = readdir(dirp))) {
			if (dirent_fillerat(filler, dirp, dirent, buf, 0) != 0)
				return -ENOENT;
		}
		return 0;
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
