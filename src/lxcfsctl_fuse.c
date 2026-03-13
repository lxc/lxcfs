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
#include <sys/capability.h>
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

typedef struct lxcfsctl_dentry_data {
	int type;
	pid_t initpid;
	int feature;
} lxcfsctl_dentry_data_t;

static int lxcfsctl_get_dentry_type(const char *path, lxcfsctl_dentry_data_t *data)
{
	struct fuse_context *fc = fuse_get_context();

	memset(data, 0, sizeof(*data));

	if (strcmp(path, "/lxcfs") == 0) {
		data->type = LXC_TYPE_LXCFS;

		return 0;
	} else if (strcmp(path, "/lxcfs/pidns") == 0) {
		data->type = LXC_TYPE_LXCFS_PIDNS_SUBDIR;

		return 0;
	} else if (strncmp(path, "/lxcfs/pidns/", STRLITERALLEN("/lxcfs/pidns/")) == 0) {
		unsigned int pid;
		char subpathbuf[101] = { 0 };
		const char *subpath;

		if (strncmp(path, "/lxcfs/pidns/current", STRLITERALLEN("/lxcfs/pidns/current")) == 0) {
			pid = fc->pid;
			subpath = path + STRLITERALLEN("/lxcfs/pidns/current");
		} else {
			int i;

			/* this path is only allowed for host admin */
			if (!proc_has_capability_in(getpid(), fc->pid, CAP_SYS_ADMIN))
				return -ENOENT;

			i = sscanf(path, "/lxcfs/pidns/%u%100s", &pid, subpathbuf);
			if (i < 1)
				return -ENOENT;
			subpathbuf[sizeof(subpathbuf)-1] = '\0';
			subpath = subpathbuf;
		}

		if (lookup_initpid_in_store(pid) < 0)
			return -ENOENT;

		data->initpid = pid;

		if (strlen(subpath) == 0) {
			data->type = LXC_TYPE_LXCFS_PIDNS_PID_SUBDIR;

			return 0;
		} else if (strcmp(subpath, "/features") == 0) {
			data->type = LXC_TYPE_LXCFS_PIDNS_PID_FEATURES_SUBDIR;

			return 0;
		} else if (strncmp(subpath, "/features/", STRLITERALLEN("/features/")) == 0) {
			const char *feature = subpath + STRLITERALLEN("/features/");

			for (int i = 0; per_instance_features[i].name; i++) {
				if (strcmp(per_instance_features[i].name, feature) == 0) {
					data->type = LXC_TYPE_LXCFS_PIDNS_PID_FEATURES_F_SUBFILE;
					data->feature = i;
					return 0;
				}
			}

			return -ENOENT;
		}
	}

	return -ENOENT;
}

__lxcfs_fuse_ops int lxcfsctl_getattr(const char *path, struct stat *sb)
{
	lxcfsctl_dentry_data_t d_data;
	struct timespec now;

	memset(sb, 0, sizeof(struct stat));
	if (clock_gettime(CLOCK_REALTIME, &now) < 0)
		return -EINVAL;

	sb->st_uid = sb->st_gid = 0;
	sb->st_atim = sb->st_mtim = sb->st_ctim = now;

	if (lxcfsctl_get_dentry_type(path, &d_data))
		return -ENOENT;

	switch (d_data.type) {
	case LXC_TYPE_LXCFS:
	case LXC_TYPE_LXCFS_PIDNS_SUBDIR:
	case LXC_TYPE_LXCFS_PIDNS_PID_SUBDIR:
	case LXC_TYPE_LXCFS_PIDNS_CURPID_SUBDIR:
	case LXC_TYPE_LXCFS_PIDNS_PID_FEATURES_SUBDIR:
		sb->st_mode = S_IFDIR | 00555;
		sb->st_nlink = 2;

		return 0;
	case LXC_TYPE_LXCFS_PIDNS_PID_FEATURES_F_SUBFILE:
		sb->st_size = 1;

		sb->st_mode = S_IFREG | 00444;
		sb->st_nlink = 1;
		return 0;
	}

	return -ENOENT;
}

static int lxcfs_features_dir_filler(fuse_fill_dir_t filler, void *buf)
{
	for (int i = 0; per_instance_features[i].name; i++) {
		if (dir_filler(filler, buf, per_instance_features[i].name, 0) != 0)
			return -ENOENT;
	}

	return 0;
}

struct pidns_iter_filler_args {
	fuse_fill_dir_t filler;
	void *buf;
};

int features_dir_filler(struct pidns_store *cur, void *data)
{
	struct pidns_iter_filler_args *args = data;
	char dname[INTTYPE_TO_STRLEN(typeof(cur->initpid))];

	snprintf(dname, sizeof(dname), "%d", cur->initpid);

	if (dir_filler(args->filler, args->buf, dname, 0) != 0)
		return -ENOENT;

	return 0;
}

static int lxcfs_pidns_dir_filler(fuse_fill_dir_t filler, void *buf)
{
	struct pidns_iter_filler_args args = {
		.filler = filler,
		.buf = buf,
	};

	return iter_initpid_store(features_dir_filler, &args);
}

__lxcfs_fuse_ops int lxcfsctl_readdir(const char *path, void *buf,
				      fuse_fill_dir_t filler, off_t offset,
				      struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	struct file_info *f = INTTYPE_TO_PTR(fi->fh);

	if (!liblxcfs_functional())
		return -EIO;

	if (!f)
		return -EIO;

	switch (f->type) {
	case LXC_TYPE_LXCFS:
		if (dir_filler(filler, buf, ".", 0) != 0 ||
		    dir_filler(filler, buf, "..", 0) != 0 ||
		    dir_filler(filler, buf, "pidns", 0) != 0)
			return -ENOENT;
		return 0;
	case LXC_TYPE_LXCFS_PIDNS_SUBDIR:
		if (dir_filler(filler, buf, ".",	0) != 0 ||
		    dir_filler(filler, buf, "..",	0) != 0 ||
		    dir_filler(filler, buf, "current", 0) != 0)
			return -ENOENT;

		/* show all pid namespaces for the host admin */
		if (proc_has_capability_in(getpid(), fc->pid, CAP_SYS_ADMIN) &&
		    lxcfs_pidns_dir_filler(filler, buf))
			return -ENOENT;

		return 0;
	case LXC_TYPE_LXCFS_PIDNS_PID_SUBDIR:
	case LXC_TYPE_LXCFS_PIDNS_CURPID_SUBDIR:
		if (dir_filler(filler, buf, ".",	0) != 0 ||
		    dir_filler(filler, buf, "..",	0) != 0 ||
		    dir_filler(filler, buf, "features", 0) != 0)
			return -ENOENT;
		return 0;
	case LXC_TYPE_LXCFS_PIDNS_PID_FEATURES_SUBDIR:
		if (dir_filler(filler, buf, ".",	0) != 0 ||
		    dir_filler(filler, buf, "..",	0) != 0)
			return -ENOENT;
		return lxcfs_features_dir_filler(filler, buf);
	}

	return -EINVAL;
}

typedef struct lxcfsctl_file_data {
	/* increase version if the structure was changed */
	__u16 version;

	pid_t initpid;
	int feature;
} lxcfsctl_file_data_t;

__lxcfs_fuse_ops int lxcfsctl_open(const char *path, struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	__do_free struct file_info *info = NULL;
	int type = -1;
	__do_free lxcfsctl_file_data_t *private_data = NULL;
	lxcfsctl_dentry_data_t d_data;

	if (!liblxcfs_functional())
		return -EIO;

	if (lxcfsctl_get_dentry_type(path, &d_data))
		return -ENOENT;

	if (!proc_has_capability_in(d_data.initpid, fc->pid, CAP_SYS_ADMIN) &&
	    !proc_has_capability_in(getpid(), fc->pid, CAP_SYS_ADMIN))
		return -EACCES;

	type = d_data.type;
	if (type == -1)
		return -ENOENT;

	private_data = zalloc(sizeof(*private_data));
	if (!private_data)
		return -EIO;

	private_data->version = 1;
	private_data->initpid = d_data.initpid;
	private_data->feature = d_data.feature;

	info = zalloc(sizeof(*info));
	if (!info)
		return -ENOMEM;

	info->type = type;
	info->buflen = BUF_RESERVE_SIZE;

	info->buf = malloc(info->buflen);
	if (!info->buf)
		return -ENOMEM;

	memset(info->buf, 0, info->buflen);
	/* set actual size to buffer size */
	info->size = info->buflen;

	info->private_data = move_ptr(private_data);

	fi->fh = PTR_TO_UINT64(move_ptr(info));
	return 0;
}

__lxcfs_fuse_ops int lxcfsctl_release(const char *path, struct fuse_file_info *fi)
{
	struct file_info *f;

	f = INTTYPE_TO_PTR(fi->fh);
	if (!f)
		return 0;

	/* free lxcfsctl_file_data_t */
	free_disarm(f->private_data);

	do_release_file_info(fi);
	return 0;
}

__lxcfs_fuse_ops int lxcfsctl_opendir(const char *path, struct fuse_file_info *fi)
{
	__do_free struct file_info *dir_info = NULL;
	int type = -1;
	lxcfsctl_dentry_data_t d_data;

	if (!liblxcfs_functional())
		return -EIO;

	if (lxcfsctl_get_dentry_type(path, &d_data))
		return -ENOENT;

	type = d_data.type;

	if (type == -1)
		return -ENOENT;

	dir_info = zalloc(sizeof(*dir_info));
	if (!dir_info)
		return -ENOMEM;

	dir_info->type = type;
	dir_info->buf = NULL;
	dir_info->file = NULL;
	dir_info->buflen = 0;

	fi->fh = PTR_TO_UINT64(move_ptr(dir_info));
	return 0;
}

__lxcfs_fuse_ops int lxcfsctl_releasedir(const char *path, struct fuse_file_info *fi)
{
	do_release_file_info(fi);
	return 0;
}

static int lxcfsctl_read_feature(char *buf, size_t size, off_t offset,
				 struct fuse_file_info *fi)
{
	struct file_info *d = INTTYPE_TO_PTR(fi->fh);
	char *cache = d->buf;
	ssize_t total_len = 0, ret = 0;
	lxcfsctl_dentry_data_t *d_data = d->private_data;
	bool state;

	if (offset) {
		size_t left;

		if (offset > d->size)
			return -EINVAL;

		if (!d->cached)
			return 0;

		left = d->size - offset;
		total_len = left > size ? size : left;
		memcpy(buf, cache + offset, total_len);

		return total_len;
	}

	state = check_set_lxcfs_feature(d_data->initpid, LXCFS_FEATURE_CHECK, (1 << d_data->feature));

	ret = snprintf(d->buf, d->buflen, "%d\n", state);
	if (ret < 0 || ret >= d->buflen)
		return -EIO;
	total_len = ret;

	d->cached = 1;
	d->size = total_len;
	if ((size_t)total_len > size)
		total_len = size;
	memcpy(buf, d->buf, total_len);

	return total_len;
}

static int lxcfsctl_write_feature(const char *buf, size_t size,
				  off_t offset, struct fuse_file_info *fi)
{
	struct file_info *f = INTTYPE_TO_PTR(fi->fh);
	lxcfsctl_dentry_data_t *d_data;

	if (!size)
		return -EINVAL;

	if (!liblxcfs_functional())
		return -EIO;

	if (!f)
		return -EIO;

	if (f->type != LXC_TYPE_LXCFS_PIDNS_PID_FEATURES_F_SUBFILE)
		return -EINVAL;

	d_data = f->private_data;
	if (!d_data)
		return -EIO;

	if (buf[0] == '0') {
		if (!check_set_lxcfs_feature(d_data->initpid, LXCFS_FEATURE_CLEAR, (1 << d_data->feature)))
			return -EIO;

		return size;
	} else if (buf[0] == '1') {
		if (!check_set_lxcfs_feature(d_data->initpid, LXCFS_FEATURE_SET, (1 << d_data->feature)))
			return -EIO;

		return size;
	}

	return -EINVAL;
}

__lxcfs_fuse_ops int lxcfsctl_write(const char *path, char *buf, size_t size,
				    off_t offset, struct fuse_file_info *fi)
{
	struct file_info *f = INTTYPE_TO_PTR(fi->fh);

	if (!size)
		return -EINVAL;

	if (!liblxcfs_functional())
		return -EIO;

	if (!f)
		return -EIO;

	switch (f->type) {
	case LXC_TYPE_LXCFS_PIDNS_PID_FEATURES_F_SUBFILE:
		return lxcfsctl_write_feature(buf, size, offset, fi);
	}

	return -EOPNOTSUPP;
}

__lxcfs_fuse_ops int lxcfsctl_read(const char *path, char *buf, size_t size,
				   off_t offset, struct fuse_file_info *fi)
{
	struct file_info *f = INTTYPE_TO_PTR(fi->fh);

	if (!liblxcfs_functional())
		return -EIO;

	if (!f)
		return -EIO;

	switch (f->type) {
	case LXC_TYPE_LXCFS_PIDNS_PID_FEATURES_F_SUBFILE:
		return lxcfsctl_read_feature(buf, size, offset, fi);
	}

	return -EOPNOTSUPP;
}

__lxcfs_fuse_ops int lxcfsctl_access(const char *path, int mask)
{
	return -EOPNOTSUPP;
}

__lxcfs_fuse_ops int lxcfsctl_readlink(const char *path, char *buf, size_t size)
{
	return -EOPNOTSUPP;
}
