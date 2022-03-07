/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
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

#include "proc_fuse.h"

#include "bindings.h"
#include "cgroup_fuse.h"
#include "cgroups/cgroup.h"
#include "cgroups/cgroup_utils.h"
#include "cpuset_parse.h"
#include "lxcfs_fuse_compat.h"
#include "memory_utils.h"
#include "proc_loadavg.h"
#include "proc_cpuview.h"
#include "utils.h"

struct memory_stat {
	uint64_t hierarchical_memory_limit;
	uint64_t hierarchical_memsw_limit;
	uint64_t total_cache;
	uint64_t total_rss;
	uint64_t total_rss_huge;
	uint64_t total_shmem;
	uint64_t total_mapped_file;
	uint64_t total_dirty;
	uint64_t total_writeback;
	uint64_t total_swap;
	uint64_t total_pgpgin;
	uint64_t total_pgpgout;
	uint64_t total_pgfault;
	uint64_t total_pgmajfault;
	uint64_t total_inactive_anon;
	uint64_t total_active_anon;
	uint64_t total_inactive_file;
	uint64_t total_active_file;
	uint64_t total_unevictable;
};

static off_t get_procfile_size(const char *path)
{
	__do_fclose FILE *f = NULL;
	__do_free char *line = NULL;
	size_t len = 0;
	ssize_t sz, answer = 0;

	f = fopen(path, "re");
	if (!f)
		return 0;

	while ((sz = getline(&line, &len, f)) != -1)
		answer += sz;

	return answer;
}

__lxcfs_fuse_ops int proc_getattr(const char *path, struct stat *sb)
{
	struct timespec now;

	memset(sb, 0, sizeof(struct stat));
	if (clock_gettime(CLOCK_REALTIME, &now) < 0)
		return -EINVAL;

	sb->st_uid = sb->st_gid = 0;
	sb->st_atim = sb->st_mtim = sb->st_ctim = now;
	if (strcmp(path, "/proc") == 0) {
		sb->st_mode = S_IFDIR | 00555;
		sb->st_nlink = 2;
		return 0;
	}

	if (strcmp(path, "/proc/meminfo")	== 0 ||
	    strcmp(path, "/proc/cpuinfo")	== 0 ||
	    strcmp(path, "/proc/uptime")	== 0 ||
	    strcmp(path, "/proc/stat")		== 0 ||
	    strcmp(path, "/proc/diskstats")	== 0 ||
	    strcmp(path, "/proc/swaps")		== 0 ||
	    strcmp(path, "/proc/loadavg")	== 0 ||
	    strcmp(path, "/proc/slabinfo")	== 0) {
		sb->st_size = get_procfile_size(path);
		sb->st_mode = S_IFREG | 00444;
		sb->st_nlink = 1;
		return 0;
	}

	return -ENOENT;
}

__lxcfs_fuse_ops int proc_readdir(const char *path, void *buf,
				  fuse_fill_dir_t filler, off_t offset,
				  struct fuse_file_info *fi)
{
	if (DIR_FILLER(filler, buf, ".",		NULL, 0) != 0 ||
	    DIR_FILLER(filler, buf, "..",		NULL, 0) != 0 ||
	    DIR_FILLER(filler, buf, "cpuinfo",	NULL, 0) != 0 ||
	    DIR_FILLER(filler, buf, "meminfo",	NULL, 0) != 0 ||
	    DIR_FILLER(filler, buf, "stat",		NULL, 0) != 0 ||
	    DIR_FILLER(filler, buf, "uptime",	NULL, 0) != 0 ||
	    DIR_FILLER(filler, buf, "diskstats",	NULL, 0) != 0 ||
	    DIR_FILLER(filler, buf, "swaps",	NULL, 0) != 0 ||
	    DIR_FILLER(filler, buf, "loadavg",	NULL, 0) != 0 ||
	    DIR_FILLER(filler, buf, "slabinfo",	NULL, 0) != 0)
		return -EINVAL;

	return 0;
}

__lxcfs_fuse_ops int proc_open(const char *path, struct fuse_file_info *fi)
{
	__do_free struct file_info *info = NULL;
	int type = -1;

	if (strcmp(path, "/proc/meminfo") == 0)
		type = LXC_TYPE_PROC_MEMINFO;
	else if (strcmp(path, "/proc/cpuinfo") == 0)
		type = LXC_TYPE_PROC_CPUINFO;
	else if (strcmp(path, "/proc/uptime") == 0)
		type = LXC_TYPE_PROC_UPTIME;
	else if (strcmp(path, "/proc/stat") == 0)
		type = LXC_TYPE_PROC_STAT;
	else if (strcmp(path, "/proc/diskstats") == 0)
		type = LXC_TYPE_PROC_DISKSTATS;
	else if (strcmp(path, "/proc/swaps") == 0)
		type = LXC_TYPE_PROC_SWAPS;
	else if (strcmp(path, "/proc/loadavg") == 0)
		type = LXC_TYPE_PROC_LOADAVG;
	else if (strcmp(path, "/proc/slabinfo") == 0)
		type = LXC_TYPE_PROC_SLABINFO;
	if (type == -1)
		return -ENOENT;

	info = zalloc(sizeof(*info));
	if (!info)
		return -ENOMEM;

	info->type = type;

	info->buflen = get_procfile_size(path) + BUF_RESERVE_SIZE;

	info->buf = zalloc(info->buflen);
	if (!info->buf)
		return -ENOMEM;
	/* set actual size to buffer size */
	info->size = info->buflen;

	fi->fh = PTR_TO_UINT64(move_ptr(info));
	return 0;
}

__lxcfs_fuse_ops int proc_access(const char *path, int mask)
{
	if (strcmp(path, "/proc") == 0 && access(path, R_OK) == 0)
		return 0;

	/* these are all read-only */
	if ((mask & ~R_OK) != 0)
		return -EACCES;

	return 0;
}

__lxcfs_fuse_ops int proc_release(const char *path, struct fuse_file_info *fi)
{
	do_release_file_info(fi);
	return 0;
}

static uint64_t get_memlimit(const char *cgroup, bool swap)
{
	__do_free char *memlimit_str = NULL;
	uint64_t memlimit = 0;
	int ret;

	if (swap)
		ret = cgroup_ops->get_memory_swap_max(cgroup_ops, cgroup, &memlimit_str);
	else
		ret = cgroup_ops->get_memory_max(cgroup_ops, cgroup, &memlimit_str);
	if (ret > 0 && memlimit_str[0] && safe_uint64(memlimit_str, &memlimit, 10) < 0)
		lxcfs_error("Failed to convert memory%s.max=%s for cgroup %s",
			    swap ? ".swap" : "", memlimit_str, cgroup);

	return memlimit;
}

/*
 * This function taken from glibc-2.32, as POSIX dirname("/some-dir") will
 * return "/some-dir" as opposed to "/", which breaks `get_min_memlimit()`
 */
static char *gnu_dirname(char *path)
{
	static const char dot[] = ".";
	char *last_slash;

	/* Find last '/'.  */
	last_slash = path != NULL ? strrchr(path, '/') : NULL;

	if (last_slash != NULL && last_slash != path && last_slash[1] == '\0') {
		/* Determine whether all remaining characters are slashes.  */
		char *runp;

		for (runp = last_slash; runp != path; --runp)
			if (runp[-1] != '/')
				break;

		/* The '/' is the last character, we have to look further.  */
		if (runp != path)
			last_slash = memrchr(path, '/', runp - path);
	}

	if (last_slash != NULL) {
		/* Determine whether all remaining characters are slashes.  */
		char *runp;

		for (runp = last_slash; runp != path; --runp)
			if (runp[-1] != '/')
				break;

		/* Terminate the path.  */
		if (runp == path) {
			/*
			 * The last slash is the first character in the string.
			 * We have to return "/".  As a special case we have to
			 * return "//" if there are exactly two slashes at the
			 * beginning of the string.  See XBD 4.10 Path Name
			 * Resolution for more information
			 */
			if (last_slash == path + 1)
				++last_slash;
			else
				last_slash = path + 1;
		} else
			last_slash = runp;

		last_slash[0] = '\0';
	} else {
		/*
		 * This assignment is ill-designed but the XPG specs require to
		 * return a string containing "." in any case no directory part
		 * is found and so a static and constant string is required.
		 */
		path = (char *)dot;
	}

	return path;
}

static uint64_t get_min_memlimit(const char *cgroup, bool swap)
{
	__do_free char *copy = NULL;
	uint64_t memlimit = 0, retlimit = 0;

	copy = strdup(cgroup);
	if (!copy)
		return log_error_errno(0, ENOMEM, "Failed to allocate memory");

	retlimit = get_memlimit(copy, swap);

	/*
	 * If the cgroup doesn't start with / (probably won't happen), dirname()
	 * will terminate with "" instead of "/"
	 */
	while (*copy && strcmp(copy, "/") != 0) {
		char *it = copy;

		it = gnu_dirname(it);
		memlimit = get_memlimit(it, swap);
		if (memlimit > 0 && memlimit < retlimit)
			retlimit = memlimit;
	};

	return retlimit;
}

static inline bool startswith(const char *line, const char *pref)
{
	return strncmp(line, pref, strlen(pref)) == 0;
}

static void get_swap_info(const char *cgroup, uint64_t memlimit,
			  uint64_t memusage, uint64_t *swtotal,
			  uint64_t *swusage, uint64_t *memswpriority)
{
	__do_free char *memswusage_str = NULL, *memswpriority_str = NULL;
	uint64_t memswlimit = 0, memswusage = 0;
	int ret;

	*swtotal = *swusage = 0;
	*memswpriority = 1;

	memswlimit = get_min_memlimit(cgroup, true);
	if (memswlimit > 0) {
		ret = cgroup_ops->get_memory_swap_current(cgroup_ops, cgroup, &memswusage_str);
		if (ret < 0 || safe_uint64(memswusage_str, &memswusage, 10) != 0)
			return;

		if (liblxcfs_memory_is_cgroupv2()) {
			*swtotal = memswlimit / 1024;
			*swusage = memswusage / 1024;
		} else {
			if (memlimit > memswlimit)
				*swtotal = 0;
			else
				*swtotal = (memswlimit - memlimit) / 1024;
			if (memusage > memswusage || swtotal == 0)
				*swusage = 0;
			else
				*swusage = (memswusage - memusage) / 1024;
		}

		ret = cgroup_ops->get_memory_swappiness(cgroup_ops, cgroup, &memswpriority_str);
		if (ret >= 0)
			safe_uint64(memswpriority_str, memswpriority, 10);
	}
}

static int proc_swaps_read(char *buf, size_t size, off_t offset,
			   struct fuse_file_info *fi)
{
	__do_free char *cgroup = NULL, *memusage_str = NULL,
		 *memswusage_str = NULL, *memswpriority_str = NULL;
	struct fuse_context *fc = fuse_get_context();
	bool wants_swap = lxcfs_has_opt(fuse_get_context()->private_data, LXCFS_SWAP_ON);
	struct file_info *d = INTTYPE_TO_PTR(fi->fh);
	uint64_t memlimit = 0, memusage = 0,
		 swtotal = 0, swusage = 0, memswpriority = 1,
		 hostswtotal = 0, hostswfree = 0;
	ssize_t total_len = 0;
	ssize_t l = 0;
	char *cache = d->buf;
	int ret;
	__do_free char *line = NULL;
	__do_free void *fopen_cache = NULL;
	__do_fclose FILE *f = NULL;
	size_t linelen = 0;

	if (offset) {
		size_t left;

		if (offset > d->size)
			return -EINVAL;

		if (!d->cached)
			return 0;

		left = d->size - offset;
		total_len = left > size ? size: left;
		memcpy(buf, cache + offset, total_len);

		return total_len;
	}

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;

	cgroup = get_pid_cgroup(initpid, "memory");
	if (!cgroup)
		return read_file_fuse("/proc/swaps", buf, size, d);
	prune_init_slice(cgroup);

	memlimit = get_min_memlimit(cgroup, false);

	ret = cgroup_ops->get_memory_current(cgroup_ops, cgroup, &memusage_str);
	if (ret < 0)
		return 0;

	if (safe_uint64(memusage_str, &memusage, 10) < 0)
		lxcfs_error("Failed to convert memusage %s", memusage_str);

	if (wants_swap)
		get_swap_info(cgroup, memlimit, memusage, &swtotal, &swusage, &memswpriority);

	total_len = snprintf(d->buf, d->size, "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n");

	/* Read host total and free values */
	f = fopen_cached("/proc/meminfo", "re", &fopen_cache);
	if (!f)
		return 0;

	while (getline(&line, &linelen, f) != -1) {
		if (startswith(line, "SwapTotal:"))
			sscanf(line, "SwapTotal:      %8" PRIu64 " kB", &hostswtotal);
		else if (startswith(line, "SwapFree:"))
			sscanf(line, "SwapFree:      %8" PRIu64 " kB", &hostswfree);
	}

	if (wants_swap) {
		/* The total amount of swap is always reported to be the
		   lesser of the RAM+SWAP limit or the SWAP device size.
		   This is because the kernel can swap as much as it
		   wants and not only up to swtotal. */
		swtotal = memlimit / 1024 + swtotal;
		if (hostswtotal < swtotal) {
			swtotal = hostswtotal;
		}

		/* When swappiness is 0, pretend we can't swap. */
		if (memswpriority == 0) {
			swtotal = swusage;
		}
	}

	if (swtotal > 0) {
		l = snprintf(d->buf + total_len, d->size - total_len,
			     "none%*svirtual\t\t%" PRIu64 "\t%" PRIu64 "\t0\n",
			     36, " ", swtotal, swusage);
		total_len += l;
	}

	if (total_len < 0 || l < 0)
		return log_error(0, "Failed writing to cache");

	d->cached = 1;
	d->size = (int)total_len;

	if ((size_t)total_len > size)
		total_len = size;
	memcpy(buf, d->buf, total_len);

	return total_len;
}

static void get_blkio_io_value(char *str, unsigned major, unsigned minor,
			       char *iotype, uint64_t *v)
{
	char *eol;
	char key[32];
	size_t len;

	memset(key, 0, 32);
	snprintf(key, 32, "%u:%u %s", major, minor, iotype);

	*v = 0;
	len = strlen(key);
	while (*str) {
		if (startswith(str, key)) {
			sscanf(str + len, "%" PRIu64, v);
			return;
		}
		eol = strchr(str, '\n');
		if (!eol)
			return;
		str = eol + 1;
	}
}

struct lxcfs_diskstats {
	unsigned int major;		/*  1 - major number */
	unsigned int minor;		/*  2 - minor mumber */
	char dev_name[72];		/*  3 - device name */
	uint64_t read;			/*  4 - reads completed successfully */
	uint64_t read_merged;		/*  5 - reads merged */
	uint64_t read_sectors;		/*  6 - sectors read */
	uint64_t read_ticks;		/*  7 - time spent reading (ms) */
	uint64_t write;			/*  8 - writes completed */
	uint64_t write_merged;		/*  9 - writes merged */
	uint64_t write_sectors; 	/* 10 - sectors written */
	uint64_t write_ticks;		/* 11 - time spent writing (ms) */
	uint64_t ios_pgr;		/* 12 - I/Os currently in progress */
	uint64_t total_ticks;		/* 13 - time spent doing I/Os (ms) */
	uint64_t rq_ticks;		/* 14 - weighted time spent doing I/Os (ms) */
	uint64_t discard;		/* 15 - discards completed successfully	(4.18+) */
	uint64_t discard_merged;	/* 16 - discards merged			(4.18+) */
	uint64_t discard_sectors;	/* 17 - sectors discarded		(4.18+) */
	uint64_t discard_ticks;		/* 18 - time spent discarding		(4.18+) */
};

static int proc_diskstats_read(char *buf, size_t size, off_t offset,
			       struct fuse_file_info *fi)
{
	__do_free char *cg = NULL, *io_serviced_str = NULL,
		       *io_merged_str = NULL, *io_service_bytes_str = NULL,
		       *io_wait_time_str = NULL, *io_service_time_str = NULL,
		       *line = NULL;
	__do_free void *fopen_cache = NULL;
	__do_fclose FILE *f = NULL;
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = INTTYPE_TO_PTR(fi->fh);
	struct lxcfs_diskstats stats = {};
	/* helper fields */
	uint64_t read_service_time, write_service_time, discard_service_time, read_wait_time,
	    write_wait_time, discard_wait_time;
	char *cache = d->buf;
	size_t cache_size = d->buflen;
	size_t linelen = 0, total_len = 0;
	int i = 0;
	int ret;

	if (offset) {
		size_t left;

		if (offset > d->size)
			return -EINVAL;

		if (!d->cached)
			return 0;

		left = d->size - offset;
		total_len = left > size ? size: left;
		memcpy(buf, cache + offset, total_len);

		return total_len;
	}

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;

	cg = get_pid_cgroup(initpid, "blkio");
	if (!cg)
		return read_file_fuse("/proc/diskstats", buf, size, d);
	prune_init_slice(cg);

	ret = cgroup_ops->get_io_serviced(cgroup_ops, cg, &io_serviced_str);
	if (ret < 0) {
		if (ret == -EOPNOTSUPP)
			return read_file_fuse("/proc/diskstats", buf, size, d);
	}

	ret = cgroup_ops->get_io_merged(cgroup_ops, cg, &io_merged_str);
	if (ret < 0) {
		if (ret == -EOPNOTSUPP)
			return read_file_fuse("/proc/diskstats", buf, size, d);
	}

	ret = cgroup_ops->get_io_service_bytes(cgroup_ops, cg, &io_service_bytes_str);
	if (ret < 0) {
		if (ret == -EOPNOTSUPP)
			return read_file_fuse("/proc/diskstats", buf, size, d);
	}

	ret = cgroup_ops->get_io_wait_time(cgroup_ops, cg, &io_wait_time_str);
	if (ret < 0) {
		if (ret == -EOPNOTSUPP)
			return read_file_fuse("/proc/diskstats", buf, size, d);
	}

	ret = cgroup_ops->get_io_service_time(cgroup_ops, cg, &io_service_time_str);
	if (ret < 0) {
		if (ret == -EOPNOTSUPP)
			return read_file_fuse("/proc/diskstats", buf, size, d);
	}

	f = fopen_cached("/proc/diskstats", "re", &fopen_cache);
	if (!f)
		return 0;

	while (getline(&line, &linelen, f) != -1) {
		ssize_t l;
		char lbuf[256];

		i = sscanf(line, "%u %u %71s", &stats.major, &stats.minor, stats.dev_name);
		if (i != 3)
			continue;

		get_blkio_io_value(io_serviced_str, stats.major, stats.minor, "Read", &stats.read);
		get_blkio_io_value(io_serviced_str, stats.major, stats.minor, "Write", &stats.write);
		get_blkio_io_value(io_serviced_str, stats.major, stats.minor, "Discard", &stats.discard);

		get_blkio_io_value(io_merged_str, stats.major, stats.minor, "Read", &stats.read_merged);
		get_blkio_io_value(io_merged_str, stats.major, stats.minor, "Write", &stats.write_merged);
		get_blkio_io_value(io_merged_str, stats.major, stats.minor, "Discard", &stats.discard_merged);

		get_blkio_io_value(io_service_bytes_str, stats.major, stats.minor, "Read", &stats.read_sectors);
		stats.read_sectors = stats.read_sectors / 512;
		get_blkio_io_value(io_service_bytes_str, stats.major, stats.minor, "Write", &stats.write_sectors);
		stats.write_sectors = stats.write_sectors / 512;
		get_blkio_io_value(io_service_bytes_str, stats.major, stats.minor, "Discard", &stats.discard_sectors);
		stats.discard_sectors = stats.discard_sectors / 512;

		get_blkio_io_value(io_service_time_str, stats.major, stats.minor, "Read", &read_service_time);
		read_service_time = read_service_time / 1000000;
		get_blkio_io_value(io_wait_time_str, stats.major, stats.minor, "Read", &read_wait_time);
		read_wait_time = read_wait_time / 1000000;
		stats.read_ticks = read_service_time + read_wait_time;

		get_blkio_io_value(io_service_time_str, stats.major, stats.minor, "Write", &write_service_time);
		write_service_time = write_service_time / 1000000;
		get_blkio_io_value(io_wait_time_str, stats.major, stats.minor, "Write", &write_wait_time);
		write_wait_time = write_wait_time / 1000000;
		stats.write_ticks = write_service_time + write_wait_time;

		get_blkio_io_value(io_service_time_str, stats.major, stats.minor, "Discard", &discard_service_time);
		discard_service_time = discard_service_time / 1000000;
		get_blkio_io_value(io_wait_time_str, stats.major, stats.minor, "Discard", &discard_wait_time);
		discard_wait_time = discard_wait_time / 1000000;
		stats.discard_ticks = discard_service_time + discard_wait_time;

		get_blkio_io_value(io_service_time_str, stats.major, stats.minor, "Total", &stats.total_ticks);
		stats.total_ticks = stats.total_ticks / 1000000;

		memset(lbuf, 0, 256);
		if (stats.read || stats.write || stats.read_merged || stats.write_merged ||
		    stats.read_sectors || stats.write_sectors || stats.read_ticks ||
		    stats.write_ticks || stats.ios_pgr || stats.total_ticks || stats.rq_ticks ||
		    stats.discard_merged || stats.discard_sectors || stats.discard_ticks)
			snprintf(
				lbuf,
				256,
				"%u       %u" /* major, minor */
				" %s"         /* dev_name */
				" %" PRIu64   /* read */
				" %" PRIu64   /* read_merged */
				" %" PRIu64   /* read_sectors */
				" %" PRIu64   /* read_ticks */
				" %" PRIu64   /* write */
				" %" PRIu64   /* write_merged */
				" %" PRIu64   /* write_sectors */
				" %" PRIu64   /* write_ticks */
				" %" PRIu64   /* ios_pgr */
				" %" PRIu64   /* total_ticks */
				" %" PRIu64   /* rq_ticks */
				" %" PRIu64   /* discard_merged */
				" %" PRIu64   /* discard_sectors */
				" %" PRIu64   /* discard_ticks */
				"\n",
				stats.major,
				stats.minor,
				stats.dev_name,
				stats.read,
				stats.read_merged,
				stats.read_sectors,
				stats.read_ticks,
				stats.write,
				stats.write_merged,
				stats.write_sectors,
				stats.write_ticks,
				stats.ios_pgr,
				stats.total_ticks,
				stats.rq_ticks,
				stats.discard_merged,
				stats.discard_sectors,
				stats.discard_ticks);
		else
			continue;

		l = snprintf(cache, cache_size, "%s", lbuf);
		if (l < 0)
			return log_error(0, "Failed to write cache");
		if ((size_t)l >= cache_size)
			return log_error(0, "Write to cache was truncated");

		cache += l;
		cache_size -= l;
		total_len += l;
	}

	d->cached = 1;
	d->size = total_len;
	if (total_len > size)
		total_len = size;
	memcpy(buf, d->buf, total_len);

	return total_len;
}

#ifdef RELOADTEST
static inline void iwashere(void)
{
	mknod("/tmp/lxcfs-iwashere", S_IFREG, 0644);
}
#endif

/*
 * This function retrieves the busy time of a group of tasks by looking at
 * cpuacct.usage. Unfortunately, this only makes sense when the container has
 * been given it's own cpuacct cgroup. If not, this function will take the busy
 * time of all other taks that do not actually belong to the container into
 * account as well. If someone has a clever solution for this please send a
 * patch!
 */
static double get_reaper_busy(pid_t task)
{
	__do_free char *cgroup = NULL, *usage_str = NULL;
	uint64_t usage = 0;
	pid_t initpid;

	initpid = lookup_initpid_in_store(task);
	if (initpid <= 0)
		return 0;

	cgroup = get_pid_cgroup(initpid, "cpuacct");
	if (!cgroup)
		return 0;
	prune_init_slice(cgroup);

	if (!cgroup_ops->get(cgroup_ops, "cpuacct", cgroup, "cpuacct.usage", &usage_str))
		return 0;

	if (safe_uint64(usage_str, &usage, 10) < 0)
		lxcfs_error("Failed to convert usage %s", usage_str);

	return ((double)usage / 1000000000);
}

static uint64_t get_reaper_start_time(pid_t pid)
{
	__do_free void *fopen_cache = NULL;
	__do_fclose FILE *f = NULL;
	int ret;
	uint64_t starttime;
	char path[STRLITERALLEN("/proc/") + LXCFS_NUMSTRLEN64 +
		  STRLITERALLEN("/stat") + 1];
	pid_t qpid;

	qpid = lookup_initpid_in_store(pid);
	if (qpid <= 0)
		return ret_errno(EINVAL);

	ret = snprintf(path, sizeof(path), "/proc/%d/stat", qpid);
	if (ret < 0 || (size_t)ret >= sizeof(path))
		return ret_errno(EINVAL);

	f = fopen_cached(path, "re", &fopen_cache);
	if (!f)
		return ret_errno(EINVAL);

	/* Note that the *scanf() argument supression requires that length
	 * modifiers such as "l" are omitted. Otherwise some compilers will yell
	 * at us. It's like telling someone you're not married and then asking
	 * if you can bring your wife to the party.
	 */
	ret = fscanf(f, "%*d "      /* (1)  pid         %d   */
			"%*s "      /* (2)  comm        %s   */
			"%*c "      /* (3)  state       %c   */
			"%*d "      /* (4)  ppid        %d   */
			"%*d "      /* (5)  pgrp        %d   */
			"%*d "      /* (6)  session     %d   */
			"%*d "      /* (7)  tty_nr      %d   */
			"%*d "      /* (8)  tpgid       %d   */
			"%*u "      /* (9)  flags       %u   */
			"%*u "      /* (10) minflt      %lu  */
			"%*u "      /* (11) cminflt     %lu  */
			"%*u "      /* (12) majflt      %lu  */
			"%*u "      /* (13) cmajflt     %lu  */
			"%*u "      /* (14) utime       %lu  */
			"%*u "      /* (15) stime       %lu  */
			"%*d "      /* (16) cutime      %ld  */
			"%*d "      /* (17) cstime      %ld  */
			"%*d "      /* (18) priority    %ld  */
			"%*d "      /* (19) nice        %ld  */
			"%*d "      /* (20) num_threads %ld  */
			"%*d "      /* (21) itrealvalue %ld  */
			"%" PRIu64, /* (22) starttime   %llu */
		     &starttime);
	if (ret != 1)
		return ret_errno(EINVAL);

	return ret_set_errno(starttime, 0);
}

static double get_reaper_start_time_in_sec(pid_t pid)
{
	uint64_t clockticks, ticks_per_sec;
	int64_t ret;
	double res = 0;

	clockticks = get_reaper_start_time(pid);
	if (clockticks <= 0)
		return log_debug(0, "Failed to retrieve start time of pid %d", pid);

	ret = sysconf(_SC_CLK_TCK);
	if (ret < 0)
		return log_debug(0, "Failed to determine number of clock ticks in a second");

	ticks_per_sec = (uint64_t)ret;
	res = (double)clockticks / ticks_per_sec;
	return res;
}

static double get_reaper_age(pid_t pid)
{
	uint64_t uptime_ms;
	double procstart, procage;

	/*
	 * We need to substract the time the process has started since system
	 * boot minus the time when the system has started to get the actual
	 * reaper age.
	 */
	procstart = get_reaper_start_time_in_sec(pid);
	procage = procstart;
	if (procstart > 0) {
		int ret;
		struct timespec spec;

		ret = clock_gettime(CLOCK_BOOTTIME, &spec);
		if (ret < 0)
			return 0;

		uptime_ms = (spec.tv_sec * 1000) + (spec.tv_nsec * 1e-6);
		procage = (uptime_ms - (procstart * 1000)) / 1000;
	}

	return procage;
}

/*
 * We read /proc/uptime and reuse its second field.
 * For the first field, we use the mtime for the reaper for
 * the calling pid as returned by getreaperage
 */
static int proc_uptime_read(char *buf, size_t size, off_t offset,
			    struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = INTTYPE_TO_PTR(fi->fh);
	char *cache = d->buf;
	ssize_t total_len = 0, ret = 0;
	double busytime, idletime, reaperage;

#ifdef RELOADTEST
	iwashere();
#endif

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

	reaperage = get_reaper_age(fc->pid);
	/*
	 * To understand why this is done, please read the comment to the
	 * get_reaper_busy() function.
	 */
	idletime = reaperage;
	busytime = get_reaper_busy(fc->pid);
	if (reaperage >= busytime)
		idletime = reaperage - busytime;

	ret = snprintf(d->buf, d->buflen, "%.2lf %.2lf\n", reaperage, idletime);
	if (ret < 0 || ret >= d->buflen)
		return read_file_fuse("/proc/uptime", buf, size, d);
	total_len = ret;

	d->cached = 1;
	d->size = total_len;
	if ((size_t)total_len > size)
		total_len = size;
	memcpy(buf, d->buf, total_len);

	return total_len;
}

#define CPUALL_MAX_SIZE (BUF_RESERVE_SIZE / 2)
static int proc_stat_read(char *buf, size_t size, off_t offset,
			  struct fuse_file_info *fi)
{
	__do_free char *cg = NULL, *cpuset = NULL, *line = NULL;
	__do_free void *fopen_cache = NULL;
	__do_free struct cpuacct_usage *cg_cpu_usage = NULL;
	__do_fclose FILE *f = NULL;
	struct fuse_context *fc = fuse_get_context();
	struct lxcfs_opts *opts = (struct lxcfs_opts *)fc->private_data;
	struct file_info *d = INTTYPE_TO_PTR(fi->fh);
	size_t linelen = 0, total_len = 0;
	int curcpu = -1; /* cpu numbering starts at 0 */
	int physcpu = 0;
	uint64_t user = 0, nice = 0, system = 0, idle = 0, iowait = 0, irq = 0,
		 softirq = 0, steal = 0, guest = 0, guest_nice = 0;
	uint64_t user_sum = 0, nice_sum = 0, system_sum = 0, idle_sum = 0,
		 iowait_sum = 0, irq_sum = 0, softirq_sum = 0, steal_sum = 0,
		 guest_sum = 0, guest_nice_sum = 0;
	char cpuall[CPUALL_MAX_SIZE];
	/* reserve for cpu all */
	char *cache = d->buf + CPUALL_MAX_SIZE;
	size_t cache_size = d->buflen - CPUALL_MAX_SIZE;
	int cg_cpu_usage_size = 0;

	if (offset) {
		size_t left;

		if (offset > d->size)
			return -EINVAL;

		if (!d->cached)
			return 0;

		left = d->size - offset;
		total_len = left > size ? size : left;
		memcpy(buf, d->buf + offset, total_len);

		return total_len;
	}

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;

	/*
	 * when container run with host pid namespace initpid == 1, cgroup will "/"
	 * we should return host os's /proc contents.
	 * in some case cpuacct_usage.all in "/" will larger then /proc/stat
	 */
	if (initpid == 1)
		return read_file_fuse("/proc/stat", buf, size, d);

	cg = get_pid_cgroup(initpid, "cpuset");
	if (!cg)
		return read_file_fuse("/proc/stat", buf, size, d);
	prune_init_slice(cg);

	cpuset = get_cpuset(cg);
	if (!cpuset)
		return 0;

	f = fopen_cached("/proc/stat", "re", &fopen_cache);
	if (!f)
		return 0;

	/* Skip first system cpu line. */
	if (getline(&line, &linelen, f) < 0)
		return log_error(0, "proc_stat_read read first line failed");

	/*
	 * Read cpuacct.usage_all for all CPUs.
	 * If the cpuacct cgroup is present, it is used to calculate the container's
	 * CPU usage. If not, values from the host's /proc/stat are used.
	 */
	if (read_cpuacct_usage_all(cg, cpuset, &cg_cpu_usage, &cg_cpu_usage_size) == 0) {
		if (cgroup_ops->can_use_cpuview(cgroup_ops) && opts && opts->use_cfs) {
			total_len = cpuview_proc_stat(cg, cpuset, cg_cpu_usage,
						      cg_cpu_usage_size, f,
						      d->buf, d->buflen);
			goto out;
		}
	} else {
		lxcfs_v("proc_stat_read failed to read from cpuacct, falling back to the host's /proc/stat");
	}

	while (getline(&line, &linelen, f) != -1) {
		ssize_t l;
		char cpu_char[10]; /* That's a lot of cores */
		char *c;
		uint64_t all_used, cg_used, new_idle;
		int ret;

		if (strlen(line) == 0)
			continue;
		if (sscanf(line, "cpu%9[^ ]", cpu_char) != 1) {
			/* not a ^cpuN line containing a number N, just print it */
			l = snprintf(cache, cache_size, "%s", line);
			if (l < 0)
				return log_error(0, "Failed to write cache");
			if ((size_t)l >= cache_size)
				return log_error(0, "Write to cache was truncated");

			cache += l;
			cache_size -= l;
			total_len += l;

			continue;
		}

		if (sscanf(cpu_char, "%d", &physcpu) != 1)
			continue;

		if (!cpu_in_cpuset(physcpu, cpuset))
			continue;

		curcpu++;

		ret = sscanf(
			   line,
			   "%*s"        /* <skip> */
			   " %" PRIu64  /* user */
			   " %" PRIu64  /* nice */
			   " %" PRIu64  /* system */
			   " %" PRIu64  /* idle */
			   " %" PRIu64  /* iowait */
			   " %" PRIu64  /* irq */
			   " %" PRIu64  /* softirq */
			   " %" PRIu64  /* steal */
			   " %" PRIu64  /* guest */
			   " %" PRIu64, /* guest_nice */
			   &user,
			   &nice,
			   &system,
			   &idle,
			   &iowait,
			   &irq,
			   &softirq,
			   &steal,
			   &guest,
			   &guest_nice);
		if (ret != 10 || !cg_cpu_usage) {
			c = strchr(line, ' ');
			if (!c)
				continue;

			l = snprintf(cache, cache_size, "cpu%d%s", curcpu, c);
			if (l < 0)
				return log_error(0, "Failed to write cache");
			if ((size_t)l >= cache_size)
				return log_error(0, "Write to cache was truncated");

			cache += l;
			cache_size -= l;
			total_len += l;

			if (ret != 10)
				continue;
		}

		if (cg_cpu_usage) {
			if (physcpu >= cg_cpu_usage_size)
				break;

			all_used = user + nice + system + iowait + irq + softirq + steal + guest + guest_nice;
			cg_used = cg_cpu_usage[physcpu].user + cg_cpu_usage[physcpu].system;

			if (all_used >= cg_used) {
				new_idle = idle + (all_used - cg_used);
			} else {
				lxcfs_debug("cpu%d from %s has unexpected cpu time: %" PRIu64 " in /proc/stat, %" PRIu64 " in cpuacct.usage_all; unable to determine idle time",
					    curcpu, cg, all_used, cg_used);
				new_idle = idle;
			}

			l = snprintf(cache, cache_size,
				     "cpu%d %" PRIu64 " 0 %" PRIu64 " %" PRIu64 " 0 0 0 0 0 0\n",
				     curcpu, cg_cpu_usage[physcpu].user,
				     cg_cpu_usage[physcpu].system, new_idle);
			if (l < 0)
				return log_error(0, "Failed to write cache");
			if ((size_t)l >= cache_size)
				return log_error(0, "Write to cache was truncated");

			cache += l;
			cache_size -= l;
			total_len += l;

			user_sum += cg_cpu_usage[physcpu].user;
			system_sum += cg_cpu_usage[physcpu].system;
			idle_sum += new_idle;
		} else {
			user_sum += user;
			nice_sum += nice;
			system_sum += system;
			idle_sum += idle;
			iowait_sum += iowait;
			irq_sum += irq;
			softirq_sum += softirq;
			steal_sum += steal;
			guest_sum += guest;
			guest_nice_sum += guest_nice;
		}
	}

	cache = d->buf;

	int cpuall_len = snprintf(
			cpuall,
			CPUALL_MAX_SIZE,
			"cpu  "
			" %" PRIu64 /* user_sum */
			" %" PRIu64 /* nice_sum */
			" %" PRIu64 /* system_sum */
			" %" PRIu64 /* idle_sum */
			" %" PRIu64 /* iowait_sum */
			" %" PRIu64 /* irq_sum */
			" %" PRIu64 /* softirq_sum */
			" %" PRIu64 /* steal_sum */
			" %" PRIu64 /* guest_sum */
			" %" PRIu64 /* guest_nice_sum */
			"\n",
			user_sum,
			nice_sum,
			system_sum,
			idle_sum,
			iowait_sum,
			irq_sum,
			softirq_sum,
			steal_sum,
			guest_sum,
			guest_nice_sum);
	if (cpuall_len > 0 && cpuall_len < CPUALL_MAX_SIZE) {
		memcpy(cache, cpuall, cpuall_len);
		cache += cpuall_len;
	} else {
		/* shouldn't happen */
		lxcfs_error("proc_stat_read copy cpuall failed, cpuall_len=%d", cpuall_len);
		cpuall_len = 0;
	}

	memmove(cache, d->buf + CPUALL_MAX_SIZE, total_len);
	total_len += cpuall_len;

out:
	d->cached = 1;
	d->size = total_len;
	if (total_len > size)
		total_len = size;

	memcpy(buf, d->buf, total_len);
	return total_len;
}

/* Note that "memory.stat" in cgroup2 is hierarchical by default. */
static bool cgroup_parse_memory_stat(const char *cgroup, struct memory_stat *mstat)
{
	__do_close int fd = -EBADF;
	__do_fclose FILE *f = NULL;
	__do_free char *line = NULL;
	__do_free void *fdopen_cache = NULL;
	bool unified;
	size_t len = 0;
	ssize_t linelen;

	fd = cgroup_ops->get_memory_stats_fd(cgroup_ops, cgroup);
	if (fd < 0)
		return false;

	f = fdopen_cached(fd, "re", &fdopen_cache);
	if (!f)
		return false;

	unified = pure_unified_layout(cgroup_ops);
	while ((linelen = getline(&line, &len, f)) != -1) {
		if (!unified && startswith(line, "hierarchical_memory_limit")) {
			sscanf(line, "hierarchical_memory_limit %" PRIu64, &(mstat->hierarchical_memory_limit));
		} else if (!unified && startswith(line, "hierarchical_memsw_limit")) {
			sscanf(line, "hierarchical_memsw_limit %" PRIu64, &(mstat->hierarchical_memsw_limit));
		} else if (startswith(line, unified ? "file" :"total_cache")) {
			sscanf(line, unified ? "file %" PRIu64 : "total_cache %" PRIu64, &(mstat->total_cache));
		} else if (!unified && startswith(line, "total_rss")) {
			sscanf(line, "total_rss %" PRIu64, &(mstat->total_rss));
		} else if (!unified && startswith(line, "total_rss_huge")) {
			sscanf(line, "total_rss_huge %" PRIu64, &(mstat->total_rss_huge));
		} else if (startswith(line, unified ? "shmem" : "total_shmem")) {
			sscanf(line, unified ? "shmem %" PRIu64 : "total_shmem %" PRIu64, &(mstat->total_shmem));
		} else if (startswith(line, unified ? "file_mapped" : "total_mapped_file")) {
			sscanf(line, unified ? "file_mapped %" PRIu64 : "total_mapped_file %" PRIu64, &(mstat->total_mapped_file));
		} else if (!unified && startswith(line, "total_dirty")) {
			sscanf(line, "total_dirty %" PRIu64, &(mstat->total_dirty));
		} else if (!unified && startswith(line, "total_writeback")) {
			sscanf(line, "total_writeback %" PRIu64, &(mstat->total_writeback));
		} else if (!unified && startswith(line, "total_swap")) {
			sscanf(line, "total_swap %" PRIu64, &(mstat->total_swap));
		} else if (!unified && startswith(line, "total_pgpgin")) {
			sscanf(line, "total_pgpgin %" PRIu64, &(mstat->total_pgpgin));
		} else if (!unified && startswith(line, "total_pgpgout")) {
			sscanf(line, "total_pgpgout %" PRIu64, &(mstat->total_pgpgout));
		} else if (startswith(line, unified ? "pgfault" : "total_pgfault")) {
			sscanf(line, unified ? "pgfault %" PRIu64 : "total_pgfault %" PRIu64, &(mstat->total_pgfault));
		} else if (startswith(line, unified ? "pgmajfault" : "total_pgmajfault")) {
			sscanf(line, unified ? "pgmajfault %" PRIu64 : "total_pgmajfault %" PRIu64, &(mstat->total_pgmajfault));
		} else if (startswith(line, unified ? "inactive_anon" : "total_inactive_anon")) {
			sscanf(line, unified ? "inactive_anon %" PRIu64 : "total_inactive_anon %" PRIu64, &(mstat->total_inactive_anon));
		} else if (startswith(line, unified ? "active_anon" : "total_active_anon")) {
			sscanf(line, unified ? "active_anon %" PRIu64 : "total_active_anon %" PRIu64, &(mstat->total_active_anon));
		} else if (startswith(line, unified ? "inactive_file" : "total_inactive_file")) {
			sscanf(line, unified ? "inactive_file %" PRIu64 : "total_inactive_file %" PRIu64, &(mstat->total_inactive_file));
		} else if (startswith(line, unified ? "active_file" : "total_active_file")) {
			sscanf(line, unified ? "active_file %" PRIu64 : "total_active_file %" PRIu64, &(mstat->total_active_file));
		} else if (startswith(line, unified ? "unevictable" : "total_unevictable")) {
			sscanf(line, unified ? "unevictable %" PRIu64 : "total_unevictable %" PRIu64, &(mstat->total_unevictable));
		}
	}

	return true;
}

static int proc_meminfo_read(char *buf, size_t size, off_t offset,
			     struct fuse_file_info *fi)
{
	__do_free char *cgroup = NULL, *line = NULL, *memusage_str = NULL,
		       *memswusage_str = NULL, *memswpriority_str = NULL;
	__do_free void *fopen_cache = NULL;
	__do_fclose FILE *f = NULL;
	struct fuse_context *fc = fuse_get_context();
	bool wants_swap = lxcfs_has_opt(fuse_get_context()->private_data, LXCFS_SWAP_ON);
	struct file_info *d = INTTYPE_TO_PTR(fi->fh);
	uint64_t memlimit = 0, memusage = 0,
		 hosttotal = 0, swfree = 0, swusage = 0, swtotal = 0,
		 memswpriority = 1;
	struct memory_stat mstat = {};
	size_t linelen = 0, total_len = 0;
	char *cache = d->buf;
	size_t cache_size = d->buflen;
	int ret;

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

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;

	cgroup = get_pid_cgroup(initpid, "memory");
	if (!cgroup)
		return read_file_fuse("/proc/meminfo", buf, size, d);

	prune_init_slice(cgroup);

	/* memory limits */
	ret = cgroup_ops->get_memory_current(cgroup_ops, cgroup, &memusage_str);
	if (ret < 0)
		return read_file_fuse("/proc/meminfo", buf, size, d);

	if (safe_uint64(memusage_str, &memusage, 10) < 0)
		lxcfs_error("Failed to convert memusage %s", memusage_str);

	if (!cgroup_parse_memory_stat(cgroup, &mstat))
		return read_file_fuse("/proc/meminfo", buf, size, d);

	memlimit = get_min_memlimit(cgroup, false);

	/*
	 * Following values are allowed to fail, because swapaccount might be
	 * turned off for current kernel.
	 */
	if (wants_swap)
		get_swap_info(cgroup, memlimit, memusage, &swtotal, &swusage, &memswpriority);

	f = fopen_cached("/proc/meminfo", "re", &fopen_cache);
	if (!f)
		return read_file_fuse("/proc/meminfo", buf, size, d);

	memusage /= 1024;
	memlimit /= 1024;
	while (getline(&line, &linelen, f) != -1) {
		ssize_t l;
		char *printme, lbuf[100];

		memset(lbuf, 0, 100);
		if (startswith(line, "MemTotal:")) {
			sscanf(line+sizeof("MemTotal:")-1, "%" PRIu64, &hosttotal);
			if (memlimit == 0)
				memlimit = hosttotal;

			if (hosttotal < memlimit)
				memlimit = hosttotal;
			snprintf(lbuf, 100, "MemTotal:       %8" PRIu64 " kB\n", memlimit);
			printme = lbuf;
		} else if (startswith(line, "MemFree:")) {
			snprintf(lbuf, 100, "MemFree:        %8" PRIu64 " kB\n", memlimit - memusage);
			printme = lbuf;
		} else if (startswith(line, "MemAvailable:")) {
			snprintf(lbuf, 100, "MemAvailable:   %8" PRIu64 " kB\n", memlimit - memusage + mstat.total_cache / 1024);
			printme = lbuf;
		} else if (startswith(line, "SwapTotal:")) {
			if (wants_swap) {
				uint64_t hostswtotal = 0;

				sscanf(line + STRLITERALLEN("SwapTotal:"), "%" PRIu64, &hostswtotal);

				/* The total amount of swap is always reported to be the
				   lesser of the RAM+SWAP limit or the SWAP device size.
				   This is because the kernel can swap as much as it
				   wants and not only up to swtotal. */

				if (!liblxcfs_memory_is_cgroupv2())
					swtotal += memlimit;

				if (hostswtotal < swtotal) {
					swtotal = hostswtotal;
				}

				/* When swappiness is 0, pretend we can't swap. */
				if (memswpriority == 0) {
					swtotal = swusage;
				}
			}

			snprintf(lbuf, 100, "SwapTotal:      %8" PRIu64 " kB\n", swtotal);
			printme = lbuf;
		} else if (startswith(line, "SwapFree:")) {
			if (wants_swap) {
				swfree = swtotal - swusage;
			}

			snprintf(lbuf, 100, "SwapFree:       %8" PRIu64 " kB\n", swfree);
			printme = lbuf;
		} else if (startswith(line, "Slab:")) {
			snprintf(lbuf, 100, "Slab:           %8" PRIu64 " kB\n", (uint64_t)0);
			printme = lbuf;
		} else if (startswith(line, "Buffers:")) {
			snprintf(lbuf, 100, "Buffers:        %8" PRIu64 " kB\n", (uint64_t)0);
			printme = lbuf;
		} else if (startswith(line, "Cached:")) {
			snprintf(lbuf, 100, "Cached:         %8" PRIu64 " kB\n",
				 mstat.total_cache / 1024);
			printme = lbuf;
		} else if (startswith(line, "SwapCached:")) {
			snprintf(lbuf, 100, "SwapCached:     %8" PRIu64 " kB\n", (uint64_t)0);
			printme = lbuf;
		} else if (startswith(line, "Active:")) {
			snprintf(lbuf, 100, "Active:         %8" PRIu64 " kB\n",
				 (mstat.total_active_anon +
				  mstat.total_active_file) /
				     1024);
			printme = lbuf;
		} else if (startswith(line, "Inactive:")) {
			snprintf(lbuf, 100, "Inactive:       %8" PRIu64 " kB\n",
				 (mstat.total_inactive_anon +
				  mstat.total_inactive_file) /
				     1024);
			printme = lbuf;
		} else if (startswith(line, "Active(anon):")) {
			snprintf(lbuf, 100, "Active(anon):   %8" PRIu64 " kB\n",
				 mstat.total_active_anon / 1024);
			printme = lbuf;
		} else if (startswith(line, "Inactive(anon):")) {
			snprintf(lbuf, 100, "Inactive(anon): %8" PRIu64 " kB\n",
				 mstat.total_inactive_anon / 1024);
			printme = lbuf;
		} else if (startswith(line, "Active(file):")) {
			snprintf(lbuf, 100, "Active(file):   %8" PRIu64 " kB\n",
				 mstat.total_active_file / 1024);
			printme = lbuf;
		} else if (startswith(line, "Inactive(file):")) {
			snprintf(lbuf, 100, "Inactive(file): %8" PRIu64 " kB\n",
				 mstat.total_inactive_file / 1024);
			printme = lbuf;
		} else if (startswith(line, "Unevictable:")) {
			snprintf(lbuf, 100, "Unevictable:    %8" PRIu64 " kB\n",
				 mstat.total_unevictable / 1024);
			printme = lbuf;
 		} else if (startswith(line, "Dirty:")) {
			snprintf(lbuf, 100, "Dirty:          %8" PRIu64 " kB\n",
				 mstat.total_dirty / 1024);
			printme = lbuf;
 		} else if (startswith(line, "Writeback:")) {
			snprintf(lbuf, 100, "Writeback:      %8" PRIu64 " kB\n",
				 mstat.total_writeback / 1024);
			printme = lbuf;
 		} else if (startswith(line, "AnonPages:")) {
			snprintf(lbuf, 100, "AnonPages:      %8" PRIu64 " kB\n",
				 (mstat.total_active_anon +
				  mstat.total_inactive_anon - mstat.total_shmem) /
				     1024);
			printme = lbuf;
 		} else if (startswith(line, "Mapped:")) {
			snprintf(lbuf, 100, "Mapped:         %8" PRIu64 " kB\n",
				 mstat.total_mapped_file / 1024);
			printme = lbuf;
		} else if (startswith(line, "SReclaimable:")) {
			snprintf(lbuf, 100, "SReclaimable:   %8" PRIu64 " kB\n", (uint64_t)0);
			printme = lbuf;
		} else if (startswith(line, "SUnreclaim:")) {
			snprintf(lbuf, 100, "SUnreclaim:     %8" PRIu64 " kB\n", (uint64_t)0);
			printme = lbuf;
		} else if (startswith(line, "Shmem:")) {
			snprintf(lbuf, 100, "Shmem:          %8" PRIu64 " kB\n",
				 mstat.total_shmem / 1024);
			printme = lbuf;
		} else if (startswith(line, "ShmemHugePages:")) {
			snprintf(lbuf, 100, "ShmemHugePages: %8" PRIu64 " kB\n", (uint64_t)0);
			printme = lbuf;
		} else if (startswith(line, "ShmemPmdMapped:")) {
			snprintf(lbuf, 100, "ShmemPmdMapped: %8" PRIu64 " kB\n", (uint64_t)0);
 			printme = lbuf;
 		} else if (startswith(line, "AnonHugePages:")) {
			snprintf(lbuf, 100, "AnonHugePages:  %8" PRIu64 " kB\n",
				 mstat.total_rss_huge / 1024);
			printme = lbuf;
 		} else {
 			printme = line;
		}

		l = snprintf(cache, cache_size, "%s", printme);
		if (l < 0)
			return log_error(0, "Failed to write cache");
		if ((size_t)l >= cache_size)
			return log_error(0, "Write to cache was truncated");

		cache += l;
		cache_size -= l;
		total_len += l;
	}

	d->cached = 1;
	d->size = total_len;
	if (total_len > size)
		total_len = size;
	memcpy(buf, d->buf, total_len);

	return total_len;
}

static int proc_slabinfo_read(char *buf, size_t size, off_t offset,
			      struct fuse_file_info *fi)
{
	__do_free char *cgroup = NULL, *line = NULL;
	__do_free void *fopen_cache = NULL;
	__do_fclose FILE *f = NULL;
	__do_close int fd = -EBADF;
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = INTTYPE_TO_PTR(fi->fh);
	size_t linelen = 0, total_len = 0;
	char *cache = d->buf;
	size_t cache_size = d->buflen;
	pid_t initpid;

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

	initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;

	cgroup = get_pid_cgroup(initpid, "memory");
	if (!cgroup)
		return read_file_fuse("/proc/slabinfo", buf, size, d);

	prune_init_slice(cgroup);

	fd = cgroup_ops->get_memory_slabinfo_fd(cgroup_ops, cgroup);
	if (fd < 0)
		return read_file_fuse("/proc/slabinfo", buf, size, d);

	f = fdopen_cached(fd, "re", &fopen_cache);
	if (!f)
		return read_file_fuse("/proc/slabinfo", buf, size, d);

	while (getline(&line, &linelen, f) != -1) {
		ssize_t l = snprintf(cache, cache_size, "%s", line);
		if (l < 0)
			return log_error(0, "Failed to write cache");
		if ((size_t)l >= cache_size)
			return log_error(0, "Write to cache was truncated");

		cache += l;
		cache_size -= l;
		total_len += l;
	}

	d->cached = 1;
	d->size = total_len;
	if (total_len > size)
		total_len = size;
	memcpy(buf, d->buf, total_len);

	return total_len;
}

__lxcfs_fuse_ops int proc_read(const char *path, char *buf, size_t size,
			       off_t offset, struct fuse_file_info *fi)
{
	struct file_info *f = INTTYPE_TO_PTR(fi->fh);

	switch (f->type) {
	case LXC_TYPE_PROC_MEMINFO:
		if (liblxcfs_functional())
			return proc_meminfo_read(buf, size, offset, fi);

		return read_file_fuse_with_offset(LXC_TYPE_PROC_MEMINFO_PATH,
						  buf, size, offset, f);
	case LXC_TYPE_PROC_CPUINFO:
		if (liblxcfs_functional())
			return proc_cpuinfo_read(buf, size, offset, fi);

		return read_file_fuse_with_offset(LXC_TYPE_PROC_CPUINFO_PATH,
						  buf, size, offset, f);
	case LXC_TYPE_PROC_UPTIME:
		if (liblxcfs_functional())
			return proc_uptime_read(buf, size, offset, fi);

		return read_file_fuse_with_offset(LXC_TYPE_PROC_UPTIME_PATH,
						  buf, size, offset, f);
	case LXC_TYPE_PROC_STAT:
		if (liblxcfs_functional())
			return proc_stat_read(buf, size, offset, fi);

		return read_file_fuse_with_offset(LXC_TYPE_PROC_STAT_PATH, buf,
						  size, offset, f);
	case LXC_TYPE_PROC_DISKSTATS:
		if (liblxcfs_functional())
			return proc_diskstats_read(buf, size, offset, fi);

		return read_file_fuse_with_offset(LXC_TYPE_PROC_DISKSTATS_PATH,
						  buf, size, offset, f);
	case LXC_TYPE_PROC_SWAPS:
		if (liblxcfs_functional())
			return proc_swaps_read(buf, size, offset, fi);

		return read_file_fuse_with_offset(LXC_TYPE_PROC_SWAPS_PATH, buf,
						  size, offset, f);
	case LXC_TYPE_PROC_LOADAVG:
		if (liblxcfs_functional())
			return proc_loadavg_read(buf, size, offset, fi);

		return read_file_fuse_with_offset(LXC_TYPE_PROC_LOADAVG_PATH,
						  buf, size, offset, f);
	case LXC_TYPE_PROC_SLABINFO:
		if (liblxcfs_functional())
			return proc_slabinfo_read(buf, size, offset, fi);

		return read_file_fuse_with_offset(LXC_TYPE_PROC_SLABINFO_PATH,
						  buf, size, offset, f);
	}

	return -EINVAL;
}
