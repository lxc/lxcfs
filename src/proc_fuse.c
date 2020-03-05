/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 26
#endif

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

#include "bindings.h"
#include "config.h"
#include "cgroup_fuse.h"
#include "cgroups/cgroup.h"
#include "cgroups/cgroup_utils.h"
#include "cpuset_parse.h"
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

int proc_getattr(const char *path, struct stat *sb)
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
	    strcmp(path, "/proc/loadavg")	== 0) {
		sb->st_size = 0;
		sb->st_mode = S_IFREG | 00444;
		sb->st_nlink = 1;
		return 0;
	}

	return -ENOENT;
}

int proc_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		 off_t offset, struct fuse_file_info *fi)
{
	if (filler(buf, ".",		NULL, 0) != 0 ||
	    filler(buf, "..",		NULL, 0) != 0 ||
	    filler(buf, "cpuinfo",	NULL, 0) != 0 ||
	    filler(buf, "meminfo",	NULL, 0) != 0 ||
	    filler(buf, "stat",		NULL, 0) != 0 ||
	    filler(buf, "uptime",	NULL, 0) != 0 ||
	    filler(buf, "diskstats",	NULL, 0) != 0 ||
	    filler(buf, "swaps",	NULL, 0) != 0 ||
	    filler(buf, "loadavg",	NULL, 0) != 0)
		return -EINVAL;

	return 0;
}

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

int proc_open(const char *path, struct fuse_file_info *fi)
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
	if (type == -1)
		return -ENOENT;

	info = malloc(sizeof(*info));
	if (!info)
		return -ENOMEM;

	memset(info, 0, sizeof(*info));
	info->type = type;

	info->buflen = get_procfile_size(path) + BUF_RESERVE_SIZE;

	info->buf = malloc(info->buflen);
	if (!info->buf)
		return -ENOMEM;

	memset(info->buf, 0, info->buflen);
	/* set actual size to buffer size */
	info->size = info->buflen;

	fi->fh = PTR_TO_UINT64(move_ptr(info));
	return 0;
}

int proc_access(const char *path, int mask)
{
	if (strcmp(path, "/proc") == 0 && access(path, R_OK) == 0)
		return 0;

	/* these are all read-only */
	if ((mask & ~R_OK) != 0)
		return -EACCES;

	return 0;
}

int proc_release(const char *path, struct fuse_file_info *fi)
{
	do_release_file_info(fi);
	return 0;
}

static unsigned long get_memlimit(const char *cgroup, bool swap)
{
	__do_free char *memlimit_str = NULL;
	unsigned long memlimit = -1;
	int ret;

	if (swap)
		ret = cgroup_ops->get_memory_swap_max(cgroup_ops, cgroup, &memlimit_str);
	else
		ret = cgroup_ops->get_memory_max(cgroup_ops, cgroup, &memlimit_str);
	if (ret > 0)
		memlimit = strtoul(memlimit_str, NULL, 10);

	return memlimit;
}

static unsigned long get_min_memlimit(const char *cgroup, bool swap)
{
	__do_free char *copy = NULL;
	unsigned long memlimit = 0;
	unsigned long retlimit;

	copy = strdup(cgroup);
	if (!copy)
		return log_error_errno(0, ENOMEM, "Failed to allocate memory");

	retlimit = get_memlimit(copy, swap);

	while (strcmp(copy, "/") != 0) {
		char *it = copy;

		it = dirname(it);
		memlimit = get_memlimit(it, swap);
		if (memlimit != -1 && memlimit < retlimit)
			retlimit = memlimit;
	};

	return retlimit;
}

static inline bool startswith(const char *line, const char *pref)
{
	return strncmp(line, pref, strlen(pref)) == 0;
}

static int proc_swaps_read(char *buf, size_t size, off_t offset,
			   struct fuse_file_info *fi)
{
	__do_free char *cg = NULL, *memswlimit_str = NULL, *memusage_str = NULL,
		       *memswusage_str = NULL;
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = INTTYPE_TO_PTR(fi->fh);
	unsigned long memswlimit = 0, memlimit = 0, memusage = 0,
		      memswusage = 0, swap_total = 0, swap_free = 0;
	ssize_t total_len = 0;
	ssize_t l = 0;
	char *cache = d->buf;
	int ret;

	if (offset) {
		int left;

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

	cg = get_pid_cgroup(initpid, "memory");
	if (!cg)
		return read_file_fuse("/proc/swaps", buf, size, d);
	prune_init_slice(cg);

	memlimit = get_min_memlimit(cg, false);

	ret = cgroup_ops->get_memory_current(cgroup_ops, cg, &memusage_str);
	if (ret < 0)
		return 0;

	memusage = strtoul(memusage_str, NULL, 10);

	ret = cgroup_ops->get_memory_swap_max(cgroup_ops, cg, &memswlimit_str);
	if (ret >= 0)
		ret = cgroup_ops->get_memory_swap_current(cgroup_ops, cg, &memswusage_str);
	if (ret >= 0) {
		memswlimit = get_min_memlimit(cg, true);
		memswusage = strtoul(memswusage_str, NULL, 10);
		swap_total = (memswlimit - memlimit) / 1024;
		swap_free = (memswusage - memusage) / 1024;
	}

	total_len = snprintf(d->buf, d->size, "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n");

	/* When no mem + swap limit is specified or swapaccount=0*/
	if (!memswlimit) {
		__do_free char *line = NULL;
		__do_free void *fopen_cache = NULL;
		__do_fclose FILE *f = NULL;
		size_t linelen = 0;

		f = fopen_cached("/proc/meminfo", "re", &fopen_cache);
		if (!f)
			return 0;

		while (getline(&line, &linelen, f) != -1) {
			if (startswith(line, "SwapTotal:"))
				sscanf(line, "SwapTotal:      %8lu kB", &swap_total);
			else if (startswith(line, "SwapFree:"))
				sscanf(line, "SwapFree:      %8lu kB", &swap_free);
		}
	}

	if (swap_total > 0) {
		l = snprintf(d->buf + total_len, d->size - total_len,
				"none%*svirtual\t\t%lu\t%lu\t0\n", 36, " ",
				swap_total, swap_free);
		total_len += l;
	}

	if (total_len < 0 || l < 0)
		return log_error(0, "Failed writing to cache");

	d->cached = 1;
	d->size = (int)total_len;

	if (total_len > size)
		total_len = size;
	memcpy(buf, d->buf, total_len);

	return total_len;
}

static void get_blkio_io_value(char *str, unsigned major, unsigned minor,
			       char *iotype, unsigned long *v)
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
			sscanf(str + len, "%lu", v);
			return;
		}
		eol = strchr(str, '\n');
		if (!eol)
			return;
		str = eol+1;
	}
}

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
	unsigned long read = 0, write = 0;
	unsigned long read_merged = 0, write_merged = 0;
	unsigned long read_sectors = 0, write_sectors = 0;
	unsigned long read_ticks = 0, write_ticks = 0;
	unsigned long ios_pgr = 0, tot_ticks = 0, rq_ticks = 0;
	unsigned long rd_svctm = 0, wr_svctm = 0, rd_wait = 0, wr_wait = 0;
	char *cache = d->buf;
	size_t cache_size = d->buflen;
	size_t linelen = 0, total_len = 0;
	unsigned int major = 0, minor = 0;
	int i = 0;
	int ret;
	char dev_name[72];

	if (offset){
		int left;

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

		i = sscanf(line, "%u %u %71s", &major, &minor, dev_name);
		if (i != 3)
			continue;

		get_blkio_io_value(io_serviced_str, major, minor, "Read", &read);
		get_blkio_io_value(io_serviced_str, major, minor, "Write", &write);
		get_blkio_io_value(io_merged_str, major, minor, "Read", &read_merged);
		get_blkio_io_value(io_merged_str, major, minor, "Write", &write_merged);
		get_blkio_io_value(io_service_bytes_str, major, minor, "Read", &read_sectors);
		read_sectors = read_sectors/512;
		get_blkio_io_value(io_service_bytes_str, major, minor, "Write", &write_sectors);
		write_sectors = write_sectors/512;

		get_blkio_io_value(io_service_time_str, major, minor, "Read", &rd_svctm);
		rd_svctm = rd_svctm/1000000;
		get_blkio_io_value(io_wait_time_str, major, minor, "Read", &rd_wait);
		rd_wait = rd_wait/1000000;
		read_ticks = rd_svctm + rd_wait;

		get_blkio_io_value(io_service_time_str, major, minor, "Write", &wr_svctm);
		wr_svctm =  wr_svctm/1000000;
		get_blkio_io_value(io_wait_time_str, major, minor, "Write", &wr_wait);
		wr_wait =  wr_wait/1000000;
		write_ticks = wr_svctm + wr_wait;

		get_blkio_io_value(io_service_time_str, major, minor, "Total", &tot_ticks);
		tot_ticks =  tot_ticks/1000000;

		memset(lbuf, 0, 256);
		if (read || write || read_merged || write_merged || read_sectors || write_sectors || read_ticks || write_ticks)
			snprintf(lbuf, 256, "%u       %u %s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
				major, minor, dev_name, read, read_merged, read_sectors, read_ticks,
				write, write_merged, write_sectors, write_ticks, ios_pgr, tot_ticks, rq_ticks);
		else
			continue;

		l = snprintf(cache, cache_size, "%s", lbuf);
		if (l < 0)
			return log_error(0, "Failed to write cache");
		if (l >= cache_size)
			return log_error(0, "Write to cache was truncated");

		cache += l;
		cache_size -= l;
		total_len += l;
	}

	d->cached = 1;
	d->size = total_len;
	if (total_len > size ) total_len = size;
	memcpy(buf, d->buf, total_len);

	return total_len;
}

#if RELOADTEST
static inline void iwashere(void)
{
	mknod("/tmp/lxcfs-iwashere", S_IFREG, 0644);
}
#endif

/* This function retrieves the busy time of a group of tasks by looking at
 * cpuacct.usage. Unfortunately, this only makes sense when the container has
 * been given it's own cpuacct cgroup. If not, this function will take the busy
 * time of all other taks that do not actually belong to the container into
 * account as well. If someone has a clever solution for this please send a
 * patch!
 */
static double get_reaper_busy(pid_t task)
{
	__do_free char *cgroup = NULL, *usage_str = NULL;
	unsigned long usage = 0;
	pid_t initpid;

	initpid = lookup_initpid_in_store(task);
	if (initpid <= 0)
		return 0;

	cgroup = get_pid_cgroup(initpid, "cpuacct");
	if (!cgroup)
		return 0;
	prune_init_slice(cgroup);
	if (!cgroup_ops->get(cgroup_ops, "cpuacct", cgroup, "cpuacct.usage",
			     &usage_str))
		return 0;

	usage = strtoul(usage_str, NULL, 10);
	return ((double)usage / 1000000000);
}

static uint64_t get_reaper_start_time(pid_t pid)
{
	__do_free void *fopen_cache = NULL;
	__do_fclose FILE *f = NULL;
	int ret;
	uint64_t starttime;
	/* strlen("/proc/") = 6
	 * +
	 * LXCFS_NUMSTRLEN64
	 * +
	 * strlen("/stat") = 5
	 * +
	 * \0 = 1
	 * */
#define __PROC_PID_STAT_LEN (6 + LXCFS_NUMSTRLEN64 + 5 + 1)
	char path[__PROC_PID_STAT_LEN];
	pid_t qpid;

	qpid = lookup_initpid_in_store(pid);
	if (qpid <= 0) {
		/* Caller can check for EINVAL on 0. */
		errno = EINVAL;
		return 0;
	}

	ret = snprintf(path, __PROC_PID_STAT_LEN, "/proc/%d/stat", qpid);
	if (ret < 0 || ret >= __PROC_PID_STAT_LEN) {
		/* Caller can check for EINVAL on 0. */
		errno = EINVAL;
		return 0;
	}

	f = fopen_cached(path, "re", &fopen_cache);
	if (!f) {
		/* Caller can check for EINVAL on 0. */
		errno = EINVAL;
		return 0;
	}

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
		return ret_set_errno(0, EINVAL);

	return ret_set_errno(starttime, 0);
}

static double get_reaper_start_time_in_sec(pid_t pid)
{
	uint64_t clockticks, ticks_per_sec;
	int64_t ret;
	double res = 0;

	clockticks = get_reaper_start_time(pid);
	if (clockticks == 0 && errno == EINVAL)
		return log_debug(0, "Failed to retrieve start time of pid %d", pid);

	ret = sysconf(_SC_CLK_TCK);
	if (ret < 0 && errno == EINVAL)
		return log_debug(0, "Failed to determine number of clock ticks in a second");

	ticks_per_sec = (uint64_t)ret;
	res = (double)clockticks / ticks_per_sec;
	return res;
}

static double get_reaper_age(pid_t pid)
{
	uint64_t uptime_ms;
	double procstart, procage;

	/* We need to substract the time the process has started since system
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

		/* We could make this more precise here by using the tv_nsec
		 * field in the timespec struct and convert it to milliseconds
		 * and then create a double for the seconds and milliseconds but
		 * that seems more work than it is worth.
		 */
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
	double busytime = get_reaper_busy(fc->pid);
	char *cache = d->buf;
	ssize_t total_len = 0;
	double idletime, reaperage;

#if RELOADTEST
	iwashere();
#endif

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

	reaperage = get_reaper_age(fc->pid);
	/*
	 * To understand why this is done, please read the comment to the
	 * get_reaper_busy() function.
	 */
	idletime = reaperage;
	if (reaperage >= busytime)
		idletime = reaperage - busytime;

	total_len = snprintf(d->buf, d->buflen, "%.2lf %.2lf\n", reaperage, idletime);
	if (total_len < 0 || total_len >= d->buflen)
		return log_error(0, "Failed to write to cache");

	d->size = (int)total_len;
	d->cached = 1;

	if (total_len > size)
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
	struct file_info *d = INTTYPE_TO_PTR(fi->fh);
	size_t linelen = 0, total_len = 0;
	int curcpu = -1; /* cpu numbering starts at 0 */
	int physcpu = 0;
	unsigned long user = 0, nice = 0, system = 0, idle = 0, iowait = 0,
		      irq = 0, softirq = 0, steal = 0, guest = 0, guest_nice = 0;
	unsigned long user_sum = 0, nice_sum = 0, system_sum = 0, idle_sum = 0,
		      iowait_sum = 0, irq_sum = 0, softirq_sum = 0,
		      steal_sum = 0, guest_sum = 0, guest_nice_sum = 0;
	char cpuall[CPUALL_MAX_SIZE];
	/* reserve for cpu all */
	char *cache = d->buf + CPUALL_MAX_SIZE;
	size_t cache_size = d->buflen - CPUALL_MAX_SIZE;
	int cg_cpu_usage_size = 0;

	if (offset) {
		int left;

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

	/*
	 * Read cpuacct.usage_all for all CPUs.
	 * If the cpuacct cgroup is present, it is used to calculate the container's
	 * CPU usage. If not, values from the host's /proc/stat are used.
	 */
	if (read_cpuacct_usage_all(cg, cpuset, &cg_cpu_usage, &cg_cpu_usage_size) != 0)
		lxcfs_v("%s\n", "proc_stat_read failed to read from cpuacct, falling back to the host's /proc/stat");

	f = fopen_cached("/proc/stat", "re", &fopen_cache);
	if (!f)
		return 0;

	//skip first line
	if (getline(&line, &linelen, f) < 0)
		return log_error(0, "proc_stat_read read first line failed");

	if (cgroup_ops->can_use_cpuview(cgroup_ops) && cg_cpu_usage) {
		total_len = cpuview_proc_stat(cg, cpuset, cg_cpu_usage, cg_cpu_usage_size,
				f, d->buf, d->buflen);
		goto out;
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
			if (l >= cache_size)
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

		ret = sscanf(line, "%*s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
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
			if (l >= cache_size)
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
				lxcfs_error("cpu%d from %s has unexpected cpu time: %" PRIu64 " in /proc/stat, %" PRIu64 " in cpuacct.usage_all; unable to determine idle time",
					    curcpu, cg, all_used, cg_used);
				new_idle = idle;
			}

			l = snprintf(cache, cache_size,
				     "cpu%d %" PRIu64 " 0 %" PRIu64 " %" PRIu64 " 0 0 0 0 0 0\n",
				     curcpu, cg_cpu_usage[physcpu].user,
				     cg_cpu_usage[physcpu].system, new_idle);
			if (l < 0)
				return log_error(0, "Failed to write cache");
			if (l >= cache_size)
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

	int cpuall_len = snprintf(cpuall, CPUALL_MAX_SIZE, "cpu  %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
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
	__do_close_prot_errno int fd = -EBADF;
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
	__do_free char *cgroup = NULL, *line = NULL,
		       *memusage_str = NULL, *memstat_str = NULL,
		       *memswlimit_str = NULL, *memswusage_str = NULL;
	__do_free void *fopen_cache = NULL;
	__do_fclose FILE *f = NULL;
	struct fuse_context *fc = fuse_get_context();
	struct lxcfs_opts *opts = (struct lxcfs_opts *)fuse_get_context()->private_data;
	struct file_info *d = INTTYPE_TO_PTR(fi->fh);
	uint64_t memlimit = 0, memusage = 0, memswlimit = 0, memswusage = 0,
		 hosttotal = 0;
	struct memory_stat mstat = {};
	size_t linelen = 0, total_len = 0;
	char *cache = d->buf;
	size_t cache_size = d->buflen;
	int ret;

	if (offset) {
		int left;

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

	memlimit = get_min_memlimit(cgroup, false);

	ret = cgroup_ops->get_memory_current(cgroup_ops, cgroup, &memusage_str);
	if (ret < 0)
		return 0;

	if (!cgroup_parse_memory_stat(cgroup, &mstat))
		return 0;

	/*
	 * Following values are allowed to fail, because swapaccount might be
	 * turned off for current kernel.
	 */
	ret = cgroup_ops->get_memory_swap_max(cgroup_ops, cgroup, &memswlimit_str);
	if (ret >= 0)
		ret = cgroup_ops->get_memory_swap_current(cgroup_ops, cgroup, &memswusage_str);
	if (ret >= 0) {
		memswlimit = get_min_memlimit(cgroup, true);
		memswusage = strtoul(memswusage_str, NULL, 10);
		memswlimit = memswlimit / 1024;
		memswusage = memswusage / 1024;
	}

	memusage = strtoul(memusage_str, NULL, 10);
	memlimit /= 1024;
	memusage /= 1024;

	f = fopen_cached("/proc/meminfo", "re", &fopen_cache);
	if (!f)
		return 0;

	while (getline(&line, &linelen, f) != -1) {
		ssize_t l;
		char *printme, lbuf[100];

		memset(lbuf, 0, 100);
		if (startswith(line, "MemTotal:")) {
			sscanf(line+sizeof("MemTotal:")-1, "%" PRIu64, &hosttotal);
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
		} else if (startswith(line, "SwapTotal:") && memswlimit > 0 &&
			   opts && opts->swap_off == false) {
			memswlimit -= memlimit;
			snprintf(lbuf, 100, "SwapTotal:      %8" PRIu64 " kB\n", memswlimit);
			printme = lbuf;
		} else if (startswith(line, "SwapTotal:") && opts && opts->swap_off == true) {
			snprintf(lbuf, 100, "SwapTotal:      %8" PRIu64 " kB\n", (uint64_t)0);
			printme = lbuf;
		} else if (startswith(line, "SwapFree:") && memswlimit > 0 &&
			   memswusage > 0 && opts && opts->swap_off == false) {
			uint64_t swaptotal = memswlimit,
				 swapusage = memusage > memswusage
						 ? 0
						 : memswusage - memusage,
				 swapfree = swapusage < swaptotal
						? swaptotal - swapusage
						: 0;
			snprintf(lbuf, 100, "SwapFree:       %8" PRIu64 " kB\n", swapfree);
			printme = lbuf;
		} else if (startswith(line, "SwapFree:") && opts && opts->swap_off == true) {
			snprintf(lbuf, 100, "SwapFree:       %8" PRIu64 " kB\n", (uint64_t)0);
			printme = lbuf;
		} else if (startswith(line, "Slab:")) {
			snprintf(lbuf, 100, "Slab:        %8" PRIu64 " kB\n", (uint64_t)0);
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
		} else if (startswith(line, "Active(anon)")) {
			snprintf(lbuf, 100, "Active(anon):   %8" PRIu64 " kB\n",
				 mstat.total_active_anon / 1024);
			printme = lbuf;
		} else if (startswith(line, "Inactive(anon)")) {
			snprintf(lbuf, 100, "Inactive(anon): %8" PRIu64 " kB\n",
				 mstat.total_inactive_anon / 1024);
			printme = lbuf;
		} else if (startswith(line, "Active(file)")) {
			snprintf(lbuf, 100, "Active(file):   %8" PRIu64 " kB\n",
				 mstat.total_active_file / 1024);
			printme = lbuf;
		} else if (startswith(line, "Inactive(file)")) {
			snprintf(lbuf, 100, "Inactive(file): %8" PRIu64 " kB\n",
				 mstat.total_inactive_file / 1024);
			printme = lbuf;
		} else if (startswith(line, "Unevictable")) {
			snprintf(lbuf, 100, "Unevictable:    %8" PRIu64 " kB\n",
				 mstat.total_unevictable / 1024);
			printme = lbuf;
 		} else if (startswith(line, "Dirty")) {
			snprintf(lbuf, 100, "Dirty:          %8" PRIu64 " kB\n",
				 mstat.total_dirty / 1024);
			printme = lbuf;
 		} else if (startswith(line, "Writeback")) {
			snprintf(lbuf, 100, "Writeback:      %8" PRIu64 " kB\n",
				 mstat.total_writeback / 1024);
			printme = lbuf;
 		} else if (startswith(line, "AnonPages")) {
			snprintf(lbuf, 100, "AnonPages:      %8" PRIu64 " kB\n",
				 (mstat.total_active_anon +
				  mstat.total_inactive_anon - mstat.total_shmem) /
				     1024);
			printme = lbuf;
 		} else if (startswith(line, "Mapped")) {
			snprintf(lbuf, 100, "Mapped:         %8" PRIu64 " kB\n",
				 mstat.total_mapped_file / 1024);
			printme = lbuf;
		} else if (startswith(line, "SReclaimable")) {
			snprintf(lbuf, 100, "SReclaimable:   %8" PRIu64 " kB\n", (uint64_t)0);
			printme = lbuf;
		} else if (startswith(line, "SUnreclaim")) {
			snprintf(lbuf, 100, "SUnreclaim:     %8" PRIu64 " kB\n", (uint64_t)0);
			printme = lbuf;
		} else if (startswith(line, "Shmem:")) {
			snprintf(lbuf, 100, "Shmem:          %8" PRIu64 " kB\n",
				 mstat.total_shmem / 1024);
			printme = lbuf;
		} else if (startswith(line, "ShmemHugePages")) {
			snprintf(lbuf, 100, "ShmemHugePages: %8" PRIu64 " kB\n", (uint64_t)0);
			printme = lbuf;
		} else if (startswith(line, "ShmemPmdMapped")) {
			snprintf(lbuf, 100, "ShmemPmdMapped: %8" PRIu64 " kB\n", (uint64_t)0);
 			printme = lbuf;
 		} else if (startswith(line, "AnonHugePages")) {
			snprintf(lbuf, 100, "AnonHugePages:  %8" PRIu64 " kB\n",
				 mstat.total_rss_huge / 1024);
			printme = lbuf;
 		} else {
 			printme = line;
		}

		l = snprintf(cache, cache_size, "%s", printme);
		if (l < 0)
			return log_error(0, "Failed to write cache");
		if (l >= cache_size)
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

int proc_read(const char *path, char *buf, size_t size, off_t offset,
	      struct fuse_file_info *fi)
{
	struct file_info *f = INTTYPE_TO_PTR(fi->fh);

	switch (f->type) {
	case LXC_TYPE_PROC_MEMINFO:
		return proc_meminfo_read(buf, size, offset, fi);
	case LXC_TYPE_PROC_CPUINFO:
		return proc_cpuinfo_read(buf, size, offset, fi);
	case LXC_TYPE_PROC_UPTIME:
		return proc_uptime_read(buf, size, offset, fi);
	case LXC_TYPE_PROC_STAT:
		return proc_stat_read(buf, size, offset, fi);
	case LXC_TYPE_PROC_DISKSTATS:
		return proc_diskstats_read(buf, size, offset, fi);
	case LXC_TYPE_PROC_SWAPS:
		return proc_swaps_read(buf, size, offset, fi);
	case LXC_TYPE_PROC_LOADAVG:
		return proc_loadavg_read(buf, size, offset, fi);
	}

	return -EINVAL;
}
