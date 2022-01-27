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

#include "proc_cpuview.h"

#include "bindings.h"
#include "cgroup_fuse.h"
#include "cpuset_parse.h"
#include "cgroups/cgroup.h"
#include "cgroups/cgroup_utils.h"
#include "memory_utils.h"
#include "proc_loadavg.h"
#include "utils.h"

/* Data for CPU view */
struct cg_proc_stat {
	char *cg;
	struct cpuacct_usage *usage; 	/* Real usage as read from the host's /proc/stat. */
	struct cpuacct_usage *view; 	/* Usage stats reported to the container. */
	int cpu_count;
	pthread_mutex_t lock; 		/* For node manipulation. */
	struct cg_proc_stat *next;
};

struct cg_proc_stat_head {
	struct cg_proc_stat *next;
	time_t lastcheck;

	/*
	 * For access to the list. Reading can be parallel, pruning is exclusive.
	 */
	pthread_rwlock_t lock;
};

#define CPUVIEW_HASH_SIZE 100
static struct cg_proc_stat_head *proc_stat_history[CPUVIEW_HASH_SIZE];

static void reset_proc_stat_node(struct cg_proc_stat *node,
				 struct cpuacct_usage *usage, int cpu_count)
{
	lxcfs_debug("Resetting stat node for %s\n", node->cg);
	memcpy(node->usage, usage, sizeof(struct cpuacct_usage) * cpu_count);

	for (int i = 0; i < cpu_count; i++) {
		node->view[i].user = 0;
		node->view[i].system = 0;
		node->view[i].idle = 0;
	}

	node->cpu_count = cpu_count;
}

static bool expand_proc_stat_node(struct cg_proc_stat *node, int cpu_count)
{
	__do_free struct cpuacct_usage *new_usage = NULL, *new_view = NULL;

	/* Allocate new memory */
	new_usage = zalloc(sizeof(struct cpuacct_usage) * cpu_count);
	if (!new_usage)
		return false;

	new_view = zalloc(sizeof(struct cpuacct_usage) * cpu_count);
	if (!new_view)
		return false;

	/* Copy existing data & initialize new elements */
	for (int i = 0; i < cpu_count; i++) {
		if (i < node->cpu_count) {
			new_usage[i].user 	= node->usage[i].user;
			new_usage[i].system 	= node->usage[i].system;
			new_usage[i].idle 	= node->usage[i].idle;

			new_view[i].user 	= node->view[i].user;
			new_view[i].system 	= node->view[i].system;
			new_view[i].idle 	= node->view[i].idle;
		}
	}

	free(node->usage);
	node->usage = move_ptr(new_usage);

	free(node->view);
	node->view = move_ptr(new_view);
	node->cpu_count = cpu_count;

	return true;
}

static void free_proc_stat_node(struct cg_proc_stat *node)
{
	if (node) {
		/*
		 * We're abusing the usage pointer to indicate that
		 * pthread_mutex_init() was successful. Don't judge me.
		 */
		if (node->usage)
			pthread_mutex_destroy(&node->lock);
		free_disarm(node->cg);
		free_disarm(node->usage);
		free_disarm(node->view);
		free_disarm(node);
	}
}

define_cleanup_function(struct cg_proc_stat *, free_proc_stat_node);

static struct cg_proc_stat *add_proc_stat_node(struct cg_proc_stat *new_node)
{
	call_cleaner(free_proc_stat_node) struct cg_proc_stat *new = new_node;
	struct cg_proc_stat *rv = new_node;
	int hash = calc_hash(new->cg) % CPUVIEW_HASH_SIZE;
	struct cg_proc_stat_head *head = proc_stat_history[hash];
	struct cg_proc_stat *cur;

	pthread_rwlock_wrlock(&head->lock);

	if (!head->next) {
		head->next = move_ptr(new);
		goto out_rwlock_unlock;
	}

	cur = head->next;

	for (;;) {
		/*
		 * The node to be added is already present in the list, so
		 * free the newly allocated one and return the one we found.
		 */
		if (strcmp(cur->cg, new->cg) == 0) {
			rv = cur;
			goto out_rwlock_unlock;
		}

		/* Keep walking. */
		if (cur->next) {
			cur = cur->next;
			continue;
		}

		/* Add new node to end of list. */
		cur->next = move_ptr(new);
		goto out_rwlock_unlock;
	}

out_rwlock_unlock:
	pthread_rwlock_unlock(&head->lock);
	return move_ptr(rv);
}

static struct cg_proc_stat *new_proc_stat_node(struct cpuacct_usage *usage,
					       int cpu_count, const char *cg)
{
	call_cleaner(free_proc_stat_node) struct cg_proc_stat *node = NULL;
	__do_free struct cpuacct_usage *new_usage = NULL;

	node = zalloc(sizeof(struct cg_proc_stat));
	if (!node)
		return NULL;

	node->cg = strdup(cg);
	if (!node->cg)
		return NULL;

	new_usage = memdup(usage, sizeof(struct cpuacct_usage) * cpu_count);
	if (!new_usage)
		return NULL;

	node->view = zalloc(sizeof(struct cpuacct_usage) * cpu_count);
	if (!node->view)
		return NULL;

	node->cpu_count = cpu_count;

	if (pthread_mutex_init(&node->lock, NULL))
		return NULL;
	/*
	 * We're abusing the usage pointer to indicate that
	 * pthread_mutex_init() was successful. Don't judge me.
	 */
	node->usage = move_ptr(new_usage);

	return move_ptr(node);
}

static bool cgroup_supports(const char *controller, const char *cgroup,
			    const char *file)
{
	__do_free char *path = NULL;
	int cfd;

	cfd = get_cgroup_fd(controller);
	if (cfd < 0)
		return false;

	path = must_make_path_relative(cgroup, file, NULL);
	return faccessat(cfd, path, F_OK, 0) == 0;
}

static struct cg_proc_stat *prune_proc_stat_list(struct cg_proc_stat *node)
{
	struct cg_proc_stat *first = NULL;

	for (struct cg_proc_stat *prev = NULL; node; ) {
		if (!cgroup_supports("cpu", node->cg, "cpu.shares")) {
			struct cg_proc_stat *cur = node;

			if (prev)
				prev->next = node->next;
			else
				first = node->next;

			node = node->next;
			lxcfs_debug("Removing stat node for %s\n", cur);

			free_proc_stat_node(cur);
		} else {
			if (!first)
				first = node;
			prev = node;
			node = node->next;
		}
	}

	return first;
}

#define PROC_STAT_PRUNE_INTERVAL 10
static void prune_proc_stat_history(void)
{
	time_t now = time(NULL);

	for (int i = 0; i < CPUVIEW_HASH_SIZE; i++) {
		pthread_rwlock_wrlock(&proc_stat_history[i]->lock);

		if ((proc_stat_history[i]->lastcheck + PROC_STAT_PRUNE_INTERVAL) > now) {
			pthread_rwlock_unlock(&proc_stat_history[i]->lock);
			return;
		}

		if (proc_stat_history[i]->next) {
			proc_stat_history[i]->next = prune_proc_stat_list(proc_stat_history[i]->next);
			proc_stat_history[i]->lastcheck = now;
		}

		pthread_rwlock_unlock(&proc_stat_history[i]->lock);
	}
}

static struct cg_proc_stat *find_proc_stat_node(struct cg_proc_stat_head *head,
						const char *cg)
{
	struct cg_proc_stat *node;

	pthread_rwlock_rdlock(&head->lock);

	if (!head->next) {
		pthread_rwlock_unlock(&head->lock);
		return NULL;
	}

	node = head->next;

	do {
		if (strcmp(cg, node->cg) == 0)
			goto out;
	} while ((node = node->next));

	node = NULL;

out:
	pthread_rwlock_unlock(&head->lock);
	prune_proc_stat_history();
	return node;
}

static struct cg_proc_stat *find_or_create_proc_stat_node(struct cpuacct_usage *usage,
							  int cpu_count, const char *cg)
{
	int hash = calc_hash(cg) % CPUVIEW_HASH_SIZE;
	struct cg_proc_stat_head *head = proc_stat_history[hash];
	struct cg_proc_stat *node;

	node = find_proc_stat_node(head, cg);
	if (!node) {
		node = new_proc_stat_node(usage, cpu_count, cg);
		if (!node)
			return NULL;

		node = add_proc_stat_node(node);
		lxcfs_debug("New stat node (%d) for %s\n", cpu_count, cg);
	}

	pthread_mutex_lock(&node->lock);

	/*
	 * If additional CPUs on the host have been enabled, CPU usage counter
	 * arrays have to be expanded.
	 */
	if (node->cpu_count < cpu_count) {
		lxcfs_debug("Expanding stat node %d->%d for %s\n",
			    node->cpu_count, cpu_count, cg);

		if (!expand_proc_stat_node(node, cpu_count)) {
			pthread_mutex_unlock(&node->lock);
			return log_debug(NULL, "Unable to expand stat node %d->%d for %s", node->cpu_count, cpu_count, cg);
		}
	}

	return node;
}

static void add_cpu_usage(uint64_t *surplus, struct cpuacct_usage *usage,
			  uint64_t *counter, uint64_t threshold)
{
	uint64_t free_space, to_add;

	free_space = threshold - usage->user - usage->system;

	if (free_space > usage->idle)
		free_space = usage->idle;

	if (free_space > *surplus)
		to_add = *surplus;
	else
		to_add = free_space;

	*counter += to_add;
	usage->idle -= to_add;
	*surplus -= to_add;
}

static uint64_t diff_cpu_usage(struct cpuacct_usage *older,
			       struct cpuacct_usage *newer,
			       struct cpuacct_usage *diff, int cpu_count)
{
	uint64_t sum = 0;

	for (int i = 0; i < cpu_count; i++) {
		if (!newer[i].online)
			continue;

		/*
		 * When cpuset is changed on the fly, the CPUs might get
		 * reordered. We could either reset all counters, or check
		 * that the substractions below will return expected results.
		 */
		if (newer[i].user > older[i].user)
			diff[i].user = newer[i].user - older[i].user;
		else
			diff[i].user = 0;

		if (newer[i].system > older[i].system)
			diff[i].system = newer[i].system - older[i].system;
		else
			diff[i].system = 0;

		if (newer[i].idle > older[i].idle)
			diff[i].idle = newer[i].idle - older[i].idle;
		else
			diff[i].idle = 0;

		sum += diff[i].user;
		sum += diff[i].system;
		sum += diff[i].idle;
	}

	return sum;
}

/*
 * Read cgroup CPU quota parameters from `cpu.cfs_quota_us` or
 * `cpu.cfs_period_us`, depending on `param`. Parameter value is returned
 * through `value`.
 */
static bool read_cpu_cfs_param(const char *cg, const char *param, int64_t *value)
{
	__do_free char *str = NULL;
	char file[STRLITERALLEN("cpu.cfs_period_us") + 1];
	bool first = true;
	int ret;

	if (pure_unified_layout(cgroup_ops)) {
		first = !strcmp(param, "quota");
		ret = snprintf(file, sizeof(file), "cpu.max");
	} else {
		ret = snprintf(file, sizeof(file), "cpu.cfs_%s_us", param);
	}
	if (ret < 0 || (size_t)ret >= sizeof(file))
		return false;

	if (!cgroup_ops->get(cgroup_ops, "cpu", cg, file, &str))
		return false;

	return sscanf(str, first ? "%" PRId64 : "%*d %" PRId64, value) == 1;
}

/*
 * Return the exact number of visible CPUs based on CPU quotas.
 * If there is no quota set, zero is returned.
 */
static double exact_cpu_count(const char *cg)
{
	double rv;
	int nprocs;
	int64_t cfs_quota, cfs_period;

	if (!read_cpu_cfs_param(cg, "quota", &cfs_quota))
		return 0;

	if (!read_cpu_cfs_param(cg, "period", &cfs_period))
		return 0;

	if (cfs_quota <= 0 || cfs_period <= 0)
		return 0;

	rv = (double)cfs_quota / (double)cfs_period;

	nprocs = get_nprocs();

	if (rv > nprocs)
		rv = nprocs;

	return rv;
}

/*
 * Return true if cfs quota of the cgroup is neg / not set
 */
static bool cfs_quota_disabled(const char *cg)
{
	int64_t cfs_quota;

	if (!read_cpu_cfs_param(cg, "quota", &cfs_quota))
		return true;

	return cfs_quota < 0;
}

/*
 * Return the maximum number of visible CPUs based on CPU quotas.
 * If there is no quota set, zero is returned.
 */
int max_cpu_count(const char *cg)
{
	__do_free char *cpuset = NULL;
	int rv, nprocs;
	int64_t cfs_quota, cfs_period;
	int nr_cpus_in_cpuset = 0;

	if (!read_cpu_cfs_param(cg, "quota", &cfs_quota))
		return 0;

	if (!read_cpu_cfs_param(cg, "period", &cfs_period))
		return 0;

	cpuset = get_cpuset(cg);
	if (cpuset)
		nr_cpus_in_cpuset = cpu_number_in_cpuset(cpuset);

	if (cfs_quota <= 0 || cfs_period <= 0) {
		if (nr_cpus_in_cpuset > 0)
			return nr_cpus_in_cpuset;

		return 0;
	}

	rv = cfs_quota / cfs_period;

	/*
	 * In case quota/period does not yield a whole number, add one CPU for
	 * the remainder.
	 */
	if ((cfs_quota % cfs_period) > 0)
		rv += 1;

	nprocs = get_nprocs();
	if (rv > nprocs)
		rv = nprocs;

	/* Use min value in cpu quota and cpuset. */
	if (nr_cpus_in_cpuset > 0 && nr_cpus_in_cpuset < rv)
		rv = nr_cpus_in_cpuset;

	return rv;
}

int cpuview_proc_stat(const char *cg, const char *cpuset,
		      struct cpuacct_usage *cg_cpu_usage, int cg_cpu_usage_size,
		      FILE *f, char *buf, size_t buf_size)
{
	__do_free char *line = NULL;
	__do_free struct cpuacct_usage *diff = NULL;
	size_t linelen = 0, total_len = 0;
	int curcpu = -1; /* cpu numbering starts at 0 */
	int physcpu, i;
	int cpu_cnt = 0;
	uint64_t user = 0, nice = 0, system = 0, idle = 0, iowait = 0, irq = 0,
		 softirq = 0, steal = 0, guest = 0, guest_nice = 0;
	uint64_t user_sum = 0, system_sum = 0, idle_sum = 0;
	uint64_t user_surplus = 0, system_surplus = 0;
	int nprocs, max_cpus;
	ssize_t l;
	uint64_t total_sum, threshold;
	struct cg_proc_stat *stat_node;

	nprocs = get_nprocs_conf();
	if (cg_cpu_usage_size < nprocs)
		nprocs = cg_cpu_usage_size;

	/* Read all CPU stats and stop when we've encountered other lines */
	while (getline(&line, &linelen, f) != -1) {
		int ret;
		char cpu_char[10]; /* That's a lot of cores */
		uint64_t all_used, cg_used;

		if (strlen(line) == 0)
			continue;

		/* not a ^cpuN line containing a number N */
		if (sscanf(line, "cpu%9[^ ]", cpu_char) != 1)
			break;

		if (sscanf(cpu_char, "%d", &physcpu) != 1)
			continue;

		if (physcpu >= cg_cpu_usage_size)
			continue;

		curcpu++;
		cpu_cnt++;

		if (!cpu_in_cpuset(physcpu, cpuset)) {
			for (i = curcpu; i <= physcpu; i++)
				cg_cpu_usage[i].online = false;
			continue;
		}

		if (curcpu < physcpu) {
			/* Some CPUs may be disabled */
			for (i = curcpu; i < physcpu; i++)
				cg_cpu_usage[i].online = false;

			curcpu = physcpu;
		}

		cg_cpu_usage[curcpu].online = true;

		ret = sscanf(line, "%*s %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "lu",
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
		if (ret != 10)
			continue;

		all_used = user + nice + system + iowait + irq + softirq + steal + guest + guest_nice;
		cg_used = cg_cpu_usage[curcpu].user + cg_cpu_usage[curcpu].system;

		if (all_used >= cg_used) {
			cg_cpu_usage[curcpu].idle = idle + (all_used - cg_used);
		} else {
			lxcfs_v("cpu%d from %s has unexpected cpu time: %" PRIu64 " in /proc/stat, %" PRIu64 " in cpuacct.usage_all; unable to determine idle time",
				curcpu, cg, all_used, cg_used);
			cg_cpu_usage[curcpu].idle = idle;
		}
	}

	/* Cannot use more CPUs than is available in cpuset. */
	max_cpus = max_cpu_count(cg);
	if (max_cpus > cpu_cnt || !max_cpus)
		max_cpus = cpu_cnt;

	/* takes lock pthread_mutex_lock(&node->lock) */
	stat_node = find_or_create_proc_stat_node(cg_cpu_usage, nprocs, cg);
	if (!stat_node)
		return log_error(0, "Failed to find/create stat node for %s", cg);

	diff = zalloc(sizeof(struct cpuacct_usage) * nprocs);
	if (!diff)
		goto out_pthread_mutex_unlock;

	/*
	 * If the new values are LOWER than values stored in memory, it means
	 * the cgroup has been reset/recreated and we should reset too.
	 */
	for (curcpu = 0; curcpu < nprocs; curcpu++) {
		if (!cg_cpu_usage[curcpu].online)
			continue;

		if (cg_cpu_usage[curcpu].user < stat_node->usage[curcpu].user)
			reset_proc_stat_node(stat_node, cg_cpu_usage, nprocs);

		break;
	}

	total_sum = diff_cpu_usage(stat_node->usage, cg_cpu_usage, diff, nprocs);

	for (curcpu = 0, i = -1; curcpu < nprocs; curcpu++) {
		stat_node->usage[curcpu].online = cg_cpu_usage[curcpu].online;

		if (!stat_node->usage[curcpu].online)
			continue;

		i++;

		stat_node->usage[curcpu].user 	+= diff[curcpu].user;
		stat_node->usage[curcpu].system += diff[curcpu].system;
		stat_node->usage[curcpu].idle 	+= diff[curcpu].idle;

		if (max_cpus > 0 && i >= max_cpus) {
			user_surplus 	+= diff[curcpu].user;
			system_surplus 	+= diff[curcpu].system;
		}
	}

	/* Calculate usage counters of visible CPUs */
	if (max_cpus > 0) {
		uint64_t diff_user = 0;
		uint64_t diff_system = 0;
		uint64_t diff_idle = 0;
		uint64_t max_diff_idle = 0;
		uint64_t max_diff_idle_index = 0;
		double exact_cpus;
		/* threshold = maximum usage per cpu, including idle */
		threshold = total_sum / cpu_cnt * max_cpus;

		for (curcpu = 0, i = -1; curcpu < nprocs; curcpu++) {
			if (!stat_node->usage[curcpu].online)
				continue;

			i++;

			if (i == max_cpus)
				break;

			if (diff[curcpu].user + diff[curcpu].system >= threshold)
				continue;

			/* Add user */
			add_cpu_usage(&user_surplus, &diff[curcpu],
				      &diff[curcpu].user, threshold);

			if (diff[curcpu].user + diff[curcpu].system >= threshold)
				continue;

			/* If there is still room, add system */
			add_cpu_usage(&system_surplus, &diff[curcpu],
				      &diff[curcpu].system, threshold);
		}

		if (user_surplus > 0)
			lxcfs_debug("leftover user: %" PRIu64 "for %s\n", user_surplus, cg);
		if (system_surplus > 0)
			lxcfs_debug("leftover system: %" PRIu64 "for %s\n", system_surplus, cg);

		for (curcpu = 0, i = -1; curcpu < nprocs; curcpu++) {
			if (!stat_node->usage[curcpu].online)
				continue;

			i++;

			if (i == max_cpus)
				break;

			stat_node->view[curcpu].user 	+= diff[curcpu].user;
			stat_node->view[curcpu].system 	+= diff[curcpu].system;
			stat_node->view[curcpu].idle 	+= diff[curcpu].idle;

			diff_user 	+= diff[curcpu].user;
			diff_system 	+= diff[curcpu].system;
			diff_idle 	+= diff[curcpu].idle;
			if (diff[curcpu].idle > max_diff_idle) {
				max_diff_idle 		= diff[curcpu].idle;
				max_diff_idle_index 	= curcpu;
			}

			lxcfs_v("curcpu: %d, diff_user: %" PRIu64 ", diff_system: %" PRIu64 ", diff_idle: %" PRIu64 "\n", curcpu, diff[curcpu].user, diff[curcpu].system, diff[curcpu].idle);
		}
		lxcfs_v("total. diff_user: %" PRIu64 ", diff_system: %" PRIu64 ", diff_idle: %" PRIu64 "\n", diff_user, diff_system, diff_idle);

		for (curcpu = 0; curcpu < nprocs; curcpu++) {
			user_sum 	+= stat_node->view[curcpu].user;
			system_sum 	+= stat_node->view[curcpu].system;
			idle_sum 	+= stat_node->view[curcpu].idle;
		}

		/* revise cpu usage view to support partial cpu case. */
		exact_cpus = exact_cpu_count(cg);

		/* skip revise cpu when cfs quota is disabled (exact_cpus == 0) */
		if (!cfs_quota_disabled(cg) && exact_cpus < (double)max_cpus){
			uint64_t delta = (uint64_t)((double)(diff_user + diff_system + diff_idle) * (1 - exact_cpus / (double)max_cpus));

			lxcfs_v("revising cpu usage view to match the exact cpu count [%f]\n", exact_cpus);
			lxcfs_v("delta: %" PRIu64 "\n", delta);
			lxcfs_v("idle_sum before: %" PRIu64 "\n", idle_sum);
			if (idle_sum > delta)
				idle_sum = idle_sum - delta;
			else
				idle_sum = 0;
			lxcfs_v("idle_sum after: %l" PRIu64 "\n", idle_sum);

			curcpu = max_diff_idle_index;
			lxcfs_v("curcpu: %d, idle before: %" PRIu64 "\n", curcpu, stat_node->view[curcpu].idle);
			if (stat_node->view[curcpu].idle > delta)
				stat_node->view[curcpu].idle = stat_node->view[curcpu].idle - delta;
			else
				stat_node->view[curcpu].idle = 0;
			lxcfs_v("curcpu: %d, idle after: %" PRIu64 "\n", curcpu, stat_node->view[curcpu].idle);
		}
	} else {
		for (curcpu = 0; curcpu < nprocs; curcpu++) {
			if (!stat_node->usage[curcpu].online)
				continue;

			stat_node->view[curcpu].user 	= stat_node->usage[curcpu].user;
			stat_node->view[curcpu].system 	= stat_node->usage[curcpu].system;
			stat_node->view[curcpu].idle 	= stat_node->usage[curcpu].idle;

			user_sum 	+= stat_node->view[curcpu].user;
			system_sum 	+= stat_node->view[curcpu].system;
			idle_sum 	+= stat_node->view[curcpu].idle;
		}
	}

	/* Render the file */
	/* cpu-all */
	l = snprintf(buf, buf_size,
		     "cpu  %" PRIu64 " 0 %" PRIu64 " %" PRIu64 " 0 0 0 0 0 0\n",
		     user_sum, system_sum, idle_sum);
	lxcfs_v("cpu-all: %s\n", buf);
	if (l < 0) {
		lxcfs_error("Failed to write cache");
		total_len = 0;
		goto out_pthread_mutex_unlock;
	}
	if ((size_t)l >= buf_size) {
		lxcfs_error("Write to cache was truncated");
		total_len = 0;
		goto out_pthread_mutex_unlock;
	}

	buf += l;
	buf_size -= l;
	total_len += l;

	/* Render visible CPUs 
	Assume there are K CPUs: 0, 1, 2, ..., K-1.
	Among them, there are M online CPUs with index: a1, a2, ... aN ... aM (M >= N)
	N = max_cpus, M = number of online CPUs

	There will be N rendered cpus, indexed from 0 to N-1, cpu times of the cpus are calculated from those formula:
	- user_time[0] = stat_node->view[0].user + stat_node->view[1].user + ... + stat_node->view[a1].user
	- user_time[1] = stat_node->view[a1+1].user + stat_node->view[a1+1].user + ... + stat_node->view[a2].user
	...
	- user_time[N-2] = stat_node->view[a(N-2)+1].user + stat_node->view[a(N-2)+2].user + ... 
	                    + stat_node->view[a(N-1)].user
	- user_time[N-1] = stat_node->view[a(N-1)+1].user + stat_node->view[a(N-1)+2].user + ...
	                    + stat_node->view[aN] + ... + stat_node->view[K-1] (sum of all remaining CPUs)
	
	Similar formula applied for system and idle time
	*/

	uint64_t curcpu_view_user_sum = 0, curcpu_view_system_sum = 0, curcpu_view_idle_sum = 0;
	for (curcpu = 0, i = -1; curcpu < nprocs; curcpu++) {
		curcpu_view_user_sum += stat_node->view[curcpu].user;
		curcpu_view_system_sum += stat_node->view[curcpu].system;
		curcpu_view_idle_sum += stat_node->view[curcpu].idle;

		if (!stat_node->usage[curcpu].online && curcpu < nprocs - 1) {
			continue;
		}
		
		i++;

		if (max_cpus > 0 && i >= max_cpus) {
			// max(i) = count(rendered cpus) = max_cpus - 1
			i--;
		}

		if (max_cpus > 0 && i == max_cpus - 1 && curcpu < nprocs - 1) {
			// last 'rendered' cpu, sum until reaches the last cpu
			continue;
		}

		l = snprintf(buf, buf_size, "cpu%d %" PRIu64 " 0 %" PRIu64 " %" PRIu64 " 0 0 0 0 0 0\n",
			     i,
			     curcpu_view_user_sum,
			     curcpu_view_system_sum,
			     curcpu_view_idle_sum);
		lxcfs_v("cpu: %s\n", buf);
		if (l < 0) {
			lxcfs_error("Failed to write cache");
			total_len = 0;
			goto out_pthread_mutex_unlock;
		}
		if ((size_t)l >= buf_size) {
			lxcfs_error("Write to cache was truncated");
			total_len = 0;
			goto out_pthread_mutex_unlock;
		}

		buf += l;
		buf_size -= l;
		total_len += l;

		curcpu_view_user_sum = 0;
		curcpu_view_system_sum = 0;
		curcpu_view_idle_sum = 0;
	}

	/* Pass the rest of /proc/stat, start with the last line read */
	l = snprintf(buf, buf_size, "%s", line);
	if (l < 0) {
		lxcfs_error("Failed to write cache");
		total_len = 0;
		goto out_pthread_mutex_unlock;
	}
	if ((size_t)l >= buf_size) {
		lxcfs_error("Write to cache was truncated");
		total_len = 0;
		goto out_pthread_mutex_unlock;
	}

	buf += l;
	buf_size -= l;
	total_len += l;

	/* Pass the rest of the host's /proc/stat */
	while (getline(&line, &linelen, f) != -1) {
		l = snprintf(buf, buf_size, "%s", line);
		if (l < 0) {
			lxcfs_error("Failed to write cache");
			total_len = 0;
			goto out_pthread_mutex_unlock;
		}
		if ((size_t)l >= buf_size) {
			lxcfs_error("Write to cache was truncated");
			total_len = 0;
			goto out_pthread_mutex_unlock;
		}

		buf += l;
		buf_size -= l;
		total_len += l;
	}

out_pthread_mutex_unlock:
	if (stat_node)
		pthread_mutex_unlock(&stat_node->lock);

	return total_len;
}

/*
 * check whether this is a '^processor" line in /proc/cpuinfo
 */
static inline bool is_processor_line(const char *line)
{
	int cpu;
	return sscanf(line, "processor       : %d", &cpu) == 1;
}

static inline bool cpuline_in_cpuset(const char *line, const char *cpuset)
{
	int cpu;

	if (sscanf(line, "processor       : %d", &cpu) == 1)
		return cpu_in_cpuset(cpu, cpuset);

	return false;
}

int proc_cpuinfo_read(char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	__do_free char *cg = NULL, *cpuset = NULL, *line = NULL;
	__do_free void *fopen_cache = NULL;
	__do_fclose FILE *f = NULL;
	struct fuse_context *fc = fuse_get_context();
	struct lxcfs_opts *opts = (struct lxcfs_opts *)fc->private_data;
	struct file_info *d = INTTYPE_TO_PTR(fi->fh);
	size_t linelen = 0, total_len = 0;
	bool am_printing = false, firstline = true, is_s390x = false;
	int curcpu = -1, cpu, max_cpus = 0;
	bool use_view;
	char *cache = d->buf;
	size_t cache_size = d->buflen;

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

	cg = get_pid_cgroup(initpid, "cpuset");
	if (!cg)
		return read_file_fuse("proc/cpuinfo", buf, size, d);
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

	f = fopen_cached("/proc/cpuinfo", "re", &fopen_cache);
	if (!f)
		return 0;

	while (getline(&line, &linelen, f) != -1) {
		ssize_t l;
		if (firstline) {
			firstline = false;
			if (strstr(line, "IBM/S390") != NULL) {
				is_s390x = true;
				am_printing = true;
				continue;
			}
		}

		if (strncmp(line, "# processors:", 12) == 0)
			continue;

		if (is_processor_line(line)) {
			if (use_view && max_cpus > 0 && (curcpu + 1) == max_cpus)
				break;

			am_printing = cpuline_in_cpuset(line, cpuset);
			if (am_printing) {
				curcpu++;
				l = snprintf(cache, cache_size, "processor	: %d\n", curcpu);
				if (l < 0)
					return log_error(0, "Failed to write cache");
				if ((size_t)l >= cache_size)
					return log_error(0, "Write to cache was truncated");
				cache += l;
				cache_size -= l;
				total_len += l;
			}
			continue;
		} else if (is_s390x && sscanf(line, "processor %d:", &cpu) == 1) {
			char *p;

			if (use_view && max_cpus > 0 && (curcpu + 1) == max_cpus)
				break;

			if (!cpu_in_cpuset(cpu, cpuset))
				continue;

			curcpu ++;
			p = strchr(line, ':');
			if (!p || !*p)
				return 0;
			p++;

			l = snprintf(cache, cache_size, "processor %d:%s", curcpu, p);
			if (l < 0)
				return log_error(0, "Failed to write cache");
			if ((size_t)l >= cache_size)
				return log_error(0, "Write to cache was truncated");

			cache += l;
			cache_size -= l;
			total_len += l;
			continue;

		}
		if (am_printing) {
			l = snprintf(cache, cache_size, "%s", line);
			if (l < 0)
				return log_error(0, "Failed to write cache");
			if ((size_t)l >= cache_size)
				return log_error(0, "Write to cache was truncated");

			cache += l;
			cache_size -= l;
			total_len += l;
		}
	}

	if (is_s390x) {
		__do_free char *origcache = d->buf;
		ssize_t l;

		d->buf = malloc(d->buflen);
		if (!d->buf) {
			d->buf = move_ptr(origcache);
			return 0;
		}

		cache = d->buf;
		cache_size = d->buflen;
		total_len = 0;
		l = snprintf(cache, cache_size, "vendor_id       : IBM/S390\n");
		if (l < 0 || (size_t)l >= cache_size)
			return 0;

		cache_size -= l;
		cache += l;
		total_len += l;
		l = snprintf(cache, cache_size, "# processors    : %d\n", curcpu + 1);
		if (l < 0 || (size_t)l >= cache_size)
			return 0;

		cache_size -= l;
		cache += l;
		total_len += l;
		l = snprintf(cache, cache_size, "%s", origcache);
		if (l < 0 || (size_t)l >= cache_size)
			return 0;
		total_len += l;
	}

	d->cached = 1;
	d->size = total_len;
	if (total_len > size)
		total_len = size;

	/* read from off 0 */
	memcpy(buf, d->buf, total_len);

	return total_len;
}

/*
 * Returns 0 on success.
 * It is the caller's responsibility to free `return_usage`, unless this
 * function returns an error.
 */
int read_cpuacct_usage_all(char *cg, char *cpuset,
			   struct cpuacct_usage **return_usage, int *size)
{
	__do_free char *usage_str = NULL;
	__do_free struct cpuacct_usage *cpu_usage = NULL;
	int i = 0, j = 0, read_pos = 0, read_cnt = 0;
	int cpucount;
	int ret;
	int cg_cpu;
	uint64_t cg_user, cg_system;
	int64_t ticks_per_sec;

	ticks_per_sec = sysconf(_SC_CLK_TCK);
	if (ticks_per_sec < 0 && errno == EINVAL) {
		lxcfs_debug("%m - Failed to determine number of ticks per second");
		return -1;
	}

	cpucount = get_nprocs_conf();
	cpu_usage = malloc(sizeof(struct cpuacct_usage) * cpucount);
	if (!cpu_usage)
		return -ENOMEM;

	memset(cpu_usage, 0, sizeof(struct cpuacct_usage) * cpucount);
	if (!cgroup_ops->get(cgroup_ops, "cpuacct", cg, "cpuacct.usage_all", &usage_str)) {
		char *sep = " \t\n";
		char *tok;

		/* Read cpuacct.usage_percpu instead. */
		lxcfs_debug("Falling back to cpuacct.usage_percpu");
		if (!cgroup_ops->get(cgroup_ops, "cpuacct", cg, "cpuacct.usage_percpu", &usage_str))
			return -1;

		lxc_iterate_parts(tok, usage_str, sep) {
			uint64_t percpu_user;

			if (i >= cpucount)
				break;

			tok = trim_whitespace_in_place(tok);
			ret = safe_uint64(tok, &percpu_user, 10);
			if (ret)
				return -1;

			/* Convert the time from nanoseconds to USER_HZ */
			cpu_usage[i].user = percpu_user / 1000.0 / 1000 / 1000 * ticks_per_sec;
			cpu_usage[i].system = cpu_usage[i].user;
			i++;
			lxcfs_debug("cpu%d with time %s", i, tok);
		}
	} else {
		if (sscanf(usage_str, "cpu user system\n%n", &read_cnt) != 0)
			return log_error(-1, "read_cpuacct_usage_all reading first line from %s/cpuacct.usage_all failed", cg);

		read_pos += read_cnt;

		for (i = 0, j = 0; i < cpucount; i++) {
			ret = sscanf(usage_str + read_pos,
					"%d %" PRIu64 " %" PRIu64 "\n%n", &cg_cpu,
					&cg_user, &cg_system, &read_cnt);

			if (ret == EOF)
				break;

			if (ret != 3)
				return log_error(-EINVAL, "Failed to parse cpuacct.usage_all line %s from cgroup %s",
						usage_str + read_pos, cg);

			read_pos += read_cnt;

			/* Convert the time from nanoseconds to USER_HZ */
			cpu_usage[j].user = cg_user / 1000.0 / 1000 / 1000 * ticks_per_sec;
			cpu_usage[j].system = cg_system / 1000.0 / 1000 / 1000 * ticks_per_sec;
			j++;
		}
	}

	*return_usage = move_ptr(cpu_usage);
	*size = cpucount;
	return 0;
}

static bool cpuview_init_head(struct cg_proc_stat_head **head)
{
	__do_free struct cg_proc_stat_head *h;

	h = zalloc(sizeof(struct cg_proc_stat_head));
	if (!h)
		return false;

	if (pthread_rwlock_init(&h->lock, NULL))
		return false;

	h->lastcheck = time(NULL);

	*head = move_ptr(h);
	return true;
}

bool init_cpuview(void)
{
	int i;

	for (i = 0; i < CPUVIEW_HASH_SIZE; i++)
		proc_stat_history[i] = NULL;

	for (i = 0; i < CPUVIEW_HASH_SIZE; i++) {
		if (!cpuview_init_head(&proc_stat_history[i]))
			goto err;
	}

	return true;

err:
	for (i = 0; i < CPUVIEW_HASH_SIZE; i++) {
		if (proc_stat_history[i])
			free_disarm(proc_stat_history[i]);
	}

	return false;
}

static void cpuview_free_head(struct cg_proc_stat_head *head)
{
	struct cg_proc_stat *node;

	if (head->next) {
		node = head->next;

		for (;;) {
			struct cg_proc_stat *cur = node;
			node = node->next;
			free_proc_stat_node(cur);
			if (!node)
				break;
		}
	}

	pthread_rwlock_destroy(&head->lock);
	free_disarm(head);
}

void free_cpuview(void)
{
	for (int i = 0; i < CPUVIEW_HASH_SIZE; i++)
		if (proc_stat_history[i])
			cpuview_free_head(proc_stat_history[i]);
}
