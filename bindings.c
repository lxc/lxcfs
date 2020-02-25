/* lxcfs
 *
 * Copyright © 2014-2016 Canonical, Inc
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
 *
 * See COPYING file for details.
 */

#define FUSE_USE_VERSION 26

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
#include "memory_utils.h"
#include "utils.h"

/* Define pivot_root() if missing from the C library */
#ifndef HAVE_PIVOT_ROOT
static int pivot_root(const char * new_root, const char * put_old)
{
#ifdef __NR_pivot_root
return syscall(__NR_pivot_root, new_root, put_old);
#else
errno = ENOSYS;
return -1;
#endif
}
#else
extern int pivot_root(const char * new_root, const char * put_old);
#endif

struct cpuacct_usage {
	uint64_t user;
	uint64_t system;
	uint64_t idle;
	bool online;
};

/* The function of hash table.*/
#define LOAD_SIZE 100 /*the size of hash_table */
#define FLUSH_TIME 5  /*the flush rate */
#define DEPTH_DIR 3   /*the depth of per cgroup */
/* The function of calculate loadavg .*/
#define FSHIFT		11		/* nr of bits of precision */
#define FIXED_1		(1<<FSHIFT)	/* 1.0 as fixed-point */
#define EXP_1		1884		/* 1/exp(5sec/1min) as fixed-point */
#define EXP_5		2014		/* 1/exp(5sec/5min) */
#define EXP_15		2037		/* 1/exp(5sec/15min) */
#define LOAD_INT(x) ((x) >> FSHIFT)
#define LOAD_FRAC(x) LOAD_INT(((x) & (FIXED_1-1)) * 100)
/*
 * This parameter is used for proc_loadavg_read().
 * 1 means use loadavg, 0 means not use.
 */
static int loadavg = 0;
static volatile sig_atomic_t loadavg_stop = 0;
static int calc_hash(const char *name)
{
	unsigned int hash = 0;
	unsigned int x = 0;
	/* ELFHash algorithm. */
	while (*name) {
		hash = (hash << 4) + *name++;
		x = hash & 0xf0000000;
		if (x != 0)
			hash ^= (x >> 24);
		hash &= ~x;
	}
	return (hash & 0x7fffffff);
}

struct load_node {
	char *cg;  /*cg */
	unsigned long avenrun[3];		/* Load averages */
	unsigned int run_pid;
	unsigned int total_pid;
	unsigned int last_pid;
	int cfd; /* The file descriptor of the mounted cgroup */
	struct  load_node *next;
	struct  load_node **pre;
};

struct load_head {
	/*
	 * The lock is about insert load_node and refresh load_node.To the first
	 * load_node of each hash bucket, insert and refresh in this hash bucket is
	 * mutually exclusive.
	 */
	pthread_mutex_t lock;
	/*
	 * The rdlock is about read loadavg and delete load_node.To each hash
	 * bucket, read and delete is mutually exclusive. But at the same time, we
	 * allow paratactic read operation. This rdlock is at list level.
	 */
	pthread_rwlock_t rdlock;
	/*
	 * The rilock is about read loadavg and insert load_node.To the first
	 * load_node of each hash bucket, read and insert is mutually exclusive.
	 * But at the same time, we allow paratactic read operation.
	 */
	pthread_rwlock_t rilock;
	struct load_node *next;
};

static struct load_head load_hash[LOAD_SIZE]; /* hash table */
/*
 * init_load initialize the hash table.
 * Return 0 on success, return -1 on failure.
 */
static int init_load(void)
{
	int i;
	int ret;

	for (i = 0; i < LOAD_SIZE; i++) {
		load_hash[i].next = NULL;
		ret = pthread_mutex_init(&load_hash[i].lock, NULL);
		if (ret != 0) {
			lxcfs_error("%s\n", "Failed to initialize lock");
			goto out3;
		}
		ret = pthread_rwlock_init(&load_hash[i].rdlock, NULL);
		if (ret != 0) {
			lxcfs_error("%s\n", "Failed to initialize rdlock");
			goto out2;
		}
		ret = pthread_rwlock_init(&load_hash[i].rilock, NULL);
		if (ret != 0) {
			lxcfs_error("%s\n", "Failed to initialize rilock");
			goto out1;
		}
	}
	return 0;
out1:
	pthread_rwlock_destroy(&load_hash[i].rdlock);
out2:
	pthread_mutex_destroy(&load_hash[i].lock);
out3:
	while (i > 0) {
		i--;
		pthread_mutex_destroy(&load_hash[i].lock);
		pthread_rwlock_destroy(&load_hash[i].rdlock);
		pthread_rwlock_destroy(&load_hash[i].rilock);
	}
	return -1;
}

static void insert_node(struct load_node **n, int locate)
{
	struct load_node *f;

	pthread_mutex_lock(&load_hash[locate].lock);
	pthread_rwlock_wrlock(&load_hash[locate].rilock);
	f = load_hash[locate].next;
	load_hash[locate].next = *n;

	(*n)->pre = &(load_hash[locate].next);
	if (f)
		f->pre = &((*n)->next);
	(*n)->next = f;
	pthread_mutex_unlock(&load_hash[locate].lock);
	pthread_rwlock_unlock(&load_hash[locate].rilock);
}
/*
 * locate_node() finds special node. Not return NULL means success.
 * It should be noted that rdlock isn't unlocked at the end of code
 * because this function is used to read special node. Delete is not
 * allowed before read has ended.
 * unlock rdlock only in proc_loadavg_read().
 */
static struct load_node *locate_node(char *cg, int locate)
{
	struct load_node *f = NULL;
	int i = 0;

	pthread_rwlock_rdlock(&load_hash[locate].rilock);
	pthread_rwlock_rdlock(&load_hash[locate].rdlock);
	if (load_hash[locate].next == NULL) {
		pthread_rwlock_unlock(&load_hash[locate].rilock);
		return f;
	}
	f = load_hash[locate].next;
	pthread_rwlock_unlock(&load_hash[locate].rilock);
	while (f && ((i = strcmp(f->cg, cg)) != 0))
		f = f->next;
	return f;
}

/* Delete the load_node n and return the next node of it. */
static struct load_node *del_node(struct load_node *n, int locate)
{
	struct load_node *g;

	pthread_rwlock_wrlock(&load_hash[locate].rdlock);
	if (n->next == NULL) {
		*(n->pre) = NULL;
	} else {
		*(n->pre) = n->next;
		n->next->pre = n->pre;
	}
	g = n->next;
	free_disarm(n->cg);
	free_disarm(n);
	pthread_rwlock_unlock(&load_hash[locate].rdlock);
	return g;
}

static void load_free(void)
{
	struct load_node *f, *p;

	for (int i = 0; i < LOAD_SIZE; i++) {
		pthread_mutex_lock(&load_hash[i].lock);
		pthread_rwlock_wrlock(&load_hash[i].rilock);
		pthread_rwlock_wrlock(&load_hash[i].rdlock);
		if (load_hash[i].next == NULL) {
			pthread_mutex_unlock(&load_hash[i].lock);
			pthread_mutex_destroy(&load_hash[i].lock);
			pthread_rwlock_unlock(&load_hash[i].rilock);
			pthread_rwlock_destroy(&load_hash[i].rilock);
			pthread_rwlock_unlock(&load_hash[i].rdlock);
			pthread_rwlock_destroy(&load_hash[i].rdlock);
			continue;
		}

		for (f = load_hash[i].next; f;) {
			free_disarm(f->cg);
			p = f->next;
			free_disarm(f);
			f = p;
		}

		pthread_mutex_unlock(&load_hash[i].lock);
		pthread_mutex_destroy(&load_hash[i].lock);
		pthread_rwlock_unlock(&load_hash[i].rilock);
		pthread_rwlock_destroy(&load_hash[i].rilock);
		pthread_rwlock_unlock(&load_hash[i].rdlock);
		pthread_rwlock_destroy(&load_hash[i].rdlock);
	}
}

/* Data for CPU view */
struct cg_proc_stat {
	char *cg;
	struct cpuacct_usage *usage; // Real usage as read from the host's /proc/stat
	struct cpuacct_usage *view; // Usage stats reported to the container
	int cpu_count;
	pthread_mutex_t lock; // For node manipulation
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

static bool cpuview_init_head(struct cg_proc_stat_head **head)
{
	*head = malloc(sizeof(struct cg_proc_stat_head));
	if (!(*head)) {
		lxcfs_error("%s\n", strerror(errno));
		return false;
	}

	(*head)->lastcheck = time(NULL);
	(*head)->next = NULL;

	if (pthread_rwlock_init(&(*head)->lock, NULL) != 0) {
		lxcfs_error("%s\n", "Failed to initialize list lock");
		free_disarm(*head);
		return false;
	}

	return true;
}

static bool init_cpuview()
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

static void free_proc_stat_node(struct cg_proc_stat *node)
{
	pthread_mutex_destroy(&node->lock);
	free_disarm(node->cg);
	free_disarm(node->usage);
	free_disarm(node->view);
	free_disarm(node);
}

static void cpuview_free_head(struct cg_proc_stat_head *head)
{
	struct cg_proc_stat *node, *tmp;

	if (head->next) {
		node = head->next;

		for (;;) {
			tmp = node;
			node = node->next;
			free_proc_stat_node(tmp);

			if (!node)
				break;
		}
	}

	pthread_rwlock_destroy(&head->lock);
	free_disarm(head);
}

static void free_cpuview()
{
	int i;

	for (i = 0; i < CPUVIEW_HASH_SIZE; i++) {
		if (proc_stat_history[i])
			cpuview_free_head(proc_stat_history[i]);
	}
}

/*
 * A table caching which pid is init for a pid namespace.
 * When looking up which pid is init for $qpid, we first
 * 1. Stat /proc/$qpid/ns/pid.
 * 2. Check whether the ino_t is in our store.
 *   a. if not, fork a child in qpid's ns to send us
 *	 ucred.pid = 1, and read the initpid.  Cache
 *	 initpid and creation time for /proc/initpid
 *	 in a new store entry.
 *   b. if so, verify that /proc/initpid still matches
 *	 what we have saved.  If not, clear the store
 *	 entry and go back to a.  If so, return the
 *	 cached initpid.
 */
struct pidns_init_store {
	ino_t ino;          // inode number for /proc/$pid/ns/pid
	pid_t initpid;      // the pid of nit in that ns
	long int ctime;     // the time at which /proc/$initpid was created
	struct pidns_init_store *next;
	long int lastcheck;
};

/* lol - look at how they are allocated in the kernel */
#define PIDNS_HASH_SIZE 4096
#define HASH(x) ((x) % PIDNS_HASH_SIZE)

static struct pidns_init_store *pidns_hash_table[PIDNS_HASH_SIZE];
static pthread_mutex_t pidns_store_mutex = PTHREAD_MUTEX_INITIALIZER;
static void lock_mutex(pthread_mutex_t *l)
{
	int ret;

	if ((ret = pthread_mutex_lock(l)) != 0) {
		lxcfs_error("returned:%d %s\n", ret, strerror(ret));
		exit(1);
	}
}

struct cgroup_ops *cgroup_ops;

static void unlock_mutex(pthread_mutex_t *l)
{
	int ret;

	if ((ret = pthread_mutex_unlock(l)) != 0) {
		lxcfs_error("returned:%d %s\n", ret, strerror(ret));
		exit(1);
	}
}

static void store_lock(void)
{
	lock_mutex(&pidns_store_mutex);
}

static void store_unlock(void)
{
	unlock_mutex(&pidns_store_mutex);
}

/* Must be called under store_lock */
static bool initpid_still_valid(struct pidns_init_store *e, struct stat *nsfdsb)
{
	struct stat initsb;
	char fnam[100];

	snprintf(fnam, 100, "/proc/%d", e->initpid);
	if (stat(fnam, &initsb) < 0)
		return false;

	lxcfs_debug("Comparing ctime %ld == %ld for pid %d.\n", e->ctime,
		    initsb.st_ctime, e->initpid);

	if (e->ctime != initsb.st_ctime)
		return false;
	return true;
}

/* Must be called under store_lock */
static void remove_initpid(struct pidns_init_store *e)
{
	struct pidns_init_store *tmp;
	int h;

	lxcfs_debug("Remove_initpid: removing entry for %d.\n", e->initpid);

	h = HASH(e->ino);
	if (pidns_hash_table[h] == e) {
		pidns_hash_table[h] = e->next;
		free_disarm(e);
		return;
	}

	tmp = pidns_hash_table[h];
	while (tmp) {
		if (tmp->next == e) {
			tmp->next = e->next;
			free_disarm(e);
			return;
		}
		tmp = tmp->next;
	}
}

#define PURGE_SECS 5
/* Must be called under store_lock */
static void prune_initpid_store(void)
{
	static long int last_prune = 0;
	struct pidns_init_store *e, *prev, *delme;
	long int now, threshold;
	int i;

	if (!last_prune) {
		last_prune = time(NULL);
		return;
	}
	now = time(NULL);
	if (now < last_prune + PURGE_SECS)
		return;

	lxcfs_debug("%s\n", "Pruning.");

	last_prune = now;
	threshold = now - 2 * PURGE_SECS;

	for (i = 0; i < PIDNS_HASH_SIZE; i++) {
		for (prev = NULL, e = pidns_hash_table[i]; e; ) {
			if (e->lastcheck < threshold) {

				lxcfs_debug("Removing cached entry for %d.\n", e->initpid);

				delme = e;
				if (prev)
					prev->next = e->next;
				else
					pidns_hash_table[i] = e->next;
				e = e->next;
				free_disarm(delme);
			} else {
				prev = e;
				e = e->next;
			}
		}
	}
}

/* Must be called under store_lock */
static void save_initpid(struct stat *sb, pid_t pid)
{
	struct pidns_init_store *e;
	char fpath[100];
	struct stat procsb;
	int h;

	lxcfs_debug("Save_initpid: adding entry for %d.\n", pid);

	snprintf(fpath, 100, "/proc/%d", pid);
	if (stat(fpath, &procsb) < 0)
		return;
	do {
		e = malloc(sizeof(*e));
	} while (!e);
	e->ino = sb->st_ino;
	e->initpid = pid;
	e->ctime = procsb.st_ctime;
	h = HASH(e->ino);
	e->next = pidns_hash_table[h];
	e->lastcheck = time(NULL);
	pidns_hash_table[h] = e;
}

/*
 * Given the stat(2) info for a nsfd pid inode, lookup the init_pid_store
 * entry for the inode number and creation time.  Verify that the init pid
 * is still valid.  If not, remove it.  Return the entry if valid, NULL
 * otherwise.
 * Must be called under store_lock
 */
static struct pidns_init_store *lookup_verify_initpid(struct stat *sb)
{
	int h = HASH(sb->st_ino);
	struct pidns_init_store *e = pidns_hash_table[h];

	while (e) {
		if (e->ino == sb->st_ino) {
			if (initpid_still_valid(e, sb)) {
				e->lastcheck = time(NULL);
				return e;
			}
			remove_initpid(e);
			return NULL;
		}
		e = e->next;
	}

	return NULL;
}

struct cgfs_files {
	char *name;
	uint32_t uid, gid;
	uint32_t mode;
};

static void print_subsystems(void)
{
	int i = 0;

	fprintf(stderr, "mount namespace: %d\n", cgroup_ops->mntns_fd);
	fprintf(stderr, "hierarchies:\n");
	for (struct hierarchy **h = cgroup_ops->hierarchies; h && *h; h++, i++) {
		__do_free char *controllers = lxc_string_join(",", (const char **)(*h)->controllers, false);
		fprintf(stderr, " %2d: fd: %3d: %s\n", i, (*h)->fd, controllers ?: "");
	}
}

bool cgfs_param_exist(const char *controller, const char *cgroup, const char *file)
{
	int ret, cfd;
	size_t len;
	char *fnam;

	cfd = get_cgroup_fd(controller);
	if (cfd < 0)
		return false;

	/* Make sure we pass a relative path to *at() family of functions.
	 * . + /cgroup + / + file + \0
	 */
	len = strlen(cgroup) + strlen(file) + 3;
	fnam = alloca(len);
	ret = snprintf(fnam, len, "%s%s/%s", dot_or_empty(cgroup), cgroup, file);
	if (ret < 0 || (size_t)ret >= len)
		return false;

	return (faccessat(cfd, fnam, F_OK, 0) == 0);
}

#define SEND_CREDS_OK 0
#define SEND_CREDS_NOTSK 1
#define SEND_CREDS_FAIL 2
static bool recv_creds(int sock, struct ucred *cred, char *v);
static int wait_for_pid(pid_t pid);
static int send_creds(int sock, struct ucred *cred, char v, bool pingfirst);
static int send_creds_clone_wrapper(void *arg);

/*
 * clone a task which switches to @task's namespace and writes '1'.
 * over a unix sock so we can read the task's reaper's pid in our
 * namespace
 *
 * Note: glibc's fork() does not respect pidns, which can lead to failed
 * assertions inside glibc (and thus failed forks) if the child's pid in
 * the pidns and the parent pid outside are identical. Using clone prevents
 * this issue.
 */
static void write_task_init_pid_exit(int sock, pid_t target)
{
	char fnam[100];
	pid_t pid;
	int fd, ret;
	size_t stack_size = sysconf(_SC_PAGESIZE);
	void *stack = alloca(stack_size);

	ret = snprintf(fnam, sizeof(fnam), "/proc/%d/ns/pid", (int)target);
	if (ret < 0 || ret >= sizeof(fnam))
		_exit(1);

	fd = open(fnam, O_RDONLY);
	if (fd < 0) {
		perror("write_task_init_pid_exit open of ns/pid");
		_exit(1);
	}
	if (setns(fd, 0)) {
		perror("write_task_init_pid_exit setns 1");
		close(fd);
		_exit(1);
	}
	pid = clone(send_creds_clone_wrapper, stack + stack_size, SIGCHLD, &sock);
	if (pid < 0)
		_exit(1);
	if (pid != 0) {
		if (!wait_for_pid(pid))
			_exit(1);
		_exit(0);
	}
}

static int send_creds_clone_wrapper(void *arg) {
	struct ucred cred;
	char v;
	int sock = *(int *)arg;

	/* we are the child */
	cred.uid = 0;
	cred.gid = 0;
	cred.pid = 1;
	v = '1';
	if (send_creds(sock, &cred, v, true) != SEND_CREDS_OK)
		return 1;
	return 0;
}

static pid_t get_init_pid_for_task(pid_t task)
{
	int sock[2];
	pid_t pid;
	pid_t ret = -1;
	char v = '0';
	struct ucred cred;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sock) < 0) {
		perror("socketpair");
		return -1;
	}

	pid = fork();
	if (pid < 0)
		goto out;
	if (!pid) {
		close(sock[1]);
		write_task_init_pid_exit(sock[0], task);
		_exit(0);
	}

	if (!recv_creds(sock[1], &cred, &v))
		goto out;
	ret = cred.pid;

out:
	close(sock[0]);
	close(sock[1]);
	if (pid > 0)
		wait_for_pid(pid);
	return ret;
}

pid_t lookup_initpid_in_store(pid_t qpid)
{
	pid_t answer = 0;
	struct stat sb;
	struct pidns_init_store *e;
	char fnam[100];

	snprintf(fnam, 100, "/proc/%d/ns/pid", qpid);
	store_lock();
	if (stat(fnam, &sb) < 0)
		goto out;
	e = lookup_verify_initpid(&sb);
	if (e) {
		answer = e->initpid;
		goto out;
	}
	answer = get_init_pid_for_task(qpid);
	if (answer > 0)
		save_initpid(&sb, answer);

out:
	/* we prune at end in case we are returning
	 * the value we were about to return */
	prune_initpid_store();
	store_unlock();
	return answer;
}

static int wait_for_pid(pid_t pid)
{
	int status, ret;

	if (pid <= 0)
		return -1;

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;
		return -1;
	}
	if (ret != pid)
		goto again;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;
	return 0;
}

char *get_pid_cgroup(pid_t pid, const char *contrl)
{
	int cfd;

	cfd = get_cgroup_fd(contrl);
	if (cfd < 0)
		return false;

	if (pure_unified_layout(cgroup_ops))
		return cg_unified_get_current_cgroup(pid);

	return cg_legacy_get_current_cgroup(pid, contrl);
}

#define INITSCOPE "/init.scope"
void prune_init_slice(char *cg)
{
	char *point;
	size_t cg_len = strlen(cg), initscope_len = strlen(INITSCOPE);

	if (cg_len < initscope_len)
		return;

	point = cg + cg_len - initscope_len;
	if (strcmp(point, INITSCOPE) == 0) {
		if (point == cg)
			*(point+1) = '\0';
		else
			*point = '\0';
	}
}

#define POLLIN_SET ( EPOLLIN | EPOLLHUP | EPOLLRDHUP )

static bool wait_for_sock(int sock, int timeout)
{
	struct epoll_event ev;
	int epfd, ret, now, starttime, deltatime, saved_errno;

	if ((starttime = time(NULL)) < 0)
		return false;

	if ((epfd = epoll_create(1)) < 0) {
		lxcfs_error("%s\n", "Failed to create epoll socket: %m.");
		return false;
	}

	ev.events = POLLIN_SET;
	ev.data.fd = sock;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev) < 0) {
		lxcfs_error("%s\n", "Failed adding socket to epoll: %m.");
		close(epfd);
		return false;
	}

again:
	if ((now = time(NULL)) < 0) {
		close(epfd);
		return false;
	}

	deltatime = (starttime + timeout) - now;
	if (deltatime < 0) { // timeout
		errno = 0;
		close(epfd);
		return false;
	}
	ret = epoll_wait(epfd, &ev, 1, 1000*deltatime + 1);
	if (ret < 0 && errno == EINTR)
		goto again;
	saved_errno = errno;
	close(epfd);

	if (ret <= 0) {
		errno = saved_errno;
		return false;
	}
	return true;
}

static int msgrecv(int sockfd, void *buf, size_t len)
{
	if (!wait_for_sock(sockfd, 2))
		return -1;
	return recv(sockfd, buf, len, MSG_DONTWAIT);
}

static int send_creds(int sock, struct ucred *cred, char v, bool pingfirst)
{
	struct msghdr msg = { 0 };
	struct iovec iov;
	struct cmsghdr *cmsg;
	char cmsgbuf[CMSG_SPACE(sizeof(*cred))];
	char buf[1];
	buf[0] = 'p';

	if (pingfirst) {
		if (msgrecv(sock, buf, 1) != 1) {
			lxcfs_error("%s\n", "Error getting reply from server over socketpair.");
			return SEND_CREDS_FAIL;
		}
	}

	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_CREDENTIALS;
	memcpy(CMSG_DATA(cmsg), cred, sizeof(*cred));

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	buf[0] = v;
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(sock, &msg, 0) < 0) {
		lxcfs_error("Failed at sendmsg: %s.\n",strerror(errno));
		if (errno == 3)
			return SEND_CREDS_NOTSK;
		return SEND_CREDS_FAIL;
	}

	return SEND_CREDS_OK;
}

static bool recv_creds(int sock, struct ucred *cred, char *v)
{
	struct msghdr msg = { 0 };
	struct iovec iov;
	struct cmsghdr *cmsg;
	char cmsgbuf[CMSG_SPACE(sizeof(*cred))];
	char buf[1];
	int ret;
	int optval = 1;

	*v = '1';

	cred->pid = -1;
	cred->uid = -1;
	cred->gid = -1;

	if (setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		lxcfs_error("Failed to set passcred: %s\n", strerror(errno));
		return false;
	}
	buf[0] = '1';
	if (write(sock, buf, 1) != 1) {
		lxcfs_error("Failed to start write on scm fd: %s\n", strerror(errno));
		return false;
	}

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (!wait_for_sock(sock, 2)) {
		lxcfs_error("Timed out waiting for scm_cred: %s\n", strerror(errno));
		return false;
	}
	ret = recvmsg(sock, &msg, MSG_DONTWAIT);
	if (ret < 0) {
		lxcfs_error("Failed to receive scm_cred: %s\n", strerror(errno));
		return false;
	}

	cmsg = CMSG_FIRSTHDR(&msg);

	if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred)) &&
			cmsg->cmsg_level == SOL_SOCKET &&
			cmsg->cmsg_type == SCM_CREDENTIALS) {
		memcpy(cred, CMSG_DATA(cmsg), sizeof(*cred));
	}
	*v = buf[0];

	return true;
}

struct pid_ns_clone_args {
	int *cpipe;
	int sock;
	pid_t tpid;
	int (*wrapped) (int, pid_t); // pid_from_ns or pid_to_ns
};

static bool startswith(const char *line, const char *pref)
{
	if (strncmp(line, pref, strlen(pref)) == 0)
		return true;
	return false;
}

/* Note that "memory.stat" in cgroup2 is hierarchical by default. */
static void parse_memstat(int version,
			  char *memstat,
			  unsigned long *cached,
			  unsigned long *active_anon,
			  unsigned long *inactive_anon,
			  unsigned long *active_file,
			  unsigned long *inactive_file,
			  unsigned long *unevictable,
			  unsigned long *shmem)
{
	char *eol;

	while (*memstat) {
		if (startswith(memstat, is_unified_controller(version)
					    ? "cache"
					    : "total_cache")) {
			sscanf(memstat + 11, "%lu", cached);
			*cached /= 1024;
		} else if (startswith(memstat, is_unified_controller(version)
						   ? "active_anon"
						   : "total_active_anon")) {
			sscanf(memstat + 17, "%lu", active_anon);
			*active_anon /= 1024;
		} else if (startswith(memstat, is_unified_controller(version)
						   ? "inactive_anon"
						   : "total_inactive_anon")) {
			sscanf(memstat + 19, "%lu", inactive_anon);
			*inactive_anon /= 1024;
		} else if (startswith(memstat, is_unified_controller(version)
						   ? "active_file"
						   : "total_active_file")) {
			sscanf(memstat + 17, "%lu", active_file);
			*active_file /= 1024;
		} else if (startswith(memstat, is_unified_controller(version)
						   ? "inactive_file"
						   : "total_inactive_file")) {
			sscanf(memstat + 19, "%lu", inactive_file);
			*inactive_file /= 1024;
		} else if (startswith(memstat, is_unified_controller(version)
						   ? "unevictable"
						   : "total_unevictable")) {
			sscanf(memstat + 17, "%lu", unevictable);
			*unevictable /= 1024;
		} else if (startswith(memstat, is_unified_controller(version)
						   ? "shmem"
						   : "total_shmem")) {
			sscanf(memstat + 11, "%lu", shmem);
			*shmem /= 1024;
		}
		eol = strchr(memstat, '\n');
		if (!eol)
			return;
		memstat = eol+1;
	}
}

static void get_blkio_io_value(char *str, unsigned major, unsigned minor, char *iotype, unsigned long *v)
{
	char *eol;
	char key[32];

	memset(key, 0, 32);
	snprintf(key, 32, "%u:%u %s", major, minor, iotype);

	size_t len = strlen(key);
	*v = 0;

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

int read_file_fuse(const char *path, char *buf, size_t size, struct file_info *d)
{
	__do_free char *line = NULL;
	__do_fclose FILE *f = NULL;
	size_t linelen = 0, total_len = 0;
	char *cache = d->buf;
	size_t cache_size = d->buflen;

	f = fopen(path, "r");
	if (!f)
		return 0;

	while (getline(&line, &linelen, f) != -1) {
		ssize_t l = snprintf(cache, cache_size, "%s", line);
		if (l < 0) {
			perror("Error writing to cache");
			return 0;
		}
		if (l >= cache_size) {
			lxcfs_error("%s\n", "Internal error: truncated write to cache.");
			return 0;
		}
		cache += l;
		cache_size -= l;
		total_len += l;
	}

	d->size = total_len;
	if (total_len > size)
		total_len = size;

	/* read from off 0 */
	memcpy(buf, d->buf, total_len);

	if (d->size > total_len)
		d->cached = d->size - total_len;
	return total_len;
}

/*
 * FUSE ops for /proc
 */

static unsigned long get_memlimit(const char *cgroup, bool swap)
{
	int ret;
	__do_free char *memlimit_str = NULL;
	unsigned long memlimit = -1;

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

static int proc_meminfo_read(char *buf, size_t size, off_t offset,
			     struct fuse_file_info *fi)
{
	__do_free char *cgroup = NULL, *line = NULL,
		       *memusage_str = NULL, *memstat_str = NULL,
		       *memswlimit_str = NULL, *memswusage_str = NULL;
	__do_fclose FILE *f = NULL;
	struct fuse_context *fc = fuse_get_context();
	struct lxcfs_opts *opts = (struct lxcfs_opts *) fuse_get_context()->private_data;
	struct file_info *d = (struct file_info *)fi->fh;
	unsigned long memlimit = 0, memusage = 0, memswlimit = 0,
		      memswusage = 0, cached = 0, hosttotal = 0, active_anon = 0,
		      inactive_anon = 0, active_file = 0, inactive_file = 0,
		      unevictable = 0, shmem = 0, hostswtotal = 0;
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

	ret = cgroup_ops->get_memory_stats(cgroup_ops, cgroup, &memstat_str);
	if (ret < 0)
		return 0;
	parse_memstat(ret, memstat_str, &cached, &active_anon, &inactive_anon,
		      &active_file, &inactive_file, &unevictable, &shmem);

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

	f = fopen("/proc/meminfo", "r");
	if (!f)
		return 0;

	while (getline(&line, &linelen, f) != -1) {
		ssize_t l;
		char *printme, lbuf[100];

		memset(lbuf, 0, 100);
		if (startswith(line, "MemTotal:")) {
			sscanf(line+sizeof("MemTotal:")-1, "%lu", &hosttotal);
			if (hosttotal < memlimit)
				memlimit = hosttotal;
			snprintf(lbuf, 100, "MemTotal:       %8lu kB\n", memlimit);
			printme = lbuf;
		} else if (startswith(line, "MemFree:")) {
			snprintf(lbuf, 100, "MemFree:        %8lu kB\n", memlimit - memusage);
			printme = lbuf;
		} else if (startswith(line, "MemAvailable:")) {
			snprintf(lbuf, 100, "MemAvailable:   %8lu kB\n", memlimit - memusage + cached);
			printme = lbuf;
		} else if (startswith(line, "SwapTotal:") && memswlimit > 0 &&
			   opts && opts->swap_off == false) {
			sscanf(line+sizeof("SwapTotal:")-1, "%lu", &hostswtotal);
			if (hostswtotal < memswlimit)
				memswlimit = hostswtotal;
			snprintf(lbuf, 100, "SwapTotal:      %8lu kB\n", memswlimit);
			printme = lbuf;
		} else if (startswith(line, "SwapTotal:") && opts && opts->swap_off == true) {
			snprintf(lbuf, 100, "SwapTotal:      %8lu kB\n", 0UL);
			printme = lbuf;
		} else if (startswith(line, "SwapFree:") && memswlimit > 0 &&
			   memswusage > 0 && opts && opts->swap_off == false) {
			unsigned long swaptotal = memswlimit,
				      swapusage = memusage > memswusage
						      ? 0
						      : memswusage - memusage,
				      swapfree = swapusage < swaptotal
						     ? swaptotal - swapusage
						     : 0;
			snprintf(lbuf, 100, "SwapFree:       %8lu kB\n", swapfree);
			printme = lbuf;
		} else if (startswith(line, "SwapFree:") && opts && opts->swap_off == true) {
			snprintf(lbuf, 100, "SwapFree:       %8lu kB\n", 0UL);
			printme = lbuf;
		} else if (startswith(line, "Slab:")) {
			snprintf(lbuf, 100, "Slab:        %8lu kB\n", 0UL);
			printme = lbuf;
		} else if (startswith(line, "Buffers:")) {
			snprintf(lbuf, 100, "Buffers:        %8lu kB\n", 0UL);
			printme = lbuf;
		} else if (startswith(line, "Cached:")) {
			snprintf(lbuf, 100, "Cached:         %8lu kB\n", cached);
			printme = lbuf;
		} else if (startswith(line, "SwapCached:")) {
			snprintf(lbuf, 100, "SwapCached:     %8lu kB\n", 0UL);
			printme = lbuf;
		} else if (startswith(line, "Active:")) {
			snprintf(lbuf, 100, "Active:         %8lu kB\n",
					active_anon + active_file);
			printme = lbuf;
		} else if (startswith(line, "Inactive:")) {
			snprintf(lbuf, 100, "Inactive:       %8lu kB\n",
					inactive_anon + inactive_file);
			printme = lbuf;
		} else if (startswith(line, "Active(anon)")) {
			snprintf(lbuf, 100, "Active(anon):   %8lu kB\n", active_anon);
			printme = lbuf;
		} else if (startswith(line, "Inactive(anon)")) {
			snprintf(lbuf, 100, "Inactive(anon): %8lu kB\n", inactive_anon);
			printme = lbuf;
		} else if (startswith(line, "Active(file)")) {
			snprintf(lbuf, 100, "Active(file):   %8lu kB\n", active_file);
			printme = lbuf;
		} else if (startswith(line, "Inactive(file)")) {
			snprintf(lbuf, 100, "Inactive(file): %8lu kB\n", inactive_file);
			printme = lbuf;
		} else if (startswith(line, "Unevictable")) {
			snprintf(lbuf, 100, "Unevictable:    %8lu kB\n", unevictable);
			printme = lbuf;
		} else if (startswith(line, "SReclaimable")) {
			snprintf(lbuf, 100, "SReclaimable:   %8lu kB\n", 0UL);
			printme = lbuf;
		} else if (startswith(line, "SUnreclaim")) {
			snprintf(lbuf, 100, "SUnreclaim:     %8lu kB\n", 0UL);
			printme = lbuf;
		} else if (startswith(line, "Shmem:")) {
			snprintf(lbuf, 100, "Shmem:          %8lu kB\n", shmem);
			printme = lbuf;
		} else if (startswith(line, "ShmemHugePages")) {
			snprintf(lbuf, 100, "ShmemHugePages: %8lu kB\n", 0UL);
			printme = lbuf;
		} else if (startswith(line, "ShmemPmdMapped")) {
			snprintf(lbuf, 100, "ShmemPmdMapped: %8lu kB\n", 0UL);
			printme = lbuf;
		} else
			printme = line;

		l = snprintf(cache, cache_size, "%s", printme);
		if (l < 0) {
			perror("Error writing to cache");
			return 0;

		}
		if (l >= cache_size) {
			lxcfs_error("%s\n", "Internal error: truncated write to cache.");
			return 0;
		}

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

/*
 * Read the cpuset.cpus for cg
 * Return the answer in a newly allocated string which must be freed
 */
char *get_cpuset(const char *cg)
{
	char *value = NULL;
	int ret;

	ret = cgroup_ops->get_cpuset_cpus(cgroup_ops, cg, &value);
	if (ret < 0)
		return NULL;

	return value;
}

bool cpu_in_cpuset(int cpu, const char *cpuset);

static bool cpuline_in_cpuset(const char *line, const char *cpuset)
{
	int cpu;

	if (sscanf(line, "processor       : %d", &cpu) != 1)
		return false;
	return cpu_in_cpuset(cpu, cpuset);
}

/*
 * Read cgroup CPU quota parameters from `cpu.cfs_quota_us` or `cpu.cfs_period_us`,
 * depending on `param`. Parameter value is returned throuh `value`.
 */
static bool read_cpu_cfs_param(const char *cg, const char *param, int64_t *value)
{
	__do_free char *str = NULL;
	char file[11 + 6 + 1]; /* cpu.cfs__us + quota/period + \0 */

	snprintf(file, sizeof(file), "cpu.cfs_%s_us", param);

	if (!cgroup_ops->get(cgroup_ops, "cpu", cg, file, &str))
		return false;

	if (sscanf(str, "%ld", value) != 1)
		return false;

	return true;
}

/*
 * Return the maximum number of visible CPUs based on CPU quotas.
 * If there is no quota set, zero is returned.
 */
int max_cpu_count(const char *cg)
{
	int rv, nprocs;
	int64_t cfs_quota, cfs_period;
	int nr_cpus_in_cpuset = 0;
	char *cpuset = NULL;

	if (!read_cpu_cfs_param(cg, "quota", &cfs_quota))
		return 0;

	if (!read_cpu_cfs_param(cg, "period", &cfs_period))
		return 0;

	cpuset = get_cpuset(cg);
	if (cpuset)
		nr_cpus_in_cpuset = cpu_number_in_cpuset(cpuset);

	if (cfs_quota <= 0 || cfs_period <= 0){
		if (nr_cpus_in_cpuset > 0)
			return nr_cpus_in_cpuset;

		return 0;
	}

	rv = cfs_quota / cfs_period;

	/* In case quota/period does not yield a whole number, add one CPU for
	 * the remainder.
	 */
	if ((cfs_quota % cfs_period) > 0)
		rv += 1;

	nprocs = get_nprocs();

	if (rv > nprocs)
		rv = nprocs;

	/* use min value in cpu quota and cpuset */
	if (nr_cpus_in_cpuset > 0 && nr_cpus_in_cpuset < rv)
		rv = nr_cpus_in_cpuset;

	return rv;
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
 * check whether this is a '^processor" line in /proc/cpuinfo
 */
static bool is_processor_line(const char *line)
{
	int cpu;

	if (sscanf(line, "processor       : %d", &cpu) == 1)
		return true;
	return false;
}

static int proc_cpuinfo_read(char *buf, size_t size, off_t offset,
			     struct fuse_file_info *fi)
{
	__do_free char *cg = NULL, *cpuset = NULL, *line = NULL;
	__do_fclose FILE *f = NULL;
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = (struct file_info *)fi->fh;
	size_t linelen = 0, total_len = 0;
	bool am_printing = false, firstline = true, is_s390x = false;
	int curcpu = -1, cpu, max_cpus = 0;
	bool use_view;
	char *cache = d->buf;
	size_t cache_size = d->buflen;

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
	cg = get_pid_cgroup(initpid, "cpuset");
	if (!cg)
		return read_file_fuse("proc/cpuinfo", buf, size, d);
	prune_init_slice(cg);

	cpuset = get_cpuset(cg);
	if (!cpuset)
		return 0;

	use_view = cgroup_ops->can_use_cpuview(cgroup_ops);
	if (use_view)
		max_cpus = max_cpu_count(cg);

	f = fopen("/proc/cpuinfo", "r");
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
			if (use_view && max_cpus > 0 && (curcpu+1) == max_cpus)
				break;
			am_printing = cpuline_in_cpuset(line, cpuset);
			if (am_printing) {
				curcpu ++;
				l = snprintf(cache, cache_size, "processor	: %d\n", curcpu);
				if (l < 0) {
					perror("Error writing to cache");
					return 0;
				}
				if (l >= cache_size) {
					lxcfs_error("%s\n", "Internal error: truncated write to cache.");
					return 0;
				}
				cache += l;
				cache_size -= l;
				total_len += l;
			}
			continue;
		} else if (is_s390x && sscanf(line, "processor %d:", &cpu) == 1) {
			char *p;
			if (use_view && max_cpus > 0 && (curcpu+1) == max_cpus)
				break;
			if (!cpu_in_cpuset(cpu, cpuset))
				continue;
			curcpu ++;
			p = strchr(line, ':');
			if (!p || !*p)
				return 0;
			p++;
			l = snprintf(cache, cache_size, "processor %d:%s", curcpu, p);
			if (l < 0) {
				perror("Error writing to cache");
				return 0;
			}
			if (l >= cache_size) {
				lxcfs_error("%s\n", "Internal error: truncated write to cache.");
				return 0;
			}
			cache += l;
			cache_size -= l;
			total_len += l;
			continue;

		}
		if (am_printing) {
			l = snprintf(cache, cache_size, "%s", line);
			if (l < 0) {
				perror("Error writing to cache");
				return 0;
			}
			if (l >= cache_size) {
				lxcfs_error("%s\n", "Internal error: truncated write to cache.");
				return 0;
			}
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
		if (l < 0 || l >= cache_size)
			return 0;

		cache_size -= l;
		cache += l;
		total_len += l;
		l = snprintf(cache, cache_size, "# processors    : %d\n", curcpu + 1);
		if (l < 0 || l >= cache_size)
			return 0;

		cache_size -= l;
		cache += l;
		total_len += l;
		l = snprintf(cache, cache_size, "%s", origcache);
		if (l < 0 || l >= cache_size)
			return 0;
		total_len += l;
	}

	d->cached = 1;
	d->size = total_len;
	if (total_len > size ) total_len = size;

	/* read from off 0 */
	memcpy(buf, d->buf, total_len);
	return total_len;
}

static uint64_t get_reaper_start_time(pid_t pid)
{
	int ret;
	FILE *f;
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

	f = fopen(path, "r");
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
	if (ret != 1) {
		fclose(f);
		/* Caller can check for EINVAL on 0. */
		errno = EINVAL;
		return 0;
	}

	fclose(f);

	errno = 0;
	return starttime;
}

static double get_reaper_start_time_in_sec(pid_t pid)
{
	uint64_t clockticks, ticks_per_sec;
	int64_t ret;
	double res = 0;

	clockticks = get_reaper_start_time(pid);
	if (clockticks == 0 && errno == EINVAL) {
		lxcfs_debug("failed to retrieve start time of pid %d\n", pid);
		return 0;
	}

	ret = sysconf(_SC_CLK_TCK);
	if (ret < 0 && errno == EINVAL) {
		lxcfs_debug(
		    "%s\n",
		    "failed to determine number of clock ticks in a second");
		return 0;
	}

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
 * Returns 0 on success.
 * It is the caller's responsibility to free `return_usage`, unless this
 * function returns an error.
 */
static int read_cpuacct_usage_all(char *cg, char *cpuset, struct cpuacct_usage **return_usage, int *size)
{
	__do_free char *usage_str = NULL;
	__do_free struct cpuacct_usage *cpu_usage = NULL;
	int cpucount = get_nprocs_conf();
	int read_pos = 0, read_cnt=0;
	int i, j, ret;
	int cg_cpu;
	uint64_t cg_user, cg_system;
	int64_t ticks_per_sec;

	ticks_per_sec = sysconf(_SC_CLK_TCK);

	if (ticks_per_sec < 0 && errno == EINVAL) {
		lxcfs_v(
			"%s\n",
			"read_cpuacct_usage_all failed to determine number of clock ticks "
			"in a second");
		return -1;
	}

	cpu_usage = malloc(sizeof(struct cpuacct_usage) * cpucount);
	if (!cpu_usage)
		return -ENOMEM;

	memset(cpu_usage, 0, sizeof(struct cpuacct_usage) * cpucount);
	if (!cgroup_ops->get(cgroup_ops, "cpuacct", cg, "cpuacct.usage_all", &usage_str)) {
		char *data = NULL;
		int i = 0, read_pos = 0, read_cnt=0;
		size_t sz = 0, asz = 0;

		/* read cpuacct.usage_percpu instead. */
		lxcfs_v("failed to read cpuacct.usage_all. reading cpuacct.usage_percpu instead\n%s", "");
		if (!cgroup_ops->get(cgroup_ops, "cpuacct", cg, "cpuacct.usage_percpu", &usage_str))
			return -1;
		lxcfs_v("usage_str: %s\n", usage_str);

		/* convert cpuacct.usage_percpu into cpuacct.usage_all. */
		lxcfs_v("converting cpuacct.usage_percpu into cpuacct.usage_all\n%s", "");

		must_strcat(&data, &sz, &asz, "cpu user system\n");

		while (sscanf(usage_str + read_pos, "%lu %n", &cg_user, &read_cnt) > 0) {
			lxcfs_debug("i: %d, cg_user: %lu, read_pos: %d, read_cnt: %d\n", i, cg_user, read_pos, read_cnt);
			must_strcat(&data, &sz, &asz, "%d %lu 0\n", i, cg_user);
			i++;
			read_pos += read_cnt;
		}

		usage_str = data;

		lxcfs_v("usage_str: %s\n", usage_str);
	}

	if (sscanf(usage_str, "cpu user system\n%n", &read_cnt) != 0) {
		lxcfs_error("read_cpuacct_usage_all reading first line from "
				"%s/cpuacct.usage_all failed.\n", cg);
		return -1;
	}

	read_pos += read_cnt;

	for (i = 0, j = 0; i < cpucount; i++) {
		ret = sscanf(usage_str + read_pos, "%d %lu %lu\n%n", &cg_cpu, &cg_user,
				&cg_system, &read_cnt);

		if (ret == EOF)
			break;

		if (ret != 3) {
			lxcfs_error("read_cpuacct_usage_all reading from %s/cpuacct.usage_all "
					"failed.\n", cg);
			return -1;
		}

		read_pos += read_cnt;

		/* Convert the time from nanoseconds to USER_HZ */
		cpu_usage[j].user = cg_user / 1000.0 / 1000 / 1000 * ticks_per_sec;
		cpu_usage[j].system = cg_system / 1000.0 / 1000 / 1000 * ticks_per_sec;
		j++;
	}

	*return_usage = move_ptr(cpu_usage);
	*size = cpucount;
	return 0;
}

static unsigned long diff_cpu_usage(struct cpuacct_usage *older, struct cpuacct_usage *newer, struct cpuacct_usage *diff, int cpu_count)
{
	int i;
	unsigned long sum = 0;

	for (i = 0; i < cpu_count; i++) {
		if (!newer[i].online)
			continue;

		/* When cpuset is changed on the fly, the CPUs might get reordered.
		 * We could either reset all counters, or check that the substractions
		 * below will return expected results.
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

static void add_cpu_usage(unsigned long *surplus, struct cpuacct_usage *usage, unsigned long *counter, unsigned long threshold)
{
	unsigned long free_space, to_add;

	free_space = threshold - usage->user - usage->system;

	if (free_space > usage->idle)
		free_space = usage->idle;

	to_add = free_space > *surplus ? *surplus : free_space;

	*counter += to_add;
	usage->idle -= to_add;
	*surplus -= to_add;
}

static struct cg_proc_stat *prune_proc_stat_list(struct cg_proc_stat *node)
{
	struct cg_proc_stat *first = NULL, *prev, *tmp;

	for (prev = NULL; node; ) {
		if (!cgfs_param_exist("cpu", node->cg, "cpu.shares")) {
			tmp = node;
			lxcfs_debug("Removing stat node for %s\n", node->cg);

			if (prev)
				prev->next = node->next;
			else
				first = node->next;

			node = node->next;
			free_proc_stat_node(tmp);
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
	int i;
	time_t now = time(NULL);

	for (i = 0; i < CPUVIEW_HASH_SIZE; i++) {
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

static struct cg_proc_stat *find_proc_stat_node(struct cg_proc_stat_head *head, const char *cg)
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

static struct cg_proc_stat *new_proc_stat_node(struct cpuacct_usage *usage, int cpu_count, const char *cg)
{
	struct cg_proc_stat *node;
	int i;

	node = malloc(sizeof(struct cg_proc_stat));
	if (!node)
		goto err;

	node->cg = NULL;
	node->usage = NULL;
	node->view = NULL;

	node->cg = malloc(strlen(cg) + 1);
	if (!node->cg)
		goto err;

	strcpy(node->cg, cg);

	node->usage = malloc(sizeof(struct cpuacct_usage) * cpu_count);
	if (!node->usage)
		goto err;

	memcpy(node->usage, usage, sizeof(struct cpuacct_usage) * cpu_count);

	node->view = malloc(sizeof(struct cpuacct_usage) * cpu_count);
	if (!node->view)
		goto err;

	node->cpu_count = cpu_count;
	node->next = NULL;

	if (pthread_mutex_init(&node->lock, NULL) != 0) {
		lxcfs_error("%s\n", "Failed to initialize node lock");
		goto err;
	}

	for (i = 0; i < cpu_count; i++) {
		node->view[i].user = 0;
		node->view[i].system = 0;
		node->view[i].idle = 0;
	}

	return node;

err:
	if (node && node->cg)
		free(node->cg);
	if (node && node->usage)
		free(node->usage);
	if (node && node->view)
		free(node->view);
	if (node)
		free(node);

	return NULL;
}

static struct cg_proc_stat *add_proc_stat_node(struct cg_proc_stat *new_node)
{
	int hash = calc_hash(new_node->cg) % CPUVIEW_HASH_SIZE;
	struct cg_proc_stat_head *head = proc_stat_history[hash];
	struct cg_proc_stat *node, *rv = new_node;

	pthread_rwlock_wrlock(&head->lock);

	if (!head->next) {
		head->next = new_node;
		goto out;
	}

	node = head->next;

	for (;;) {
		if (strcmp(node->cg, new_node->cg) == 0) {
			/* The node is already present, return it */
			free_proc_stat_node(new_node);
			rv = node;
			goto out;
		}

		if (node->next) {
			node = node->next;
			continue;
		}

		node->next = new_node;
		goto out;
	}

out:
	pthread_rwlock_unlock(&head->lock);
	return rv;
}

static bool expand_proc_stat_node(struct cg_proc_stat *node, int cpu_count)
{
	__do_free struct cpuacct_usage *new_usage = NULL, *new_view = NULL;

	/* Allocate new memory */
	new_usage = malloc(sizeof(struct cpuacct_usage) * cpu_count);
	if (!new_usage)
		return false;

	new_view = malloc(sizeof(struct cpuacct_usage) * cpu_count);
	if (!new_view)
		return false;

	/* Copy existing data & initialize new elements */
	for (int i = 0; i < cpu_count; i++) {
		if (i < node->cpu_count) {
			new_usage[i].user = node->usage[i].user;
			new_usage[i].system = node->usage[i].system;
			new_usage[i].idle = node->usage[i].idle;

			new_view[i].user = node->view[i].user;
			new_view[i].system = node->view[i].system;
			new_view[i].idle = node->view[i].idle;
		} else {
			new_usage[i].user = 0;
			new_usage[i].system = 0;
			new_usage[i].idle = 0;

			new_view[i].user = 0;
			new_view[i].system = 0;
			new_view[i].idle = 0;
		}
	}

	free(node->usage);
	node->usage = move_ptr(new_usage);

	free(node->view);
	node->view = move_ptr(new_view);
	node->cpu_count = cpu_count;

	return true;
}

static struct cg_proc_stat *find_or_create_proc_stat_node(struct cpuacct_usage *usage, int cpu_count, const char *cg)
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

	/* If additional CPUs on the host have been enabled, CPU usage counter
	 * arrays have to be expanded */
	if (node->cpu_count < cpu_count) {
		lxcfs_debug("Expanding stat node %d->%d for %s\n",
				node->cpu_count, cpu_count, cg);

		if (!expand_proc_stat_node(node, cpu_count)) {
			pthread_mutex_unlock(&node->lock);
			lxcfs_debug("Unable to expand stat node %d->%d for %s\n",
					node->cpu_count, cpu_count, cg);
			return NULL;
		}
	}

	return node;
}

static void reset_proc_stat_node(struct cg_proc_stat *node, struct cpuacct_usage *usage, int cpu_count)
{
	int i;

	lxcfs_debug("Resetting stat node for %s\n", node->cg);
	memcpy(node->usage, usage, sizeof(struct cpuacct_usage) * cpu_count);

	for (i = 0; i < cpu_count; i++) {
		node->view[i].user = 0;
		node->view[i].system = 0;
		node->view[i].idle = 0;
	}

	node->cpu_count = cpu_count;
}

static int cpuview_proc_stat(const char *cg, const char *cpuset,
			     struct cpuacct_usage *cg_cpu_usage,
			     int cg_cpu_usage_size, FILE *f, char *buf,
			     size_t buf_size)
{
	__do_free char *line = NULL;
	__do_free struct cpuacct_usage *diff = NULL;
	size_t linelen = 0, total_len = 0, l;
	int curcpu = -1; /* cpu numbering starts at 0 */
	int physcpu, i;
	int max_cpus = max_cpu_count(cg), cpu_cnt = 0;
	unsigned long user = 0, nice = 0, system = 0, idle = 0, iowait = 0,
		      irq = 0, softirq = 0, steal = 0, guest = 0, guest_nice = 0;
	unsigned long user_sum = 0, system_sum = 0, idle_sum = 0;
	unsigned long user_surplus = 0, system_surplus = 0;
	unsigned long total_sum, threshold;
	struct cg_proc_stat *stat_node;
	int nprocs = get_nprocs_conf();

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

		curcpu ++;
		cpu_cnt ++;

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

		if (ret != 10)
			continue;

		all_used = user + nice + system + iowait + irq + softirq + steal + guest + guest_nice;
		cg_used = cg_cpu_usage[curcpu].user + cg_cpu_usage[curcpu].system;

		if (all_used >= cg_used) {
			cg_cpu_usage[curcpu].idle = idle + (all_used - cg_used);

		} else {
			lxcfs_error("cpu%d from %s has unexpected cpu time: %lu in /proc/stat, "
					"%lu in cpuacct.usage_all; unable to determine idle time\n",
					curcpu, cg, all_used, cg_used);
			cg_cpu_usage[curcpu].idle = idle;
		}
	}

	/* Cannot use more CPUs than is available due to cpuset */
	if (max_cpus > cpu_cnt)
		max_cpus = cpu_cnt;

	stat_node = find_or_create_proc_stat_node(cg_cpu_usage, nprocs, cg);

	if (!stat_node) {
		lxcfs_error("unable to find/create stat node for %s\n", cg);
		return 0;
	}

	diff = malloc(sizeof(struct cpuacct_usage) * nprocs);
	if (!diff) {
		return 0;
	}

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

		stat_node->usage[curcpu].user += diff[curcpu].user;
		stat_node->usage[curcpu].system += diff[curcpu].system;
		stat_node->usage[curcpu].idle += diff[curcpu].idle;

		if (max_cpus > 0 && i >= max_cpus) {
			user_surplus += diff[curcpu].user;
			system_surplus += diff[curcpu].system;
		}
	}

	/* Calculate usage counters of visible CPUs */
	if (max_cpus > 0) {
		unsigned long diff_user = 0;
		unsigned long diff_system = 0;
		unsigned long diff_idle = 0;
		unsigned long max_diff_idle = 0;
		unsigned long max_diff_idle_index = 0;
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
			lxcfs_debug("leftover user: %lu for %s\n", user_surplus, cg);
		if (system_surplus > 0)
			lxcfs_debug("leftover system: %lu for %s\n", system_surplus, cg);

		for (curcpu = 0, i = -1; curcpu < nprocs; curcpu++) {
			if (!stat_node->usage[curcpu].online)
				continue;

			i++;

			if (i == max_cpus)
				break;

			stat_node->view[curcpu].user += diff[curcpu].user;
			stat_node->view[curcpu].system += diff[curcpu].system;
			stat_node->view[curcpu].idle += diff[curcpu].idle;

			user_sum += stat_node->view[curcpu].user;
			system_sum += stat_node->view[curcpu].system;
			idle_sum += stat_node->view[curcpu].idle;

			diff_user += diff[curcpu].user;
			diff_system += diff[curcpu].system;
			diff_idle += diff[curcpu].idle;
			if (diff[curcpu].idle > max_diff_idle) {
				max_diff_idle = diff[curcpu].idle;
				max_diff_idle_index = curcpu;
			}

			lxcfs_v("curcpu: %d, diff_user: %lu, diff_system: %lu, diff_idle: %lu\n", curcpu, diff[curcpu].user, diff[curcpu].system, diff[curcpu].idle);
		}
		lxcfs_v("total. diff_user: %lu, diff_system: %lu, diff_idle: %lu\n", diff_user, diff_system, diff_idle);

		/* revise cpu usage view to support partial cpu case. */
		exact_cpus = exact_cpu_count(cg);
		if (exact_cpus < (double)max_cpus){
			unsigned long delta = (unsigned long)((double)(diff_user + diff_system + diff_idle) * (1 - exact_cpus / (double)max_cpus));

			lxcfs_v("revising cpu usage view to match the exact cpu count [%f]\n", exact_cpus);
			lxcfs_v("delta: %lu\n", delta);
			lxcfs_v("idle_sum before: %lu\n", idle_sum);
			idle_sum = idle_sum > delta ? idle_sum - delta : 0;
			lxcfs_v("idle_sum after: %lu\n", idle_sum);

			curcpu = max_diff_idle_index;
			lxcfs_v("curcpu: %d, idle before: %lu\n", curcpu, stat_node->view[curcpu].idle);
			stat_node->view[curcpu].idle = stat_node->view[curcpu].idle > delta ? stat_node->view[curcpu].idle - delta : 0;
			lxcfs_v("curcpu: %d, idle after: %lu\n", curcpu, stat_node->view[curcpu].idle);
		}
	} else {
		for (curcpu = 0; curcpu < nprocs; curcpu++) {
			if (!stat_node->usage[curcpu].online)
				continue;

			stat_node->view[curcpu].user = stat_node->usage[curcpu].user;
			stat_node->view[curcpu].system = stat_node->usage[curcpu].system;
			stat_node->view[curcpu].idle = stat_node->usage[curcpu].idle;

			user_sum += stat_node->view[curcpu].user;
			system_sum += stat_node->view[curcpu].system;
			idle_sum += stat_node->view[curcpu].idle;
		}
	}

	/* Render the file */
	/* cpu-all */
	l = snprintf(buf, buf_size, "cpu  %lu 0 %lu %lu 0 0 0 0 0 0\n",
			user_sum,
			system_sum,
			idle_sum);
	lxcfs_v("cpu-all: %s\n", buf);

	if (l < 0) {
		perror("Error writing to cache");
		return 0;
	}
	if (l >= buf_size) {
		lxcfs_error("%s\n", "Internal error: truncated write to cache.");
		return 0;
	}

	buf += l;
	buf_size -= l;
	total_len += l;

	/* Render visible CPUs */
	for (curcpu = 0, i = -1; curcpu < nprocs; curcpu++) {
		if (!stat_node->usage[curcpu].online)
			continue;

		i++;

		if (max_cpus > 0 && i == max_cpus)
			break;

		l = snprintf(buf, buf_size, "cpu%d %lu 0 %lu %lu 0 0 0 0 0 0\n",
				i,
				stat_node->view[curcpu].user,
				stat_node->view[curcpu].system,
				stat_node->view[curcpu].idle);
		lxcfs_v("cpu: %s\n", buf);

		if (l < 0) {
			perror("Error writing to cache");
			return 0;

		}
		if (l >= buf_size) {
			lxcfs_error("%s\n", "Internal error: truncated write to cache.");
			return 0;
		}

		buf += l;
		buf_size -= l;
		total_len += l;
	}

	/* Pass the rest of /proc/stat, start with the last line read */
	l = snprintf(buf, buf_size, "%s", line);

	if (l < 0) {
		perror("Error writing to cache");
		return 0;

	}
	if (l >= buf_size) {
		lxcfs_error("%s\n", "Internal error: truncated write to cache.");
		return 0;
	}

	buf += l;
	buf_size -= l;
	total_len += l;

	/* Pass the rest of the host's /proc/stat */
	while (getline(&line, &linelen, f) != -1) {
		l = snprintf(buf, buf_size, "%s", line);
		if (l < 0) {
			perror("Error writing to cache");
			return 0;
		}
		if (l >= buf_size) {
			lxcfs_error("%s\n", "Internal error: truncated write to cache.");
			return 0;
		}
		buf += l;
		buf_size -= l;
		total_len += l;
	}

	if (stat_node)
		pthread_mutex_unlock(&stat_node->lock);
	return total_len;
}

#define CPUALL_MAX_SIZE (BUF_RESERVE_SIZE / 2)
static int proc_stat_read(char *buf, size_t size, off_t offset,
			  struct fuse_file_info *fi)
{
	__do_free char *cg = NULL, *cpuset = NULL, *line = NULL;
	__do_free struct cpuacct_usage *cg_cpu_usage = NULL;
	__do_fclose FILE *f = NULL;
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = (struct file_info *)fi->fh;
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

	if (offset){
		if (offset > d->size)
			return -EINVAL;
		if (!d->cached)
			return 0;
		int left = d->size - offset;
		total_len = left > size ? size: left;
		memcpy(buf, d->buf + offset, total_len);
		return total_len;
	}

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	lxcfs_v("initpid: %d\n", initpid);
	if (initpid <= 0)
		initpid = fc->pid;

	/*
	 * when container run with host pid namespace initpid == 1, cgroup will "/"
	 * we should return host os's /proc contents.
	 * in some case cpuacct_usage.all in "/" will larger then /proc/stat
	 */
	if (initpid == 1) {
	    return read_file_fuse("/proc/stat", buf, size, d);
	}

	cg = get_pid_cgroup(initpid, "cpuset");
	lxcfs_v("cg: %s\n", cg);
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
	if (read_cpuacct_usage_all(cg, cpuset, &cg_cpu_usage, &cg_cpu_usage_size) != 0) {
		lxcfs_v("%s\n", "proc_stat_read failed to read from cpuacct, "
				"falling back to the host's /proc/stat");
	}

	f = fopen("/proc/stat", "r");
	if (!f)
		return 0;

	//skip first line
	if (getline(&line, &linelen, f) < 0) {
		lxcfs_error("%s\n", "proc_stat_read read first line failed.");
		return 0;
	}

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
			if (l < 0) {
				perror("Error writing to cache");
				return 0;
			}
			if (l >= cache_size) {
				lxcfs_error("%s\n", "Internal error: truncated write to cache.");
				return 0;
			}
			cache += l;
			cache_size -= l;
			total_len += l;
			continue;
		}

		if (sscanf(cpu_char, "%d", &physcpu) != 1)
			continue;
		if (!cpu_in_cpuset(physcpu, cpuset))
			continue;
		curcpu ++;

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
			if (l < 0) {
				perror("Error writing to cache");
				return 0;

			}
			if (l >= cache_size) {
				lxcfs_error("%s\n", "Internal error: truncated write to cache.");
				return 0;
			}

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
				lxcfs_error("cpu%d from %s has unexpected cpu time: %lu in /proc/stat, "
						"%lu in cpuacct.usage_all; unable to determine idle time\n",
						curcpu, cg, all_used, cg_used);
				new_idle = idle;
			}

			l = snprintf(cache, cache_size, "cpu%d %lu 0 %lu %lu 0 0 0 0 0 0\n",
					curcpu, cg_cpu_usage[physcpu].user, cg_cpu_usage[physcpu].system,
					new_idle);

			if (l < 0) {
				perror("Error writing to cache");
				return 0;

			}
			if (l >= cache_size) {
				lxcfs_error("%s\n", "Internal error: truncated write to cache.");
				return 0;
			}

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
		lxcfs_error("proc_stat_read copy cpuall failed, cpuall_len=%d.", cpuall_len);
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

#if RELOADTEST
void iwashere(void)
{
	int fd;

	fd = creat("/tmp/lxcfs-iwashere", 0644);
	if (fd >= 0)
		close(fd);
}
#endif

/*
 * We read /proc/uptime and reuse its second field.
 * For the first field, we use the mtime for the reaper for
 * the calling pid as returned by getreaperage
 */
static int proc_uptime_read(char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = (struct file_info *)fi->fh;
	double busytime = get_reaper_busy(fc->pid);
	char *cache = d->buf;
	ssize_t total_len = 0;
	double idletime, reaperage;

#if RELOADTEST
	iwashere();
#endif

	if (offset){
		if (!d->cached)
			return 0;
		if (offset > d->size)
			return -EINVAL;
		int left = d->size - offset;
		total_len = left > size ? size: left;
		memcpy(buf, cache + offset, total_len);
		return total_len;
	}

	reaperage = get_reaper_age(fc->pid);
	/* To understand why this is done, please read the comment to the
	 * get_reaper_busy() function.
	 */
	idletime = reaperage;
	if (reaperage >= busytime)
		idletime = reaperage - busytime;

	total_len = snprintf(d->buf, d->buflen, "%.2lf %.2lf\n", reaperage, idletime);
	if (total_len < 0 || total_len >=  d->buflen){
		lxcfs_error("%s\n", "failed to write to cache");
		return 0;
	}

	d->size = (int)total_len;
	d->cached = 1;

	if (total_len > size) total_len = size;

	memcpy(buf, d->buf, total_len);
	return total_len;
}

static int proc_diskstats_read(char *buf, size_t size, off_t offset,
			       struct fuse_file_info *fi)
{
	__do_free char *cg = NULL, *io_serviced_str = NULL,
		       *io_merged_str = NULL, *io_service_bytes_str = NULL,
		       *io_wait_time_str = NULL, *io_service_time_str = NULL,
		       *line = NULL;
	__do_fclose FILE *f = NULL;
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = (struct file_info *)fi->fh;
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

	f = fopen("/proc/diskstats", "r");
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
		if (l < 0) {
			perror("Error writing to fuse buf");
			return 0;
		}
		if (l >= cache_size) {
			lxcfs_error("%s\n", "Internal error: truncated write to cache.");
			return 0;
		}
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

static int proc_swaps_read(char *buf, size_t size, off_t offset,
			   struct fuse_file_info *fi)
{
	__do_free char *cg = NULL, *memswlimit_str = NULL, *memusage_str = NULL,
		       *memswusage_str = NULL;
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = (struct file_info *)fi->fh;
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
		__do_fclose FILE *f = NULL;
		size_t linelen = 0;

		f = fopen("/proc/meminfo", "r");
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

	if (total_len < 0 || l < 0) {
		perror("Error writing to cache");
		return 0;
	}

	d->cached = 1;
	d->size = (int)total_len;

	if (total_len > size) total_len = size;
	memcpy(buf, d->buf, total_len);
	return total_len;
}

/*
 * Find the process pid from cgroup path.
 * eg:from /sys/fs/cgroup/cpu/docker/containerid/cgroup.procs to find the process pid.
 * @pid_buf : put pid to pid_buf.
 * @dpath : the path of cgroup. eg: /docker/containerid or /docker/containerid/child-cgroup ...
 * @depth : the depth of cgroup in container.
 * @sum : return the number of pid.
 * @cfd : the file descriptor of the mounted cgroup. eg: /sys/fs/cgroup/cpu
 */
static int calc_pid(char ***pid_buf, char *dpath, int depth, int sum, int cfd)
{
	__do_free char *path = NULL;
	__do_close_prot_errno int fd = -EBADF;
	__do_fclose FILE *f = NULL;
	__do_closedir DIR *dir = NULL;
	struct dirent *file;
	size_t linelen = 0;
	char *line = NULL;
	int pd;
	char **pid;

	/* path = dpath + "/cgroup.procs" + /0 */
	path = malloc(strlen(dpath) + 20);
	if (!path)
		return sum;

	strcpy(path, dpath);
	fd = openat(cfd, path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return sum;

	dir = fdopendir(move_fd(fd));
	if (!dir)
		return sum;

	while (((file = readdir(dir)) != NULL) && depth > 0) {
		if (strcmp(file->d_name, ".") == 0)
			continue;

		if (strcmp(file->d_name, "..") == 0)
			continue;

		if (file->d_type == DT_DIR) {
			__do_free char *path_dir = NULL;

			/* path + '/' + d_name +/0 */
			path_dir = malloc(strlen(path) + 2 + sizeof(file->d_name));
			if (!path_dir)
				return sum;

			strcpy(path_dir, path);
			strcat(path_dir, "/");
			strcat(path_dir, file->d_name);
			pd = depth - 1;
			sum = calc_pid(pid_buf, path_dir, pd, sum, cfd);
		}
	}

	strcat(path, "/cgroup.procs");
	fd = openat(cfd, path, O_RDONLY);
	if (fd < 0)
		return sum;

	f = fdopen(move_fd(fd), "r");
	if (!f)
		return sum;

	while (getline(&line, &linelen, f) != -1) {
		pid = realloc(*pid_buf, sizeof(char *) * (sum + 1));
		if (!pid)
			return sum;
		*pid_buf = pid;

		*(*pid_buf + sum) = malloc(strlen(line) + 1);
		if (!*(*pid_buf + sum))
			return sum;

		strcpy(*(*pid_buf + sum), line);
		sum++;
	}

	return sum;
}

/*
 * calc_load calculates the load according to the following formula:
 * load1 = load0 * exp + active * (1 - exp)
 *
 * @load1: the new loadavg.
 * @load0: the former loadavg.
 * @active: the total number of running pid at this moment.
 * @exp: the fixed-point defined in the beginning.
 */
static unsigned long
calc_load(unsigned long load, unsigned long exp, unsigned long active)
{
	unsigned long newload;

	active = active > 0 ? active * FIXED_1 : 0;
	newload = load * exp + active * (FIXED_1 - exp);
	if (active >= load)
		newload += FIXED_1 - 1;

	return newload / FIXED_1;
}

/*
 * Return 0 means that container p->cg is closed.
 * Return -1 means that error occurred in refresh.
 * Positive num equals the total number of pid.
 */
static int refresh_load(struct load_node *p, char *path)
{
	__do_free char *line = NULL;
	char **idbuf;
	char proc_path[256];
	int i, ret, run_pid = 0, total_pid = 0, last_pid = 0;
	size_t linelen = 0;
	int sum, length;
	struct dirent *file;

	idbuf = malloc(sizeof(char *));
	if (!idbuf)
		return -1;

	sum = calc_pid(&idbuf, path, DEPTH_DIR, 0, p->cfd);
	/*  normal exit  */
	if (sum == 0)
		goto out;

	for (i = 0; i < sum; i++) {
		__do_closedir DIR *dp = NULL;

		/*clean up '\n' */
		length = strlen(idbuf[i])-1;
		idbuf[i][length] = '\0';
		ret = snprintf(proc_path, 256, "/proc/%s/task", idbuf[i]);
		if (ret < 0 || ret > 255) {
			lxcfs_error("%s\n", "snprintf() failed in refresh_load.");
			i = sum;
			sum = -1;
			goto err_out;
		}

		dp = opendir(proc_path);
		if (!dp) {
			lxcfs_error("%s\n", "Open proc_path failed in refresh_load.");
			continue;
		}
		while ((file = readdir(dp)) != NULL) {
			__do_fclose FILE *f = NULL;

			if (strncmp(file->d_name, ".", 1) == 0)
				continue;
			if (strncmp(file->d_name, "..", 1) == 0)
				continue;
			total_pid++;
			/* We make the biggest pid become last_pid.*/
			ret = atof(file->d_name);
			last_pid = (ret > last_pid) ? ret : last_pid;

			ret = snprintf(proc_path, 256, "/proc/%s/task/%s/status", idbuf[i], file->d_name);
			if (ret < 0 || ret > 255) {
				lxcfs_error("%s\n", "snprintf() failed in refresh_load.");
				i = sum;
				sum = -1;
				goto err_out;
			}

			f = fopen(proc_path, "r");
			if (f != NULL) {
				while (getline(&line, &linelen, f) != -1) {
					/* Find State */
					if ((line[0] == 'S') && (line[1] == 't'))
						break;
				}

			if ((line[7] == 'R') || (line[7] == 'D'))
				run_pid++;
			}
		}
	}
	/*Calculate the loadavg.*/
	p->avenrun[0] = calc_load(p->avenrun[0], EXP_1, run_pid);
	p->avenrun[1] = calc_load(p->avenrun[1], EXP_5, run_pid);
	p->avenrun[2] = calc_load(p->avenrun[2], EXP_15, run_pid);
	p->run_pid = run_pid;
	p->total_pid = total_pid;
	p->last_pid = last_pid;

err_out:
	for (; i > 0; i--)
		free(idbuf[i-1]);
out:
	free(idbuf);
	return sum;
}

/*
 * Traverse the hash table and update it.
 */
void *load_begin(void *arg)
{

	int i, sum, length, ret;
	struct load_node *f;
	int first_node;
	clock_t time1, time2;

	while (1) {
		if (loadavg_stop == 1)
			return NULL;

		time1 = clock();
		for (i = 0; i < LOAD_SIZE; i++) {
			pthread_mutex_lock(&load_hash[i].lock);
			if (load_hash[i].next == NULL) {
				pthread_mutex_unlock(&load_hash[i].lock);
				continue;
			}
			f = load_hash[i].next;
			first_node = 1;
			while (f) {
				__do_free char *path = NULL;

				length = strlen(f->cg) + 2;
					/* strlen(f->cg) + '.' or '' + \0 */
				path = malloc(length);
				if  (!path)
					goto out;

				ret = snprintf(path, length, "%s%s", dot_or_empty(f->cg), f->cg);
				if (ret < 0 || ret > length - 1) {
					/* snprintf failed, ignore the node.*/
					lxcfs_error("Refresh node %s failed for snprintf().\n", f->cg);
					goto out;
				}

				sum = refresh_load(f, path);
				if (sum == 0)
					f = del_node(f, i);
				else
out:					f = f->next;
				/* load_hash[i].lock locks only on the first node.*/
				if (first_node == 1) {
					first_node = 0;
					pthread_mutex_unlock(&load_hash[i].lock);
				}
			}
		}

		if (loadavg_stop == 1)
			return NULL;

		time2 = clock();
		usleep(FLUSH_TIME * 1000000 - (int)((time2 - time1) * 1000000 / CLOCKS_PER_SEC));
	}
}

static int proc_loadavg_read(char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = (struct file_info *)fi->fh;
	pid_t initpid;
	char *cg;
	size_t total_len = 0;
	char *cache = d->buf;
	struct load_node *n;
	int hash;
	int cfd, rv = 0;
	unsigned long a, b, c;

	if (offset) {
		if (offset > d->size)
			return -EINVAL;
		if (!d->cached)
			return 0;
		int left = d->size - offset;
		total_len = left > size ? size : left;
		memcpy(buf, cache + offset, total_len);
		return total_len;
	}
	if (!loadavg)
		return read_file_fuse("/proc/loadavg", buf, size, d);

	initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;
	cg = get_pid_cgroup(initpid, "cpu");
	if (!cg)
		return read_file_fuse("/proc/loadavg", buf, size, d);

	prune_init_slice(cg);
	hash = calc_hash(cg) % LOAD_SIZE;
	n = locate_node(cg, hash);

	/* First time */
	if (n == NULL) {
		cfd = get_cgroup_fd("cpu");
		if (cfd >= 0) {
			/*
			 * In locate_node() above, pthread_rwlock_unlock() isn't used
			 * because delete is not allowed before read has ended.
			 */
			pthread_rwlock_unlock(&load_hash[hash].rdlock);
			rv = 0;
			goto err;
		}
		do {
			n = malloc(sizeof(struct load_node));
		} while (!n);

		do {
			n->cg = malloc(strlen(cg)+1);
		} while (!n->cg);
		strcpy(n->cg, cg);
		n->avenrun[0] = 0;
		n->avenrun[1] = 0;
		n->avenrun[2] = 0;
		n->run_pid = 0;
		n->total_pid = 1;
		n->last_pid = initpid;
		n->cfd = cfd;
		insert_node(&n, hash);
	}
	a = n->avenrun[0] + (FIXED_1/200);
	b = n->avenrun[1] + (FIXED_1/200);
	c = n->avenrun[2] + (FIXED_1/200);
	total_len = snprintf(d->buf, d->buflen, "%lu.%02lu %lu.%02lu %lu.%02lu %d/%d %d\n",
		LOAD_INT(a), LOAD_FRAC(a),
		LOAD_INT(b), LOAD_FRAC(b),
		LOAD_INT(c), LOAD_FRAC(c),
		n->run_pid, n->total_pid, n->last_pid);
	pthread_rwlock_unlock(&load_hash[hash].rdlock);
	if (total_len < 0 || total_len >=  d->buflen) {
		lxcfs_error("%s\n", "Failed to write to cache");
		rv = 0;
		goto err;
	}
	d->size = (int)total_len;
	d->cached = 1;

	if (total_len > size)
		total_len = size;
	memcpy(buf, d->buf, total_len);
	rv = total_len;

err:
	free(cg);
	return rv;
}
/* Return a positive number on success, return 0 on failure.*/
pthread_t load_daemon(int load_use)
{
	int ret;
	pthread_t pid;

	ret = init_load();
	if (ret == -1) {
		lxcfs_error("%s\n", "Initialize hash_table fails in load_daemon!");
		return 0;
	}
	ret = pthread_create(&pid, NULL, load_begin, NULL);
	if (ret != 0) {
		lxcfs_error("%s\n", "Create pthread fails in load_daemon!");
		load_free();
		return 0;
	}
	/* use loadavg, here loadavg = 1*/
	loadavg = load_use;
	return pid;
}

/* Returns 0 on success. */
int stop_load_daemon(pthread_t pid)
{
	int s;

	/* Signal the thread to gracefully stop */
	loadavg_stop = 1;

	s = pthread_join(pid, NULL); /* Make sure sub thread has been canceled. */
	if (s != 0) {
		lxcfs_error("%s\n", "stop_load_daemon error: failed to join");
		return -1;
	}

	load_free();
	loadavg_stop = 0;

	return 0;
}

static off_t get_procfile_size(const char *which)
{
	FILE *f = fopen(which, "r");
	char *line = NULL;
	size_t len = 0;
	ssize_t sz, answer = 0;
	if (!f)
		return 0;

	while ((sz = getline(&line, &len, f)) != -1)
		answer += sz;
	fclose (f);
	free(line);

	return answer;
}

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
	if (strcmp(path, "/proc/meminfo") == 0 ||
			strcmp(path, "/proc/cpuinfo") == 0 ||
			strcmp(path, "/proc/uptime") == 0 ||
			strcmp(path, "/proc/stat") == 0 ||
			strcmp(path, "/proc/diskstats") == 0 ||
			strcmp(path, "/proc/swaps") == 0 ||
			strcmp(path, "/proc/loadavg") == 0) {
		sb->st_size = 0;
		sb->st_mode = S_IFREG | 00444;
		sb->st_nlink = 1;
		return 0;
	}

	return -ENOENT;
}

int proc_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
		struct fuse_file_info *fi)
{
	if (filler(buf, ".", NULL, 0) != 0 ||
	    filler(buf, "..", NULL, 0) != 0 ||
	    filler(buf, "cpuinfo", NULL, 0) != 0 ||
	    filler(buf, "meminfo", NULL, 0) != 0 ||
	    filler(buf, "stat", NULL, 0) != 0 ||
	    filler(buf, "uptime", NULL, 0) != 0 ||
	    filler(buf, "diskstats", NULL, 0) != 0 ||
	    filler(buf, "swaps", NULL, 0) != 0   ||
	    filler(buf, "loadavg", NULL, 0) != 0)
		return -EINVAL;
	return 0;
}

int proc_open(const char *path, struct fuse_file_info *fi)
{
	int type = -1;
	struct file_info *info;

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
	do {
		info->buf = malloc(info->buflen);
	} while (!info->buf);
	memset(info->buf, 0, info->buflen);
	/* set actual size to buffer size */
	info->size = info->buflen;

	fi->fh = (unsigned long)info;
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

int proc_read(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	struct file_info *f = (struct file_info *) fi->fh;

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
	default:
		return -EINVAL;
	}
}

/*
 * Functions needed to setup cgroups in the __constructor__.
 */

static bool umount_if_mounted(void)
{
	if (umount2(BASEDIR, MNT_DETACH) < 0 && errno != EINVAL) {
		lxcfs_error("Failed to unmount %s: %s.\n", BASEDIR, strerror(errno));
		return false;
	}
	return true;
}

/* __typeof__ should be safe to use with all compilers. */
typedef __typeof__(((struct statfs *)NULL)->f_type) fs_type_magic;
static bool has_fs_type(const struct statfs *fs, fs_type_magic magic_val)
{
	return (fs->f_type == (fs_type_magic)magic_val);
}

/*
 * looking at fs/proc_namespace.c, it appears we can
 * actually expect the rootfs entry to very specifically contain
 * " - rootfs rootfs "
 * IIUC, so long as we've chrooted so that rootfs is not our root,
 * the rootfs entry should always be skipped in mountinfo contents.
 */
static bool is_on_ramfs(void)
{
	FILE *f;
	char *p, *p2;
	char *line = NULL;
	size_t len = 0;
	int i;

	f = fopen("/proc/self/mountinfo", "r");
	if (!f)
		return false;

	while (getline(&line, &len, f) != -1) {
		for (p = line, i = 0; p && i < 4; i++)
			p = strchr(p + 1, ' ');
		if (!p)
			continue;
		p2 = strchr(p + 1, ' ');
		if (!p2)
			continue;
		*p2 = '\0';
		if (strcmp(p + 1, "/") == 0) {
			// this is '/'.  is it the ramfs?
			p = strchr(p2 + 1, '-');
			if (p && strncmp(p, "- rootfs rootfs ", 16) == 0) {
				free(line);
				fclose(f);
				return true;
			}
		}
	}
	free(line);
	fclose(f);
	return false;
}

static int pivot_enter()
{
	int ret = -1, oldroot = -1, newroot = -1;

	oldroot = open("/", O_DIRECTORY | O_RDONLY);
	if (oldroot < 0) {
		lxcfs_error("%s\n", "Failed to open old root for fchdir.");
		return ret;
	}

	newroot = open(ROOTDIR, O_DIRECTORY | O_RDONLY);
	if (newroot < 0) {
		lxcfs_error("%s\n", "Failed to open new root for fchdir.");
		goto err;
	}

	/* change into new root fs */
	if (fchdir(newroot) < 0) {
		lxcfs_error("Failed to change directory to new rootfs: %s.\n", ROOTDIR);
		goto err;
	}

	/* pivot_root into our new root fs */
	if (pivot_root(".", ".") < 0) {
		lxcfs_error("pivot_root() syscall failed: %s.\n", strerror(errno));
		goto err;
	}

	/*
	 * At this point the old-root is mounted on top of our new-root.
	 * To unmounted it we must not be chdir'd into it, so escape back
	 * to the old-root.
	 */
	if (fchdir(oldroot) < 0) {
		lxcfs_error("%s\n", "Failed to enter old root.");
		goto err;
	}

	if (umount2(".", MNT_DETACH) < 0) {
		lxcfs_error("%s\n", "Failed to detach old root.");
		goto err;
	}

	if (fchdir(newroot) < 0) {
		lxcfs_error("%s\n", "Failed to re-enter new root.");
		goto err;
	}

	ret = 0;

err:
	if (oldroot > 0)
		close(oldroot);
	if (newroot > 0)
		close(newroot);

	return ret;
}

static int chroot_enter()
{
	if (mount(ROOTDIR, "/", NULL, MS_REC | MS_BIND, NULL)) {
		lxcfs_error("Failed to recursively bind-mount %s into /.", ROOTDIR);
		return -1;
	}

	if (chroot(".") < 0) {
		lxcfs_error("Call to chroot() failed: %s.\n", strerror(errno));
		return -1;
	}

	if (chdir("/") < 0) {
		lxcfs_error("Failed to change directory: %s.\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int permute_and_enter(void)
{
	struct statfs sb;

	if (statfs("/", &sb) < 0) {
		lxcfs_error("%s\n", "Could not stat / mountpoint.");
		return -1;
	}

	/* has_fs_type() is not reliable. When the ramfs is a tmpfs it will
	 * likely report TMPFS_MAGIC. Hence, when it reports no we still check
	 * /proc/1/mountinfo. */
	if (has_fs_type(&sb, RAMFS_MAGIC) || is_on_ramfs())
		return chroot_enter();

	if (pivot_enter() < 0) {
		lxcfs_error("%s\n", "Could not perform pivot root.");
		return -1;
	}

	return 0;
}

/* Prepare our new clean root. */
static int permute_prepare(void)
{
	if (mkdir(ROOTDIR, 0700) < 0 && errno != EEXIST) {
		lxcfs_error("%s\n", "Failed to create directory for new root.");
		return -1;
	}

	if (mount("/", ROOTDIR, NULL, MS_BIND, 0) < 0) {
		lxcfs_error("Failed to bind-mount / for new root: %s.\n", strerror(errno));
		return -1;
	}

	if (mount(RUNTIME_PATH, ROOTDIR RUNTIME_PATH, NULL, MS_BIND, 0) < 0) {
		lxcfs_error("Failed to bind-mount /run into new root: %s.\n", strerror(errno));
		return -1;
	}

	if (mount(BASEDIR, ROOTDIR BASEDIR, NULL, MS_REC | MS_MOVE, 0) < 0) {
		printf("Failed to move " BASEDIR " into new root: %s.\n", strerror(errno));
		return -1;
	}

	return 0;
}

/* Calls chroot() on ramfs, pivot_root() in all other cases. */
static bool permute_root(void)
{
	/* Prepare new root. */
	if (permute_prepare() < 0)
		return false;

	/* Pivot into new root. */
	if (permute_and_enter() < 0)
		return false;

	return true;
}

static bool cgfs_prepare_mounts(void)
{
	if (!mkdir_p(BASEDIR, 0700)) {
		lxcfs_error("%s\n", "Failed to create lxcfs cgroup mountpoint.");
		return false;
	}

	if (!umount_if_mounted()) {
		lxcfs_error("%s\n", "Failed to clean up old lxcfs cgroup mountpoint.");
		return false;
	}

	if (unshare(CLONE_NEWNS) < 0) {
		lxcfs_error("Failed to unshare mount namespace: %s.\n", strerror(errno));
		return false;
	}

	cgroup_ops->mntns_fd = preserve_ns(getpid(), "mnt");
	if (cgroup_ops->mntns_fd < 0) {
		lxcfs_error("Failed to preserve mount namespace: %s.\n", strerror(errno));
		return false;
	}

	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, 0) < 0) {
		lxcfs_error("Failed to remount / private: %s.\n", strerror(errno));
		return false;
	}

	if (mount("tmpfs", BASEDIR, "tmpfs", 0, "size=100000,mode=700") < 0) {
		lxcfs_error("%s\n", "Failed to mount tmpfs over lxcfs cgroup mountpoint.");
		return false;
	}

	return true;
}

static bool cgfs_mount_hierarchies(void)
{
	if (!mkdir_p(BASEDIR DEFAULT_CGROUP_MOUNTPOINT, 0755))
		return false;

	if (!cgroup_ops->mount(cgroup_ops, BASEDIR))
		return false;

	for (struct hierarchy **h = cgroup_ops->hierarchies; h && *h; h++) {
		__do_free char *path = must_make_path(BASEDIR, (*h)->mountpoint, NULL);
		(*h)->fd = open(path, O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
		if ((*h)->fd < 0)
			return false;
	}

	return true;
}

static bool cgfs_setup_controllers(void)
{
	if (!cgfs_prepare_mounts())
		return false;

	if (!cgfs_mount_hierarchies()) {
		lxcfs_error("%s\n", "Failed to set up private lxcfs cgroup mounts.");
		return false;
	}

	if (!permute_root())
		return false;

	return true;
}

static void __attribute__((constructor)) lxcfs_init(void)
{
	__do_close_prot_errno int init_ns = -EBADF;
	char *cret;
	char cwd[MAXPATHLEN];

	cgroup_ops = cgroup_init();
	if (!cgroup_ops)
		log_exit("Failed to initialize cgroup support");

	/* Preserve initial namespace. */
	init_ns = preserve_ns(getpid(), "mnt");
	if (init_ns < 0)
		log_exit("Failed to preserve initial mount namespace");

	cret = getcwd(cwd, MAXPATHLEN);
		log_exit("%s - Could not retrieve current working directory", strerror(errno));

	/* This function calls unshare(CLONE_NEWNS) our initial mount namespace
	 * to privately mount lxcfs cgroups. */
	if (!cgfs_setup_controllers())
		log_exit("Failed to setup private cgroup mounts for lxcfs");

	if (setns(init_ns, 0) < 0)
		log_exit("%s - Failed to switch back to initial mount namespace", strerror(errno));

	if (!cret || chdir(cwd) < 0)
		log_exit("%s - Could not change back to original working directory", strerror(errno));

	if (!init_cpuview())
		log_exit("Failed to init CPU view");

	print_subsystems();
}

static void __attribute__((destructor)) lxcfs_exit(void)
{
	lxcfs_debug("%s\n", "Running destructor for liblxcfs");
	free_cpuview();
	cgroup_exit(cgroup_ops);
}
