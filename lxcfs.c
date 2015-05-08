/* lxcfs
 *
 * Copyright © 2014 Canonical, Inc
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
 *
 * See COPYING file for details.
 */

#define FUSE_USE_VERSION 26

#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>
#include <fuse.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <sched.h>
#include <linux/sched.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <wait.h>

#include <nih/alloc.h>
#include <nih/string.h>

#include "cgmanager.h"
#include "config.h" // for VERSION

struct lxcfs_state {
	/*
	 * a null-terminated, nih-allocated list of the mounted subsystems.  We
	 * detect this at startup.
	 */
	char **subsystems;
};
#define LXCFS_DATA ((struct lxcfs_state *) fuse_get_context()->private_data)

enum {
	LXC_TYPE_CGDIR,
	LXC_TYPE_CGFILE,
	LXC_TYPE_PROC_MEMINFO,
	LXC_TYPE_PROC_CPUINFO,
	LXC_TYPE_PROC_UPTIME,
	LXC_TYPE_PROC_STAT,
	LXC_TYPE_PROC_DISKSTATS,
};

struct file_info {
	char *controller;
	char *cgroup;
	char *file;
	int type;
	char *buf;  // unused as of yet
	int buflen;
	int size; //actual data size
};

/* reserve buffer size, for cpuall in /proc/stat */
#define BUF_RESERVE_SIZE 256

static char *must_copy_string(void *parent, const char *str)
{
	if (!str)
		return NULL;
	return NIH_MUST( nih_strdup(parent, str) );
}

/*
 * TODO - return value should denote whether child exited with failure
 * so callers can return errors.  Esp read/write of tasks and cgroup.procs
 */
static int wait_for_pid(pid_t pid)
{
	int status, ret;

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

/*
 * Given a open file * to /proc/pid/{u,g}id_map, and an id
 * valid in the caller's namespace, return the id mapped into
 * pid's namespace.
 * Returns the mapped id, or -1 on error.
 */
unsigned int
convert_id_to_ns(FILE *idfile, unsigned int in_id)
{
	unsigned int nsuid,   // base id for a range in the idfile's namespace
		     hostuid, // base id for a range in the caller's namespace
		     count;   // number of ids in this range
	char line[400];
	int ret;

	fseek(idfile, 0L, SEEK_SET);
	while (fgets(line, 400, idfile)) {
		ret = sscanf(line, "%u %u %u\n", &nsuid, &hostuid, &count);
		if (ret != 3)
			continue;
		if (hostuid + count < hostuid || nsuid + count < nsuid) {
			/*
			 * uids wrapped around - unexpected as this is a procfile,
			 * so just bail.
			 */
			fprintf(stderr, "pid wrapparound at entry %u %u %u in %s\n",
				nsuid, hostuid, count, line);
			return -1;
		}
		if (hostuid <= in_id && hostuid+count > in_id) {
			/*
			 * now since hostuid <= in_id < hostuid+count, and
			 * hostuid+count and nsuid+count do not wrap around,
			 * we know that nsuid+(in_id-hostuid) which must be
			 * less that nsuid+(count) must not wrap around
			 */
			return (in_id - hostuid) + nsuid;
		}
	}

	// no answer found
	return -1;
}

/*
 * for is_privileged_over,
 * specify whether we require the calling uid to be root in his
 * namespace
 */
#define NS_ROOT_REQD true
#define NS_ROOT_OPT false

static bool is_privileged_over(pid_t pid, uid_t uid, uid_t victim, bool req_ns_root)
{
	nih_local char *fpath = NULL;
	bool answer = false;
	uid_t nsuid;

	if (victim == -1 || uid == -1)
		return false;

	/*
	 * If the request is one not requiring root in the namespace,
	 * then having the same uid suffices.  (i.e. uid 1000 has write
	 * access to files owned by uid 1000
	 */
	if (!req_ns_root && uid == victim)
		return true;

	fpath = NIH_MUST( nih_sprintf(NULL, "/proc/%d/uid_map", pid) );
	FILE *f = fopen(fpath, "r");
	if (!f)
		return false;

	/* if caller's not root in his namespace, reject */
	nsuid = convert_id_to_ns(f, uid);
	if (nsuid)
		goto out;

	/*
	 * If victim is not mapped into caller's ns, reject.
	 * XXX I'm not sure this check is needed given that fuse
	 * will be sending requests where the vfs has converted
	 */
	nsuid = convert_id_to_ns(f, victim);
	if (nsuid == -1)
		goto out;

	answer = true;

out:
	fclose(f);
	return answer;
}

static bool perms_include(int fmode, mode_t req_mode)
{
	mode_t r;

	switch (req_mode & O_ACCMODE) {
	case O_RDONLY:
		r = S_IROTH;
		break;
	case O_WRONLY:
		r = S_IWOTH;
		break;
	case O_RDWR:
		r = S_IROTH | S_IWOTH;
		break;
	default:
		return false;
	}
	return ((fmode & r) == r);
}

static char *get_next_cgroup_dir(const char *taskcg, const char *querycg)
{
	char *start, *end;

	if (strlen(taskcg) <= strlen(querycg)) {
		fprintf(stderr, "%s: I was fed bad input\n", __func__);
		return NULL;
	}

	if (strcmp(querycg, "/") == 0)
		start = NIH_MUST( nih_strdup(NULL, taskcg + 1) );
	else
		start = NIH_MUST( nih_strdup(NULL, taskcg + strlen(querycg) + 1) );
	end = strchr(start, '/');
	if (end)
		*end = '\0';
	return start;
}

/*
 * check whether a fuse context may access a cgroup dir or file
 *
 * If file is not null, it is a cgroup file to check under cg.
 * If file is null, then we are checking perms on cg itself.
 *
 * For files we can check the mode of the list_keys result.
 * For cgroups, we must make assumptions based on the files under the
 * cgroup, because cgmanager doesn't tell us ownership/perms of cgroups
 * yet.
 */
static bool fc_may_access(struct fuse_context *fc, const char *contrl, const char *cg, const char *file, mode_t mode)
{
	nih_local struct cgm_keys **list = NULL;
	int i;

	if (!file)
		file = "tasks";

	if (*file == '/')
		file++;

	if (!cgm_list_keys(contrl, cg, &list))
		return false;
	for (i = 0; list[i]; i++) {
		if (strcmp(list[i]->name, file) == 0) {
			struct cgm_keys *k = list[i];
			if (is_privileged_over(fc->pid, fc->uid, k->uid, NS_ROOT_OPT)) {
				if (perms_include(k->mode >> 6, mode))
					return true;
			}
			if (fc->gid == k->gid) {
				if (perms_include(k->mode >> 3, mode))
					return true;
			}
			return perms_include(k->mode, mode);
		}
	}

	return false;
}

static void stripnewline(char *x)
{
	size_t l = strlen(x);
	if (l && x[l-1] == '\n')
		x[l-1] = '\0';
}

/*
 * If caller is in /a/b/c/d, he may only act on things under cg=/a/b/c/d.
 * If caller is in /a, he may act on /a/b, but not on /b.
 * if the answer is false and nextcg is not NULL, then *nextcg will point
 * to a nih_alloc'd string containing the next cgroup directory under cg
 */
static bool caller_is_in_ancestor(pid_t pid, const char *contrl, const char *cg, char **nextcg)
{
	nih_local char *fnam = NULL;
	FILE *f;
	bool answer = false;
	char *line = NULL;
	size_t len = 0;

	fnam = NIH_MUST( nih_sprintf(NULL, "/proc/%d/cgroup", pid) );
	if (!(f = fopen(fnam, "r")))
		return false;

	while (getline(&line, &len, f) != -1) {
		char *c1, *c2, *linecmp;
		if (!line[0])
			continue;
		c1 = strchr(line, ':');
		if (!c1)
			goto out;
		c1++;
		c2 = strchr(c1, ':');
		if (!c2)
			goto out;
		*c2 = '\0';
		if (strcmp(c1, contrl) != 0)
			continue;
		c2++;
		stripnewline(c2);
		/*
		 * callers pass in '/' for root cgroup, otherwise they pass
		 * in a cgroup without leading '/'
		 */
		linecmp = *cg == '/' ? c2 : c2+1;
		if (strncmp(linecmp, cg, strlen(linecmp)) != 0) {
			if (nextcg)
				*nextcg = get_next_cgroup_dir(linecmp, cg);
			goto out;
		}
		answer = true;
		goto out;
	}

out:
	fclose(f);
	free(line);
	return answer;
}

/*
 * given /cgroup/freezer/a/b, return "freezer".  this will be nih-allocated
 * and needs to be nih_freed.
 */
static char *pick_controller_from_path(struct fuse_context *fc, const char *path)
{
	const char *p1;
	char *ret, *slash;

	if (strlen(path) < 9)
		return NULL;
	if (*(path+7) != '/')
		return NULL;
	p1 = path+8;
	ret = nih_strdup(NULL, p1);
	if (!ret)
		return ret;
	slash = strstr(ret, "/");
	if (slash)
		*slash = '\0';

	/* verify that it is a subsystem */
	char **list = LXCFS_DATA ? LXCFS_DATA->subsystems : NULL;
	int i;
	if (!list) {
		nih_free(ret);
		return NULL;
	}
	for (i = 0;  list[i];  i++) {
		if (strcmp(list[i], ret) == 0)
			return ret;
	}
	nih_free(ret);
	return NULL;
}

/*
 * Find the start of cgroup in /cgroup/controller/the/cgroup/path
 * Note that the returned value may include files (keynames) etc
 */
static const char *find_cgroup_in_path(const char *path)
{
	const char *p1;

	if (strlen(path) < 9)
		return NULL;
	p1 = strstr(path+8, "/");
	if (!p1)
		return NULL;
	return p1+1;
}

static bool is_child_cgroup(const char *contr, const char *dir, const char *f)
{
	nih_local char **list = NULL;
	int i;

	if (!f)
		return false;
	if (*f == '/')
		f++;

	if (!cgm_list_children(contr, dir, &list))
		return false;
	for (i = 0; list[i]; i++) {
		if (strcmp(list[i], f) == 0)
			return true;
	}

	return false;
}

static struct cgm_keys *get_cgroup_key(const char *contr, const char *dir, const char *f)
{
	nih_local struct cgm_keys **list = NULL;
	struct cgm_keys *k;
	int i;

	if (!f)
		return NULL;
	if (*f == '/')
		f++;
	if (!cgm_list_keys(contr, dir, &list))
		return NULL;
	for (i = 0; list[i]; i++) {
		if (strcmp(list[i]->name, f) == 0) {
			k = NIH_MUST( nih_alloc(NULL, (sizeof(*k))) );
			k->name = NIH_MUST( nih_strdup(k, list[i]->name) );
			k->uid = list[i]->uid;
			k->gid = list[i]->gid;
			k->mode = list[i]->mode;
			return k;
		}
	}

	return NULL;
}

static void get_cgdir_and_path(const char *cg, char **dir, char **file)
{
	char *p;

	*dir = NIH_MUST( nih_strdup(NULL, cg) );
	*file = strrchr(cg, '/');
	if (!*file) {
		*file = NULL;
		return;
	}
	p = strrchr(*dir, '/');
	*p = '\0';
}

/*
 * FUSE ops for /cgroup
 */

static int cg_getattr(const char *path, struct stat *sb)
{
	struct timespec now;
	struct fuse_context *fc = fuse_get_context();
	nih_local char * cgdir = NULL;
	char *fpath = NULL, *path1, *path2;
	nih_local struct cgm_keys *k = NULL;
	const char *cgroup;
	nih_local char *controller = NULL;


	if (!fc)
		return -EIO;

	memset(sb, 0, sizeof(struct stat));

	if (clock_gettime(CLOCK_REALTIME, &now) < 0)
		return -EINVAL;

	sb->st_uid = sb->st_gid = 0;
	sb->st_atim = sb->st_mtim = sb->st_ctim = now;
	sb->st_size = 0;

	if (strcmp(path, "/cgroup") == 0) {
		sb->st_mode = S_IFDIR | 00755;
		sb->st_nlink = 2;
		return 0;
	}

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return -EIO;
	cgroup = find_cgroup_in_path(path);
	if (!cgroup) {
		/* this is just /cgroup/controller, return it as a dir */
		sb->st_mode = S_IFDIR | 00755;
		sb->st_nlink = 2;
		return 0;
	}

	get_cgdir_and_path(cgroup, &cgdir, &fpath);

	if (!fpath) {
		path1 = "/";
		path2 = cgdir;
	} else {
		path1 = cgdir;
		path2 = fpath;
	}

	/* check that cgcopy is either a child cgroup of cgdir, or listed in its keys.
	 * Then check that caller's cgroup is under path if fpath is a child
	 * cgroup, or cgdir if fpath is a file */

	if (is_child_cgroup(controller, path1, path2)) {
		if (!caller_is_in_ancestor(fc->pid, controller, cgroup, NULL)) {
			/* this is just /cgroup/controller, return it as a dir */
			sb->st_mode = S_IFDIR | 00555;
			sb->st_nlink = 2;
			return 0;
		}
		if (!fc_may_access(fc, controller, cgroup, NULL, O_RDONLY))
			return -EACCES;

		// get uid, gid, from '/tasks' file and make up a mode
		// That is a hack, until cgmanager gains a GetCgroupPerms fn.
		sb->st_mode = S_IFDIR | 00755;
		k = get_cgroup_key(controller, cgroup, "tasks");
		if (!k) {
			sb->st_uid = sb->st_gid = 0;
		} else {
			sb->st_uid = k->uid;
			sb->st_gid = k->gid;
		}
		sb->st_nlink = 2;
		return 0;
	}

	if ((k = get_cgroup_key(controller, path1, path2)) != NULL) {
		if (!caller_is_in_ancestor(fc->pid, controller, path1, NULL))
			return -ENOENT;
		if (!fc_may_access(fc, controller, path1, path2, O_RDONLY))
			return -EACCES;

		sb->st_mode = S_IFREG | k->mode;
		sb->st_nlink = 1;
		sb->st_uid = k->uid;
		sb->st_gid = k->gid;
		sb->st_size = 0;
		return 0;
	}

	return -ENOENT;
}

/*
 * TODO - cache these results in a table for use in opendir, free
 * in releasedir
 */
static int cg_opendir(const char *path, struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	nih_local struct cgm_keys **list = NULL;
	const char *cgroup;
	struct file_info *dir_info;
	nih_local char *controller = NULL;

	if (!fc)
		return -EIO;

	if (strcmp(path, "/cgroup") == 0) {
		cgroup = NULL;
		controller = NULL;
	} else {
		// return list of keys for the controller, and list of child cgroups
		controller = pick_controller_from_path(fc, path);
		if (!controller)
			return -EIO;

		cgroup = find_cgroup_in_path(path);
		if (!cgroup) {
			/* this is just /cgroup/controller, return its contents */
			cgroup = "/";
		}
	}

	if (cgroup && !fc_may_access(fc, controller, cgroup, NULL, O_RDONLY))
		return -EACCES;

	/* we'll free this at cg_releasedir */
	dir_info = NIH_MUST( nih_alloc(NULL, sizeof(*dir_info)) );
	dir_info->controller = must_copy_string(dir_info, controller);
	dir_info->cgroup = must_copy_string(dir_info, cgroup);
	dir_info->type = LXC_TYPE_CGDIR;
	dir_info->buf = NULL;
	dir_info->file = NULL;
	dir_info->buflen = 0;

	fi->fh = (unsigned long)dir_info;
	return 0;
}

static int cg_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
		struct fuse_file_info *fi)
{
	struct file_info *d = (struct file_info *)fi->fh;
	nih_local struct cgm_keys **list = NULL;
	int i;
	nih_local char *nextcg = NULL;
	struct fuse_context *fc = fuse_get_context();

	if (d->type != LXC_TYPE_CGDIR) {
		fprintf(stderr, "Internal error: file cache info used in readdir\n");
		return -EIO;
	}
	if (!d->cgroup && !d->controller) {
		// ls /var/lib/lxcfs/cgroup - just show list of controllers
		char **list = LXCFS_DATA ? LXCFS_DATA->subsystems : NULL;
		int i;

		if (!list)
			return -EIO;

		for (i = 0;  list[i]; i++) {
			if (filler(buf, list[i], NULL, 0) != 0) {
				return -EIO;
			}
		}
		return 0;
	}

	if (!cgm_list_keys(d->controller, d->cgroup, &list))
		// not a valid cgroup
		return -EINVAL;

	if (!caller_is_in_ancestor(fc->pid, d->controller, d->cgroup, &nextcg)) {
		if (nextcg) {
			int ret;
			ret = filler(buf, nextcg,  NULL, 0);
			if (ret != 0)
				return -EIO;
		}
		return 0;
	}

	for (i = 0; list[i]; i++) {
		if (filler(buf, list[i]->name, NULL, 0) != 0) {
			return -EIO;
		}
	}

	// now get the list of child cgroups
	nih_local char **clist = NULL;

	if (!cgm_list_children(d->controller, d->cgroup, &clist))
		return 0;
	for (i = 0; clist[i]; i++) {
		if (filler(buf, clist[i], NULL, 0) != 0) {
			return -EIO;
		}
	}
	return 0;
}

static void do_release_file_info(struct file_info *f)
{
	/*
	 * all file_info fields which are nih_alloc()d with f as parent
	 * will be automatically freed
	 */
	nih_free(f);
}

static int cg_releasedir(const char *path, struct fuse_file_info *fi)
{
	struct file_info *d = (struct file_info *)fi->fh;

	do_release_file_info(d);
	return 0;
}

static int cg_open(const char *path, struct fuse_file_info *fi)
{
	nih_local char *controller = NULL;
	const char *cgroup;
	char *fpath = NULL, *path1, *path2;
	nih_local char * cgdir = NULL;
	nih_local struct cgm_keys *k = NULL;
	struct file_info *file_info;
	struct fuse_context *fc = fuse_get_context();

	if (!fc)
		return -EIO;

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return -EIO;
	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		return -EINVAL;

	get_cgdir_and_path(cgroup, &cgdir, &fpath);
	if (!fpath) {
		path1 = "/";
		path2 = cgdir;
	} else {
		path1 = cgdir;
		path2 = fpath;
	}

	k = get_cgroup_key(controller, path1, path2);
	if (!k)
		return -EINVAL;

	if (!fc_may_access(fc, controller, path1, path2, fi->flags))
		// should never get here
		return -EACCES;

	/* we'll free this at cg_release */
	file_info = NIH_MUST( nih_alloc(NULL, sizeof(*file_info)) );
	file_info->controller = must_copy_string(file_info, controller);
	file_info->cgroup = must_copy_string(file_info, path1);
	file_info->file = must_copy_string(file_info, path2);
	file_info->type = LXC_TYPE_CGFILE;
	file_info->buf = NULL;
	file_info->buflen = 0;

	fi->fh = (unsigned long)file_info;
	return 0;
}

static int cg_release(const char *path, struct fuse_file_info *fi)
{
	struct file_info *f = (struct file_info *)fi->fh;

	do_release_file_info(f);
	return 0;
}

static int msgrecv(int sockfd, void *buf, size_t len)
{
	struct timeval tv;
	fd_set rfds;

	FD_ZERO(&rfds);
	FD_SET(sockfd, &rfds);
	tv.tv_sec = 2;
	tv.tv_usec = 0;

	if (select(sockfd+1, &rfds, NULL, NULL, &tv) <= 0)
		return -1;
	return recv(sockfd, buf, len, MSG_DONTWAIT);
}

#define SEND_CREDS_OK 0
#define SEND_CREDS_NOTSK 1
#define SEND_CREDS_FAIL 2
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
			fprintf(stderr, "%s: Error getting reply from server over socketpair\n",
				  __func__);
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
		fprintf(stderr, "%s: failed at sendmsg: %s\n", __func__,
			  strerror(errno));
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
	struct timeval tv;
	fd_set rfds;

	*v = '1';

	cred->pid = -1;
	cred->uid = -1;
	cred->gid = -1;

	if (setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		fprintf(stderr, "Failed to set passcred: %s\n", strerror(errno));
		return false;
	}
	buf[0] = '1';
	if (write(sock, buf, 1) != 1) {
		fprintf(stderr, "Failed to start write on scm fd: %s\n", strerror(errno));
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

	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	if (select(sock+1, &rfds, NULL, NULL, &tv) <= 0) {
		fprintf(stderr, "Failed to select for scm_cred: %s\n",
			  strerror(errno));
		return false;
	}
	ret = recvmsg(sock, &msg, MSG_DONTWAIT);
	if (ret < 0) {
		fprintf(stderr, "Failed to receive scm_cred: %s\n",
			  strerror(errno));
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


/*
 * pid_to_ns - reads pids from a ucred over a socket, then writes the
 * int value back over the socket.  This shifts the pid from the
 * sender's pidns into tpid's pidns.
 */
static void pid_to_ns(int sock, pid_t tpid)
{
	char v = '0';
	struct ucred cred;

	while (recv_creds(sock, &cred, &v)) {
		if (v == '1')
			exit(0);
		if (write(sock, &cred.pid, sizeof(pid_t)) != sizeof(pid_t))
			exit(1);
	}
	exit(0);
}

/*
 * pid_to_ns_wrapper: when you setns into a pidns, you yourself remain
 * in your old pidns.  Only children which you fork will be in the target
 * pidns.  So the pid_to_ns_wrapper does the setns, then forks a child to
 * actually convert pids
 */
static void pid_to_ns_wrapper(int sock, pid_t tpid)
{
	int newnsfd = -1, ret, cpipe[2];
	char fnam[100];
	pid_t cpid;
	struct timeval tv;
	fd_set s;
	char v;

	ret = snprintf(fnam, sizeof(fnam), "/proc/%d/ns/pid", tpid);
	if (ret < 0 || ret >= sizeof(fnam))
		exit(1);
	newnsfd = open(fnam, O_RDONLY);
	if (newnsfd < 0)
		exit(1);
	if (setns(newnsfd, 0) < 0)
		exit(1);
	close(newnsfd);

	if (pipe(cpipe) < 0)
		exit(1);

loop:
	cpid = fork();
	if (cpid < 0)
		exit(1);

	if (!cpid) {
		char b = '1';
		close(cpipe[0]);
		if (write(cpipe[1], &b, sizeof(char)) < 0) {
			fprintf(stderr, "%s (child): erorr on write: %s\n",
				__func__, strerror(errno));
		}
		close(cpipe[1]);
		pid_to_ns(sock, tpid);
	}
	// give the child 1 second to be done forking and
	// write it's ack
	FD_ZERO(&s);
	FD_SET(cpipe[0], &s);
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	ret = select(cpipe[0]+1, &s, NULL, NULL, &tv);
	if (ret <= 0)
		goto again;
	ret = read(cpipe[0], &v, 1);
	if (ret != sizeof(char) || v != '1') {
		goto again;
	}

	if (!wait_for_pid(cpid))
		exit(1);
	exit(0);

again:
	kill(cpid, SIGKILL);
	wait_for_pid(cpid);
	goto loop;
}

/*
 * To read cgroup files with a particular pid, we will setns into the child
 * pidns, open a pipe, fork a child - which will be the first to really be in
 * the child ns - which does the cgm_get_value and writes the data to the pipe.
 */
static bool do_read_pids(pid_t tpid, const char *contrl, const char *cg, const char *file, char **d)
{
	int sock[2] = {-1, -1};
	nih_local char *tmpdata = NULL;
	int ret;
	pid_t qpid, cpid = -1;
	bool answer = false;
	char v = '0';
	struct ucred cred;
	struct timeval tv;
	fd_set s;

	if (!cgm_get_value(contrl, cg, file, &tmpdata))
		return false;

	/*
	 * Now we read the pids from returned data one by one, pass
	 * them into a child in the target namespace, read back the
	 * translated pids, and put them into our to-return data
	 */

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sock) < 0) {
		perror("socketpair");
		exit(1);
	}

	cpid = fork();
	if (cpid == -1)
		goto out;

	if (!cpid) // child
		pid_to_ns_wrapper(sock[1], tpid);

	char *ptr = tmpdata;
	cred.uid = 0;
	cred.gid = 0;
	while (sscanf(ptr, "%d\n", &qpid) == 1) {
		cred.pid = qpid;
		ret = send_creds(sock[0], &cred, v, true);

		if (ret == SEND_CREDS_NOTSK)
			goto next;
		if (ret == SEND_CREDS_FAIL)
			goto out;

		// read converted results
		FD_ZERO(&s);
		FD_SET(sock[0], &s);
		tv.tv_sec = 2;
		tv.tv_usec = 0;
		ret = select(sock[0]+1, &s, NULL, NULL, &tv);
		if (ret <= 0) {
			fprintf(stderr, "%s: select error waiting for pid from child: %s\n",
				__func__, strerror(errno));
			goto out;
		}
		if (read(sock[0], &qpid, sizeof(qpid)) != sizeof(qpid)) {
			fprintf(stderr, "%s: error reading pid from child: %s\n",
				__func__, strerror(errno));
			goto out;
		}
		NIH_MUST( nih_strcat_sprintf(d, NULL, "%d\n", qpid) );
next:
		ptr = strchr(ptr, '\n');
		if (!ptr)
			break;
		ptr++;
	}

	cred.pid = getpid();
	v = '1';
	if (send_creds(sock[0], &cred, v, true) != SEND_CREDS_OK) {
		// failed to ask child to exit
		fprintf(stderr, "%s: failed to ask child to exit: %s\n",
			__func__, strerror(errno));
		goto out;
	}

	answer = true;

out:
	if (cpid != -1)
		wait_for_pid(cpid);
	if (sock[0] != -1) {
		close(sock[0]);
		close(sock[1]);
	}
	return answer;
}

static int cg_read(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	struct file_info *f = (struct file_info *)fi->fh;
	nih_local struct cgm_keys *k = NULL;

	if (f->type != LXC_TYPE_CGFILE) {
		fprintf(stderr, "Internal error: directory cache info used in cg_read\n");
		return -EIO;
	}

	if (offset)
		return 0;

	if (!fc)
		return -EIO;

	if (!f->controller)
		return -EINVAL;

	if ((k = get_cgroup_key(f->controller, f->cgroup, f->file)) != NULL) {
		nih_local char *data = NULL;
		int s;
		bool r;

		if (!fc_may_access(fc, f->controller, f->cgroup, f->file, O_RDONLY))
			// should never get here
			return -EACCES;

		if (strcmp(f->file, "tasks") == 0 ||
				strcmp(f->file, "/tasks") == 0 ||
				strcmp(f->file, "/cgroup.procs") == 0 ||
				strcmp(f->file, "cgroup.procs") == 0)
			// special case - we have to translate the pids
			r = do_read_pids(fc->pid, f->controller, f->cgroup, f->file, &data);
		else
			r = cgm_get_value(f->controller, f->cgroup, f->file, &data);

		if (!r)
			return -EINVAL;

		if (!data)
			return 0;
		s = strlen(data);
		if (s > size)
			s = size;
		memcpy(buf, data, s);
		if (s > 0 && s < size && data[s-1] != '\n')
			buf[s++] = '\n';

		return s;
	}

	return -EINVAL;
}

static void pid_from_ns(int sock, pid_t tpid)
{
	pid_t vpid;
	struct ucred cred;
	char v;
	struct timeval tv;
	fd_set s;
	int ret;

	cred.uid = 0;
	cred.gid = 0;
	while (1) {
		FD_ZERO(&s);
		FD_SET(sock, &s);
		tv.tv_sec = 2;
		tv.tv_usec = 0;
		ret = select(sock+1, &s, NULL, NULL, &tv);
		if (ret <= 0) {
			fprintf(stderr, "%s: bad select before read from parent: %s\n",
				__func__, strerror(errno));
			exit(1);
		}
		if ((ret = read(sock, &vpid, sizeof(pid_t))) != sizeof(pid_t)) {
			fprintf(stderr, "%s: bad read from parent: %s\n",
				__func__, strerror(errno));
			exit(1);
		}
		if (vpid == -1) // done
			break;
		v = '0';
		cred.pid = vpid;
		if (send_creds(sock, &cred, v, true) != SEND_CREDS_OK) {
			v = '1';
			cred.pid = getpid();
			if (send_creds(sock, &cred, v, false) != SEND_CREDS_OK)
				exit(1);
		}
	}
	exit(0);
}

static void pid_from_ns_wrapper(int sock, pid_t tpid)
{
	int newnsfd = -1, ret, cpipe[2];
	char fnam[100];
	pid_t cpid;
	fd_set s;
	struct timeval tv;
	char v;

	ret = snprintf(fnam, sizeof(fnam), "/proc/%d/ns/pid", tpid);
	if (ret < 0 || ret >= sizeof(fnam))
		exit(1);
	newnsfd = open(fnam, O_RDONLY);
	if (newnsfd < 0)
		exit(1);
	if (setns(newnsfd, 0) < 0)
		exit(1);
	close(newnsfd);

	if (pipe(cpipe) < 0)
		exit(1);

loop:
	cpid = fork();

	if (cpid < 0)
		exit(1);

	if (!cpid) {
		char b = '1';
		close(cpipe[0]);
		if (write(cpipe[1], &b, sizeof(char)) < 0) {
			fprintf(stderr, "%s (child): erorr on write: %s\n",
				__func__, strerror(errno));
		}
		close(cpipe[1]);
		pid_from_ns(sock, tpid);
	}

	// give the child 1 second to be done forking and
	// write it's ack
	FD_ZERO(&s);
	FD_SET(cpipe[0], &s);
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	ret = select(cpipe[0]+1, &s, NULL, NULL, &tv);
	if (ret <= 0)
		goto again;
	ret = read(cpipe[0], &v, 1);
	if (ret != sizeof(char) || v != '1') {
		goto again;
	}

	if (!wait_for_pid(cpid))
		exit(1);
	exit(0);

again:
	kill(cpid, SIGKILL);
	wait_for_pid(cpid);
	goto loop;
}

static bool do_write_pids(pid_t tpid, const char *contrl, const char *cg, const char *file, const char *buf)
{
	int sock[2] = {-1, -1};
	pid_t qpid, cpid = -1;
	bool answer = false, fail = false;

	/*
	 * write the pids to a socket, have helper in writer's pidns
	 * call movepid for us
	 */
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sock) < 0) {
		perror("socketpair");
		exit(1);
	}

	cpid = fork();
	if (cpid == -1)
		goto out;

	if (!cpid) // child
		pid_from_ns_wrapper(sock[1], tpid);

	const char *ptr = buf;
	while (sscanf(ptr, "%d", &qpid) == 1) {
		struct ucred cred;
		char v;

		if (write(sock[0], &qpid, sizeof(qpid)) != sizeof(qpid)) {
			fprintf(stderr, "%s: error writing pid to child: %s\n",
				__func__, strerror(errno));
			goto out;
		}

		if (recv_creds(sock[0], &cred, &v)) {
			if (v == '0') {
				if (!cgm_move_pid(contrl, cg, cred.pid))
					fail = true;
			}
		}

		ptr = strchr(ptr, '\n');
		if (!ptr)
			break;
		ptr++;
	}

	/* All good, write the value */
	qpid = -1;
	if (write(sock[0], &qpid ,sizeof(qpid)) != sizeof(qpid))
		fprintf(stderr, "Warning: failed to ask child to exit\n");

	if (!fail)
		answer = true;

out:
	if (cpid != -1)
		wait_for_pid(cpid);
	if (sock[0] != -1) {
		close(sock[0]);
		close(sock[1]);
	}
	return answer;
}

int cg_write(const char *path, const char *buf, size_t size, off_t offset,
	     struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	nih_local char *localbuf = NULL;
	nih_local struct cgm_keys *k = NULL;
	struct file_info *f = (struct file_info *)fi->fh;

	if (f->type != LXC_TYPE_CGFILE) {
		fprintf(stderr, "Internal error: directory cache info used in cg_write\n");
		return -EIO;
	}

	if (offset)
		return 0;

	if (!fc)
		return -EIO;

	localbuf = NIH_MUST( nih_alloc(NULL, size+1) );
	localbuf[size] = '\0';
	memcpy(localbuf, buf, size);

	if ((k = get_cgroup_key(f->controller, f->cgroup, f->file)) != NULL) {
		bool r;

		if (!fc_may_access(fc, f->controller, f->cgroup, f->file, O_WRONLY))
			return -EACCES;

		if (strcmp(f->file, "tasks") == 0 ||
				strcmp(f->file, "/tasks") == 0 ||
				strcmp(f->file, "/cgroup.procs") == 0 ||
				strcmp(f->file, "cgroup.procs") == 0)
			// special case - we have to translate the pids
			r = do_write_pids(fc->pid, f->controller, f->cgroup, f->file, localbuf);
		else
			r = cgm_set_value(f->controller, f->cgroup, f->file, localbuf);

		if (!r)
			return -EINVAL;

		return size;
	}

	return -EINVAL;
}

int cg_chown(const char *path, uid_t uid, gid_t gid)
{
	struct fuse_context *fc = fuse_get_context();
	nih_local char * cgdir = NULL;
	char *fpath = NULL, *path1, *path2;
	nih_local struct cgm_keys *k = NULL;
	const char *cgroup;
	nih_local char *controller = NULL;


	if (!fc)
		return -EIO;

	if (strcmp(path, "/cgroup") == 0)
		return -EINVAL;

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return -EINVAL;
	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		/* this is just /cgroup/controller */
		return -EINVAL;

	get_cgdir_and_path(cgroup, &cgdir, &fpath);

	if (!fpath) {
		path1 = "/";
		path2 = cgdir;
	} else {
		path1 = cgdir;
		path2 = fpath;
	}

	if (is_child_cgroup(controller, path1, path2)) {
		// get uid, gid, from '/tasks' file and make up a mode
		// That is a hack, until cgmanager gains a GetCgroupPerms fn.
		k = get_cgroup_key(controller, cgroup, "tasks");

	} else
		k = get_cgroup_key(controller, path1, path2);

	if (!k)
		return -EINVAL;

	/*
	 * This being a fuse request, the uid and gid must be valid
	 * in the caller's namespace.  So we can just check to make
	 * sure that the caller is root in his uid, and privileged
	 * over the file's current owner.
	 */
	if (!is_privileged_over(fc->pid, fc->uid, k->uid, NS_ROOT_REQD))
		return -EACCES;

	if (!cgm_chown_file(controller, cgroup, uid, gid))
		return -EINVAL;
	return 0;
}

int cg_chmod(const char *path, mode_t mode)
{
	struct fuse_context *fc = fuse_get_context();
	nih_local char * cgdir = NULL;
	char *fpath = NULL, *path1, *path2;
	nih_local struct cgm_keys *k = NULL;
	const char *cgroup;
	nih_local char *controller = NULL;

	if (!fc)
		return -EIO;

	if (strcmp(path, "/cgroup") == 0)
		return -EINVAL;

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return -EINVAL;
	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		/* this is just /cgroup/controller */
		return -EINVAL;

	get_cgdir_and_path(cgroup, &cgdir, &fpath);

	if (!fpath) {
		path1 = "/";
		path2 = cgdir;
	} else {
		path1 = cgdir;
		path2 = fpath;
	}

	if (is_child_cgroup(controller, path1, path2)) {
		// get uid, gid, from '/tasks' file and make up a mode
		// That is a hack, until cgmanager gains a GetCgroupPerms fn.
		k = get_cgroup_key(controller, cgroup, "tasks");

	} else
		k = get_cgroup_key(controller, path1, path2);

	if (!k)
		return -EINVAL;

	/*
	 * This being a fuse request, the uid and gid must be valid
	 * in the caller's namespace.  So we can just check to make
	 * sure that the caller is root in his uid, and privileged
	 * over the file's current owner.
	 */
	if (!is_privileged_over(fc->pid, fc->uid, k->uid, NS_ROOT_OPT))
		return -EPERM;

	if (!cgm_chmod_file(controller, cgroup, mode))
		return -EINVAL;
	return 0;
}

int cg_mkdir(const char *path, mode_t mode)
{
	struct fuse_context *fc = fuse_get_context();
	nih_local struct cgm_keys **list = NULL;
	char *fpath = NULL, *path1;
	nih_local char * cgdir = NULL;
	const char *cgroup;
	nih_local char *controller = NULL;

	if (!fc)
		return -EIO;


	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return -EINVAL;

	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		return -EINVAL;

	get_cgdir_and_path(cgroup, &cgdir, &fpath);
	if (!fpath)
		path1 = "/";
	else
		path1 = cgdir;

	if (!fc_may_access(fc, controller, path1, NULL, O_RDWR))
		return -EACCES;


	if (!cgm_create(controller, cgroup, fc->uid, fc->gid))
		return -EINVAL;

	return 0;
}

static int cg_rmdir(const char *path)
{
	struct fuse_context *fc = fuse_get_context();
	nih_local struct cgm_keys **list = NULL;
	char *fpath = NULL;
	nih_local char * cgdir = NULL;
	const char *cgroup;
	nih_local char *controller = NULL;

	if (!fc)
		return -EIO;


	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return -EINVAL;

	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		return -EINVAL;

	get_cgdir_and_path(cgroup, &cgdir, &fpath);
	if (!fpath)
		return -EINVAL;

	if (!fc_may_access(fc, controller, cgdir, NULL, O_WRONLY))
		return -EACCES;

	if (!cgm_remove(controller, cgroup))
		return -EINVAL;

	return 0;
}

static bool startswith(const char *line, const char *pref)
{
	if (strncmp(line, pref, strlen(pref)) == 0)
		return true;
	return false;
}

static void get_mem_cached(char *memstat, unsigned long *v)
{
	char *eol;

	*v = 0;
	while (*memstat) {
		if (startswith(memstat, "total_cache")) {
			sscanf(memstat + 11, "%lu", v);
			*v /= 1024;
			return;
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

static char *get_pid_cgroup(pid_t pid, const char *contrl)
{
	nih_local char *fnam = NULL;
	FILE *f;
	char *answer = NULL;
	char *line = NULL;
	size_t len = 0;

	fnam = NIH_MUST( nih_sprintf(NULL, "/proc/%d/cgroup", pid) );
	if (!(f = fopen(fnam, "r")))
		return false;

	while (getline(&line, &len, f) != -1) {
		char *c1, *c2;
		if (!line[0])
			continue;
		c1 = strchr(line, ':');
		if (!c1)
			goto out;
		c1++;
		c2 = strchr(c1, ':');
		if (!c2)
			goto out;
		*c2 = '\0';
		if (strcmp(c1, contrl) != 0)
			continue;
		c2++;
		stripnewline(c2);
		answer = NIH_MUST( nih_strdup(NULL, c2) );
		goto out;
	}

out:
	fclose(f);
	free(line);
	return answer;
}

/*
 * FUSE ops for /proc
 */

static int proc_meminfo_read(char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = (struct file_info *)fi->fh;
	nih_local char *cg = get_pid_cgroup(fc->pid, "memory");
	nih_local char *memlimit_str = NULL, *memusage_str = NULL, *memstat_str = NULL;
	unsigned long memlimit = 0, memusage = 0, cached = 0, hosttotal = 0;
	char *line = NULL;
	size_t linelen = 0, total_len = 0, rv = 0;
	char *cache = d->buf;
	size_t cache_size = d->buflen;
	FILE *f;

	if (offset){
		if (offset > d->size)
			return -EINVAL;
		int left = d->size - offset;
		total_len = left > size ? size: left;
		memcpy(buf, cache + offset, total_len);
		return total_len;
	}

	if (!cg)
		return 0;

	if (!cgm_get_value("memory", cg, "memory.limit_in_bytes", &memlimit_str))
		return 0;
	if (!cgm_get_value("memory", cg, "memory.usage_in_bytes", &memusage_str))
		return 0;
	if (!cgm_get_value("memory", cg, "memory.stat", &memstat_str))
		return 0;
	memlimit = strtoul(memlimit_str, NULL, 10);
	memusage = strtoul(memusage_str, NULL, 10);
	memlimit /= 1024;
	memusage /= 1024;
	get_mem_cached(memstat_str, &cached);

	f = fopen("/proc/meminfo", "r");
	if (!f)
		return 0;

	while (getline(&line, &linelen, f) != -1) {
		size_t l;
		char *printme, lbuf[100];

		memset(lbuf, 0, 100);
		if (startswith(line, "MemTotal:")) {
			sscanf(line+14, "%lu", &hosttotal);
			if (hosttotal < memlimit)
				memlimit = hosttotal;
			snprintf(lbuf, 100, "MemTotal:       %8lu kB\n", memlimit);
			printme = lbuf;
		} else if (startswith(line, "MemFree:")) {
			snprintf(lbuf, 100, "MemFree:        %8lu kB\n", memlimit - memusage);
			printme = lbuf;
		} else if (startswith(line, "MemAvailable:")) {
			snprintf(lbuf, 100, "MemAvailable:   %8lu kB\n", memlimit - memusage);
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
		} else
			printme = line;

		l = snprintf(cache, cache_size, "%s", printme);
		if (l < 0) {
			perror("Error writing to cache");
			rv = 0;
			goto err;

		}
		if (l >= cache_size) {
			fprintf(stderr, "Internal error: truncated write to cache\n");
			rv = 0;
			goto err;
		}

		cache += l;
		cache_size -= l;
		total_len += l;
	}

	d->size = total_len;
	if (total_len > size ) total_len = size;
	memcpy(buf, d->buf, total_len);

	rv = total_len;
  err:
	fclose(f);
	free(line);
	return rv;
}

/*
 * Read the cpuset.cpus for cg
 * Return the answer in a nih_alloced string
 */
static char *get_cpuset(const char *cg)
{
	char *answer;

	if (!cgm_get_value("cpuset", cg, "cpuset.cpus", &answer))
		return NULL;
	return answer;
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
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = (struct file_info *)fi->fh;
	nih_local char *cg = get_pid_cgroup(fc->pid, "cpuset");
	nih_local char *cpuset = NULL;
	char *line = NULL;
	size_t linelen = 0, total_len = 0, rv = 0;
	bool am_printing = false;
	int curcpu = -1;
	char *cache = d->buf;
	size_t cache_size = d->buflen;
	FILE *f;

	if (offset){
		if (offset > d->size)
			return -EINVAL;
		int left = d->size - offset;
		total_len = left > size ? size: left;
		memcpy(buf, cache + offset, total_len);
		return total_len;
	}

	if (!cg)
		return 0;

	cpuset = get_cpuset(cg);
	if (!cpuset)
		return 0;

	f = fopen("/proc/cpuinfo", "r");
	if (!f)
		return 0;

	while (getline(&line, &linelen, f) != -1) {
		size_t l;
		if (is_processor_line(line)) {
			am_printing = cpuline_in_cpuset(line, cpuset);
			if (am_printing) {
				curcpu ++;
				l = snprintf(cache, cache_size, "processor	: %d\n", curcpu);
				if (l < 0) {
					perror("Error writing to cache");
					rv = 0;
					goto err;
				}
				if (l >= cache_size) {
					fprintf(stderr, "Internal error: truncated write to cache\n");
					rv = 0;
					goto err;
				}
				if (l < cache_size){
					cache += l;
					cache_size -= l;
					total_len += l;
				}else{
					cache += cache_size;
					total_len += cache_size;
					cache_size = 0;
					break;
				}
			}
			continue;
		}
		if (am_printing) {
			l = snprintf(cache, cache_size, "%s", line);
			if (l < 0) {
				perror("Error writing to cache");
				rv = 0;
				goto err;
			}
			if (l >= cache_size) {
				fprintf(stderr, "Internal error: truncated write to cache\n");
				rv = 0;
				goto err;
			}
			if (l < cache_size) {
				cache += l;
				cache_size -= l;
				total_len += l;
			} else {
				cache += cache_size;
				total_len += cache_size;
				cache_size = 0;
				break;
			}
		}
	}

	d->size = total_len;
	if (total_len > size ) total_len = size;

	/* read from off 0 */
	memcpy(buf, d->buf, total_len);
	rv = total_len;
  err:
	fclose(f);
	free(line);
	return rv;
}

static int proc_stat_read(char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = (struct file_info *)fi->fh;
	nih_local char *cg = get_pid_cgroup(fc->pid, "cpuset");
	nih_local char *cpuset = NULL;
	char *line = NULL;
	size_t linelen = 0, total_len = 0, rv = 0;
	int curcpu = -1; /* cpu numbering starts at 0 */
	unsigned long user = 0, nice = 0, system = 0, idle = 0, iowait = 0, irq = 0, softirq = 0, steal = 0, guest = 0;
	unsigned long user_sum = 0, nice_sum = 0, system_sum = 0, idle_sum = 0, iowait_sum = 0,
					irq_sum = 0, softirq_sum = 0, steal_sum = 0, guest_sum = 0;
#define CPUALL_MAX_SIZE BUF_RESERVE_SIZE
	char cpuall[CPUALL_MAX_SIZE];
	/* reserve for cpu all */
	char *cache = d->buf + CPUALL_MAX_SIZE;
	size_t cache_size = d->buflen - CPUALL_MAX_SIZE;
	FILE *f;

	if (offset){
		if (offset > d->size)
			return -EINVAL;
		int left = d->size - offset;
		total_len = left > size ? size: left;
		memcpy(buf, d->buf + offset, total_len);
		return total_len;
	}

	if (!cg)
		return 0;

	cpuset = get_cpuset(cg);
	if (!cpuset)
		return 0;

	f = fopen("/proc/stat", "r");
	if (!f)
		return 0;

	//skip first line
	if (getline(&line, &linelen, f) < 0) {
		fprintf(stderr, "proc_stat_read read first line failed\n");
		goto out;
	}

	while (getline(&line, &linelen, f) != -1) {
		size_t l;
		int cpu;
		char cpu_char[10]; /* That's a lot of cores */
		char *c;

		if (sscanf(line, "cpu%9[^ ]", cpu_char) != 1) {
			/* not a ^cpuN line containing a number N, just print it */
			l = snprintf(cache, cache_size, "%s", line);
			if (l < 0) {
				perror("Error writing to cache");
				rv = 0;
				goto err;
			}
			if (l >= cache_size) {
				fprintf(stderr, "Internal error: truncated write to cache\n");
				rv = 0;
				goto err;
			}
			if (l < cache_size) {
				cache += l;
				cache_size -= l;
				total_len += l;
				continue;
			} else {
				//no more space, break it
				cache += cache_size;
				total_len += cache_size;
				cache_size = 0;
				break;
			}
		}

		if (sscanf(cpu_char, "%d", &cpu) != 1)
			continue;
		if (!cpu_in_cpuset(cpu, cpuset))
			continue;
		curcpu ++;

		c = strchr(line, ' ');
		if (!c)
			continue;
		l = snprintf(cache, cache_size, "cpu%d%s", curcpu, c);
		if (l < 0) {
			perror("Error writing to cache");
			rv = 0;
			goto err;

		}
		if (l >= cache_size) {
			fprintf(stderr, "Internal error: truncated write to cache\n");
			rv = 0;
			goto err;
		}

		cache += l;
		cache_size -= l;
		total_len += l;

		if (sscanf(line, "%*s %lu %lu %lu %lu %lu %lu %lu %lu %lu", &user, &nice, &system, &idle, &iowait, &irq,
			&softirq, &steal, &guest) != 9)
			continue;
		user_sum += user;
		nice_sum += nice;
		system_sum += system;
		idle_sum += idle;
		iowait_sum += iowait;
		irq_sum += irq;
		softirq_sum += softirq;
		steal_sum += steal;
		guest_sum += guest;
	}

	cache = d->buf;

	int cpuall_len = snprintf(cpuall, CPUALL_MAX_SIZE, "%s %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
		"cpu ", user_sum, nice_sum, system_sum, idle_sum, iowait_sum, irq_sum, softirq_sum, steal_sum, guest_sum);
	if (cpuall_len > 0 && cpuall_len < CPUALL_MAX_SIZE){
		memcpy(cache, cpuall, cpuall_len);
		cache += cpuall_len;
	}else{
		/* shouldn't happen */
		fprintf(stderr, "proc_stat_read copy cpuall failed, cpuall_len=%d\n", cpuall_len);
		cpuall_len = 0;
	}

	memmove(cache, d->buf + CPUALL_MAX_SIZE, total_len);
	total_len += cpuall_len;
	d->size = total_len;
	if (total_len > size ) total_len = size;

	memcpy(buf, d->buf, total_len);
  out:
	rv = total_len;
  err:
	fclose(f);
	free(line);
	return rv;
}

/*
 * How to guess what to present for uptime?
 * One thing we could do would be to take the date on the caller's
 * memory.usage_in_bytes file, which should equal the time of creation
 * of his cgroup.  However, a task could be in a sub-cgroup of the
 * container.  The same problem exists if we try to look at the ages
 * of processes in the caller's cgroup.
 *
 * So we'll fork a task that will enter the caller's pidns, mount a
 * fresh procfs, get the age of /proc/1, and pass that back over a pipe.
 *
 * For the second uptime #, we'll do as Stéphane had done, just copy
 * the number from /proc/uptime.  Not sure how to best emulate 'idle'
 * time.  Maybe someone can come up with a good algorithm and submit a
 * patch.  Maybe something based on cpushare info?
 */

/* return age of the reaper for $pid, taken from ctime of its procdir */
static long int get_pid1_time(pid_t pid)
{
	char fnam[100];
	int fd, cpipe[2], ret;
	struct stat sb;
	pid_t cpid;
	struct timeval tv;
	fd_set s;
	char v;

	if (unshare(CLONE_NEWNS))
		return 0;

	if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL)) {
		perror("rslave mount failed");
		return 0;
	}

	ret = snprintf(fnam, sizeof(fnam), "/proc/%d/ns/pid", pid);
	if (ret < 0 || ret >= sizeof(fnam))
		return 0;

	fd = open(fnam, O_RDONLY);
	if (fd < 0) {
		perror("get_pid1_time open of ns/pid");
		return 0;
	}
	if (setns(fd, 0)) {
		perror("get_pid1_time setns 1");
		close(fd);
		return 0;
	}
	close(fd);

	if (pipe(cpipe) < 0)
		exit(1);

loop:
	cpid = fork();
	if (cpid < 0)
		return 0;

	if (!cpid) {
		char b = '1';
		close(cpipe[0]);
		if (write(cpipe[1], &b, sizeof(char)) < 0) {
			fprintf(stderr, "%s (child): erorr on write: %s\n",
				__func__, strerror(errno));
		}
		close(cpipe[1]);
		umount2("/proc", MNT_DETACH);
		if (mount("proc", "/proc", "proc", 0, NULL)) {
			perror("get_pid1_time mount");
			return 0;
		}
		ret = lstat("/proc/1", &sb);
		if (ret) {
			perror("get_pid1_time lstat");
			return 0;
		}
		return time(NULL) - sb.st_ctime;
	}

	// give the child 1 second to be done forking and
	// write it's ack
	FD_ZERO(&s);
	FD_SET(cpipe[0], &s);
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	ret = select(cpipe[0]+1, &s, NULL, NULL, &tv);
	if (ret <= 0)
		goto again;
	ret = read(cpipe[0], &v, 1);
	if (ret != sizeof(char) || v != '1') {
		goto again;
	}

	wait_for_pid(cpid);
	exit(0);

again:
	kill(cpid, SIGKILL);
	wait_for_pid(cpid);
	goto loop;
}

static long int getreaperage(pid_t qpid)
{
	int pid, mypipe[2], ret;
	struct timeval tv;
	fd_set s;
	long int mtime, answer = 0;

	if (pipe(mypipe)) {
		return 0;
	}

	pid = fork();

	if (!pid) { // child
		mtime = get_pid1_time(qpid);
		if (write(mypipe[1], &mtime, sizeof(mtime)) != sizeof(mtime))
			fprintf(stderr, "Warning: bad write from getreaperage\n");
		exit(0);
	}

	close(mypipe[1]);
	FD_ZERO(&s);
	FD_SET(mypipe[0], &s);
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	ret = select(mypipe[0]+1, &s, NULL, NULL, &tv);
	if (ret <= 0) {
		perror("select");
		goto out;
	}
	if (!ret) {
		fprintf(stderr, "timed out\n");
		goto out;
	}
	if (read(mypipe[0], &mtime, sizeof(mtime)) != sizeof(mtime)) {
		perror("read");
		goto out;
	}
	answer = mtime;

out:
	wait_for_pid(pid);
	close(mypipe[0]);
	return answer;
}

static long int getprocidle(void)
{
	FILE *f = fopen("/proc/uptime", "r");
	long int age, idle;
	int ret;
	if (!f)
		return 0;
	ret = fscanf(f, "%ld %ld", &age, &idle);
	fclose(f);
	if (ret != 2)
		return 0;
	return idle;
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
	struct file_info *d = (struct file_info *)fi->fh;
	long int reaperage = getreaperage(fc->pid);;
	long int idletime = getprocidle();
	size_t total_len = 0;

	if (offset){
		if (offset > d->size)
			return -EINVAL;
		return 0;
	}

	total_len = snprintf(buf, size, "%ld %ld\n", reaperage, idletime);
	if (total_len < 0){
		perror("Error writing to cache");
		return 0;
	}
	if (total_len >= size){
		d->size = size;
		return size;
	}

	d->size = total_len;
	return total_len;
}

static int proc_diskstats_read(char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	char dev_name[72];
	struct fuse_context *fc = fuse_get_context();
	struct file_info *d = (struct file_info *)fi->fh;
	nih_local char *cg = get_pid_cgroup(fc->pid, "blkio");
	nih_local char *io_serviced_str = NULL, *io_merged_str = NULL, *io_service_bytes_str = NULL,
			*io_wait_time_str = NULL, *io_service_time_str = NULL;
	unsigned long read = 0, write = 0;
	unsigned long read_merged = 0, write_merged = 0;
	unsigned long read_sectors = 0, write_sectors = 0;
	unsigned long read_ticks = 0, write_ticks = 0;
	unsigned long ios_pgr = 0, tot_ticks = 0, rq_ticks = 0;
	unsigned long rd_svctm = 0, wr_svctm = 0, rd_wait = 0, wr_wait = 0;
	char *line = NULL;
	size_t linelen = 0, total_len = 0, rv = 0;
	unsigned int major = 0, minor = 0;
	int i = 0;
	FILE *f;

	if (offset){
		if (offset > d->size)
			return -EINVAL;
		return 0;
	}

	if (!cg)
		return 0;

	if (!cgm_get_value("blkio", cg, "blkio.io_serviced", &io_serviced_str))
		return 0;
	if (!cgm_get_value("blkio", cg, "blkio.io_merged", &io_merged_str))
		return 0;
	if (!cgm_get_value("blkio", cg, "blkio.io_service_bytes", &io_service_bytes_str))
		return 0;
	if (!cgm_get_value("blkio", cg, "blkio.io_wait_time", &io_wait_time_str))
		return 0;
	if (!cgm_get_value("blkio", cg, "blkio.io_service_time", &io_service_time_str))
		return 0;


	f = fopen("/proc/diskstats", "r");
	if (!f)
		return 0;

	while (getline(&line, &linelen, f) != -1) {
		size_t l;
		char *printme, lbuf[256];

		i = sscanf(line, "%u %u %71s", &major, &minor, dev_name);
		if(i == 3){
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
		}else{
			continue;
		}

		memset(lbuf, 0, 256);
		if (read || write || read_merged || write_merged || read_sectors || write_sectors || read_ticks || write_ticks) {
			snprintf(lbuf, 256, "%u       %u %s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
				major, minor, dev_name, read, read_merged, read_sectors, read_ticks,
				write, write_merged, write_sectors, write_ticks, ios_pgr, tot_ticks, rq_ticks);
			printme = lbuf;
		} else
			continue;

		l = snprintf(buf, size, "%s", printme);
		if (l < 0) {
			perror("Error writing to fuse buf");
			rv = 0;
			goto err;
		}
		if (l >= size) {
			fprintf(stderr, "Internal error: truncated write to cache\n");
			rv = 0;
			goto err;
		}
		buf += l;
		size -= l;
		total_len += l;
	}

	d->size = total_len;
	rv = total_len;
  err:
	fclose(f);
	free(line);
	return rv;
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

static int proc_getattr(const char *path, struct stat *sb)
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
			strcmp(path, "/proc/diskstats") == 0) {
		sb->st_size = 0;
		sb->st_mode = S_IFREG | 00444;
		sb->st_nlink = 1;
		return 0;
	}

	return -ENOENT;
}

static int proc_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
		struct fuse_file_info *fi)
{
	if (filler(buf, "cpuinfo", NULL, 0) != 0 ||
				filler(buf, "meminfo", NULL, 0) != 0 ||
				filler(buf, "stat", NULL, 0) != 0 ||
				filler(buf, "uptime", NULL, 0) != 0 ||
				filler(buf, "diskstats", NULL, 0) != 0)
		return -EINVAL;
	return 0;
}

static int proc_open(const char *path, struct fuse_file_info *fi)
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
	if (type == -1)
		return -ENOENT;

	info = NIH_MUST( nih_alloc(NULL, sizeof(*info)) );
	memset(info, 0, sizeof(*info));
	info->type = type;

	info->buflen = get_procfile_size(path) + BUF_RESERVE_SIZE;
	info->buf = NIH_MUST( nih_alloc(info, info->buflen) );
	memset(info->buf, 0, info->buflen);
	/* set actual size to buffer size */
	info->size = info->buflen;

	fi->fh = (unsigned long)info;
	return 0;
}

static int proc_release(const char *path, struct fuse_file_info *fi)
{
	struct file_info *f = (struct file_info *)fi->fh;

	do_release_file_info(f);
	return 0;
}

static int proc_read(const char *path, char *buf, size_t size, off_t offset,
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
	default:
		return -EINVAL;
	}
}

/*
 * FUSE ops for /
 * these just delegate to the /proc and /cgroup ops as
 * needed
 */

static int lxcfs_getattr(const char *path, struct stat *sb)
{
	if (strcmp(path, "/") == 0) {
		sb->st_mode = S_IFDIR | 00755;
		sb->st_nlink = 2;
		return 0;
	}
	if (strncmp(path, "/cgroup", 7) == 0) {
		return cg_getattr(path, sb);
	}
	if (strncmp(path, "/proc", 5) == 0) {
		return proc_getattr(path, sb);
	}
	return -EINVAL;
}

static int lxcfs_opendir(const char *path, struct fuse_file_info *fi)
{
	if (strcmp(path, "/") == 0)
		return 0;

	if (strncmp(path, "/cgroup", 7) == 0) {
		return cg_opendir(path, fi);
	}
	if (strcmp(path, "/proc") == 0)
		return 0;
	return -ENOENT;
}

static int lxcfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
		struct fuse_file_info *fi)
{
	if (strcmp(path, "/") == 0) {
		if (filler(buf, "proc", NULL, 0) != 0 ||
				filler(buf, "cgroup", NULL, 0) != 0)
			return -EINVAL;
		return 0;
	}
	if (strncmp(path, "/cgroup", 7) == 0)
		return cg_readdir(path, buf, filler, offset, fi);
	if (strcmp(path, "/proc") == 0)
		return proc_readdir(path, buf, filler, offset, fi);
	return -EINVAL;
}

static int lxcfs_releasedir(const char *path, struct fuse_file_info *fi)
{
	if (strcmp(path, "/") == 0)
		return 0;
	if (strncmp(path, "/cgroup", 7) == 0) {
		return cg_releasedir(path, fi);
	}
	if (strcmp(path, "/proc") == 0)
		return 0;
	return -EINVAL;
}

static int lxcfs_open(const char *path, struct fuse_file_info *fi)
{
	if (strncmp(path, "/cgroup", 7) == 0)
		return cg_open(path, fi);
	if (strncmp(path, "/proc", 5) == 0)
		return proc_open(path, fi);

	return -EINVAL;
}

static int lxcfs_read(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	if (strncmp(path, "/cgroup", 7) == 0)
		return cg_read(path, buf, size, offset, fi);
	if (strncmp(path, "/proc", 5) == 0)
		return proc_read(path, buf, size, offset, fi);

	return -EINVAL;
}

int lxcfs_write(const char *path, const char *buf, size_t size, off_t offset,
	     struct fuse_file_info *fi)
{
	if (strncmp(path, "/cgroup", 7) == 0) {
		return cg_write(path, buf, size, offset, fi);
	}

	return -EINVAL;
}

static int lxcfs_flush(const char *path, struct fuse_file_info *fi)
{
	return 0;
}

static int lxcfs_release(const char *path, struct fuse_file_info *fi)
{
	if (strncmp(path, "/cgroup", 7) == 0)
		return cg_release(path, fi);
	if (strncmp(path, "/proc", 5) == 0)
		return proc_release(path, fi);

	return -EINVAL;
}

static int lxcfs_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
	return 0;
}

int lxcfs_mkdir(const char *path, mode_t mode)
{
	if (strncmp(path, "/cgroup", 7) == 0)
		return cg_mkdir(path, mode);

	return -EINVAL;
}

int lxcfs_chown(const char *path, uid_t uid, gid_t gid)
{
	if (strncmp(path, "/cgroup", 7) == 0)
		return cg_chown(path, uid, gid);

	return -EINVAL;
}

/*
 * cat first does a truncate before doing ops->write.  This doesn't
 * really make sense for cgroups.  So just return 0 always but do
 * nothing.
 */
int lxcfs_truncate(const char *path, off_t newsize)
{
	if (strncmp(path, "/cgroup", 7) == 0)
		return 0;
	return -EINVAL;
}

int lxcfs_rmdir(const char *path)
{
	if (strncmp(path, "/cgroup", 7) == 0)
		return cg_rmdir(path);
	return -EINVAL;
}

int lxcfs_chmod(const char *path, mode_t mode)
{
	if (strncmp(path, "/cgroup", 7) == 0)
		return cg_chmod(path, mode);
	return -EINVAL;
}

const struct fuse_operations lxcfs_ops = {
	.getattr = lxcfs_getattr,
	.readlink = NULL,
	.getdir = NULL,
	.mknod = NULL,
	.mkdir = lxcfs_mkdir,
	.unlink = NULL,
	.rmdir = lxcfs_rmdir,
	.symlink = NULL,
	.rename = NULL,
	.link = NULL,
	.chmod = lxcfs_chmod,
	.chown = lxcfs_chown,
	.truncate = lxcfs_truncate,
	.utime = NULL,

	.open = lxcfs_open,
	.read = lxcfs_read,
	.release = lxcfs_release,
	.write = lxcfs_write,

	.statfs = NULL,
	.flush = lxcfs_flush,
	.fsync = lxcfs_fsync,

	.setxattr = NULL,
	.getxattr = NULL,
	.listxattr = NULL,
	.removexattr = NULL,

	.opendir = lxcfs_opendir,
	.readdir = lxcfs_readdir,
	.releasedir = lxcfs_releasedir,

	.fsyncdir = NULL,
	.init = NULL,
	.destroy = NULL,
	.access = NULL,
	.create = NULL,
	.ftruncate = NULL,
	.fgetattr = NULL,
};

static void usage(const char *me)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "%s mountpoint\n", me);
	fprintf(stderr, "%s -h\n", me);
	exit(1);
}

static bool is_help(char *w)
{
	if (strcmp(w, "-h") == 0 ||
			strcmp(w, "--help") == 0 ||
			strcmp(w, "-help") == 0 ||
			strcmp(w, "help") == 0)
		return true;
	return false;
}

void swallow_arg(int *argcp, char *argv[], char *which)
{
	int i;

	for (i = 1; argv[i]; i++) {
		if (strcmp(argv[i], which) != 0)
			continue;
		for (; argv[i]; i++) {
			argv[i] = argv[i+1];
		}
		(*argcp)--;
		return;
	}
}

void swallow_option(int *argcp, char *argv[], char *opt, char *v)
{
	int i;

	for (i = 1; argv[i]; i++) {
		if (!argv[i+1])
			continue;
		if (strcmp(argv[i], opt) != 0)
			continue;
		if (strcmp(argv[i+1], v) != 0) {
			fprintf(stderr, "Warning: unexpected fuse option %s\n", v);
			exit(1);
		}
		for (; argv[i+1]; i++) {
			argv[i] = argv[i+2];
		}
		(*argcp) -= 2;
		return;
	}
}

int main(int argc, char *argv[])
{
	int ret = -1;
	struct lxcfs_state *d = NULL;
	/*
	 * what we pass to fuse_main is:
	 * argv[0] -s -f -o allow_other,directio argv[1] NULL
	 */
#define NARGS 7
	char *newargv[7];

	/* accomodate older init scripts */
	swallow_arg(&argc, argv, "-s");
	swallow_arg(&argc, argv, "-f");
	swallow_option(&argc, argv, "-o", "allow_other");

	if (argc == 2  && strcmp(argv[1], "--version") == 0) {
		fprintf(stderr, "%s\n", VERSION);
		exit(0);
	}
	if (argc != 2 || is_help(argv[1]))
		usage(argv[0]);

	d = NIH_MUST( malloc(sizeof(*d)) );

	newargv[0] = argv[0];
	newargv[1] = "-s";
	newargv[2] = "-f";
	newargv[3] = "-o";
	newargv[4] = "allow_other,direct_io";
	newargv[5] = argv[1];
	newargv[6] = NULL;

	if (!cgm_escape_cgroup())
		fprintf(stderr, "WARNING: failed to escape to root cgroup\n");

	if (!cgm_get_controllers(&d->subsystems))
		goto out;

	ret = fuse_main(NARGS - 1, newargv, &lxcfs_ops, d);

out:
	free(d);
	return ret;
}
