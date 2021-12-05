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

#include "cgroup_fuse.h"

#include "bindings.h"
#include "cgroups/cgroup.h"
#include "cgroups/cgroup_utils.h"
#include "lxcfs_fuse_compat.h"
#include "memory_utils.h"
#include "utils.h"

struct cgfs_files {
	char *name;
	uint32_t uid, gid;
	uint32_t mode;
};

struct pid_ns_clone_args {
	int *cpipe;
	int sock;
	pid_t tpid;
	/* pid_from_ns or pid_to_ns. */
	int (*wrapped) (int, pid_t);
};

static inline int get_cgroup_fd_handle_named(const char *controller)
{
	if (controller && strcmp(controller, "systemd") == 0)
		return get_cgroup_fd("name=systemd");

	return get_cgroup_fd(controller);
}

static char *get_pid_cgroup_handle_named(pid_t pid, const char *controller)
{
	if (controller && strcmp(controller, "systemd") == 0)
		return get_pid_cgroup(pid, "name=systemd");

	return get_pid_cgroup(pid, controller);
}

static bool get_cgroup_handle_named(struct cgroup_ops *ops,
				    const char *controller, const char *cgroup,
				    const char *file, char **value)
{
	if (controller && strcmp(controller, "systemd") == 0)
		return cgroup_ops->get(ops, "name=systemd", cgroup, file, value);

	return cgroup_ops->get(cgroup_ops, controller, cgroup, file, value);
}

/*
 * given /cgroup/freezer/a/b, return "freezer".
 * the returned char* should NOT be freed.
 */
static char *pick_controller_from_path(struct fuse_context *fc, const char *path)
{
	const char *p1;
	char *contr, *slash;

	if (strlen(path) < 9) {
		errno = EACCES;
		return NULL;
	}
	if (*(path + 7) != '/') {
		errno = EINVAL;
		return NULL;
	}
	p1 = path + 8;
	contr = strdupa(p1);
	if (!contr) {
		errno = ENOMEM;
		return NULL;
	}
	slash = strstr(contr, "/");
	if (slash)
		*slash = '\0';

	for (struct hierarchy **h = cgroup_ops->hierarchies; h && *h; h++) {
		if ((*h)->__controllers && strcmp((*h)->__controllers, contr) == 0)
			return (*h)->__controllers;
	}
	errno = ENOENT;
	return NULL;
}

/*
 * Find the start of cgroup in /cgroup/controller/the/cgroup/path
 * Note that the returned value may include files (keynames) etc
 */
static const char *find_cgroup_in_path(const char *path)
{
	const char *p1;

	if (strlen(path) < 9) {
		errno = EACCES;
		return NULL;
	}
	p1 = strstr(path + 8, "/");
	if (!p1) {
		errno = EINVAL;
		return NULL;
	}
	errno = 0;
	return p1 + 1;
}

/*
 * split the last path element from the path in @cg.
 * @dir is newly allocated and should be freed, @last not
*/
static void get_cgdir_and_path(const char *cg, char **dir, char **last)
{
	char *p;

	do {
		*dir = strdup(cg);
	} while (!*dir);
	*last = strrchr(cg, '/');
	if (!*last) {
		*last = NULL;
		return;
	}
	p = strrchr(*dir, '/');
	*p = '\0';
}

static bool is_child_cgroup(const char *controller, const char *cgroup,
			    const char *file)
{
	__do_free char *path = NULL;
	int cfd, ret;
	struct stat sb;

	cfd = get_cgroup_fd_handle_named(controller);
	if (cfd < 0)
		return false;

	path = must_make_path_relative(cgroup, file, NULL);
	ret = fstatat(cfd, path, &sb, 0);
	if (ret < 0 || !S_ISDIR(sb.st_mode))
		return false;

	return true;
}

/*
 * If pid is in /a/b/c, they may see that /a exists, but not /b or /a/c.
 */
static bool caller_may_see_dir(pid_t pid, const char *contrl, const char *cg)
{
	bool answer = false;
	char *c2, *task_cg;
	size_t target_len, task_len;

	if (strcmp(cg, "/") == 0 || strcmp(cg, "./") == 0)
		return true;

	c2 = get_pid_cgroup_handle_named(pid, contrl);
	if (!c2)
		return false;
	prune_init_slice(c2);

	task_cg = c2 + 1;
	target_len = strlen(cg);
	task_len = strlen(task_cg);
	if (task_len == 0) {
		/* Task is in the root cg, it can see everything. This case is
		 * not handled by the strmcps below, since they test for the
		 * last /, but that is the first / that we've chopped off
		 * above.
		 */
		answer = true;
		goto out;
	}
	if (strcmp(cg, task_cg) == 0) {
		answer = true;
		goto out;
	}
	if (target_len < task_len) {
		/* looking up a parent dir */
		if (strncmp(task_cg, cg, target_len) == 0 && task_cg[target_len] == '/')
			answer = true;
		goto out;
	}
	if (target_len > task_len) {
		/* looking up a child dir */
		if (strncmp(task_cg, cg, task_len) == 0 && cg[task_len] == '/')
			answer = true;
		goto out;
	}

out:
	free(c2);
	return answer;
}

/*
 * taskcg is  a/b/c
 * querycg is /a/b/c/d/e
 * we return 'd'
 */
static char *get_next_cgroup_dir(const char *taskcg, const char *querycg)
{
	char *start, *end;

	if (strlen(taskcg) <= strlen(querycg)) {
		lxcfs_error("%s\n", "I was fed bad input.");
		return NULL;
	}

	if ((strcmp(querycg, "/") == 0) || (strcmp(querycg, "./") == 0))
		start =  strdup(taskcg + 1);
	else
		start = strdup(taskcg + strlen(querycg) + 1);
	if (!start)
		return NULL;
	end = strchr(start, '/');
	if (end)
		*end = '\0';
	return start;
}

/*
 * If pid is in /a/b/c/d, they may only act on things under cg=/a/b/c/d.
 * If pid is in /a, they may act on /a/b, but not on /b.
 * if the answer is false and nextcg is not NULL, then *nextcg will point
 * to a string containing the next cgroup directory under cg, which must be
 * freed by the caller.
 */
static bool caller_is_in_ancestor(pid_t pid, const char *contrl, const char *cg, char **nextcg)
{
	bool answer = false;
	char *c2;
	char *linecmp;

	c2 = get_pid_cgroup_handle_named(pid, contrl);
	if (!c2)
		return false;
	prune_init_slice(c2);

	/*
	 * callers pass in '/' or './' (openat()) for root cgroup, otherwise
	 * they pass in a cgroup without leading '/'
	 *
	 * The original line here was:
	 *	linecmp = *cg == '/' ? c2 : c2+1;
	 * TODO: I'm not sure why you'd want to increment when *cg != '/'?
	 *       Serge, do you know?
	 */
	if (*cg == '/' || !strncmp(cg, "./", 2))
		linecmp = c2;
	else
		linecmp = c2 + 1;
	if (strncmp(linecmp, cg, strlen(linecmp)) != 0) {
		if (nextcg) {
			*nextcg = get_next_cgroup_dir(linecmp, cg);
		}
		goto out;
	}
	answer = true;

out:
	free(c2);
	return answer;
}

static struct cgfs_files *cgfs_get_key(const char *controller,
				       const char *cgroup, const char *file)
{
	__do_free char *path = NULL;
	struct cgfs_files *newkey;
	int cfd, ret;
	struct stat sb;

	cfd = get_cgroup_fd_handle_named(controller);
	if (cfd < 0)
		return false;

	if (file && *file == '/')
		file++;

	if (file && strchr(file, '/'))
		return NULL;

	if (file)
		path = must_make_path_relative(cgroup, file, NULL);
	else
		path = must_make_path_relative(cgroup, NULL);
	ret = fstatat(cfd, path, &sb, 0);
	if (ret < 0)
		return NULL;

	newkey = must_realloc(NULL, sizeof(struct cgfs_files));

	if (file)
		newkey->name = must_copy_string(file);
	else if (strrchr(cgroup, '/'))
		newkey->name = must_copy_string(strrchr(cgroup, '/'));
	else
		newkey->name = must_copy_string(cgroup);
	newkey->uid = sb.st_uid;
	newkey->gid = sb.st_gid;
	newkey->mode = sb.st_mode;

	return newkey;
}

/*
 * Given a open file * to /proc/pid/{u,g}id_map, and an id
 * valid in the caller's namespace, return the id mapped into
 * pid's namespace.
 * Returns the mapped id, or -1 on error.
 */
static int convert_id_to_ns(FILE *idfile, unsigned int in_id)
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
			lxcfs_error("pid wrapparound at entry %u %u %u in %s\n",
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
 * specify whether we require the calling uid to be root in their
 * namespace
 */
#define NS_ROOT_REQD true
#define NS_ROOT_OPT false

#define PROCLEN 100

static bool is_privileged_over(pid_t pid, uid_t uid, uid_t victim, bool req_ns_root)
{
	FILE *f;
	char fpath[PROCLEN];
	int ret;
	bool answer = false;
	uid_t nsuid;

	if (victim == (uid_t)-1 || uid == (uid_t)-1)
		return false;

	/*
	 * If the request is one not requiring root in the namespace,
	 * then having the same uid suffices.  (i.e. uid 1000 has write
	 * access to files owned by uid 1000
	 */
	if (!req_ns_root && uid == victim)
		return true;

	ret = snprintf(fpath, PROCLEN, "/proc/%d/uid_map", pid);
	if (ret < 0 || ret >= PROCLEN)
		return false;

	f = fopen(fpath, "re");
	if (!f)
		return false;

	/* if caller's not root in their namespace, reject */
	nsuid = convert_id_to_ns(f, uid);
	if (nsuid)
		goto out;

	/*
	 * If victim is not mapped into caller's ns, reject.
	 * XXX I'm not sure this check is needed given that fuse
	 * will be sending requests where the vfs has converted
	 */
	nsuid = convert_id_to_ns(f, victim);
	if (nsuid == (uid_t)-1)
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

static void free_key(struct cgfs_files *k)
{
	if (k) {
		free_disarm(k->name);
		free_disarm(k);
	}
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
	struct cgfs_files *k = NULL;
	bool ret = false;

	k = cgfs_get_key(contrl, cg, file);
	if (!k)
		return false;

	if (is_privileged_over(fc->pid, fc->uid, k->uid, NS_ROOT_OPT)) {
		if (perms_include(k->mode >> 6, mode)) {
			ret = true;
			goto out;
		}
	}
	if (fc->gid == k->gid) {
		if (perms_include(k->mode >> 3, mode)) {
			ret = true;
			goto out;
		}
	}
	ret = perms_include(k->mode, mode);

out:
	free_key(k);
	return ret;
}

__lxcfs_fuse_ops int cg_getattr(const char *path, struct stat *sb)
{
	struct timespec now;
	struct fuse_context *fc = fuse_get_context();
	char * cgdir = NULL;
	char *last = NULL, *path1, *path2;
	struct cgfs_files *k = NULL;
	const char *cgroup;
	const char *controller = NULL;
	int ret = -ENOENT;

	if (!liblxcfs_functional())
		return -EIO;

	if (!fc || !cgroup_ops)
		return -EIO;

	memset(sb, 0, sizeof(struct stat));

	if (clock_gettime(CLOCK_REALTIME, &now) < 0)
		return -EINVAL;

	sb->st_uid = sb->st_gid = 0;
	sb->st_atim = sb->st_mtim = sb->st_ctim = now;
	sb->st_size = 0;

	if (pure_unified_layout(cgroup_ops) || strcmp(path, "/cgroup") == 0) {
		sb->st_mode = S_IFDIR | 00755;
		sb->st_nlink = 2;
		return 0;
	}

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return -errno;
	cgroup = find_cgroup_in_path(path);
	if (!cgroup) {
		/* this is just /cgroup/controller, return it as a dir */
		sb->st_mode = S_IFDIR | 00755;
		sb->st_nlink = 2;
		return 0;
	}


	get_cgdir_and_path(cgroup, &cgdir, &last);

	if (!last) {
		path1 = "/";
		path2 = cgdir;
	} else {
		path1 = cgdir;
		path2 = last;
	}

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;
	/* check that cgcopy is either a child cgroup of cgdir, or listed in its keys.
	 * Then check that caller's cgroup is under path if last is a child
	 * cgroup, or cgdir if last is a file */

	if (is_child_cgroup(controller, path1, path2)) {
		if (!caller_may_see_dir(initpid, controller, cgroup)) {
			ret = -ENOENT;
			goto out;
		}
		if (!caller_is_in_ancestor(initpid, controller, cgroup, NULL)) {
			/* this is just /cgroup/controller, return it as a dir */
			sb->st_mode = S_IFDIR | 00555;
			sb->st_nlink = 2;
			ret = 0;
			goto out;
		}
		if (!fc_may_access(fc, controller, cgroup, NULL, O_RDONLY)) {
			ret = -EACCES;
			goto out;
		}

		// get uid, gid, from '/tasks' file and make up a mode
		// That is a hack, until cgmanager gains a GetCgroupPerms fn.
		sb->st_mode = S_IFDIR | 00755;
		k = cgfs_get_key(controller, cgroup, NULL);
		if (!k) {
			sb->st_uid = sb->st_gid = 0;
		} else {
			sb->st_uid = k->uid;
			sb->st_gid = k->gid;
		}
		free_key(k);
		sb->st_nlink = 2;
		ret = 0;
		goto out;
	}

	if ((k = cgfs_get_key(controller, path1, path2)) != NULL) {
		sb->st_mode = S_IFREG | k->mode;
		sb->st_nlink = 1;
		sb->st_uid = k->uid;
		sb->st_gid = k->gid;
		sb->st_size = 4096;
		free_key(k);
		if (!caller_is_in_ancestor(initpid, controller, path1, NULL)) {
			ret = -ENOENT;
			goto out;
		}
		ret = 0;
	}

out:
	free(cgdir);
	return ret;
}

/*
 * Chown all the files in the cgroup directory.  We do this when we create a
 * cgroup on behalf of a user.
 */
static void chown_all_cgroup_files(const char *dirname, uid_t uid, gid_t gid, int fd)
{
	struct dirent *direntp;
	char path[MAXPATHLEN];
	size_t len;
	DIR *d;
	int fd1, ret;

	len = strlen(dirname);
	if (len >= MAXPATHLEN) {
		lxcfs_error("Pathname too long: %s\n", dirname);
		return;
	}

	fd1 = openat(fd, dirname, O_DIRECTORY);
	if (fd1 < 0)
		return;

	d = fdopendir(fd1);
	if (!d) {
		lxcfs_error("Failed to open %s\n", dirname);
		return;
	}

	while ((direntp = readdir(d))) {
		if (!strcmp(direntp->d_name, ".") || !strcmp(direntp->d_name, ".."))
			continue;
		ret = snprintf(path, MAXPATHLEN, "%s/%s", dirname, direntp->d_name);
		if (ret < 0 || ret >= MAXPATHLEN) {
			lxcfs_error("Pathname too long under %s\n", dirname);
			continue;
		}
		if (fchownat(fd, path, uid, gid, 0) < 0)
			lxcfs_error("Failed to chown file %s to %u:%u", path, uid, gid);
	}
	closedir(d);
}

static int cgfs_create(const char *controller, const char *cg, uid_t uid, gid_t gid)
{
	__do_free char *path = NULL;
	int cfd;

	cfd = get_cgroup_fd_handle_named(controller);
	if (cfd < 0)
		return -EINVAL;

	path = must_make_path_relative(cg, NULL);
	if (mkdirat(cfd, path, 0755) < 0)
		return -errno;

	if (uid == 0 && gid == 0)
		return 0;

	if (fchownat(cfd, path, uid, gid, 0) < 0)
		return -errno;

	chown_all_cgroup_files(path, uid, gid, cfd);

	return 0;
}

__lxcfs_fuse_ops int cg_mkdir(const char *path, mode_t mode)
{
	struct fuse_context *fc = fuse_get_context();
	char *last = NULL, *path1, *cgdir = NULL, *controller, *next = NULL;
	const char *cgroup;
	int ret;

	if (!liblxcfs_functional())
		return -EIO;

	if (!fc || !cgroup_ops || pure_unified_layout(cgroup_ops))
		return -EIO;

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return errno == ENOENT ? -EPERM : -errno;

	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		return -errno;

	get_cgdir_and_path(cgroup, &cgdir, &last);
	if (!last)
		path1 = "/";
	else
		path1 = cgdir;

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;
	if (!caller_is_in_ancestor(initpid, controller, path1, &next)) {
		if (!next)
			ret = -EINVAL;
		else if (last && strcmp(next, last) == 0)
			ret = -EEXIST;
		else
			ret = -EPERM;
		goto out;
	}

	if (!fc_may_access(fc, controller, path1, NULL, O_RDWR)) {
		ret = -EACCES;
		goto out;
	}
	if (!caller_is_in_ancestor(initpid, controller, path1, NULL)) {
		ret = -EACCES;
		goto out;
	}

	ret = cgfs_create(controller, cgroup, fc->uid, fc->gid);

out:
	free(cgdir);
	free(next);
	return ret;
}

static bool recursive_rmdir(const char *dirname, int fd, const int cfd)
{
	__do_close int dupfd = -EBADF;
	__do_closedir DIR *dir = NULL;
	bool ret = false;
	struct dirent *direntp;
	char pathname[MAXPATHLEN];

	dupfd = dup(fd);
	if (dupfd < 0)
		return false;

	dir = fdopendir(dupfd);
	if (!dir) {
		lxcfs_debug("Failed to open %s: %s.\n", dirname, strerror(errno));
		return false;
	}
	move_fd(dupfd);

	while ((direntp = readdir(dir))) {
		struct stat mystat;
		int rc;

		if (!strcmp(direntp->d_name, ".") ||
		    !strcmp(direntp->d_name, ".."))
			continue;

		rc = snprintf(pathname, MAXPATHLEN, "%s/%s", dirname, direntp->d_name);
		if (rc < 0 || rc >= MAXPATHLEN) {
			lxcfs_error("%s\n", "Pathname too long.");
			continue;
		}

		rc = fstatat(cfd, pathname, &mystat, AT_SYMLINK_NOFOLLOW);
		if (rc) {
			lxcfs_debug("Failed to stat %s: %s.\n", pathname, strerror(errno));
			continue;
		}
		if (S_ISDIR(mystat.st_mode))
			if (!recursive_rmdir(pathname, fd, cfd))
				lxcfs_debug("Error removing %s.\n", pathname);
	}

	ret = true;

	if (unlinkat(cfd, dirname, AT_REMOVEDIR) < 0) {
		lxcfs_debug("Failed to delete %s: %s.\n", dirname, strerror(errno));
		ret = false;
	}

	return ret;
}

static bool cgfs_remove(const char *controller, const char *cgroup)
{
	__do_close int fd = -EBADF;
	__do_free char *path = NULL;
	int cfd;

	cfd = get_cgroup_fd_handle_named(controller);
	if (cfd < 0)
		return false;

	path = must_make_path_relative(cgroup, NULL);
	fd = openat(cfd, path, O_DIRECTORY);
	if (fd < 0)
		return false;

	return recursive_rmdir(path, fd, cfd);
}

__lxcfs_fuse_ops int cg_rmdir(const char *path)
{
	struct fuse_context *fc = fuse_get_context();
	char *last = NULL, *cgdir = NULL, *controller, *next = NULL;
	const char *cgroup;
	int ret;

	if (!liblxcfs_functional())
		return -EIO;

	if (!fc || !cgroup_ops || pure_unified_layout(cgroup_ops))
		return -EIO;

	controller = pick_controller_from_path(fc, path);
	if (!controller) /* Someone's trying to delete "/cgroup". */
		return -EPERM;

	cgroup = find_cgroup_in_path(path);
	if (!cgroup) /* Someone's trying to delete a controller e.g. "/blkio". */
		return -EPERM;

	get_cgdir_and_path(cgroup, &cgdir, &last);
	if (!last) {
		/* Someone's trying to delete a cgroup on the same level as the
		 * "/lxc" cgroup e.g. rmdir "/cgroup/blkio/lxc" or
		 * rmdir "/cgroup/blkio/init.slice".
		 */
		ret = -EPERM;
		goto out;
	}

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;
	if (!caller_is_in_ancestor(initpid, controller, cgroup, &next)) {
		if (!last || (next && (strcmp(next, last) == 0)))
			ret = -EBUSY;
		else
			ret = -ENOENT;
		goto out;
	}

	if (!fc_may_access(fc, controller, cgdir, NULL, O_WRONLY)) {
		ret = -EACCES;
		goto out;
	}
	if (!caller_is_in_ancestor(initpid, controller, cgroup, NULL)) {
		ret = -EACCES;
		goto out;
	}

	if (!cgfs_remove(controller, cgroup)) {
		ret = -EINVAL;
		goto out;
	}

	ret = 0;

out:
	free(cgdir);
	free(next);
	return ret;
}

static bool cgfs_chmod_file(const char *controller, const char *file, mode_t mode)
{
	__do_free char *path = NULL;
	int cfd;

	cfd = get_cgroup_fd_handle_named(controller);
	if (cfd < 0)
		return false;

	path = must_make_path_relative(file, NULL);
	if (fchmodat(cfd, path, mode, 0) < 0)
		return false;

	return true;
}

__lxcfs_fuse_ops int cg_chmod(const char *path, mode_t mode)
{
	struct fuse_context *fc = fuse_get_context();
	char * cgdir = NULL, *last = NULL, *path1, *path2, *controller;
	struct cgfs_files *k = NULL;
	const char *cgroup;
	int ret;

	if (!liblxcfs_functional())
		return -EIO;

	if (!fc || !cgroup_ops || pure_unified_layout(cgroup_ops))
		return -EIO;

	if (strcmp(path, "/cgroup") == 0)
		return -EPERM;

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return errno == ENOENT ? -EPERM : -errno;

	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		/* this is just /cgroup/controller */
		return -EPERM;

	get_cgdir_and_path(cgroup, &cgdir, &last);

	if (!last) {
		path1 = "/";
		path2 = cgdir;
	} else {
		path1 = cgdir;
		path2 = last;
	}

	if (is_child_cgroup(controller, path1, path2)) {
		// get uid, gid, from '/tasks' file and make up a mode
		// That is a hack, until cgmanager gains a GetCgroupPerms fn.
		k = cgfs_get_key(controller, cgroup, "tasks");

	} else
		k = cgfs_get_key(controller, path1, path2);

	if (!k) {
		ret = -EINVAL;
		goto out;
	}

	/*
	 * This being a fuse request, the uid and gid must be valid
	 * in the caller's namespace.  So we can just check to make
	 * sure that the caller is root in their uid, and privileged
	 * over the file's current owner.
	 */
	if (!is_privileged_over(fc->pid, fc->uid, k->uid, NS_ROOT_OPT)) {
		ret = -EPERM;
		goto out;
	}

	if (!cgfs_chmod_file(controller, cgroup, mode)) {
		ret = -EINVAL;
		goto out;
	}

	ret = 0;
out:
	free_key(k);
	free(cgdir);
	return ret;
}

static inline bool is_dir(int dirfd, const char *path)
{
	struct stat st;
	return fstatat(dirfd, path, &st, 0) == 0 && S_ISDIR(st.st_mode);
}

static int chown_tasks_files(int dirfd, const char *dirname, uid_t uid, gid_t gid)
{
	__do_free char *path;

	path = must_make_path_relative(dirname, "tasks", NULL);
	if (fchownat(dirfd, path, uid, gid, 0) != 0)
		return -errno;

	free_disarm(path);
	path = must_make_path_relative(dirname, "cgroup.procs", NULL);
	if (fchownat(dirfd, path, uid, gid, 0) != 0)
		return -errno;

	return 0;
}

static int cgfs_chown_file(const char *controller, const char *file, uid_t uid, gid_t gid)
{
	__do_free char *path = NULL;
	int cfd;

	cfd = get_cgroup_fd_handle_named(controller);
	if (cfd < 0)
		return false;

	path = must_make_path_relative(file, NULL);
	if (fchownat(cfd, path, uid, gid, 0) < 0)
		return -errno;

	if (is_dir(cfd, path))
		return chown_tasks_files(cfd, path, uid, gid);

	return 0;
}

__lxcfs_fuse_ops int cg_chown(const char *path, uid_t uid, gid_t gid)
{
	struct fuse_context *fc = fuse_get_context();
	char *cgdir = NULL, *last = NULL, *path1, *path2, *controller;
	struct cgfs_files *k = NULL;
	const char *cgroup;
	int ret;

	if (!liblxcfs_functional())
		return -EIO;

	if (!fc || !cgroup_ops || pure_unified_layout(cgroup_ops))
		return -EIO;

	if (strcmp(path, "/cgroup") == 0)
		return -EPERM;

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return errno == ENOENT ? -EPERM : -errno;

	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		/* this is just /cgroup/controller */
		return -EPERM;

	get_cgdir_and_path(cgroup, &cgdir, &last);

	if (!last) {
		path1 = "/";
		path2 = cgdir;
	} else {
		path1 = cgdir;
		path2 = last;
	}

	if (is_child_cgroup(controller, path1, path2)) {
		// get uid, gid, from '/tasks' file and make up a mode
		// That is a hack, until cgmanager gains a GetCgroupPerms fn.
		k = cgfs_get_key(controller, cgroup, "tasks");

	} else
		k = cgfs_get_key(controller, path1, path2);

	if (!k) {
		ret = -EINVAL;
		goto out;
	}

	/*
	 * This being a fuse request, the uid and gid must be valid
	 * in the caller's namespace.  So we can just check to make
	 * sure that the caller is root in their uid, and privileged
	 * over the file's current owner.
	 */
	if (!is_privileged_over(fc->pid, fc->uid, k->uid, NS_ROOT_REQD)) {
		ret = -EACCES;
		goto out;
	}

	ret = cgfs_chown_file(controller, cgroup, uid, gid);

out:
	free_key(k);
	free(cgdir);

	return ret;
}

__lxcfs_fuse_ops int cg_open(const char *path, struct fuse_file_info *fi)
{
	const char *cgroup;
	char *last = NULL, *path1, *path2, * cgdir = NULL, *controller;
	struct cgfs_files *k = NULL;
	struct file_info *file_info;
	struct fuse_context *fc = fuse_get_context();
	int ret;

	if (!liblxcfs_functional())
		return -EIO;

	if (!fc || !cgroup_ops || pure_unified_layout(cgroup_ops))
		return -EIO;

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return -errno;
	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		return -errno;

	get_cgdir_and_path(cgroup, &cgdir, &last);
	if (!last) {
		path1 = "/";
		path2 = cgdir;
	} else {
		path1 = cgdir;
		path2 = last;
	}

	k = cgfs_get_key(controller, path1, path2);
	if (!k) {
		ret = -EINVAL;
		goto out;
	}
	free_key(k);

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;
	if (!caller_may_see_dir(initpid, controller, path1)) {
		ret = -ENOENT;
		goto out;
	}
	if (!fc_may_access(fc, controller, path1, path2, fi->flags)) {
		ret = -EACCES;
		goto out;
	}

	/* we'll free this at cg_release */
	file_info = malloc(sizeof(*file_info));
	if (!file_info) {
		ret = -ENOMEM;
		goto out;
	}
	file_info->controller = must_copy_string(controller);
	file_info->cgroup = must_copy_string(path1);
	file_info->file = must_copy_string(path2);
	file_info->type = LXC_TYPE_CGFILE;
	file_info->buf = NULL;
	file_info->buflen = 0;

	fi->fh = PTR_TO_UINT64(file_info);
	ret = 0;

out:
	free(cgdir);
	return ret;
}

#define POLLIN_SET ( EPOLLIN | EPOLLHUP | EPOLLRDHUP )

/*
 * pid_to_ns - reads pids from a ucred over a socket, then writes the
 * int value back over the socket.  This shifts the pid from the
 * sender's pidns into tpid's pidns.
 */
static int pid_to_ns(int sock, pid_t tpid)
{
	char v = '0';
	struct ucred cred = {
		.pid = -1,
		.uid = -1,
		.gid = -1,
	};

	while (recv_creds(sock, &cred, &v)) {
		if (v == '1')
			return 0;

		if (write_nointr(sock, &cred.pid, sizeof(pid_t)) != sizeof(pid_t))
			return 1;
	}

	return 0;
}

/*
 * pid_ns_clone_wrapper - wraps pid_to_ns or pid_from_ns for usage
 * with clone(). This simply writes '1' as ACK back to the parent
 * before calling the actual wrapped function.
 */
static int pid_ns_clone_wrapper(void *arg) {
	struct pid_ns_clone_args* args = (struct pid_ns_clone_args *) arg;
	char b = '1';

	close(args->cpipe[0]);
	if (write(args->cpipe[1], &b, sizeof(char)) < 0)
		lxcfs_error("(child): error on write: %s.\n", strerror(errno));
	close(args->cpipe[1]);
	return args->wrapped(args->sock, args->tpid);
}

/*
 * pid_to_ns_wrapper: when you setns into a pidns, you yourself remain
 * in your old pidns.  Only children which you clone will be in the target
 * pidns.  So the pid_to_ns_wrapper does the setns, then clones a child to
 * actually convert pids.
 *
 * Note: glibc's fork() does not respect pidns, which can lead to failed
 * assertions inside glibc (and thus failed forks) if the child's pid in
 * the pidns and the parent pid outside are identical. Using clone prevents
 * this issue.
 */
static void pid_to_ns_wrapper(int sock, pid_t tpid)
{
	int newnsfd = -1, ret, cpipe[2];
	char fnam[100];
	pid_t cpid;
	char v;

	ret = snprintf(fnam, sizeof(fnam), "/proc/%d/ns/pid", tpid);
	if (ret < 0 || (size_t)ret >= sizeof(fnam))
		_exit(1);
	newnsfd = open(fnam, O_RDONLY);
	if (newnsfd < 0)
		_exit(1);
	if (setns(newnsfd, 0) < 0)
		_exit(1);
	close(newnsfd);

	if (pipe(cpipe) < 0)
		_exit(1);

	struct pid_ns_clone_args args = {
		.cpipe = cpipe,
		.sock = sock,
		.tpid = tpid,
		.wrapped = &pid_to_ns
	};

	cpid = lxcfs_clone(pid_ns_clone_wrapper, &args, 0);
	if (cpid < 0)
		_exit(1);

	/* Give the child 1 second to be done forking and write its ack. */
	if (!wait_for_sock(cpipe[0], 1))
		_exit(1);
	ret = read(cpipe[0], &v, 1);
	if (ret != sizeof(char) || v != '1')
		_exit(1);

	if (!wait_for_pid(cpid))
		_exit(1);
	_exit(0);
}

/*
 * append pid to *src.
 * src: a pointer to a char* in which ot append the pid.
 * sz: the number of characters printed so far, minus trailing \0.
 * asz: the allocated size so far
 * pid: the pid to append
 */
static void must_strcat_pid(char **src, size_t *sz, size_t *asz, pid_t pid)
{
	must_strcat(src, sz, asz, "%d\n", (int)pid);
}

/*
 * To read cgroup files with a particular pid, we will setns into the child
 * pidns, open a pipe, fork a child - which will be the first to really be in
 * the child ns - which does the cgfs_get_value and writes the data to the pipe.
 */
static bool do_read_pids(pid_t tpid, const char *contrl, const char *cg,
			 const char *file, char **d)
{
	int sock[2] = {-1, -1};
	char *tmpdata = NULL;
	int ret;
	pid_t qpid, cpid = -1;
	bool answer = false;
	char v = '0';
	struct ucred cred;
	size_t sz = 0, asz = 0;

	if (!get_cgroup_handle_named(cgroup_ops, contrl, cg, file, &tmpdata))
		return false;

	/*
	 * Now we read the pids from returned data one by one, pass
	 * them into a child in the target namespace, read back the
	 * translated pids, and put them into our to-return data
	 */

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sock) < 0) {
		perror("socketpair");
		free(tmpdata);
		return false;
	}

	cpid = fork();
	if (cpid == -1)
		goto out;

	if (!cpid) // child - exits when done
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
		if (!wait_for_sock(sock[0], 2)) {
			lxcfs_error("Timed out waiting for pid from child: %s.\n", strerror(errno));
			goto out;
		}
		if (read(sock[0], &qpid, sizeof(qpid)) != sizeof(qpid)) {
			lxcfs_error("Error reading pid from child: %s.\n", strerror(errno));
			goto out;
		}
		must_strcat_pid(d, &sz, &asz, qpid);
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
		lxcfs_error("Failed to ask child to exit: %s.\n", strerror(errno));
		goto out;
	}

	answer = true;

out:
	free(tmpdata);
	if (cpid != -1)
		wait_for_pid(cpid);
	if (sock[0] != -1) {
		close(sock[0]);
		close(sock[1]);
	}
	return answer;
}

__lxcfs_fuse_ops int cg_read(const char *path, char *buf, size_t size,
			     off_t offset, struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	struct file_info *f = INTTYPE_TO_PTR(fi->fh);
	struct cgfs_files *k = NULL;
	char *data = NULL;
	int ret;
	size_t s;
	bool r;

	if (!liblxcfs_functional())
		return -EIO;

	if (!fc || !cgroup_ops || pure_unified_layout(cgroup_ops))
		return -EIO;

	if (f->type != LXC_TYPE_CGFILE) {
		lxcfs_error("%s\n", "Internal error: directory cache info used in cg_read.");
		return -EIO;
	}

	if (offset)
		return 0;

	if (!f->controller)
		return -EINVAL;

	if ((k = cgfs_get_key(f->controller, f->cgroup, f->file)) == NULL) {
		return -EINVAL;
	}
	free_key(k);


	if (!fc_may_access(fc, f->controller, f->cgroup, f->file, O_RDONLY)) {
		ret = -EACCES;
		goto out;
	}

	if (strcmp(f->file, "tasks") == 0 ||
			strcmp(f->file, "/tasks") == 0 ||
			strcmp(f->file, "/cgroup.procs") == 0 ||
			strcmp(f->file, "cgroup.procs") == 0)
		// special case - we have to translate the pids
		r = do_read_pids(fc->pid, f->controller, f->cgroup, f->file, &data);
	else
		r = get_cgroup_handle_named(cgroup_ops, f->controller, f->cgroup, f->file, &data);

	if (!r) {
		ret = -EINVAL;
		goto out;
	}

	if (!data) {
		ret = 0;
		goto out;
	}
	s = strlen(data);
	if (s > size)
		s = size;
	memcpy(buf, data, s);
	if ((s > 0) && (s < size) && (data[s - 1] != '\n'))
		buf[s++] = '\n';

	ret = s;

out:
	free(data);
	return ret;
}

__lxcfs_fuse_ops int cg_opendir(const char *path, struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	const char *cgroup;
	struct file_info *dir_info;
	char *controller = NULL;

	if (!liblxcfs_functional())
		return -EIO;

	if (!fc || !cgroup_ops)
		return -EIO;

	if (pure_unified_layout(cgroup_ops) || strcmp(path, "/cgroup") == 0) {
		cgroup = NULL;
		controller = NULL;
	} else {
		// return list of keys for the controller, and list of child cgroups
		controller = pick_controller_from_path(fc, path);
		if (!controller)
			return -errno;

		cgroup = find_cgroup_in_path(path);
		if (!cgroup) {
			/* this is just /cgroup/controller, return its contents */
			cgroup = "/";
		}
	}

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;
	if (cgroup) {
		if (!caller_may_see_dir(initpid, controller, cgroup))
			return -ENOENT;
		if (!fc_may_access(fc, controller, cgroup, NULL, O_RDONLY))
			return -EACCES;
	}

	/* we'll free this at cg_releasedir */
	dir_info = malloc(sizeof(*dir_info));
	if (!dir_info)
		return -ENOMEM;
	dir_info->controller = must_copy_string(controller);
	dir_info->cgroup = must_copy_string(cgroup);
	dir_info->type = LXC_TYPE_CGDIR;
	dir_info->buf = NULL;
	dir_info->file = NULL;
	dir_info->buflen = 0;

	fi->fh = PTR_TO_UINT64(dir_info);
	return 0;
}

__lxcfs_fuse_ops int cg_release(const char *path, struct fuse_file_info *fi)
{
	do_release_file_info(fi);
	return 0;
}

__lxcfs_fuse_ops int cg_releasedir(const char *path, struct fuse_file_info *fi)
{
	do_release_file_info(fi);
	return 0;
}

static FILE *open_pids_file(const char *controller, const char *cgroup)
{
	__do_close int fd = -EBADF;
	__do_free char *path = NULL;
	int cfd;
	FILE *f;

	cfd = get_cgroup_fd_handle_named(controller);
	if (cfd < 0)
		return false;

	path = must_make_path_relative(cgroup, "cgroup.procs", NULL);
	fd = openat(cfd, path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	f = fdopen(fd, "we");
	if (!f)
		return NULL;
	/* Transfer ownership of fd to fdopen(). */
	move_fd(fd);

	return f;
}

static int pid_from_ns(int sock, pid_t tpid)
{
	pid_t vpid;
	struct ucred cred;
	char v;
	int ret;

	cred.uid = 0;
	cred.gid = 0;
	while (1) {
		if (!wait_for_sock(sock, 2)) {
			lxcfs_error("%s\n", "Timeout reading from parent.");
			return 1;
		}
		if ((ret = read(sock, &vpid, sizeof(pid_t))) != sizeof(pid_t)) {
			lxcfs_error("Bad read from parent: %s.\n", strerror(errno));
			return 1;
		}
		if (vpid == -1) // done
			break;
		v = '0';
		cred.pid = vpid;
		if (send_creds(sock, &cred, v, true) != SEND_CREDS_OK) {
			v = '1';
			cred.pid = getpid();
			if (send_creds(sock, &cred, v, false) != SEND_CREDS_OK)
				return 1;
		}
	}
	return 0;
}

static void pid_from_ns_wrapper(int sock, pid_t tpid)
{
	int newnsfd = -1, ret, cpipe[2];
	char fnam[100];
	pid_t cpid;
	char v;

	ret = snprintf(fnam, sizeof(fnam), "/proc/%d/ns/pid", tpid);
	if (ret < 0 || (size_t)ret >= sizeof(fnam))
		_exit(1);
	newnsfd = open(fnam, O_RDONLY);
	if (newnsfd < 0)
		_exit(1);
	if (setns(newnsfd, 0) < 0)
		_exit(1);
	close(newnsfd);

	if (pipe(cpipe) < 0)
		_exit(1);

	struct pid_ns_clone_args args = {
		.cpipe = cpipe,
		.sock = sock,
		.tpid = tpid,
		.wrapped = &pid_from_ns
	};

	cpid = lxcfs_clone(pid_ns_clone_wrapper, &args, 0);
	if (cpid < 0)
		_exit(1);

	// give the child 1 second to be done forking and
	// write its ack
	if (!wait_for_sock(cpipe[0], 1))
		_exit(1);
	ret = read(cpipe[0], &v, 1);
	if (ret != sizeof(char) || v != '1')
		_exit(1);

	if (!wait_for_pid(cpid))
		_exit(1);
	_exit(0);
}

/*
 * get_pid_creds: get the real uid and gid of @pid from
 * /proc/$$/status
 * (XXX should we use euid here?)
 */
static void get_pid_creds(pid_t pid, uid_t *uid, gid_t *gid)
{
	char line[400];
	uid_t u;
	gid_t g;
	FILE *f;

	*uid = -1;
	*gid = -1;
	sprintf(line, "/proc/%d/status", pid);
	if ((f = fopen(line, "re")) == NULL) {
		lxcfs_error("Error opening %s: %s\n", line, strerror(errno));
		return;
	}
	while (fgets(line, 400, f)) {
		if (strncmp(line, "Uid:", 4) == 0) {
			if (sscanf(line+4, "%u", &u) != 1) {
				lxcfs_error("bad uid line for pid %u\n", pid);
				fclose(f);
				return;
			}
			*uid = u;
		} else if (strncmp(line, "Gid:", 4) == 0) {
			if (sscanf(line+4, "%u", &g) != 1) {
				lxcfs_error("bad gid line for pid %u\n", pid);
				fclose(f);
				return;
			}
			*gid = g;
		}
	}
	fclose(f);
}

/*
 * Given host @uid, return the uid to which it maps in
 * @pid's user namespace, or -1 if none.
 */
static bool hostuid_to_ns(uid_t uid, pid_t pid, uid_t *answer)
{
	FILE *f;
	char line[400];

	sprintf(line, "/proc/%d/uid_map", pid);
	if ((f = fopen(line, "re")) == NULL) {
		return false;
	}

	*answer = convert_id_to_ns(f, uid);
	fclose(f);

	if (*answer == (uid_t)-1)
		return false;
	return true;
}

/*
 * May the requestor @r move victim @v to a new cgroup?
 * This is allowed if
 *   . they are the same task
 *   . they are ownedy by the same uid
 *   . @r is root on the host, or
 *   . @v's uid is mapped into @r's where @r is root.
 */
static bool may_move_pid(pid_t r, uid_t r_uid, pid_t v)
{
	uid_t v_uid, tmpuid;
	gid_t v_gid;

	if (r == v)
		return true;
	if (r_uid == 0)
		return true;
	get_pid_creds(v, &v_uid, &v_gid);
	if (r_uid == v_uid)
		return true;
	if (hostuid_to_ns(r_uid, r, &tmpuid) && tmpuid == 0
			&& hostuid_to_ns(v_uid, r, &tmpuid))
		return true;
	return false;
}

static bool do_write_pids(pid_t tpid, uid_t tuid, const char *contrl,
			  const char *cg, const char *file, const char *buf)
{
	int sock[2] = {-1, -1};
	pid_t qpid, cpid = -1;
	FILE *pids_file = NULL;
	bool answer = false, fail = false;

	pids_file = open_pids_file(contrl, cg);
	if (!pids_file)
		return false;

	/*
	 * write the pids to a socket, have helper in writer's pidns
	 * call movepid for us
	 */
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sock) < 0) {
		perror("socketpair");
		goto out;
	}

	cpid = fork();
	if (cpid == -1)
		goto out;

	if (!cpid) { // child
		fclose(pids_file);
		pid_from_ns_wrapper(sock[1], tpid);
	}

	const char *ptr = buf;
	while (sscanf(ptr, "%d", &qpid) == 1) {
		struct ucred cred;
		char v;

		if (write(sock[0], &qpid, sizeof(qpid)) != sizeof(qpid)) {
			lxcfs_error("Error writing pid to child: %s.\n", strerror(errno));
			goto out;
		}

		if (recv_creds(sock[0], &cred, &v)) {
			if (v == '0') {
				if (!may_move_pid(tpid, tuid, cred.pid)) {
					fail = true;
					break;
				}
				if (fprintf(pids_file, "%d", (int) cred.pid) < 0)
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
		lxcfs_error("%s\n", "Warning: failed to ask child to exit.");

	if (!fail)
		answer = true;

out:
	if (cpid != -1)
		wait_for_pid(cpid);
	if (sock[0] != -1) {
		close(sock[0]);
		close(sock[1]);
	}
	if (pids_file) {
		if (fclose(pids_file) != 0)
			answer = false;
	}
	return answer;
}

static bool cgfs_set_value(const char *controller, const char *cgroup,
			   const char *file, const char *value)
{
	__do_close int fd = -EBADF;
	__do_free char *path = NULL;
	int cfd;
	size_t len;
	ssize_t ret;

	cfd = get_cgroup_fd_handle_named(controller);
	if (cfd < 0)
		return false;

	path = must_make_path_relative(cgroup, file, NULL);

	fd = openat(cfd, path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return false;

	len = strlen(value);
	ret = write_nointr(fd, value, len);
	if (ret < 0)
		return false;

	return (size_t)ret == len;
}

__lxcfs_fuse_ops int cg_write(const char *path, const char *buf, size_t size,
			      off_t offset, struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();
	char *localbuf = NULL;
	struct cgfs_files *k = NULL;
	struct file_info *f = INTTYPE_TO_PTR(fi->fh);
	bool r;

	if (!liblxcfs_functional())
		return -EIO;

	if (!fc || !cgroup_ops || pure_unified_layout(cgroup_ops))
		return -EIO;

	if (f->type != LXC_TYPE_CGFILE) {
		lxcfs_error("%s\n", "Internal error: directory cache info used in cg_write.");
		return -EIO;
	}

	if (offset)
		return 0;

	localbuf = alloca(size+1);
	localbuf[size] = '\0';
	memcpy(localbuf, buf, size);

	if ((k = cgfs_get_key(f->controller, f->cgroup, f->file)) == NULL) {
		size = -EINVAL;
		goto out;
	}

	if (!fc_may_access(fc, f->controller, f->cgroup, f->file, O_WRONLY)) {
		size = -EACCES;
		goto out;
	}

	if (strcmp(f->file, "tasks") == 0 ||
			strcmp(f->file, "/tasks") == 0 ||
			strcmp(f->file, "/cgroup.procs") == 0 ||
			strcmp(f->file, "cgroup.procs") == 0)
		// special case - we have to translate the pids
		r = do_write_pids(fc->pid, fc->uid, f->controller, f->cgroup, f->file, localbuf);
	else
		r = cgfs_set_value(f->controller, f->cgroup, f->file, localbuf);

	if (!r)
		size = -EINVAL;

out:
	free_key(k);
	return size;
}

static bool cgfs_iterate_cgroup(const char *controller, const char *cgroup,
				bool directories, void ***list, size_t typesize,
				void *(*iterator)(const char *, const char *, const char *))
{
	__do_close int fd = -EBADF;
	__do_free char *path = NULL;
	__do_closedir DIR *dir = NULL;
	size_t sz = 0, asz = 0;
	int cfd;
	struct dirent *dirent;

	cfd = get_cgroup_fd_handle_named(controller);
	*list = NULL;
	if (cfd < 0)
		return false;

	path = must_make_path_relative(cgroup, NULL);
	fd = openat(cfd, path, O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return false;

	dir = fdopendir(fd);
	if (!dir)
		return false;
	/* Transfer ownership of fd to fdopendir(). */
	move_fd(fd);

	while ((dirent = readdir(dir))) {
		int ret;
		char pathname[MAXPATHLEN];
		struct stat mystat;

		if (strcmp(dirent->d_name, ".") == 0)
			continue;

		if (strcmp(dirent->d_name, "..") == 0)
			continue;

		ret = snprintf(pathname, sizeof(pathname), "%s/%s", path, dirent->d_name);
		if (ret < 0 || (size_t)ret >= sizeof(pathname)) {
			lxcfs_error("Pathname too long under %s\n", path);
			continue;
		}

		ret = fstatat(cfd, pathname, &mystat, AT_SYMLINK_NOFOLLOW);
		if (ret) {
			lxcfs_error("Failed to stat %s: %s\n", pathname, strerror(errno));
			continue;
		}

		if (!directories && !S_ISREG(mystat.st_mode))
			continue;

		if (directories && !S_ISDIR(mystat.st_mode))
			continue;

		if (sz + 2 >= asz) {
			asz += BATCH_SIZE;
			*list = must_realloc(*list, asz * typesize);
		}
		(*list)[sz] = (*iterator)(controller, path, dirent->d_name);
		(*list)[sz + 1] = NULL;
		sz++;
	}

	return true;
}

static void *make_key_list_entry(const char *controller, const char *cgroup,
				 const char *dir_entry)
{
	struct cgfs_files *entry;

	entry = cgfs_get_key(controller, cgroup, dir_entry);
	if (!entry)
		lxcfs_error("Failed to retrieve files under %s:%s\n",
			    controller, cgroup);
	return entry;
}

static bool cgfs_list_keys(const char *controller, const char *cgroup,
			   struct cgfs_files ***keys)
{
	return cgfs_iterate_cgroup(controller, cgroup, false, (void ***)keys,
				   sizeof(*keys), &make_key_list_entry);
}

static void *make_children_list_entry(const char *controller,
				      const char *cgroup, const char *dir_entry)
{
	return strdup(dir_entry);
}

static bool cgfs_list_children(const char *controller, const char *cgroup,
			       char ***list)
{
	return cgfs_iterate_cgroup(controller, cgroup, true, (void ***)list,
				   sizeof(*list), &make_children_list_entry);
}

static void free_keys(struct cgfs_files **keys)
{
	if (!keys)
		return;

	for (int i = 0; keys[i]; i++)
		free_key(keys[i]);

	free_disarm(keys);
}

__lxcfs_fuse_ops int cg_readdir(const char *path, void *buf,
				fuse_fill_dir_t filler, off_t offset,
				struct fuse_file_info *fi)
{
	struct file_info *d = INTTYPE_TO_PTR(fi->fh);
	struct cgfs_files **list = NULL;
	int i, ret;
	char *nextcg = NULL;
	struct fuse_context *fc = fuse_get_context();
	char **clist = NULL;

	if (!liblxcfs_functional())
		return -EIO;

	if (!fc || !cgroup_ops)
		return -EIO;

	if (pure_unified_layout(cgroup_ops)) {
		ret = 0;
		goto out;
	}

	if (DIR_FILLER(filler, buf, ".", NULL, 0) != 0 || DIR_FILLER(filler, buf, "..", NULL, 0) != 0)
		return -EIO;

	if (d->type != LXC_TYPE_CGDIR) {
		lxcfs_error("%s\n", "Internal error: file cache info used in readdir.");
		return -EIO;
	}
	if (!d->cgroup && !d->controller) {
		/*
		 * ls /var/lib/lxcfs/cgroup - just show list of controllers.
		 * This only works with the legacy hierarchy.
		 */
		for (struct hierarchy **h = cgroup_ops->hierarchies; h && *h; h++) {
			if (is_unified_hierarchy(*h))
				continue;

			if ((*h)->__controllers && DIR_FILLER(filler, buf, (*h)->__controllers, NULL, 0))
				return -EIO;
		}

		return 0;
	}

	if (!cgfs_list_keys(d->controller, d->cgroup, &list)) {
		// not a valid cgroup
		ret = -EINVAL;
		goto out;
	}

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;
	if (!caller_is_in_ancestor(initpid, d->controller, d->cgroup, &nextcg)) {
		if (nextcg) {
			ret = DIR_FILLER(filler, buf, nextcg,  NULL, 0);
			free(nextcg);
			if (ret != 0) {
				ret = -EIO;
				goto out;
			}
		}
		ret = 0;
		goto out;
	}

	for (i = 0; list && list[i]; i++) {
		if (DIR_FILLER(filler, buf, list[i]->name, NULL, 0) != 0) {
			ret = -EIO;
			goto out;
		}
	}

	// now get the list of child cgroups

	if (!cgfs_list_children(d->controller, d->cgroup, &clist)) {
		ret = 0;
		goto out;
	}
	if (clist) {
		for (i = 0; clist[i]; i++) {
			if (DIR_FILLER(filler, buf, clist[i], NULL, 0) != 0) {
				ret = -EIO;
				goto out;
			}
		}
	}
	ret = 0;

out:
	free_keys(list);
	if (clist) {
		for (i = 0; clist[i]; i++)
			free(clist[i]);
		free(clist);
	}
	return ret;
}

__lxcfs_fuse_ops int cg_access(const char *path, int mode)
{
	int ret;
	const char *cgroup;
	char *path1, *path2, *controller;
	char *last = NULL, *cgdir = NULL;
	struct cgfs_files *k = NULL;
	struct fuse_context *fc = fuse_get_context();

	if (!liblxcfs_functional())
		return -EIO;

	if (!fc || !cgroup_ops || pure_unified_layout(cgroup_ops))
		return -EIO;

	if (strcmp(path, "/cgroup") == 0)
		return 0;

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return -errno;
	cgroup = find_cgroup_in_path(path);
	if (!cgroup) {
		// access("/sys/fs/cgroup/systemd", mode) - rx allowed, w not
		if ((mode & W_OK) == 0)
			return 0;
		return -EACCES;
	}

	get_cgdir_and_path(cgroup, &cgdir, &last);
	if (!last) {
		path1 = "/";
		path2 = cgdir;
	} else {
		path1 = cgdir;
		path2 = last;
	}

	k = cgfs_get_key(controller, path1, path2);
	if (!k) {
		if ((mode & W_OK) == 0)
			ret = 0;
		else
			ret = -EACCES;
		goto out;
	}
	free_key(k);

	pid_t initpid = lookup_initpid_in_store(fc->pid);
	if (initpid <= 1 || is_shared_pidns(initpid))
		initpid = fc->pid;
	if (!caller_may_see_dir(initpid, controller, path1)) {
		ret = -ENOENT;
		goto out;
	}
	if (!fc_may_access(fc, controller, path1, path2, mode)) {
		ret = -EACCES;
		goto out;
	}

	ret = 0;

out:
	free(cgdir);
	return ret;
}
