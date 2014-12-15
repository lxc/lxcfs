/* lxcfs
 *
 * Copyright © 2014 Canonical, Inc
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * NOTES - make sure to run this as -s to avoid threading.
 * TODO - can we enforce that here from the code?
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

#include <nih/alloc.h>
#include <nih/string.h>

#include "cgmanager.h"

struct lxcfs_state {
	/*
	 * a null-terminated, nih-allocated list of the mounted subsystems.  We
	 * detect this at startup.
	 */
	char **subsystems;
};
#define LXCFS_DATA ((struct lxcfs_state *) fuse_get_context()->private_data)

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
			fprintf(stderr, "pid wrapparound at entry %u %u %u in %s",
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

static bool is_privileged_over(pid_t pid, uid_t uid, uid_t victim)
{
	nih_local char *fpath = NULL;
	bool answer = false;
	uid_t nsuid;

	if (uid == victim)
		return true;

	/* check /proc/pid/uid_map */
	fpath = NIH_MUST( nih_sprintf(NULL, "/proc/%d/uid_map", pid) );
	FILE *f = fopen(fpath, "r");
	if (!f)
		return false;

	nsuid = convert_id_to_ns(f, uid);
	if (nsuid)
		goto out;

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
	fprintf(stderr, "perms_include: checking whether %d includes %d\n",
		fmode, req_mode);
	return (fmode & req_mode) == req_mode;
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
			if (is_privileged_over(fc->pid, fc->uid, k->uid)) {
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

static size_t get_file_size(const char *contrl, const char *cg, const char *f)
{
	nih_local char *data = NULL;
	size_t s;
	if (!cgm_get_value(contrl, cg, f, &data))
		return -EINVAL;
	s = strlen(data);
	return s;
}
/*
 * gettattr fn for anything under /cgroup
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
		if (!fc_may_access(fc, controller, cgroup, NULL, O_RDONLY))
			return -EPERM;

		// get uid, gid, from '/tasks' file and make up a mode
		// That is a hack, until cgmanager gains a GetCgroupPerms fn.
		sb->st_mode = S_IFDIR | 00755;
		k = get_cgroup_key(controller, cgroup, "tasks");
		if (!k) {
			fprintf(stderr, "Failed to find a tasks file for %s\n", cgroup);
			sb->st_uid = sb->st_gid = 0;
		} else {
			fprintf(stderr, "found a tasks file for %s\n", cgroup);
			sb->st_uid = k->uid;
			sb->st_gid = k->gid;
		}
		sb->st_nlink = 2;
		return 0;
	}

	if ((k = get_cgroup_key(controller, path1, path2)) != NULL) {
		if (!fc_may_access(fc, controller, path1, path2, O_RDONLY))
			return -EPERM;

		sb->st_mode = S_IFREG | k->mode;
		sb->st_nlink = 1;
		sb->st_uid = k->uid;
		sb->st_gid = k->gid;
		sb->st_size = get_file_size(controller, path1, path2);
		return 0;
	}

	return -ENOENT;
}

static int cg_opendir(const char *path, struct fuse_file_info *fi)
{
	return 0;
}

/*
 * readdir function for anything under /cgroup
 */
static int cg_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
		struct fuse_file_info *fi)
{
	struct fuse_context *fc = fuse_get_context();

	if (!fc)
		return -EIO;

	if (strcmp(path, "/cgroup") == 0) {
		// get list of controllers
		char **list = LXCFS_DATA ? LXCFS_DATA->subsystems : NULL;
		int i;

		if (!list)
			return -EIO;
		/* TODO - collect the list of controllers at fuse_init */
		for (i = 0;  list[i]; i++) {
			if (filler(buf, list[i], NULL, 0) != 0) {
				return -EIO;
			}
		}
		return 0;
	}

	// return list of keys for the controller, and list of child cgroups
	nih_local struct cgm_keys **list = NULL;
	const char *cgroup;
	nih_local char *controller = NULL;
	int i;

	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return -EIO;

	cgroup = find_cgroup_in_path(path);
	if (!cgroup) {
		/* this is just /cgroup/controller, return its contents */
		cgroup = "/";
	}

	if (!fc_may_access(fc, controller, cgroup, NULL, O_RDONLY))
		return -EPERM;

	if (!cgm_list_keys(controller, cgroup, &list))
		return -EINVAL;
	for (i = 0; list[i]; i++) {
		fprintf(stderr, "adding key %s\n", list[i]->name);
		if (filler(buf, list[i]->name, NULL, 0) != 0) {
			return -EIO;
		}
	}

	// now get the list of child cgroups
	nih_local char **clist;

	if (!cgm_list_children(controller, cgroup, &clist))
		return 0;
	for (i = 0; clist[i]; i++) {
		fprintf(stderr, "adding child %s\n", clist[i]);
		if (filler(buf, clist[i], NULL, 0) != 0) {
			return -EIO;
		}
	}
	return 0;
}

static int cg_releasedir(const char *path, struct fuse_file_info *fi)
{
	return 0;
}

static int cg_open(const char *path, struct fuse_file_info *fi)
{
	nih_local char *controller = NULL;
	const char *cgroup;
	char *fpath = NULL, *path1, *path2;
	nih_local char * cgdir = NULL;
	nih_local struct cgm_keys *k = NULL;
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

	if ((k = get_cgroup_key(controller, path1, path2)) != NULL) {
		if (!fc_may_access(fc, controller, path1, path2, fi->flags))
			return -EPERM;

		/* TODO - we want to cache this info for read/write */
		return 0;
	}

	return -EINVAL;
}

static int cg_read(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	nih_local char *controller = NULL;
	const char *cgroup;
	char *fpath = NULL, *path1, *path2;
	struct fuse_context *fc = fuse_get_context();
	nih_local char * cgdir = NULL;
	nih_local struct cgm_keys *k = NULL;

	if (offset)
		return -EIO;

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

	if ((k = get_cgroup_key(controller, path1, path2)) != NULL) {
		nih_local char *data = NULL;
		int s;

		if (!fc_may_access(fc, controller, path1, path2, fi->flags))
			return -EPERM;

		if (!cgm_get_value(controller, path1, path2, &data))
			return -EINVAL;

		s = strlen(data);
		if (s > size)
			s = size;
		memcpy(buf, data, s);

fprintf(stderr, "cg_read: returning %d: %s\n", s, buf);
		return s;
	}

	return -EINVAL;
}

int cg_mkdir(const char *path, mode_t mode)
{
	struct fuse_context *fc = fuse_get_context();
	nih_local struct cgm_keys **list = NULL;
	char *fpath = NULL, *path1;
	nih_local char * cgdir = NULL;
	const char *cgroup;
	nih_local char *controller = NULL;

fprintf(stderr, "XXX cg_mkdir: starting for %s\n", path);
	if (!fc)
		return -EIO;


	controller = pick_controller_from_path(fc, path);
	if (!controller)
		return -EIO;

	cgroup = find_cgroup_in_path(path);
	if (!cgroup)
		return -EIO;

	get_cgdir_and_path(cgroup, &cgdir, &fpath);
	if (!fpath)
		path1 = "/";
	else
		path1 = cgdir;

	if (!fc_may_access(fc, controller, path1, NULL, O_RDWR))
		return -EPERM;


	if (!cgm_create(controller, cgroup, fc->uid, fc->gid))
		return -EINVAL;

	return 0;
}

/*
 * So far I'm not actually using cg_ops and proc_ops, but listing them
 * here makes it clearer who is supporting what.  Still I prefer to 
 * call the real functions and not cg_ops->getattr.
 */
const struct fuse_operations cg_ops = {
	.getattr = cg_getattr,
	.readlink = NULL,
	.getdir = NULL,
	.mknod = NULL,
	.mkdir = cg_mkdir,
	.unlink = NULL,
	.rmdir = NULL,
	.symlink = NULL,
	.rename = NULL,
	.link = NULL,
	.chmod = NULL,
	.chown = NULL,
	.truncate = NULL,
	.utime = NULL,
	.open = cg_open,
	.read = cg_read,
	.write = NULL,
	.statfs = NULL,
	.flush = NULL,
	.release = NULL,
	.fsync = NULL,

	.setxattr = NULL,
	.getxattr = NULL,
	.listxattr = NULL,
	.removexattr = NULL,

	.opendir = cg_opendir,
	.readdir = cg_readdir,
	.releasedir = cg_releasedir,

	.fsyncdir = NULL,
	.init = NULL,
	.destroy = NULL,
	.access = NULL,
	.create = NULL,
	.ftruncate = NULL,
	.fgetattr = NULL,
};

static int proc_getattr(const char *path, struct stat *sb)
{
	if (strcmp(path, "/proc") != 0)
		return -EINVAL;
	sb->st_mode = S_IFDIR | 00755;
	sb->st_nlink = 2;
	return 0;
}

const struct fuse_operations proc_ops = {
	.getattr = proc_getattr,
	.readlink = NULL,
	.getdir = NULL,
	.mknod = NULL,
	.mkdir = NULL,
	.unlink = NULL,
	.rmdir = NULL,
	.symlink = NULL,
	.rename = NULL,
	.link = NULL,
	.chmod = NULL,
	.chown = NULL,
	.truncate = NULL,
	.utime = NULL,
	.open = NULL,
	.read = NULL,
	.write = NULL,
	.statfs = NULL,
	.flush = NULL,
	.release = NULL,
	.fsync = NULL,

	.setxattr = NULL,
	.getxattr = NULL,
	.listxattr = NULL,
	.removexattr = NULL,

	.opendir = NULL,
	.readdir = NULL,
	.releasedir = NULL,

	.fsyncdir = NULL,
	.init = NULL,
	.destroy = NULL,
	.access = NULL,
	.create = NULL,
	.ftruncate = NULL,
	.fgetattr = NULL,
};

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
	if (strncmp(path, "/proc", 7) == 0) {
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
	return -EINVAL;
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
	if (strncmp(path, "/cgroup", 7) == 0) {
		return cg_readdir(path, buf, filler, offset, fi);
	}
	return -EINVAL;
}

static int lxcfs_releasedir(const char *path, struct fuse_file_info *fi)
{
	if (strcmp(path, "/") == 0)
		return 0;
	if (strncmp(path, "/cgroup", 7) == 0) {
		return cg_releasedir(path, fi);
	}
	return -EINVAL;
}

static int lxcfs_open(const char *path, struct fuse_file_info *fi)
{
	if (strncmp(path, "/cgroup", 7) == 0) {
		return cg_open(path, fi);
	}

	return -EINVAL;
}

static int lxcfs_read(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	if (strncmp(path, "/cgroup", 7) == 0) {
		return cg_read(path, buf, size, offset, fi);
	}

	return -EINVAL;
}

static int lxcfs_flush(const char *path, struct fuse_file_info *fi)
{
	return 0;
}

static int lxcfs_release(const char *path, struct fuse_file_info *fi)
{
	return 0;
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

const struct fuse_operations lxcfs_ops = {
	.getattr = lxcfs_getattr,
	.readlink = NULL,
	.getdir = NULL,
	.mknod = NULL,
	.mkdir = lxcfs_mkdir,
	.unlink = NULL,
	.rmdir = NULL,
	.symlink = NULL,
	.rename = NULL,
	.link = NULL,
	.chmod = NULL,
	.chown = NULL,
	.truncate = NULL,
	.utime = NULL,

	.open = lxcfs_open,
	.read = lxcfs_read,
	.release = lxcfs_release,
	.write = NULL,

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
	fprintf(stderr, "%s [FUSE and mount options] mountpoint\n", me);
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

int main(int argc, char *argv[])
{
	int ret;
	struct lxcfs_state *d;

	if (argc < 2 || is_help(argv[1]))
		usage(argv[0]);

	d = malloc(sizeof(*d));
	if (!d)
		return -1;

	if (!cgm_escape_cgroup())
		fprintf(stderr, "WARNING: failed to escape to root cgroup\n");

	if (!cgm_get_controllers(&d->subsystems))
		return -1;

	ret = fuse_main(argc, argv, &lxcfs_ops, d);

	return ret;
}
