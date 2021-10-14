/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <utime.h>

void test_open(const char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd >= 0) {
		fprintf(stderr, "leak at open of %s\n", path);
		exit(1);
	}
	if (errno != ENOENT) {
		fprintf(stderr, "leak at open of %s: errno was %d\n", path, errno);
		exit(1);
	}
}

void test_stat(const char *path)
{
	struct stat sb;
	if (stat(path, &sb) >= 0) {
		fprintf(stderr, "leak at stat of %s\n", path);
		exit(1);
	}
	if (errno != ENOENT) {
		fprintf(stderr, "leak at stat of %s: errno was %d\n", path, errno);
		exit(1);
	}
}

void test_access(const char *path)
{
	if (access(path, O_RDONLY) >= 0) {
		fprintf(stderr, "leak at access of %s\n", path);
		exit(1);
	}
	if (errno != ENOENT) {
		fprintf(stderr, "leak at access of %s: errno was %d\n", path, errno);
		exit(1);
	}
}

void test_bind(const char *path)
{
	int sfd;
	struct sockaddr_un my_addr;

	sfd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (sfd < 0) {
		fprintf(stderr, "Failed to open a socket for bind test\n");
		exit(1);
	}
	memset(&my_addr, 0, sizeof(struct sockaddr_un));
	my_addr.sun_family = AF_UNIX;
	strncpy(my_addr.sun_path, path,
			sizeof(my_addr.sun_path) - 1);
	if (bind(sfd, (struct sockaddr *) &my_addr,
				sizeof(struct sockaddr_un)) != -1) {
		fprintf(stderr, "leak at bind of %s\n", path);
		exit(1);
	}
	if (errno != ENOENT && errno != ENOSYS) {
		fprintf(stderr, "leak at bind of %s: errno was %s\n", path, strerror(errno));
		exit(1);
	}
	close(sfd);
}

void test_bindmount(const char *path)
{
	if (mount(path, path, "none", MS_BIND, NULL) == 0) {
		fprintf(stderr, "leak at bind mount of %s\n", path);
		exit(1);
	}
}

void test_truncate(const char *path)
{
	if (truncate(path, 0) == 0) {
		fprintf(stderr, "leak at truncate of %s\n", path);
		exit(1);
	}
}

void test_chdir(const char *path)
{
	if (chdir(path) == 0) {
		fprintf(stderr, "leak at chdir to %s\n", path);
		exit(1);
	}
}

void test_rename(const char *path)
{
	char *d = strdupa(path), *tmpname;
	d = dirname(d);
	size_t len = strlen(path) + 30;

	tmpname = alloca(len);
	snprintf(tmpname, len, "%s/%d", d, (int)getpid());
	if (rename(path, tmpname) == 0 || errno != ENOENT) {
		fprintf(stderr, "leak at rename of %s\n", path);
		exit(1);
	}
}

void test_mkdir(const char *path)
{
	size_t len = strlen(path) + 30;
	char *tmpname = alloca(len);
	snprintf(tmpname, len, "%s/%d", path, (int)getpid());

	if (mkdir(path, 0755) == 0) {
		fprintf(stderr, "leak at mkdir of %s\n", path);
		exit(1);
	}
	if (errno != ENOENT) {
		fprintf(stderr, "leak at mkdir of %s, errno was %s\n", path, strerror(errno));
		exit(1);
	}
	if (mkdir(tmpname, 0755) == 0) {
		fprintf(stderr, "leak at mkdir of %s\n", tmpname);
		exit(1);
	}
	if (errno != ENOENT) {
		fprintf(stderr, "leak at mkdir of %s, errno was %s\n", path, strerror(errno));
		exit(1);
	}
}

void test_rmdir(const char *path)
{
	size_t len = strlen(path) + 30;
	char *tmpname = alloca(len);
	snprintf(tmpname, len, "%s/%d", path, (int)getpid());

	if (rmdir(path) == 0 || errno != ENOENT) {
		fprintf(stderr, "leak at rmdir of %s\n", path);
		exit(1);
	}
	if (rmdir(tmpname) == 0 || errno != ENOENT) {
		fprintf(stderr, "leak at rmdir of %s\n", tmpname);
		exit(1);
	}
}

void test_creat(const char *path)
{
	if (creat(path, 0755) >= 0) {
		fprintf(stderr, "leak at creat of %s\n", path);
		exit(1);
	}
	if (errno != ENOENT && errno != ENOSYS) {
		fprintf(stderr, "leak at creat of %s: errno was %s\n", path, strerror(errno));
		exit(1);
	}
}

void test_link(const char *path)
{
	char *d = strdupa(path), *tmpname;
	d = dirname(d);
	size_t len = strlen(path) + 30;
	tmpname = alloca(len);
	snprintf(tmpname, len, "%s/%d", d, (int)getpid());

	if (link(path, tmpname) == 0) {
		fprintf(stderr, "leak at link of %s\n", path);
		exit(1);
	}
	if (errno != ENOENT && errno != ENOSYS) {
		fprintf(stderr, "leak at link of %s: errno was %s\n", path, strerror(errno));
		exit(1);
	}

	if (link(tmpname, path) == 0) {
		fprintf(stderr, "leak at link (2) of %s\n", path);
		exit(1);
	}
	if (errno != ENOENT && errno != ENOSYS) {
		fprintf(stderr, "leak at link (2) of %s: errno was %s\n", path, strerror(errno));
		exit(1);
	}
}

void test_unlink(const char *path)
{
	if (unlink(path) == 0) {
		fprintf(stderr, "leak at unlink of %s\n", path);
		exit(1);
	}
	if (errno != ENOENT && errno != ENOSYS) {
		fprintf(stderr, "leak at unlink of %s: errno was %s\n", path, strerror(errno));
		exit(1);
	}
}

void test_symlink(const char *path)
{
	char *d = strdupa(path), *tmpname;
	d = dirname(d);
	size_t len = strlen(path) + 30;
	tmpname = alloca(len);
	snprintf(tmpname, len, "%s/%d", d, (int)getpid());

	if (symlink(tmpname, path) == 0) {
		fprintf(stderr, "leak at symlink of %s\n", path);
		exit(1);
	}
	if (errno != ENOENT && errno != ENOSYS) {
		fprintf(stderr, "leak at symlink of %s: errno was %s\n", path, strerror(errno));
		exit(1);
	}
	if (symlink(path, tmpname) == 0) {
		fprintf(stderr, "leak at symlink (2) of %s\n", path);
		exit(1);
	}
	if (errno != ENOENT && errno != ENOSYS) {
		fprintf(stderr, "leak at symlink (2) of %s: errno was %s\n", path, strerror(errno));
		exit(1);
	}
}

void test_readlink(const char *path)
{
	char *dest = alloca(2 * strlen(path));

	if (readlink(path, dest, 2 * strlen(path)) >= 0) {
		fprintf(stderr, "leak at readlink of %s\n", path);
		exit(1);
	}
	if (errno != ENOENT && errno != ENOSYS) {
		fprintf(stderr, "leak at readlink of %s: errno was %s\n", path, strerror(errno));
		exit(1);
	}
}

void test_chmod(const char *path)
{
	if (chmod(path, 0755) == 0) {
		fprintf(stderr, "leak at chmod of %s\n", path);
		exit(1);
	}
	if (errno != ENOENT && errno != ENOSYS) {
		fprintf(stderr, "leak at chmod of %s: errno was %s\n", path, strerror(errno));
		exit(1);
	}
}

void test_chown(const char *path)
{
	if (chown(path, 0, 0) == 0) {
		fprintf(stderr, "leak at chown of %s\n", path);
		exit(1);
	}
	if (errno != ENOENT && errno != ENOSYS) {
		fprintf(stderr, "leak at chown of %s: errno was %s\n", path, strerror(errno));
		exit(1);
	}
}

void test_lchown(const char *path)
{
	if (lchown(path, 0, 0) == 0) {
		fprintf(stderr, "leak at lchown of %s\n", path);
		exit(1);
	}
	if (errno != ENOENT && errno != ENOSYS) {
		fprintf(stderr, "leak at lchown of %s: errno was %s\n", path, strerror(errno));
		exit(1);
	}
}

void test_mknod(const char *path)
{
	if (mknod(path, 0755, makedev(0, 0)) == 0) {
		fprintf(stderr, "leak at mknod of %s\n", path);
		exit(1);
	}
	if (errno != ENOENT && errno != ENOSYS) {
		fprintf(stderr, "leak at mknod of %s: errno was %s\n", path, strerror(errno));
		exit(1);
	}
}

void test_chroot(const char *path)
{
	if (chroot(path) == 0) {
		fprintf(stderr, "leak at chroot of %s\n", path);
		exit(1);
	}
	if (errno != ENOENT && errno != ENOSYS) {
		fprintf(stderr, "leak at chroot of %s: errno was %s\n", path, strerror(errno));
		exit(1);
	}
}

void test_xattrs(const char *path)
{
	/*
	 * might consider doing all of:
	 *  setxattr
	 *  lsetxattr
	 *  getxattr
	 *  lgetxattr
	 *  listxattr
	 *  llistxattr
	 *  removexattr
	 *  lremovexattr
	 */
	 char value[200];
	 if (getxattr(path, "security.selinux", value, 200) >= 0) {
		fprintf(stderr, "leak at getxattr of %s\n", path);
		exit(1);
	}
	if (errno != ENOENT && errno != ENOSYS) {
		fprintf(stderr, "leak at getxattr of %s: errno was %s\n", path, strerror(errno));
		exit(1);
	}
}

void test_utimes(const char *path)
{
	struct utimbuf times;
	times.actime = 0;
	times.modtime = 0;

	if (utime(path, &times) == 0) {
		fprintf(stderr, "leak at utime of %s\n", path);
		exit(1);
	}
	if (errno != ENOENT && errno != ENOSYS) {
		fprintf(stderr, "leak at utime of %s: errno was %s\n", path, strerror(errno));
		exit(1);
	}
}

void test_openat(const char *path)
{
	char *d = strdupa(path), *f, *tmpname;
	int fd, fd2;
	f = basename(d);
	d = dirname(d);
	fd = open(d, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Error in openat test: could not open parent dir\n");
		fprintf(stderr, "(this is expected on the second run)\n");
		return;
	}
	fd2 = openat(fd, f, O_RDONLY);
	if (fd2 >= 0 || errno != ENOENT) {
		fprintf(stderr, "leak at openat of %s\n", f);
		exit(1);
	}
	size_t len = strlen(path) + strlen("/cgroup.procs") + 1;
	tmpname = alloca(len);
	snprintf(tmpname, len, "%s/cgroup.procs", f);
	fd2 = openat(fd, tmpname, O_RDONLY);
	if (fd2 >= 0 || errno != ENOENT) {
		fprintf(stderr, "leak at openat of %s\n", tmpname);
		exit(1);
	}
	close(fd);
}

int main(int argc, char *argv[])
{
	char *procspath;
	size_t len;

	if (geteuid() != 0) {
		fprintf(stderr, "Run me as root\n");
		exit(1);
	}

	if (argc != 2)  {
		fprintf(stderr, "Usage: %s [lxcfs_test_cgroup_path]\n", argv[0]);
		exit(1);
	}

	/* Try syscalls on the directory and on $directory/cgroup.procs */
	len = strlen(argv[1]) + strlen("/cgroup.procs") + 1;
	procspath = alloca(len);
	snprintf(procspath, len, "%s/cgroup.procs", argv[1]);

	test_open(argv[1]);
	test_open(procspath);
	test_stat(argv[1]);
	test_stat(procspath);
	test_access(argv[1]);
	test_access(procspath);

	test_bind(argv[1]);
	test_bind(procspath);
	test_bindmount(argv[1]);
	test_bindmount(procspath);
	test_truncate(argv[1]);
	test_truncate(procspath);
	test_chdir(argv[1]);
	test_chdir(procspath);
	test_rename(argv[1]);
	test_rename(procspath);
	test_mkdir(argv[1]);
	test_mkdir(procspath);
	test_rmdir(argv[1]);
	test_rmdir(procspath);
	test_creat(argv[1]);
	test_creat(procspath);
	test_link(argv[1]);
	test_link(procspath);
	test_unlink(argv[1]);
	test_unlink(procspath);
	test_symlink(argv[1]);
	test_symlink(procspath);
	test_readlink(argv[1]);
	test_readlink(procspath);
	test_chmod(argv[1]);
	test_chmod(procspath);
	test_chown(argv[1]);
	test_chown(procspath);
	test_lchown(argv[1]);
	test_lchown(procspath);
	test_mknod(argv[1]);
	test_mknod(procspath);
	test_chroot(argv[1]);
	test_chroot(procspath);
	test_xattrs(argv[1]);
	test_xattrs(procspath);
	test_utimes(argv[1]);
	test_utimes(procspath);

	test_openat(argv[1]);
	// meh...  linkat etc?

	printf("All tests passed\n");
	return 0;
}
