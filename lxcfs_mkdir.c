/* lxcfs
 *
 * Copyright © 2015 Canonical, Inc
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
 *
 * See COPYING file for details.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#include "cgmanager.h"

void do_mkdir(char *argv[])
{
	uid_t uid;
	gid_t gid;
	unsigned long int tmp;
	const char *controller = argv[3], *cgroup = argv[4];
	errno = 0;
	tmp = strtoul(argv[1], NULL, 10);
	if (tmp < 0 || errno != 0)
		exit(1);
	uid = (uid_t) tmp;
	tmp = strtoul(argv[2], NULL, 10);
	if (tmp < 0 || errno != 0)
		exit(1);
	gid = (gid_t) tmp;
	if (setresgid(gid, gid, gid) != 0) {
		fprintf(stderr, "Error dropping root group\n");
		exit(1);
	}
	if (setresuid(uid, uid, uid) != 0) {
		fprintf(stderr, "Error dropping root uid\n");
		exit(1);
	}
	if (!cgm_create(controller, cgroup)) {
		exit(1);
	}
}

/*
 * lxcfs execs us to create directories, using
 *     lxcfs-mkdir uid gid controller cgroup
 */
int main(int argc, char *argv[])
{
	if (getuid() || getgid())
		exit(1);
	if (argc != 5)
		exit(1);
	do_mkdir(argv);
	exit(0);
}
