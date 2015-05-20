/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 * (C) Copyright Canonical, Inc, 2014
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
 * Serge Hallyn <serge.hallyn@ubuntu.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>
#include <pthread.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdbool.h>

#include <nih-dbus/dbus_connection.h>
#include <cgmanager/cgmanager-client.h>
#include <nih/alloc.h>
#include <nih/error.h>
#include <nih/string.h>

#include "cgmanager.h"

static __thread NihDBusProxy *cgroup_manager = NULL;
static __thread int32_t api_version;

static void cgm_dbus_disconnect(void)
{
       if (cgroup_manager) {
	       dbus_connection_flush(cgroup_manager->connection);
	       dbus_connection_close(cgroup_manager->connection);
               nih_free(cgroup_manager);
       }
       cgroup_manager = NULL;
}

#define CGMANAGER_DBUS_SOCK "unix:path=/sys/fs/cgroup/cgmanager/sock"
static bool cgm_dbus_connect(void)
{
	DBusError dbus_error;
	static DBusConnection *connection;

	dbus_error_init(&dbus_error);

	connection = dbus_connection_open_private(CGMANAGER_DBUS_SOCK, &dbus_error);
	if (!connection) {
		fprintf(stderr, "Failed opening dbus connection: %s: %s\n",
				dbus_error.name, dbus_error.message);
		dbus_error_free(&dbus_error);
		return false;
	}
	dbus_connection_set_exit_on_disconnect(connection, FALSE);
	dbus_error_free(&dbus_error);
	cgroup_manager = nih_dbus_proxy_new(NULL, connection,
				NULL /* p2p */,
				"/org/linuxcontainers/cgmanager", NULL, NULL);
	dbus_connection_unref(connection);
	if (!cgroup_manager) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "Error opening cgmanager proxy: %s\n", nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	// get the api version
	if (cgmanager_get_api_version_sync(NULL, cgroup_manager, &api_version) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "Error cgroup manager api version: %s\n", nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}
	return true;
}

bool cgm_get_controllers(char ***contrls)
{
	if (!cgm_dbus_connect()) {
		return false;
	}

	if ( cgmanager_list_controllers_sync(NULL, cgroup_manager, contrls) != 0 ) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to list_controllers failed: %s\n", nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	cgm_dbus_disconnect();
	return true;
}

bool cgm_list_keys(const char *controller, const char *cgroup, struct cgm_keys ***keys)
{
	if (!cgm_dbus_connect()) {
		return false;
	}

	if ( cgmanager_list_keys_sync(NULL, cgroup_manager, controller, cgroup,
				(CgmanagerListKeysOutputElement ***)keys) != 0 ) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to list_keys (%s:%s) failed: %s\n", controller, cgroup, nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	cgm_dbus_disconnect();
	return true;
}

bool cgm_list_children(const char *controller, const char *cgroup, char ***list)
{
	if (!cgm_dbus_connect()) {
		return false;
	}

	if ( cgmanager_list_children_sync(NULL, cgroup_manager, controller, cgroup, list) != 0 ) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to list_children (%s:%s) failed: %s\n", controller, cgroup, nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	cgm_dbus_disconnect();
	return true;
}

char *cgm_get_pid_cgroup(pid_t pid, const char *controller)
{
	char *output = NULL;

	if (!cgm_dbus_connect()) {
		return NULL;
	}

	if ( cgmanager_get_pid_cgroup_sync(NULL, cgroup_manager, controller, pid, &output) != 0 ) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to get_pid_cgroup (%s) failed: %s\n", controller, nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return NULL;
	}

	cgm_dbus_disconnect();
	return output;
}

bool cgm_escape_cgroup(void)
{
	if (!cgm_dbus_connect()) {
		return false;
	}

	if ( cgmanager_move_pid_abs_sync(NULL, cgroup_manager, "all", "/", (int32_t) getpid()) != 0 ) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to move_pid_abs (all:/) failed: %s\n", nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	cgm_dbus_disconnect();
	return true;
}

bool cgm_move_pid(const char *controller, const char *cgroup, pid_t pid)
{
	if (!cgm_dbus_connect()) {
		return false;
	}

	if ( cgmanager_move_pid_sync(NULL, cgroup_manager, controller, cgroup,
				(int32_t) pid) != 0 ) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to move_pid (%s:%s, %d) failed: %s\n", controller, cgroup, pid, nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	cgm_dbus_disconnect();
	return true;
}

bool cgm_get_value(const char *controller, const char *cgroup, const char *file,
		char **value)
{
	if (!cgm_dbus_connect()) {
		return false;
	}

	if ( cgmanager_get_value_sync(NULL, cgroup_manager, controller, cgroup,
			file, value) != 0 ) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to get_value (%s:%s, %s) failed: %s\n", controller, cgroup, file, nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	cgm_dbus_disconnect();
	return true;
}

bool cgm_set_value(const char *controller, const char *cgroup, const char *file,
		const char *value)
{
	if (!cgm_dbus_connect()) {
		return false;
	}

	if ( cgmanager_set_value_sync(NULL, cgroup_manager, controller, cgroup,
			file, value) != 0 ) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to set_value (%s:%s, %s, %s) failed: %s\n", controller, cgroup, file, value, nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	cgm_dbus_disconnect();
	return true;
}

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

bool cgm_create(const char *controller, const char *cg, uid_t uid, gid_t gid)
{
	int32_t e;
	pid_t pid = fork();

	if (pid) {
		if (wait_for_pid(pid) != 0)
			return false;
		return true;
	}

	if (setgroups(0, NULL))
		_exit(1);
	if (setresgid(gid, gid, gid))
		_exit(1);
	if (setresuid(uid, uid, uid))
		_exit(1);

	if (!cgm_dbus_connect()) {
		_exit(1);
	}

	if ( cgmanager_create_sync(NULL, cgroup_manager, controller, cg, &e) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to create failed (%s:%s): %s\n", controller, cg, nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		_exit(1);
	}

	cgm_dbus_disconnect();
	_exit(0);
}

bool cgm_chown_file(const char *controller, const char *cg, uid_t uid, gid_t gid)
{
	if (!cgm_dbus_connect()) {
		return false;
	}

	if ( cgmanager_chown_sync(NULL, cgroup_manager, controller, cg, uid, gid) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to chown (%s:%s, %d, %d) failed: %s\n", controller, cg, uid, gid, nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	cgm_dbus_disconnect();
	return true;
}

bool cgm_chmod_file(const char *controller, const char *file, mode_t mode)
{
	if (!cgm_dbus_connect()) {
		return false;
	}

	if ( cgmanager_chmod_sync(NULL, cgroup_manager, controller, file, "", mode) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to chmod (%s:%s, %d) failed: %s\n", controller, file, mode, nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	cgm_dbus_disconnect();
	return true;
}

bool cgm_remove(const char *controller, const char *cg)
{
	/*
	 * tempting to make remove be recursive, but this is a filesystem,
	 * so best to opt for least surprise
	 */
	int32_t r = 0, e;

	if (!cgm_dbus_connect()) {
		return false;
	}

	if ( cgmanager_remove_sync(NULL, cgroup_manager, controller, cg, r, &e) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to remove (%s:%s) failed: %s\n", controller, cg, nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	cgm_dbus_disconnect();
	return true;
}
