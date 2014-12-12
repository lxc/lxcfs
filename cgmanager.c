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
#include <netinet/in.h>
#include <net/if.h>
#include <stdbool.h>

#include <nih-dbus/dbus_connection.h>
#include <cgmanager/cgmanager-client.h>
#include <nih/alloc.h>
#include <nih/error.h>
#include <nih/string.h>

#include "cgmanager.h"

static NihDBusProxy *cgroup_manager = NULL;
static int32_t api_version;

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
		fprintf(stderr, "Failed opening dbus connection: %s: %s",
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
		fprintf(stderr, "Error opening cgmanager proxy: %s", nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	// get the api version
	if (cgmanager_get_api_version_sync(NULL, cgroup_manager, &api_version) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "Error cgroup manager api version: %s", nerr->message);
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
		fprintf(stderr, "call to list_controllers failed: %s", nerr->message);
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
		fprintf(stderr, "call to list_keys failed: %s", nerr->message);
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
		fprintf(stderr, "call to list_children failed: %s", nerr->message);
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
		fprintf(stderr, "call to get_pid_cgroup failed: %s", nerr->message);
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
		fprintf(stderr, "call to move_pid_abs failed: %s", nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	cgm_dbus_disconnect();
	return true;
}
