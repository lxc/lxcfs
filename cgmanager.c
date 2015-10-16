/*
 * Copyright © 2015 Canonical Limited
 *
 * Authors:
 *   Serge Hallyn <serge.hallyn@ubuntu.com>
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
#include "cgmanager.h"
#include <assert.h>

#include <glib.h>
#include <gio/gio.h>

#define CGM_DBUS_ADDRESS          "unix:path=/sys/fs/cgroup/cgmanager/sock"
#define CGM_REQUIRED_VERSION      9  // we need list_keys

static GDBusConnection *cgroup_manager = NULL;

static pthread_mutex_t cgm_mutex = PTHREAD_MUTEX_INITIALIZER;

static void lock_mutex(pthread_mutex_t *l)
{
	int ret;
	if ((ret = pthread_mutex_lock(l)) != 0) {
		fprintf(stderr, "pthread_mutex_lock returned:%d %s\n", ret, strerror(ret));
		exit(1);
	}
}

static void unlock_mutex(pthread_mutex_t *l)
{
	int ret;
	if ((ret = pthread_mutex_unlock(l)) != 0) {
		fprintf(stderr, "pthread_mutex_unlock returned:%d %s\n", ret, strerror(ret));
		exit(1);
	}
}

void cgm_lock(void)
{
	lock_mutex(&cgm_mutex);
}

void cgm_unlock(void)
{
	unlock_mutex(&cgm_mutex);
}

/* only called on exit, no need to lock */
void cgm_dbus_disconnect(void)
{
	GError *error = NULL;

	if (!cgroup_manager)
		return;

	if (!g_dbus_connection_flush_sync(cgroup_manager, NULL, &error)) {
		g_warning("failed to flush connection: %s."
				"Use G_DBUS_DEBUG=message for more info.", error->message);
		g_error_free(error);
	}
	if (!g_dbus_connection_close_sync(cgroup_manager, NULL, &error)) {
		g_warning("failed to close connection: %s."
				"Use G_DBUS_DEBUG=message for more info.", error->message);
		g_error_free(error);
	}
	g_object_unref(cgroup_manager);
	cgroup_manager = NULL;
}

bool cgm_dbus_connect(void)
{
	GDBusConnection *connection;
	GVariant *reply;
	GVariant *version;
	GError *error = NULL;

	// fastpath - don't lock if we have the manager
	if (cgroup_manager && !g_dbus_connection_is_closed(cgroup_manager))
		return true;

	cgm_lock();

	// TODO - do we want to add some limit to nretries?
retry:
	if (cgroup_manager) {
		if (!g_dbus_connection_is_closed(cgroup_manager)) {
			// someone else reconnect us
			cgm_unlock();
			return true;
		}
		fprintf(stderr, "cgmanager connection was closed\n");
		g_object_unref(cgroup_manager);
		cgroup_manager = NULL;
	}

	connection = g_dbus_connection_new_for_address_sync (CGM_DBUS_ADDRESS,
			G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT,
			NULL, NULL, &error);
	if (!connection) {
		g_warning("Could not connect to cgmanager: %s\n"
			"Use G_DBUS_DEBUG=message for more info.", error->message);
		g_error_free(error);
		error = NULL;
		fprintf(stderr, "Retrying...\n");
		sleep(1);
		goto retry;
	}

	reply = g_dbus_connection_call_sync (connection, NULL, "/org/linuxcontainers/cgmanager",
			"org.freedesktop.DBus.Properties", "Get",
			g_variant_new ("(ss)", "org.linuxcontainers.cgmanager0_0", "api_version"),
			G_VARIANT_TYPE ("(v)"), G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (!reply)
	{
		g_warning("Failed to get cgmanager api version: %s\n"
			"Use G_DBUS_DEBUG=message for more info.", error->message);
		g_error_free(error);
		g_object_unref (connection);
		cgm_unlock();
		return false;
	}
	g_variant_get (reply, "(v)", &version);
	g_variant_unref (reply);
	if (!g_variant_is_of_type (version, G_VARIANT_TYPE_INT32) || g_variant_get_int32 (version) < CGM_REQUIRED_VERSION)
	{
		g_warning("Cgmanager does not meet minimal API version");
		g_object_unref (connection);
		g_variant_unref (version);
		cgm_unlock();
		return false; }
	g_variant_unref (version);
	cgroup_manager = connection;

	cgm_unlock();
	return true;
}

static bool cgcall(const gchar *method_name, GVariant *parameters,
		const GVariantType *reply_type, GVariant **reply)
{
	GVariant *my_reply = NULL;
	GError *error = NULL;

	if (!cgm_dbus_connect()) {
		g_warning("Error: unable to connect to cgmanager");
		return false;
	}

	if (!reply)
		reply = &my_reply;
	/* We do this sync because we need to ensure that the calls finish
	 * before we return to _our_ caller saying that this is done.
	 */
	*reply = g_dbus_connection_call_sync (cgroup_manager, NULL, "/org/linuxcontainers/cgmanager",
			"org.linuxcontainers.cgmanager0_0", method_name,
			parameters, reply_type, G_DBUS_CALL_FLAGS_NONE,
			-1, NULL, &error);
	if (!*reply)
	{
		if (reply_type)
			g_warning ("cgmanager method call org.linuxcontainers.cgmanager0_0.%s failed: %s.  "
					"Use G_DBUS_DEBUG=message for more info.", method_name, error->message);
		g_error_free (error);
		return false;
	}
	if (my_reply)
		g_variant_unref (my_reply);
	return true;
}

// todo - can we avoid some of this alloc/copy/free when copying
// from iters?

#define MAX_CONTROLLERS 20
bool cgm_get_controllers(char ***contrls)
{
	char **list = NULL;
	GVariantIter *iter = NULL;
	GVariant *reply = NULL;
	gchar *ctrl;
	int i = 0;

	if (!cgcall("ListControllers", NULL, G_VARIANT_TYPE("(as)"), &reply))
		return false;

	do {
		list = malloc(MAX_CONTROLLERS * sizeof(*list));
	} while (!list);
	memset(list, 0, MAX_CONTROLLERS * sizeof(*list));
	g_variant_get(reply, "(as)", &iter);
	while (g_variant_iter_next(iter, "s", &ctrl)) {
		if (i >= MAX_CONTROLLERS) {
			g_warning("Too many cgroup subsystems");
			exit(1);
		}
		do {
			list[i] = strdup(ctrl);
		} while (!list[i]);
		i++;
		g_free(ctrl);
	}
	g_variant_iter_free(iter);
	g_variant_unref(reply);

	*contrls = list;
	return true;
}

void free_key(struct cgm_keys *k)
{
	if (!k)
		return;
	free(k->name);
	free(k);
}

void free_keys(struct cgm_keys **keys)
{
	int i;

	if (!keys)
		return;
	for (i = 0; keys[i]; i++) {
		free_key(keys[i]);
	}
	free(keys);
}

#define BATCH_SIZE 50
void append_key(struct cgm_keys ***keys, struct cgm_keys *newk, size_t *sz, size_t *asz)
{
	assert(keys);
	if (sz == 0) {
		*asz = BATCH_SIZE;
		*sz = 1;
		do {
			*keys = malloc(*asz * sizeof(struct cgm_keys *));
		} while (!*keys);
		(*keys)[0] = newk;
		(*keys)[1] = NULL;
		return;
	}
	if (*sz + 2 >= *asz) {
		struct cgm_keys **tmp;
		*asz += BATCH_SIZE;
		do {
			tmp = realloc(*keys, *asz * sizeof(struct cgm_keys *));
		} while (!tmp);
		*keys = tmp;
	}
	(*keys)[(*sz)++] = newk;
	(*keys)[(*sz)] = NULL;
}

bool cgm_list_keys(const char *controller, const char *cgroup, struct cgm_keys ***keys)
{
	GVariantIter *iter = NULL;
	GVariant *reply = NULL;
	size_t sz = 0, asz = 0;
	gchar *name;
	guint32 uid, gid, mode;

	if (!cgcall("ListKeys", g_variant_new("(ss)", controller, cgroup),
			G_VARIANT_TYPE("(a(suuu))"), &reply))
		return false;

	g_variant_get(reply, "(a(suuu))", &iter);
	while (g_variant_iter_next(iter, "(suuu)", &name, &uid, &gid, &mode)) {
		/* name, owner, groupid, mode) */
		struct cgm_keys *k;

		do {
			k = malloc(sizeof(*k));
		} while (!k);
		do {
			k->name = strdup(name);
		} while (!k->name);
		k->uid = uid;
		k->gid = gid;
		k->mode = mode;
		g_free(name);
		append_key(keys, k, &sz, &asz);
	}

	g_variant_iter_free(iter);
	g_variant_unref(reply);

	return true;
}

bool cgm_list_children(const char *controller, const char *cgroup, char ***list)
{
	GVariantIter *iter = NULL;
	GVariant *reply = NULL;
	gchar *child;
	size_t sz = 0, asz = 0;

	if (!cgcall("ListChildren", g_variant_new("(ss)", controller, cgroup),
			G_VARIANT_TYPE("(as)"), &reply))
		return false;

	g_variant_get(reply, "(as)", &iter);
	do {
		*list = malloc(BATCH_SIZE * sizeof(char *));
	} while (!*list);
	(*list)[0] = NULL;
	while (g_variant_iter_next(iter, "s", &child)) {
		if (sz+2 >= asz) {
			char **tmp;
			asz += BATCH_SIZE;
			do {
				tmp = realloc(*list, asz * sizeof(char *));
			} while  (!tmp);
			*list = tmp;
		}
		do {
			(*list)[sz] = strdup(child);
		} while (!(*list)[sz]);
		(*list)[sz+1] = NULL;
		sz++;
		g_free(child);
	}

	g_variant_iter_free(iter);
	g_variant_unref(reply);

	return true;
}

bool cgm_escape_cgroup(void)
{
	return cgcall("MovePidAbs", g_variant_new("(ssi)", "all", "/", getpid()),
			G_VARIANT_TYPE_UNIT, NULL);
}

bool cgm_move_pid(const char *controller, const char *cgroup, pid_t pid)
{
	return cgcall("MovePid", g_variant_new("(ssi)", controller, cgroup, pid),
			G_VARIANT_TYPE_UNIT, NULL);
}

bool cgm_get_value(const char *controller, const char *cgroup, const char *file,
		char **value)
{
	GVariant *reply = NULL;
	gchar *str;

	if (!cgcall("GetValue", g_variant_new("(sss)", controller, cgroup, file),
			G_VARIANT_TYPE("(s)"), &reply))
		return false;

	g_variant_get(reply, "(s)", &str);
	g_variant_unref(reply);

	do {
		*value = strdup(str);
	} while (!*value);
	g_free(str);

	return true;
}

bool cgm_set_value(const char *controller, const char *cgroup, const char *file,
		const char *value)
{
	return cgcall("SetValue", g_variant_new("(ssss)", controller, cgroup, file, value),
			G_VARIANT_TYPE_UNIT, NULL);
}

bool cgm_create(const char *controller, const char *cg)
{
	if (!cgcall("Create", g_variant_new("(ss)", controller, cg),
				G_VARIANT_TYPE ("(i)"), NULL))
		return false;

	return true;
}

bool cgm_chown_file(const char *controller, const char *cg, uid_t uid, gid_t gid)
{
	return cgcall("Chown", g_variant_new("(ssii)", controller, cg, uid, gid),
			G_VARIANT_TYPE_UNIT, NULL);
}

bool cgm_chmod_file(const char *controller, const char *file, mode_t mode)
{
	return cgcall("Chmod", g_variant_new("(sssi)", controller, file, "", mode), G_VARIANT_TYPE_UNIT, NULL);
}

bool cgm_remove(const char *controller, const char *cg)
{
	return cgcall("Remove", g_variant_new ("(ssi)", "all", cg, 1), G_VARIANT_TYPE ("(i)"), NULL);
}
