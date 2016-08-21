/* pam-cgfs
 *
 * Copyright © 2016 Canonical, Inc
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
 *
 * When a user logs in, this pam module will create cgroups which the user
 * may administer, either for all controllers or for any controllers listed
 * on the command line (if any are listed).
 *
 * The cgroup created will be "user/$user/0" for the first session,
 * "user/$user/1" for the second, etc.
 *
 * name=systemd is handled specially.  If the host is an upstart system
 * or the login is noninteractive, then the logged in user does not get
 * a cgroup created.  On a systemd interactive login, one is created but
 * not chowned to the user.  In the former case, we create one as usual,
 * in the latter case we simply chown whatever cgroup the user is in.
 *
 * All requested cgroups must be mounted under /sys/fs/cgroup/$controller,
 * no messing around with finding mountpoints.
 *
 * See COPYING file for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <pwd.h>
#include <stdbool.h>
#include <dirent.h>

#define PAM_SM_SESSION
#include <security/_pam_macros.h>
#include <security/pam_modules.h>

#include <linux/unistd.h>

static bool initialized;

static void mysyslog(int err, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	openlog("PAM-CGFS", LOG_CONS|LOG_PID, LOG_AUTH);
	vsyslog(err, format, args);
	va_end(args);
	closelog();
}

static char *must_strcat(const char *first, ...) __attribute__((sentinel));

static char *must_strcat(const char *first, ...)
{
	va_list args;
	char *dest, *cur, *new;
	size_t len;

	do {
		dest = strdup(first);
	} while (!dest);
	len = strlen(dest);

	va_start(args, first);

	while ((cur = va_arg(args, char *)) != NULL) {
		size_t newlen = len + strlen(cur);
		do {
			new = realloc(dest, newlen + 1);
		} while (!new);
		dest = new;
		strcat(dest, cur);
		len = newlen;
	}
	va_end(args);

	return dest;
}

static bool exists(const char *path)
{
	struct stat sb;
	int ret;

	ret = stat(path, &sb);
	return ret == 0;
}

static bool is_dir(const char *path)
{
	struct stat sb;

	if (stat(path, &sb) < 0)
		return false;
	if (S_ISDIR(sb.st_mode))
		return true;
	return false;
}

static bool mkdir_p(const char *root, char *path)
{
	char *b, orig, *e;

	if (strlen(path) < strlen(root))
		return false;
	if (strlen(path) == strlen(root))
		return true;

	b = path + strlen(root) + 1;
	while (1) {
		while (*b && *b == '/')
			b++;
		if (!*b)
			return true;
		e = b + 1;
		while (*e && *e != '/')
			e++;
		orig = *e;
		if (orig)
			*e = '\0';
		if (exists(path))
			goto next;
		if (mkdir(path, 0755) < 0) {
#if DEBUG
			fprintf(stderr, "Failed to create %s: %m\n", path);
#endif
			return false;
		}
next:
		if (!orig)
			return true;
		*e = orig;
		b = e + 1;
	}

}

struct controller {
	struct controller *next;
	int id;
	bool systemd_created;
	char *name;
	char *mount_path;
	char *init_path;
	char *cur_path;
};

#define MAXCONTROLLERS 20
static struct controller *controllers[MAXCONTROLLERS];

/*
 * if cpu and cpuacct are comounted, it's possible a mount
 * exists for only one.  Find it.
 */
static char *find_controller_path(struct controller *c)
{
	while (c) {
		char *path = must_strcat("/sys/fs/cgroup/", c->name, NULL);
		if (exists(path))
			return path;
		free(path);
		if (strncmp(c->name, "name=", 5) == 0) {
			path = must_strcat("/sys/fs/cgroup/", c->name + 5, NULL);
			if (exists(path))
				return path;
			free(path);
		}
		c = c->next;
	}
	return NULL;
}

/* Find the path at which each controller is mounted. */
static void get_mounted_paths(void)
{
	int i;
	struct controller *c;
	char *path;

	for (i = 0; i < MAXCONTROLLERS; i++) {
		c = controllers[i];
		if (!c || c->mount_path)
			continue;
		path = find_controller_path(c);
		if (!path)
			continue;
		while (c) {
			c->mount_path = path;
			c = c->next;
		}
	}
}

static void add_controller(int id, char *tok, char *cur_path)
{
	struct controller *c;

	do {
		c = malloc(sizeof(struct controller));
	} while (!c);
	do {
		c->name = strdup(tok);
	} while (!c->name);
	do {
		c->cur_path = strdup(cur_path);
	} while (!c->cur_path);
	c->id = id;
	c->next = controllers[id];
	c->mount_path = NULL;
	c->init_path = NULL;
	controllers[id] = c;
}

static void drop_controller(int which)
{
	struct controller *c = controllers[which];

	if (c) {
		free(c->init_path); // all comounts share this
		free(c->mount_path);
	}
	while (c) {
		struct controller *tmp = c->next;
		free(c->name);
		free(c->cur_path);
		free(c);
		c = tmp;
	}
	controllers[which] = NULL;
}

static bool single_in_filter(char *c, const char *filter)
{
	char *dup = strdupa(filter), *tok;
	for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
		if (strcmp(c, tok) == 0)
			return true;
	}
	return false;
}

static bool controller_in_filter(struct controller *controller, const char *filter)
{
	struct controller *c;

	for (c = controller; c; c = c->next) {
		if (single_in_filter(c->name, filter))
			return true;
	}
	return false;
}

/*
 * Passed a comma-delimited list of requested controllers.
 * Pulls any controllers not in the list out of the
 * list of controllers
 */
static void filter_controllers(const char *filter)
{
	int i;
	for (i = 0; i < MAXCONTROLLERS; i++) {
		if (!controllers[i])
			continue;
		if (filter && !controller_in_filter(controllers[i], filter))
			drop_controller(i);
	}
}

#define INIT_SCOPE "/init.scope"
static void prune_init_scope(char *cg)
{
	char *point;
	size_t cg_len, initscope_len;

	if (!cg)
		return;

	cg_len = strlen(cg);
	initscope_len = strlen(INIT_SCOPE);
	if (cg_len < initscope_len)
		return;

	point = cg + cg_len - initscope_len;
	if (strcmp(point, INIT_SCOPE) == 0) {
		if (point == cg)
			*(point+1) = '\0';
		else
			*point = '\0';
	}
}

static bool fill_in_init_paths(void)
{
	FILE *f;
	char *line = NULL;
	size_t len = 0;
	struct controller *c;
	bool ret = false;

	f = fopen("/proc/1/cgroup", "r");
	if (!f)
		return false;
	while (getline(&line, &len, f) != -1) {
		int id;
		char *subsystems, *ip;
		if (sscanf(line, "%d:%m[^:]:%ms", &id, &subsystems, &ip) != 3) {
			mysyslog(LOG_ERR, "Corrupt /proc/1/cgroup\n");
			goto out;
		}
		free(subsystems);
		if (id < 0 || id > 20) {
			mysyslog(LOG_ERR, "Too many subsystems\n");
			free(ip);
			goto out;
		}
		if (ip[0] != '/') {
			free(ip);
			mysyslog(LOG_ERR, "ERROR: init cgroup path is not absolute!\n");
			goto out;
		}
		prune_init_scope(ip);
		for (c = controllers[id]; c; c = c->next) {
			if (strcmp(c->name, "name=systemd") == 0)
				c->systemd_created = strcmp(ip, c->cur_path) != 0;
			c->init_path = ip;
		}
	}
	ret = true;
out:
	fclose(f);
	free(line);
	return ret;
}

#if DEBUG
static void print_found_controllers(void) {
	struct controller *c;
	int i;

	for (i = 0; i < MAXCONTROLLERS; i++) {
		c = controllers[i];
		if (!c) {
			fprintf(stderr, "Nothing in controller %d\n", i);
			continue;
		}
		fprintf(stderr, "Controller %d:\n", i);
		while (c) {
			fprintf(stderr, " Next mount: index %d name %s\n", c->id, c->name);
			fprintf(stderr, "             mount path %s\n", c->mount_path ? c->mount_path : "(none)");
			fprintf(stderr, "             init task path %s\n", c->init_path);
			fprintf(stderr, "             login task path %s\n", c->cur_path);
			c = c->next;
		}
	}
}
#else
static inline void print_found_controllers(void) { };
#endif
/*
 * Get the list of cgroup controllers currently mounted.
 * This includes both kernel and named subsystems, so get the list from
 * /proc/self/cgroup rather than /proc/cgroups.
 */
static bool get_active_controllers(void)
{
	FILE *f;
	char *line = NULL, *tok, *cur_path;
	size_t len = 0;

	f = fopen("/proc/self/cgroup", "r");
	if (!f)
		return false;
	while (getline(&line, &len, f) != -1) {
		int id;
		char *subsystems;
		if (sscanf(line, "%d:%m[^:]:%ms", &id, &subsystems, &cur_path) != 3) {
			mysyslog(LOG_ERR, "Corrupt /proc/self/cgroup\n");
			fclose(f);
			free(line);
			return false;
		}
		if (id < 0 || id > 20) {
			mysyslog(LOG_ERR, "Too many subsystems\n");
			free(subsystems);
			free(cur_path);
			fclose(f);
			free(line);
			return false;
		}
		for (tok = strtok(subsystems, ","); tok; tok = strtok(NULL, ","))
			add_controller(id, tok, cur_path);
		free(subsystems);
		free(cur_path);
	}
	fclose(f);
	free(line);

	get_mounted_paths();

	if (!fill_in_init_paths()) {
		mysyslog(LOG_ERR, "Failed finding cgroups for init task\n");
		return false;
	}

	print_found_controllers();

	initialized = true;

	return true;
}

/*
 * In Ubuntu 14.04, the paths created for us were
 * '/user/$uid.user/$something.session'
 * This can be merged better with systemd_created_slice_for_us(), but keeping
 * it separate makes it easier to reason about the correctness.
 */
static bool systemd_v1_created_slice(struct controller *c, const char *in, uid_t uid)
{
	char *p, *copy = strdupa(in);
	size_t len;
	int id;

	if (strlen(copy) < strlen("/user/1.user/1.session"))
		return false;
	p = copy + strlen(copy) - 1;

	/* skip any trailing '/' (shouldn't be any, but be sure) */
	while (p >= copy && *p == '/')
		*(p--) = '\0';
	if (p < copy)
		return false;

	/* Get last path element */
	while (p >= copy && *p != '/')
		p--;
	if (p < copy)
		return false;
	/* make sure it is something.session */
	len = strlen(p+1);
	if (len < strlen("1.session") ||
			strncmp(p+1 + len - 8, ".session", 8) != 0)
		return false;

	/* ok last path piece checks out, now check the second to last */
	*(p+1) = '\0';
	while (p >= copy && *(--p) != '/');
	if (sscanf(p+1, "%d.user/", &id) != 1)
		return false;

	if (id != (int)uid)
		return false;

	return true;
}

/*
 * So long as our path relative to init starts with /user.slice/user-$uid.slice,
 * assumem it belongs to $uid and chown it
 */
static bool under_systemd_user_slice(struct controller *c, uid_t uid)
{
	char buf[100];
	size_t curlen, initlen;

	curlen = strlen(c->cur_path);
	initlen = strlen(c->init_path);
	if (curlen <= initlen)
		return false;
	if (strncmp(c->cur_path, c->init_path, initlen) != 0)
		return false;
	snprintf(buf, 100, "/user.slice/user-%d.slice/", (int)uid);
	if (initlen == 1)
		initlen = 0; // skip the '/'
	return strncmp(c->cur_path + initlen, buf, strlen(buf)) == 0;
}

/*
 * the systemd-created path is: user-$uid.slice/session-c$session.scope
 * If that is not the end of our systemd path, then we're not part of
 * the PAM call that created that path.
 *
 * The last piece is chowned to $uid, the user- part not.
 * Note - if the user creates paths that look like what we're looking for
 * to 'fool' us, either
 *   . they fool us, we create new cgroups, and they get auto-logged-out.
 *   . they fool a root sudo, systemd cgroup is not changed but chowned,
 *     and they lose ownership of their cgroups
 */
static bool systemd_created_slice_for_us(struct controller *c, const char *in, uid_t uid)
{
	char *p, *copy = strdupa(in);
	size_t len;
	int id;

	if (systemd_v1_created_slice(c, in, uid))
		return true;

	if (under_systemd_user_slice(c, uid))
		return true;

	if (strlen(copy) < strlen("/user-0.slice/session-0.scope"))
		return false;
	p = copy + strlen(copy) - 1;
	/* skip any trailing '/' (shouldn't be any, but be sure) */
	while (p >= copy && *p == '/')
		*(p--) = '\0';
	if (p < copy)
		return false;

	/* Get last path element */
	while (p >= copy && *p != '/')
		p--;
	if (p < copy)
		return false;
	/* make sure it is session-something.scope */
	len = strlen(p+1);
	if (strncmp(p+1, "session-", strlen("session-")) != 0 ||
			strncmp(p+1 + len - 6, ".scope", 6) != 0)
		return false;

	/* ok last path piece checks out, now check the second to last */
	*(p+1) = '\0';
	while (p >= copy && *(--p) != '/');
	if (sscanf(p+1, "user-%d.slice/", &id) != 1)
		return false;

	if (id != (int)uid)
		return false;

	return true;
}
/*
 * Handle systemd creation.  Return true if all's done.  Returns false if
 * the caller needs to create=chown a cgroup
 */
static bool handle_systemd_create(struct controller *c, uid_t uid, gid_t gid)
{
	char *user_path;

	if (!c->systemd_created)
		return false;

	user_path = must_strcat(c->mount_path, c->cur_path, NULL);

	// Is this actually our cgroup, or was it created for someone
	// else?
	if (!systemd_created_slice_for_us(c, user_path, uid)) {
		c->systemd_created = false;
		free(user_path);
		return false;
	}

	// a name=systemd cgroup has already been created, just chown it
	if (chown(user_path, uid, gid) < 0)
		mysyslog(LOG_WARNING, "Failed to chown %s to %d:%d: %m\n",
				user_path, (int)uid, (int)gid);
	free(user_path);
	return true;
}

static bool cgfs_create_forone(struct controller *c, uid_t uid, gid_t gid, const char *cg, bool *existed)
{
	while (c) {
		if (!c->mount_path || !c->init_path)
			goto next;

		if (strcmp(c->name, "name=systemd") == 0 && handle_systemd_create(c, uid, gid))
			return true;

		char *path = must_strcat(c->mount_path, c->init_path, cg, NULL);
#if DEBUG
		fprintf(stderr, "Creating %s for %s\n", path, c->name);
#endif
		if (exists(path)) {
			free(path);
			*existed = true;
#if DEBUG
			fprintf(stderr, "%s existed\n", path);
#endif
			return false;
		}

		bool pass = mkdir_p(c->mount_path, path);
#if DEBUG
		fprintf(stderr, "Creating %s %s\n", path, pass ? "succeeded" : "failed");
#endif
		if (pass) {
			if (chown(path, uid, gid) < 0)
				mysyslog(LOG_WARNING, "Failed to chown %s to %d:%d: %m\n",
					path, (int)uid, (int)gid);
		}
		free(path);
		if (pass)
			return true;
next:
		c = c->next;
	}
	return false;
}

static void recursive_rmdir(const char *path)
{
	struct dirent *direntp;
	DIR *dir;

	dir = opendir(path);
	if (!dir)
		return;
	while ((direntp = readdir(dir))!= NULL) {
		if (!strcmp(direntp->d_name, ".") ||
				!strcmp(direntp->d_name, ".."))
			continue;

		char *dpath = must_strcat(path, "/", direntp->d_name, NULL);
		if (is_dir(dpath)) {
			recursive_rmdir(dpath);
#if DEBUG
			fprintf(stderr, "attempting to remove %s\n", dpath);
#endif
			if (rmdir(dpath) < 0) {
#if DEBUG
				fprintf(stderr, "Failed removing %s: %m\n", dpath);
#endif
			}
		}
		free(dpath);
	}

	closedir(dir);
}

/*
 * Try to remove a cgroup in a controller to cleanup during failure.
 * All mounts of comounted controllers are the same, so we just look
 * for the first mount which exists, try to remove the directory, and
 * return.
 */
static void cgfs_remove_forone(int idx, const char *cg)
{
	struct controller *c = controllers[idx];
	char *path;

	while (c) {
		if (c->mount_path) {
			path = must_strcat(c->mount_path, cg, NULL);
			recursive_rmdir(path);
			free(path);
		}
		c = c->next;
	}
}

static bool cgfs_create(const char *cg, uid_t uid, gid_t gid, bool *existed)
{
	*existed = false;
	int i, j;

#if DEBUG
	fprintf(stderr, "creating %s\n", cg);
#endif
	for (i = 0; i < MAXCONTROLLERS; i++) {
		struct controller *c = controllers[i];

		if (!c)
			continue;

		if (!cgfs_create_forone(c, uid, gid, cg, existed)) {
			for (j = 0; j < i; j++)
				cgfs_remove_forone(j, cg);
			return false;
		}
	}

	return true;
}

static bool write_int(char *path, int v)
{
	FILE *f = fopen(path, "w");
	bool ret = true;

	if (!f)
		return false;
	if (fprintf(f, "%d\n", v) < 0)
		ret = false;
	if (fclose(f) != 0)
		ret = false;
	return ret;
}

static bool do_enter(struct controller *c, const char *cg)
{
	char *path;
	bool pass;

	while (c) {
		if (!c->mount_path || !c->init_path)
			goto next;
		path = must_strcat(c->mount_path, c->init_path, cg, "/cgroup.procs", NULL);
		if (!exists(path)) {
			free(path);
			path = must_strcat(c->mount_path, c->init_path, cg, "/tasks", NULL);
		}
#if DEBUG
		fprintf(stderr, "Attempting to enter %s:%s using %s\n", c->name, cg, path);
#endif
		pass = write_int(path, (int)getpid());
		free(path);
		if (pass) /* only have to enter one of the comounts */
			return true;
#if DEBUG
		if (!pass)
			fprintf(stderr, "Failed to enter %s:%s\n", c->name, cg);
#endif
next:
		c = c->next;
	}

	return false;
}

static bool cgfs_enter(const char *cg, bool skip_systemd)
{
	int i;

	for (i = 0; i < MAXCONTROLLERS; i++) {
		struct controller *c = controllers[i];

		if (!c)
			continue;

		if (strcmp(c->name, "name=systemd") == 0) {
			if (skip_systemd)
				continue;
			if (c->systemd_created)
				continue;
		}

		if (!do_enter(c, cg))
			return false;
	}

	return true;
}

static void cgfs_escape(void)
{
	if (!cgfs_enter("/", true)) {
		mysyslog(LOG_WARNING, "Failed to escape to init's cgroup\n");
	}
}

static bool get_uid_gid(const char *user, uid_t *uid, gid_t *gid)
{
	struct passwd *pwent;

	pwent = getpwnam(user);
	if (!pwent)
		return false;
	*uid = pwent->pw_uid;
	*gid = pwent->pw_gid;

	return true;
}

#define DIRNAMSZ 200
static int handle_login(const char *user)
{
	int idx = 0, ret;
	bool existed;
	uid_t uid = 0;
	gid_t gid = 0;
	char cg[MAXPATHLEN];

	if (!get_uid_gid(user, &uid, &gid)) {
		mysyslog(LOG_ERR, "Failed to get uid and gid for %s\n", user);
		return PAM_SESSION_ERR;
	}

	cgfs_escape();

	while (idx >= 0) {
		ret = snprintf(cg, MAXPATHLEN, "/user/%s/%d", user, idx);
		if (ret < 0 || ret >= MAXPATHLEN) {
			mysyslog(LOG_ERR, "username too long\n");
			return PAM_SESSION_ERR;
		}

		existed = false;
		if (!cgfs_create(cg, uid, gid, &existed)) {
			if (existed) {
				idx++;
				continue;
			}
			mysyslog(LOG_ERR, "Failed to create a cgroup for user %s\n", user);
			return PAM_SESSION_ERR;
		}

		if (!cgfs_enter(cg, false)) {
			mysyslog(LOG_ERR, "Failed to enter user cgroup %s for user %s\n", cg, user);
			return PAM_SESSION_ERR;
		}
		break;
	}

	return PAM_SUCCESS;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
		const char **argv)
{
	const char *PAM_user = NULL;
	int ret;

	if (!get_active_controllers()) {
		mysyslog(LOG_ERR, "Failed to get list of controllers\n");
		return PAM_SESSION_ERR;
	}

	if (argc > 1 && strcmp(argv[0], "-c") == 0)
		filter_controllers(argv[1]);

	ret = pam_get_user(pamh, &PAM_user, NULL);
	if (ret != PAM_SUCCESS) {
		mysyslog(LOG_ERR, "PAM-CGFS: couldn't get user\n");
		return PAM_SESSION_ERR;
	}

	ret = handle_login(PAM_user);
	return ret;
}

static void prune_empty_cgroups(struct controller *c, const char *user)
{
	while (c) {
		if (!c->mount_path || !c->init_path)
			goto next;
		char *path = must_strcat(c->mount_path, c->init_path, "user/", user, NULL);
#if DEBUG
	fprintf(stderr, "Pruning %s\n", path);
#endif
		recursive_rmdir(path);
		free(path);
next:
		c = c->next;
	}
}

/*
 * Since we can't rely on kernel's autoremove, remove stale cgroups
 * any time the user logs out.
 */
static void prune_user_cgs(const char *user)
{
	int i;

	for (i = 0; i < MAXCONTROLLERS; i++)
		prune_empty_cgroups(controllers[i], user);
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
		const char **argv)
{
	const char *PAM_user = NULL;
	int ret = pam_get_user(pamh, &PAM_user, NULL);

	if (ret != PAM_SUCCESS) {
		mysyslog(LOG_ERR, "PAM-CGFS: couldn't get user\n");
		return PAM_SESSION_ERR;
	}

	if (!initialized) {
		get_active_controllers();
		if (argc > 1 && strcmp(argv[0], "-c") == 0)
			filter_controllers(argv[1]);
	}

	prune_user_cgs(PAM_user);
	return PAM_SUCCESS;
}
