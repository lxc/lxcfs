#include <stdbool.h>

bool cgfs_setup_controllers(void);
char *find_mounted_controller(const char *controller);
char *must_copy_string(const char *str);

bool cgfs_set_value(const char *controller, const char *cgroup, const char *file,
		const char *value);
int cgfs_create(const char *controller, const char *cg);
bool cgfs_remove(const char *controller, const char *cg);
bool cgfs_chmod_file(const char *controller, const char *file, mode_t mode);
int cgfs_chown_file(const char *controller, const char *cg, uid_t uid, gid_t gid);
FILE *open_pids_file(const char *controller, const char *cgroup);
bool cgfs_list_children(const char *controller, const char *cgroup, char ***list);
bool cgfs_get_value(const char *controller, const char *cgroup, const char *file,
		char **value);
bool cgfs_get_value(const char *controller, const char *cgroup, const char *file,
		char **value);

/*
 * hierarchies, i.e. 'cpu,cpuacct'
 */
char **hierarchies;
int num_hierarchies;

struct cgfs_files {
	char *name;
	uint32_t uid, gid;
	uint32_t mode;
};
void free_key(struct cgfs_files *k);
void free_keys(struct cgfs_files **keys);

struct cgfs_files *cgfs_get_key(const char *controller, const char *cgroup, const char *file);
bool cgfs_list_keys(const char *controller, const char *cgroup, struct cgfs_files ***keys);
bool is_child_cgroup(const char *controller, const char *cgroup, const char *f);
