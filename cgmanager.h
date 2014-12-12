struct cgm_keys {
	char *name;
	uint32_t uid, gid;
	uint32_t mode;
};

bool cgm_get_controllers(char ***contrls);
bool cgm_list_keys(const char *controller, const char *cgroup, struct cgm_keys ***keys);
bool cgm_list_children(const char *controller, const char *cgroup, char ***list);
char *cgm_get_pid_cgroup(pid_t pid, const char *controller);

bool cgm_escape_cgroup(void);
