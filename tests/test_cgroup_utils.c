#include "src/cgroups/cgroup_utils.h"

void test_extract_cgroup2_super_opts(void) {
    const char *opts = "rw,nosuid,nodev,noexec,relatime,memory_localevents,memory_recursiveprot";
    const char *result = extract_cgroup2_super_opts(opts);
    if (result == NULL || strcmp(result, "memory_localevents,memory_recursiveprot") != 0) {
        fprintf(stderr, "Test failed: expected 'memory_localevents,memory_recursiveprot', got '%s'\n", result ? result : "NULL");
        exit(1);
    }
}

void test_extract_cgroup2_super_opts_not_match(void) {
    const char *opts = "rw,nosuid,nodev,noexec,relatime";
    const char *result = extract_cgroup2_super_opts(opts);
    if (result != NULL) {
        fprintf(stderr, "Test failed: expected NULL, got '%s'\n", result);
        exit(1);
    }
}

int main(int argc, char *argv[]) {
    test_extract_cgroup2_super_opts();
    test_extract_cgroup2_super_opts_not_match();
	printf("All tests passed\n");
    return 0;
}