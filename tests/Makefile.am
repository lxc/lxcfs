EXTRA_DIST = \
	cpusetrange.c \
	main.sh \
	test_cgroup \
	test_confinement.sh \
	test_meminfo_hierarchy.sh \
	test_proc \
	test-read.c \
	test_read_proc.sh \
	test_reload.sh \
	test_sigusr2.sh \
	test_syscalls.c

TEST_READ: test-read.c
	$(CC) -o test-read test-read.c
TEST_CPUSET: cpusetrange.c
	$(CC) -I../ -I../src/ -o cpusetrange cpusetrange.c ../src/cpuset_parse.c
TEST_SYSCALLS: test_syscalls.c
	$(CC) -o test_syscalls test_syscalls.c

tests: TEST_READ TEST_CPUSET TEST_SYSCALLS
