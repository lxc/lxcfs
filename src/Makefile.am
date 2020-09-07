AM_CFLAGS = -Wall -ggdb -D_GNU_SOURCE -DSBINDIR=\"$(SBINDIR)\" -pthread
AM_CFLAGS += $(FUSE_CFLAGS)
AM_CFLAGS += -DLIBDIR=\"$(LIBDIR)\"
AM_LDFLAGS = $(FUSE_LIBS) -pthread
#AM_CFLAGS += -DDEBUG
#AM_CFLAGS += -DVERBOSE

AM_CFLAGS += -DRUNTIME_PATH=\"$(RUNTIME_PATH)\"

liblxcfs_la_SOURCES = api_extensions.h \
		      bindings.c bindings.h \
		      cgroup_fuse.c cgroup_fuse.h \
		      cgroups/cgfsng.c \
		      cgroups/cgroup.c cgroups/cgroup.h \
		      cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
		      cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
		      cpuset_parse.c cpuset_parse.h \
		      lxcfs_fuse_compat.h \
		      macro.h \
		      memory_utils.h \
		      proc_cpuview.c proc_cpuview.h \
		      proc_fuse.c proc_fuse.h \
		      proc_loadavg.c proc_loadavg.h \
		      syscall_numbers.h \
		      sysfs_fuse.c sysfs_fuse.h \
		      utils.c utils.h
liblxcfs_la_CFLAGS = $(AM_CFLAGS)

if ENABLE_ASAN
liblxcfs_la_CFLAGS += -fsanitize=address \
		      -fno-omit-frame-pointer
endif

if ENABLE_UBSAN
liblxcfs_la_CFLAGS += -fsanitize=undefined
endif

liblxcfs_la_LDFLAGS = $(AM_CFLAGS) -module -avoid-version -shared

liblxcfstest_la_SOURCES = api_extensions.h \
			  bindings.c bindings.h \
			  cgroup_fuse.c cgroup_fuse.h \
			  cgroups/cgfsng.c \
			  cgroups/cgroup.c cgroups/cgroup.h \
			  cgroups/cgroup2_devices.c cgroups/cgroup2_devices.h \
			  cgroups/cgroup_utils.c cgroups/cgroup_utils.h \
			  cpuset_parse.c cpuset_parse.h \
			  lxcfs_fuse_compat.h \
			  macro.h \
			  memory_utils.h \
			  proc_cpuview.c proc_cpuview.h \
			  proc_fuse.c proc_fuse.h \
			  proc_loadavg.c proc_loadavg.h \
			  syscall_numbers.h \
			  sysfs_fuse.c sysfs_fuse.h \
			  utils.c utils.h
liblxcfstest_la_CFLAGS = $(AM_CFLAGS) -DRELOADTEST

if ENABLE_ASAN
liblxcfstest_la_CFLAGS += -fsanitize=address \
			  -fno-omit-frame-pointer
endif

if ENABLE_UBSAN
liblxcfstest_la_CFLAGS += -fsanitize=undefined
endif

liblxcfstest_la_LDFLAGS = $(AM_CFLAGS) -module -avoid-version -shared

noinst_HEADERS = api_extensions.h \
		 bindings.h \
		 cgroup_fuse.h \
		 cgroups/cgroup.h \
		 cgroups/cgroup2_devices.h \
		 cgroups/cgroup_utils.h \
		 cpuset_parse.h \
		 lxcfs_fuse_compat.h \
		 macro.h \
		 memory_utils.h \
		 proc_cpuview.h \
		 proc_fuse.h \
		 proc_loadavg.h \
		 syscall_numbers.h \
		 sysfs_fuse.h \
		 utils.h

sodir=$(libdir)
lxcfs_LTLIBRARIES = liblxcfs.la
EXTRA_LTLIBRARIES = liblxcfstest.la

lxcfs_SOURCES = lxcfs.c
lxcfs_LDADD = -ldl
lxcfs_CFLAGS = $(AM_CFLAGS)
lxcfs_LDFLAGS = $(AM_LDFLAGS)
bin_PROGRAMS = lxcfs

TEST_READ: tests/test-read.c
	$(CC) -o tests/test-read \
		tests/test-read.c
TEST_CPUSET: tests/cpusetrange.c cpuset_parse.c
	$(CC) -o tests/cpusetrange \
		tests/cpusetrange.c \
		cpuset_parse.c
TEST_SYSCALLS: tests/test_syscalls.c
	$(CC) -o tests/test_syscalls \
		tests/test_syscalls.c
tests: TEST_READ TEST_CPUSET TEST_SYSCALLS
