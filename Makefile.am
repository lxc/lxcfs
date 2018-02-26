ACLOCAL_AMFLAGS = -I m4

SUBDIRS = tests share config
DIST_SUBDIRS = tests share config

AM_CFLAGS = -Wall -ggdb -D_GNU_SOURCE -DSBINDIR=\"$(SBINDIR)\" -pthread
AM_CFLAGS += $(FUSE_CFLAGS)
AM_CFLAGS += -DLIBDIR=\"$(LIBDIR)\"
AM_LDFLAGS = $(FUSE_LIBS) -pthread
#AM_CFLAGS += -DDEBUG

AM_CFLAGS += -DRUNTIME_PATH=\"$(RUNTIME_PATH)\"

liblxcfs_la_SOURCES = macro.h bindings.c cpuset.c bindings.h
liblxcfs_la_CFLAGS = $(AM_CFLAGS)
liblxcfs_la_LDFLAGS = $(AM_CFLAGS) -module -avoid-version -shared

liblxcfstest_la_SOURCES = bindings.c cpuset.c bindings.h macro.h
liblxcfstest_la_CFLAGS = $(AM_CFLAGS) -DRELOADTEST
liblxcfstest_la_LDFLAGS = $(AM_CFLAGS) -module -avoid-version -shared

noinst_HEADERS = bindings.h macro.h

sodir=$(libdir)
lxcfs_LTLIBRARIES = liblxcfs.la
EXTRA_LTLIBRARIES = liblxcfstest.la

lxcfs_SOURCES = lxcfs.c
lxcfs_LDADD = -ldl
lxcfs_CFLAGS = $(AM_CFLAGS)
lxcfs_LDFLAGS = $(AM_LDFLAGS)
bin_PROGRAMS = lxcfs

EXTRA_DIST = \
	lxcfs.man.add

if HAVE_HELP2MAN
man_MANS = lxcfs.1

lxcfs.1: lxcfs lxcfs.man.add
	$(HELP2MAN) -n "Set up cgroup fs for containers" --no-discard-stderr -s 1 -I lxcfs.man.add -N ./lxcfs > lxcfs.1
endif

TEST_READ: tests/test-read.c
	$(CC) -o tests/test-read tests/test-read.c
TEST_CPUSET: tests/cpusetrange.c cpuset.c
	$(CC) -o tests/cpusetrange tests/cpusetrange.c cpuset.c
TEST_SYSCALLS: tests/test_syscalls.c
	$(CC) -o tests/test_syscalls tests/test_syscalls.c

tests: TEST_READ TEST_CPUSET TEST_SYSCALLS

distclean:
	rm -rf .deps/ \
		INSTALL \
		Makefile \
		Makefile.in \
		aclocal.m4 \
		autom4te.cache/ \
		compile \
		config.guess \
		config.h \
		config.h.in \
		config.log \
		config.status \
		config.sub \
		configure \
		depcomp \
		install-sh \
		libtool \
		ltmain.sh \
		lxcfs \
		lxcfs.1 \
		lxcfs.o \
		m4/ \
		missing \
		stamp-h1 \
		tests/test_syscalls \
		*.lo *.la
