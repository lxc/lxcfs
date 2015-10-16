ACLOCAL_AMFLAGS = -I m4

SUBDIRS = tests share
DIST_SUBDIRS = tests share

VERSION_CURRENT  = 0
VERSION_REVISION = 0
VERSION_AGE      = 0

AM_CFLAGS = -Wall -ggdb -D_GNU_SOURCE -DSBINDIR=\"$(SBINDIR)\" -pthread
AM_CFLAGS += $(DBUS_CFLAGS) $(FUSE_CFLAGS) $(GLIB_CFLAGS) $(GLIBDBUS_CFLAGS) $(GIO_CFLAGS)
AM_LDFLAGS = $(DBUS_LIBS) $(FUSE_LIBS) $(GLIB_LIBS) -pthread $(GLIBDBUS_LIBS) $(GIO_LIBS)

bin_PROGRAMS = lxcfs lxcfs_mkdir

lxcfs_SOURCES = lxcfs.c cgmanager.c cgmanager.h cpuset.c
lxcfs_mkdir_SOURCES = lxcfs_mkdir.c cgmanager.c cgmanager.h cpuset.c

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

tests: TEST_READ TEST_CPUSET

distclean:
	rm -rf .deps/ \
		INSTALL \
		Makefile \
		Makefile.in \
		aclocal.m4 \
		autom4te.cache/ \
		cgmanager.o \
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
		stamp-h1
