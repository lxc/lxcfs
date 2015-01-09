ACLOCAL_AMFLAGS = -I m4

SUBDIRS = tests
DIST_SUBDIRS = tests

VERSION_CURRENT  = 0
VERSION_REVISION = 0
VERSION_AGE      = 0

AM_CFLAGS = -Wall -ggdb -D_GNU_SOURCE -DSBINDIR=\"$(SBINDIR)\"
AM_CFLAGS += $(DBUS_CFLAGS) $(NIH_CFLAGS) $(NIH_DBUS_CFLAGS) $(CGMANAGER_CFLAGS) $(FUSE_CFLAGS)
AM_LDFLAGS = $(DBUS_LIBS) $(NIH_LIBS) $(NIH_DBUS_LIBS) $(CGMANAGER_LIBS) $(FUSE_LIBS)

bin_PROGRAMS = lxcfs

lxcfs_SOURCES = lxcfs.c cgmanager.c cgmanager.h

EXTRA_DIST = \
	lxcfs.man.add

if HAVE_HELP2MAN
man_MANS = lxcfs.1

lxcfs.1: lxcfs lxcfs.man.add
	$(HELP2MAN) -n "Set up cgroup fs for containers" --no-discard-stderr -s 1 -I lxcfs.man.add -N ./lxcfs > lxcfs.1
endif

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
