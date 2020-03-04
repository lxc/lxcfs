ACLOCAL_AMFLAGS = -I m4

LIBTOOL_DEPS = @LIBTOOL_DEPS@
SUBDIRS = config share src tests doc
DIST_SUBDIRS = config share src tests doc

EXTRA_DIST = lxcfs.spec

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status libtool
