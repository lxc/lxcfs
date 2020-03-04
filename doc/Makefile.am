EXTRA_DIST = lxcfs.man.add \
	     lxcfs.1

if HAVE_HELP2MAN
man_MANS = lxcfs.1

lxcfs.1: ../src/lxcfs lxcfs.man.add
	$(HELP2MAN) -n "System virtualization filesystem for containers" --no-discard-stderr -s 1 -I lxcfs.man.add -N ../src/lxcfs > lxcfs.1
endif
