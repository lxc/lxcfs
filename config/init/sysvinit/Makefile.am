EXTRA_DIST = lxcfs

if INIT_SCRIPT_SYSV
install-sysvinit: lxcfs
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/rc.d/init.d
	$(INSTALL_SCRIPT) lxcfs $(DESTDIR)$(sysconfdir)/rc.d/init.d/lxcfs

uninstall-sysvinit:
	rm -f $(DESTDIR)$(sysconfdir)/rc.d/init.d/lxcfs
	rmdir $(DESTDIR)$(sysconfdir)/rc.d/init.d || :

install-data-local: install-sysvinit
uninstall-local: uninstall-sysvinit
endif
