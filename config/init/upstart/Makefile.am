EXTRA_DIST = lxcfs.conf

if INIT_SCRIPT_UPSTART
install-upstart: lxcfs.conf
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/init/
	$(INSTALL_DATA) lxcfs.conf $(DESTDIR)$(sysconfdir)/init/

uninstall-upstart:
	rm -f $(DESTDIR)$(sysconfdir)/init/lxcfs.conf
	rmdir $(DESTDIR)$(sysconfdir)/init || :

install-data-local: install-upstart
uninstall-local: uninstall-upstart
endif
