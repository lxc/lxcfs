EXTRA_DIST = lxcfs.service

if INIT_SCRIPT_SYSTEMD
SYSTEMD_UNIT_DIR = /lib/systemd/system

install-systemd: lxcfs.service
	$(MKDIR_P) $(DESTDIR)$(SYSTEMD_UNIT_DIR)
	$(INSTALL_DATA) lxcfs.service $(DESTDIR)$(SYSTEMD_UNIT_DIR)/

uninstall-systemd:
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/lxcfs.service
	rmdir $(DESTDIR)$(SYSTEMD_UNIT_DIR) || :

install-data-local: install-systemd
uninstall-local: uninstall-systemd
endif
