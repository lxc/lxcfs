# SPDX-License-Identifier: LGPL-2.1-or-later

lxcfs_conf_data = configuration_data()
lxcfs_conf_data.set('LXCFSSHAREDIR', lxcfssharedir)
lxcfs_conf_data = configure_file(
			configuration : lxcfs_conf_data,
                        input : '00-lxcfs.conf.in',
                        output : '00-lxcfs.conf',
			install: true,
			install_dir: lxcconfdir)

lxcfs_hook_mount_data = configure_file(
			configuration : conf,
                        input : 'lxc.mount.hook.in',
                        output : 'lxc.mount.hook',
			install: true,
			install_dir: lxcfssharedir)

lxcfs_hook_reboot_data = configure_file(
			configuration : configuration_data(),
                        input : 'lxc.reboot.hook.in',
                        output : 'lxc.reboot.hook',
			install: true,
			install_dir: lxcfssharedir)
