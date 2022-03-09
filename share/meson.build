# SPDX-License-Identifier: LGPL-2.1-or-later

lxcfs_conf_data = custom_target(
    '00-lxcfs.conf',
    input: '00-lxcfs.conf.in',
    output: '00-lxcfs.conf',
    command: [
        meson_render_jinja2,
        config_h,
        '@INPUT@',
        '@OUTPUT@',
    ],
    install: true,
    install_dir: lxcconfdir)

lxcfs_hook_mount_data = custom_target(
    'lxc.mount.hook',
    input: 'lxc.mount.hook.in',
    output: 'lxc.mount.hook',
    command: [
        meson_render_jinja2,
        config_h,
        '@INPUT@',
        '@OUTPUT@',
    ],
    install: true,
    install_dir: lxcfssharedir)

lxcfs_hook_reboot_data = custom_target(
    'lxc.reboot.hook',
    input: 'lxc.reboot.hook.in',
    output: 'lxc.reboot.hook',
    command: [
        meson_render_jinja2,
        config_h,
        '@INPUT@',
        '@OUTPUT@',
    ],
    install: true,
    install_dir: lxcfssharedir)
