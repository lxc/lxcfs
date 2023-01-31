# SPDX-License-Identifier: LGPL-2.1-or-later

if 'systemd' in init_script
    systemd = dependency('systemd')
    systemd_system_unit_dir = systemd.get_pkgconfig_variable('systemdsystemunitdir')
    systemd_service = custom_target(
        'lxcfs.service',
        input: 'systemd/lxcfs.service.in',
        output: 'lxcfs.service',
        command: [
            meson_render_jinja2,
            config_h,
            '@INPUT@',
            '@OUTPUT@',
        ],
        install: true,
        install_dir: systemd_system_unit_dir)
endif

if 'upstart' in init_script
        install_data('upstart/lxcfs.conf', install_dir: join_paths(sysconfdir, 'init'))
endif

if 'openrc' in init_script
        install_data('sysvinit/lxcfs', install_dir: join_paths(sysconfdir, 'rc.d/init.d'))
endif

if 'sysvinit' in init_script
        install_data('sysvinit/lxcfs', install_dir: join_paths(sysconfdir, 'init.d'))
endif
