# SPDX-License-Identifier: LGPL-2.1-or-later

if init_script == 'systemd'
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

elif init_script == 'upstart'
        install_data('upstart/lxcfs.conf', install_dir: join_paths(sysconfdir, 'init'))
elif init_script == 'openrc'
        install_data('sysvinit/lxcfs', install_dir: join_paths(sysconfdir, 'rc.d/init.d'))
elif init_script == 'sysvinit'
        install_data('sysvinit/lxcfs', install_dir: join_paths(sysconfdir, 'init.d'))
endif
