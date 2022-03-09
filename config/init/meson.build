# SPDX-License-Identifier: LGPL-2.1-or-later

if init_script == 'systemd'
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
        install_dir: '/lib/systemd/system')

elif init_script == 'upstart'
        install_data('upstart/lxcfs.conf', install_dir: join_paths(sysconfdir, 'init'))
elif init_script == 'openrc'
        install_data('sysvinit/lxcfs', install_dir: join_paths(sysconfdir, 'rc.d/init.d/lxcfs'))
elif init_script == 'sysvinit'
        install_data('sysvinit/lxcfs', install_dir: join_paths(sysconfdir, 'rc.d/init.d/lxcfs'))
endif
