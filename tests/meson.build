# SPDX-License-Identifier: LGPL-2.1-or-later

test_programs += custom_target(
   'main.sh',
    build_by_default: want_tests != false,
    input: 'main.sh.in',
    output: 'main.sh',
    command: [
        meson_render_jinja2,
        config_h,
        '@INPUT@',
        '@OUTPUT@',
    ])

test_programs += custom_target(
    'test_cgroup',
    build_by_default: want_tests != false,
    input: 'test_cgroup.in',
    output: 'test_cgroup',
    command: [
        meson_render_jinja2,
        config_h,
        '@INPUT@',
        '@OUTPUT@',
    ])

test_programs += custom_target(
    'test_confinement.sh',
    build_by_default: want_tests != false,
    input: 'test_confinement.sh.in',
    output: 'test_confinement.sh',
    command: [
        meson_render_jinja2,
        config_h,
        '@INPUT@',
        '@OUTPUT@',
    ])

test_programs += custom_target(
    'test_meminfo_hierarchy.sh',
    build_by_default: want_tests != false,
    input: 'test_meminfo_hierarchy.sh.in',
    output: 'test_meminfo_hierarchy.sh',
    command: [
        meson_render_jinja2,
        config_h,
        '@INPUT@',
        '@OUTPUT@',
    ])

test_programs += custom_target(
   'test_proc',
    build_by_default: want_tests != false,
    input: 'test_proc.in',
    output: 'test_proc',
    command: [
        meson_render_jinja2,
        config_h,
        '@INPUT@',
        '@OUTPUT@',
    ])

test_programs += custom_target(
    'test_read_proc.sh',
    build_by_default: want_tests != false,
    input: 'test_read_proc.sh.in',
    output: 'test_read_proc.sh',
    command: [
        meson_render_jinja2,
        config_h,
        '@INPUT@',
        '@OUTPUT@',
    ])

test_programs += custom_target(
    'test_readdir',
    build_by_default: want_tests != false,
    input: 'test_readdir.in',
    output: 'test_readdir',
    command: [
        meson_render_jinja2,
        config_h,
        '@INPUT@',
        '@OUTPUT@',
    ])

test_programs += custom_target(
    'test_reload.sh',
    build_by_default: want_tests != false,
    input: 'test_reload.sh.in',
    output: 'test_reload.sh',
    command: [
        meson_render_jinja2,
        config_h,
        '@INPUT@',
        '@OUTPUT@',
    ])

test_programs += custom_target(
    'test_sigusr2.sh',
    build_by_default: want_tests != false,
    input: 'test_sigusr2.sh.in',
    output: 'test_sigusr2.sh',
    command: [
        meson_render_jinja2,
        config_h,
        '@INPUT@',
        '@OUTPUT@',
    ])

test_programs += executable(
    'test-read',
    'test-read.c',
    include_directories: config_include,
    install: false,
    build_by_default: want_tests != false)

test_programs += executable(
    'test-syscalls',
    'test_syscalls.c',
    include_directories: config_include,
    install: false,
    build_by_default: want_tests != false)

test_cpusetrange_sources = files(
    'cpusetrange.c',
    '../src/cpuset_parse.c',
    '../src/cpuset_parse.h')

test_programs += executable(
    'test-cpusetrange',
    test_cpusetrange_sources,
    include_directories: config_include,
    install: false,
    build_by_default: want_tests != false)
