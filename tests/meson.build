# SPDX-License-Identifier: LGPL-2.1-or-later

test_main = configure_file(
        input : 'main.sh.in',
        output : 'main.sh',
        configuration : conf)

test_main = configure_file(
        input : 'test_cgroup.in',
        output : 'test_cgroup',
        configuration : conf)

test_main = configure_file(
        input : 'test_confinement.sh.in',
        output : 'test_confinement.sh',
        configuration : conf)

test_main = configure_file(
        input : 'test_meminfo_hierarchy.sh.in',
        output : 'test_meminfo_hierarchy.sh',
        configuration : conf)

test_main = configure_file(
        input : 'test_proc.in',
        output : 'test_proc',
        configuration : conf)

test_main = configure_file(
        input : 'test_read_proc.sh.in',
        output : 'test_read_proc.sh',
        configuration : conf)

test_main = configure_file(
        input : 'test_readdir.in',
        output : 'test_readdir',
        configuration : conf)

test_main = configure_file(
        input : 'test_reload.sh.in',
        output : 'test_reload.sh',
        configuration : conf)

test_main = configure_file(
        input : 'test_sigusr2.sh.in',
        output : 'test_sigusr2.sh',
        configuration : conf)

test_read = executable(
        'test-read',
        'test-read.c',
	include_directories: config_include,
	install: false,
        build_by_default : want_tests != false)

test_syscalls = executable(
        'test-syscalls',
        'test_syscalls.c',
	include_directories: config_include,
	install: false,
        build_by_default : want_tests != false)

test_cpusetrange_sources = files(
		'cpusetrange.c',
		'../src/cpuset_parse.c',
		'../src/cpuset_parse.h')

test_cpusetrange = executable(
        'test-cpusetrange',
        test_cpusetrange_sources,
	include_directories: config_include,
	install: false,
        build_by_default : want_tests != false)

