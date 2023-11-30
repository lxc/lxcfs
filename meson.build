# SPDX-License-Identifier: LGPL-2.1-or-later

# Project.
project(
    'lxcfs',
    'c',
    version: '5.0.0',
    license: 'LGPLv2+',
    default_options: [
        'b_colorout=always',
        'b_asneeded=true',
        'b_pie=true',
        'c_std=gnu11',
        'warning_level=2',
    ],
    meson_version: '>= 0.50')

cc = meson.get_compiler('c')

# Templater.
if run_command(
    'python3', '-c', 'import jinja2',
    check: false).returncode() != 0
        error('python3 jinja2 missing')
endif

meson_build_sh = find_program('tools/meson-build.sh')
meson_render_jinja2 = find_program('tools/meson-render-jinja2.py')

# Configuration options.
conf = configuration_data()
conf.set_quoted('PROJECT', meson.project_name())
conf.set_quoted('PROJECT_URL', 'https://linuxcontainers.org/lxcfs/')
conf.set_quoted('PROJECT_VERSION', meson.project_version())
conf.set_quoted('PACKAGE_VERSION', meson.project_version())
conf.set('_GNU_SOURCE', true)
conf.set('_FILE_OFFSET_BITS', 64)
conf.set('__STDC_FORMAT_MACROS', true)

project_source_root = meson.current_source_dir()
project_build_root = meson.current_build_dir()

# Path handling.
prefixdir = get_option('prefix')
bindir = join_paths(prefixdir, get_option('bindir'))
libdir = join_paths(prefixdir, get_option('libdir'))
lxcfsdir = join_paths(libdir, 'lxcfs')
sysconfdir = join_paths(prefixdir, get_option('sysconfdir'))
runtimepath = join_paths(prefixdir, get_option('runtime-path'))
localstatedir = join_paths('/', get_option('localstatedir'))
datadir = join_paths(prefixdir, get_option('datadir'))

lxcfssharedir = join_paths(datadir, 'lxcfs')
lxcconfdir = join_paths(datadir, 'lxc/config/common.conf.d')
lxcmandir = join_paths(datadir, 'man')

conf.set_quoted('BINDIR', bindir)
conf.set_quoted('LIBDIR', libdir)
conf.set_quoted('LOCALSTATEDIR', localstatedir)
conf.set_quoted('DEFAULT_RUNTIME_PATH', runtimepath)
conf.set_quoted('SYSCONFDIR', sysconfdir)

conf.set_quoted('LXCCONFDIR', lxcconfdir)
conf.set_quoted('LXCFS_BUILD_ROOT', project_build_root)
conf.set_quoted('LXCFSSHAREDIR', lxcfssharedir)
conf.set_quoted('LXCFS_SOURCE_ROOT', project_source_root)
conf.set_quoted('LXCFSTARGETDIR', join_paths(localstatedir, 'lib/lxcfs'))

# Custom configuration.
init_script = get_option('init-script')
want_tests = get_option('tests')
want_docs = get_option('docs')

# Build flags.
possible_cc_flags = [
    '-Wvla',
    '-Wimplicit-fallthrough=5',
    '-Wcast-align',
    '-Wstrict-prototypes',
    '-fno-strict-aliasing',
    '-fstack-clash-protection',
    '-fstack-protector-strong',
    '--param=ssp-buffer-size=4',
    '--mcet -fcf-protection',
    '-Werror=implicit-function-declaration',
    '-Wlogical-op',
    '-Wmissing-include-dirs',
    '-Wold-style-definition',
    '-Winit-self',
    '-Wunused-but-set-variable',
    '-Wno-unused-parameter',
    '-Wfloat-equal',
    '-Wsuggest-attribute=noreturn',
    '-Werror=return-type',
    '-Werror=incompatible-pointer-types',
    '-Wformat=2',
    '-Wshadow',
    '-Wendif-labels',
    '-Werror=overflow',
    '-fdiagnostics-show-option',
    '-Werror=shift-count-overflow',
    '-Werror=shift-overflow=2',
    '-Wdate-time',
    '-Wnested-externs',
    '-fasynchronous-unwind-tables',
    '-fexceptions',
    '-Warray-bounds',
    '-Wrestrict',
    '-Wreturn-local-addr',
    '-fsanitize=cfi',
    '-Wstringop-overflow',
]

possible_link_flags = [
    '-Wl,--gc-sections',
    '-Wl,-z,relro',
    '-Wl,-z,now',
    '-Wl,-fuse-ld=gold',
]

if meson.version().version_compare('>=0.46')
    add_project_link_arguments(cc.get_supported_link_arguments(possible_link_flags), language: 'c')
else
    add_project_link_arguments(possible_link_flags, language: 'c')
endif

add_project_arguments(cc.get_supported_arguments(possible_cc_flags), language: 'c')

# Feature detection.
foreach ident: [
    ['strlcpy', '''#include <string.h>'''],
    ['strlcat', '''#include <string.h>'''],
    ['pidfd_send_signal',
     '''#include <stdlib.h>
        #include <unistd.h>
        #include <signal.h>
        #include <sys/wait.h>'''],
    ['pidfd_open',
     '''#include <stdlib.h>
        #include <unistd.h>
        #include <signal.h>
        #include <sys/wait.h>'''],
]
    have = cc.has_function(ident[0], prefix: ident[1], args: '-D_GNU_SOURCE')
    conf.set10('HAVE_' + ident[0].to_upper(), have)
endforeach

fuse_version = get_option('fuse-version')
if fuse_version == '3' or fuse_version == 'auto'
    libfuse = dependency('fuse3', required: false)
    if libfuse.found()
        conf.set10('HAVE_FUSE3', true)
        conf.set('FUSE_USE_VERSION', 35)
        if libfuse.version().version_compare('>=3.10.3')
            conf.set10('HAVE_FUSE_RETURNS_DT_TYPE', true)
        else
            conf.set10('HAVE_FUSE_RETURNS_DT_TYPE', false)
        endif
    endif
endif

if fuse_version == '2' or (not libfuse.found() and fuse_version == 'auto')
    libfuse = dependency('fuse', version: '>= 2.6')
    if libfuse.found()
        conf.set10('HAVE_FUSE', true)
        conf.set('FUSE_USE_VERSION', 26)
        conf.set10('HAVE_FUSE_RETURNS_DT_TYPE', true)
    endif
endif

if not libfuse.found()
	error('no usable fuse version found')
endif

libdl = cc.find_library('dl')
threads = dependency('threads')

config_h = configure_file(
    output: 'config.h',
    configuration: conf)
config_include = include_directories('.')
add_project_arguments('-include', 'config.h', language: 'c')

# Binary.
lxcfs_sources = files('src/lxcfs.c')
lxcfs = executable(
    'lxcfs',
    lxcfs_sources,
    dependencies: [
        threads,
        libdl,
        libfuse,
    ],
    install: true,
    install_dir: bindir)

# Library.
liblxcfs_sources = files(
    'src/api_extensions.h',
    'src/bindings.c',
    'src/bindings.h',
    'src/cgroups/cgfsng.c',
    'src/cgroups/cgroup.c',
    'src/cgroups/cgroup.h',
    'src/cgroups/cgroup_utils.c',
    'src/cgroups/cgroup_utils.h',
    'src/cgroup_fuse.c',
    'src/cgroup_fuse.h',
    'src/cpuset_parse.c',
    'src/cpuset_parse.h',
    'src/lxcfs.c',
    'src/lxcfs_fuse.h',
    'src/lxcfs_fuse_compat.h',
    'src/macro.h',
    'src/memory_utils.h',
    'src/proc_cpuview.c',
    'src/proc_cpuview.h',
    'src/proc_fuse.c',
    'src/proc_fuse.h',
    'src/proc_loadavg.c',
    'src/proc_loadavg.h',
    'src/syscall_numbers.h',
    'src/sysfs_fuse.c',
    'src/sysfs_fuse.h',
    'src/utils.c',
    'src/utils.h')

liblxcfs_common_dependencies = declare_dependency(
    sources: liblxcfs_sources,
    dependencies: [
        threads,
        libfuse,
    ])

liblxcfs = shared_module(
    'lxcfs',
    liblxcfs_sources,
    dependencies: liblxcfs_common_dependencies,
    install: true,
    install_dir: lxcfsdir)

# Tests.
test_programs = []
if want_tests == true
    liblxcfs_test = shared_module(
        'lxcfstest',
        liblxcfs_sources,
        dependencies: liblxcfs_common_dependencies,
        install: false,
        install_dir: lxcfsdir,
        c_args: '-DRELOADTEST -DDEBUG')
endif

# RPM spec.
lxcfs_spec = custom_target(
    'lxcfs.spec',
    build_by_default: true,
    input: 'lxcfs.spec.in',
    output: 'lxcfs.spec',
    command: [
        meson_render_jinja2,
        config_h,
        '@INPUT@',
        '@OUTPUT@',
    ])

# Man pages
if want_docs == true
    help2man = find_program('help2man')
    help2man_opts = [
       '--name="System virtualization filesystem for containers"',
       '--no-discard-stderr',
       '--section=1',
       '--opt-include=docs/lxcfs.man.add',
       '--no-info',
    ]
    custom_target('lxcfs.1',
        output: 'lxcfs.1',
        command: [help2man, help2man_opts, '--output=@OUTPUT@', lxcfs],
        install: true,
        install_dir: join_paths(lxcmandir, 'man1'))
endif


# Include sub-directories.
subdir('config/init')
subdir('share')
subdir('tests')

# Build overview.
status = [
    '@0@ @1@'.format(meson.project_name(), meson.project_version()),

    'FUSE version:			@0@'.format(libfuse.version()),
    'bin directory:			@0@'.format(bindir),
    'lib directory:			@0@'.format(libdir),
    'data directory:		@0@'.format(datadir),
    'local state directory:		@0@'.format(localstatedir),
    'prefix directory:		@0@'.format(prefixdir),
    'runtime directory:		@0@'.format(runtimepath),
    'sysconf directory:		@0@'.format(sysconfdir),
    'lxc conf directory:		@0@'.format(lxcconfdir),
    'lxcfs directory:		@0@'.format(lxcfsdir),
    'lxcfs shared directory:	@0@'.format(lxcfssharedir),
    'lxcfs build root directory:	@0@'.format(project_build_root),
    'lxcfs source root directory:	@0@'.format(project_source_root),
    'init system(s):		@0@'.format(init_script),
    'tests:				@0@'.format(want_tests),
    'documentation:			@0@'.format(want_docs),
]
message('\n         '.join(status))
