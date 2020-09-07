AC_PREREQ([2.69])

AC_INIT([lxcfs], [4.0.0], [lxc-devel@lists.linuxcontainers.org])

# We need pkg-config
PKG_PROG_PKG_CONFIG

AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_HEADERS([config.h])

AC_SUBST(ACLOCAL_AMFLAGS, "-I m4")
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror -Wno-portability subdir-objects])
AC_CANONICAL_HOST
AM_PROG_CC_C_O
AC_USE_SYSTEM_EXTENSIONS

# Test if we have a new enough compiler.
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#define GCC_VERSION \
	(__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)

#define CLANG_VERSION \
	(__clang_major__ * 10000 + __clang_minor__ * 100 + __clang_patchlevel__)

#if GCC_VERSION < 40700 && CLANG_VERSION < 10000
#error Sorry, your compiler is too old - please upgrade it
#endif
	]])], [valid_compiler=yes], [valid_compiler=no])
if test "x$valid_compiler" = "xno"; then
	AC_MSG_ERROR([Sorry, your compiler is too old - please upgrade it])
fi

# libtool
LT_INIT
AC_SUBST([LIBTOOL_DEPS])

AC_CONFIG_FILES([
	Makefile
	lxcfs.spec

	config/Makefile
	config/init/Makefile
	config/init/systemd/Makefile
	config/init/systemd/lxcfs.service
	config/init/sysvinit/Makefile
	config/init/upstart/Makefile

	doc/Makefile

	share/Makefile
	share/00-lxcfs.conf
	share/lxc.mount.hook
	share/lxc.reboot.hook

	src/Makefile

	tests/Makefile ])

AC_CHECK_LIB(pthread, main)

PKG_CHECK_MODULES(FUSE, fuse, [], [
	PKG_CHECK_MODULES(FUSE, fuse3, [AC_DEFINE([HAVE_FUSE3], [1], [Use fuse3])])
])

AC_PATH_PROG(HELP2MAN, help2man, false // No help2man //)
AM_CONDITIONAL([HAVE_HELP2MAN], [test "x$HELP2MAN" != "xfalse // No help2man //" ])

AC_ARG_WITH([runtime-path],
	[AC_HELP_STRING(
		[--with-runtime-path=dir],
		[runtime directory (default: /run)]
	)], [], [with_runtime_path=['/run']])

AS_AC_EXPAND(RUNTIME_PATH, "$with_runtime_path")
AS_AC_EXPAND(LXCFSSHAREDIR, "$datarootdir/lxcfs")
AS_AC_EXPAND(LXCCONFDIR, "$datarootdir/lxc/config/common.conf.d")
AS_AC_EXPAND(LXCFSTARGETDIR, "$localstatedir/lib/lxcfs")

# Detect the distribution. This is used for the default configuration and
# for some distro-specific build options.
AC_MSG_CHECKING([host distribution])
AC_ARG_WITH(distro, AS_HELP_STRING([--with-distro=DISTRO], [Specify the Linux distribution to target: One of redhat, oracle, centos, fedora, suse, gentoo, debian, arch, slackware, paldo, openmandriva or pardus.]))
if type lsb_release >/dev/null 2>&1 && test "z$with_distro" = "z"; then
	with_distro=`lsb_release -is`
fi

if test "z$with_distro" = "z"; then
	AC_CHECK_FILE(/etc/redhat-release,with_distro="redhat")
	AC_CHECK_FILE(/etc/oracle-release,with_distro="oracle")
	AC_CHECK_FILE(/etc/centos-release,with_distro="centos")
	AC_CHECK_FILE(/etc/fedora-release,with_distro="fedora")
	AC_CHECK_FILE(/etc/SuSE-release,with_distro="suse")
	AC_CHECK_FILE(/etc/gentoo-release,with_distro="gentoo")
	AC_CHECK_FILE(/etc/debian_version,with_distro="debian")
	AC_CHECK_FILE(/etc/arch-release,with_distro="arch")
	AC_CHECK_FILE(/etc/slackware-version,with_distro="slackware")
	AC_CHECK_FILE(/etc/frugalware-release,with_distro="frugalware")
	AC_CHECK_FILE(/etc/mandrakelinux-release, with_distro="openmandriva")
	AC_CHECK_FILE(/etc/mandriva-release,with_distro="openmandriva")
	AC_CHECK_FILE(/etc/pardus-release,with_distro="pardus")
	AC_CHECK_FILE(/etc/pld-release,with_distro="pld")
fi

with_distro=`echo ${with_distro} | tr '[[:upper:]]' '[[:lower:]]'`

if test "z$with_distro" = "z"; then
	with_distro="unknown"
fi

case $with_distro in
	ubuntu)
		distroconf=default.conf.ubuntu
		;;
	redhat|centos|fedora|oracle|oracleserver|pld)
		distroconf=default.conf.libvirt
		;;
	*)
		distroconf=default.conf.unknown
		;;
esac

AC_MSG_RESULT([$with_distro])
AM_CONDITIONAL([HAVE_DEBIAN], [test x"$with_distro" = "xdebian" -o x"$with_distro" = "xubuntu"])
AM_CONDITIONAL([DISTRO_UBUNTU], [test "x$with_distro" = "xubuntu"])

# Check for init system type
AC_MSG_CHECKING([for init system type])
AC_ARG_WITH([init-script],
	    [AC_HELP_STRING([--with-init-script@<:@=TYPE@<:@,TYPE,...@:>@@:>@],
			    [Type(s) of init script to install: bsd, openrc, sysvinit, systemd, upstart,
			     distro @<:@default=distro@:>@])],[],[with_init_script=distro])
case "$with_init_script" in
	distro)
		case $with_distro in
			fedora)
				init_script=systemd
				;;
			redhat|centos|oracle|oracleserver)
				init_script=sysvinit
				;;
			debian)
				init_script=upstart,systemd,sysvinit
				;;
			ubuntu)
				init_script=upstart,systemd,sysvinit
				;;
			pld)
				init_script=systemd,sysvinit
				;;
			slackware)
				echo -n "Warning: bsd init job not yet implemented"
				init_script=
				;;
                        gentoo)
				echo -n "Warning: openrc init job not yet implemented"
				init_script=
				;;
			*)
				echo -n "Linux distribution init system unknown."
				init_script=
				;;
		esac
		;;
	*)
		init_script=$with_init_script
		;;
esac

# Check valid init systems were given, run in subshell so we don't mess up IFS
(IFS="," ; for init_sys in $init_script;
do
	case "$init_sys" in
		none|bsd|openrc|sysvinit|systemd|upstart)
			;;
		*)
			exit 1
			;;
	esac
done) || AC_MSG_ERROR([Unknown init system type in $init_script])

AM_CONDITIONAL([INIT_SCRIPT_BSD], [echo "$init_script" |grep -q "bsd"])
AM_CONDITIONAL([INIT_SCRIPT_OPENRC], [echo "$init_script" |grep -q "openrc"])
AM_CONDITIONAL([INIT_SCRIPT_SYSV], [echo "$init_script" |grep -q "sysvinit"])
AM_CONDITIONAL([INIT_SCRIPT_SYSTEMD], [echo "$init_script" |grep -q "systemd"])
AM_CONDITIONAL([INIT_SCRIPT_UPSTART], [echo "$init_script" |grep -q "upstart"])
AC_MSG_RESULT($init_script)

AC_SUBST([lxcfsdir], "${libdir}/lxcfs")

# Rootfs path, where the container mount structure is assembled
AC_ARG_WITH([rootfs-path],
	[AC_HELP_STRING(
		[--with-rootfs-path=dir],
		[lxc rootfs mount point]
	)], [], [with_rootfs_path=['${libdir}/lxc/rootfs']])

AS_AC_EXPAND(LIBDIR, "$libdir")

AC_CHECK_FUNCS([strlcpy],
	AM_CONDITIONAL(HAVE_STRLCPY, true)
	AC_DEFINE(HAVE_STRLCPY,1,[Have strlcpy]),
	AM_CONDITIONAL(HAVE_STRLCPY, false))

AC_CHECK_FUNCS([strlcat],
	AM_CONDITIONAL(HAVE_STRLCAT, true)
	AC_DEFINE(HAVE_STRLCAT,1,[Have strlcat]),
	AM_CONDITIONAL(HAVE_STRLCAT, false))

AC_CHECK_FUNCS([pidfd_open],
	AM_CONDITIONAL(HAVE_PIDFD_OPEN, true)
	AC_DEFINE(HAVE_PIDFD_OPEN,1,[Supports pidfd_open]),
	AM_CONDITIONAL(HAVE_PIDFD_OPEN, false))

AC_CHECK_FUNCS([pidfd_send_signal],
	AM_CONDITIONAL(HAVE_PIDFD_SEND_SIGNAL, true)
	AC_DEFINE(HAVE_PIDFD_SEND_SIGNAL,1,[Supports pidfd_send_signal]),
	AM_CONDITIONAL(HAVE_PIDFD_SEND_SIGNAL, false))

AX_CHECK_COMPILE_FLAG([-fdiagnostics-color], [CFLAGS="$CFLAGS -fdiagnostics-color"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Wimplicit-fallthrough=5], [CFLAGS="$CFLAGS -Wimplicit-fallthrough=5"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Wcast-align], [CFLAGS="$CFLAGS -Wcast-align"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Wstrict-prototypes], [CFLAGS="$CFLAGS -Wstrict-prototypes"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-fno-strict-aliasing], [CFLAGS="$CFLAGS -fno-strict-aliasing"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-fstack-clash-protection], [CFLAGS="$CFLAGS -fstack-clash-protection"],,[-Werror])
AX_CHECK_LINK_FLAG([-fstack-protector-strong], [CFLAGS="$CFLAGS -fstack-protector-strong"],,[-Werror])
AX_CHECK_LINK_FLAG([--param=ssp-buffer-size=4], [CFLAGS="$CFLAGS --param=ssp-buffer-size=4"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-g], [CFLAGS="$CFLAGS -g"],,[-Werror])
AX_CHECK_COMPILE_FLAG([--mcet -fcf-protection], [CFLAGS="$CFLAGS --mcet -fcf-protection"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Werror=implicit-function-declaration], [CFLAGS="$CFLAGS -Werror=implicit-function-declaration"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Wlogical-op], [CFLAGS="$CFLAGS -Wlogical-op"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Wmissing-include-dirs], [CFLAGS="$CFLAGS -Wmissing-include-dirs"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Wold-style-definition], [CFLAGS="$CFLAGS -Wold-style-definition"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Winit-self], [CFLAGS="$CFLAGS -Winit-self"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Wunused-but-set-variable], [CFLAGS="$CFLAGS -Wunused-but-set-variable"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Wfloat-equal], [CFLAGS="$CFLAGS -Wfloat-equal"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Wsuggest-attribute=noreturn], [CFLAGS="$CFLAGS -Wsuggest-attribute=noreturn"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Werror=return-type], [CFLAGS="$CFLAGS -Werror=return-type"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Werror=incompatible-pointer-types], [CFLAGS="$CFLAGS -Werror=incompatible-pointer-types"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Wformat=2], [CFLAGS="$CFLAGS -Wformat=2"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Wshadow], [CFLAGS="$CFLAGS -Wshadow"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Wendif-labels], [CFLAGS="$CFLAGS -Wendif-labels"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Werror=overflow], [CFLAGS="$CFLAGS -Werror=overflow"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-fdiagnostics-show-option], [CFLAGS="$CFLAGS -fdiagnostics-show-option"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Werror=shift-count-overflow], [CFLAGS="$CFLAGS -Werror=shift-count-overflow"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Werror=shift-overflow=2], [CFLAGS="$CFLAGS -Werror=shift-overflow=2"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Wdate-time], [CFLAGS="$CFLAGS -Wdate-time"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-Wnested-externs], [CFLAGS="$CFLAGS -Wnested-externs"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-fasynchronous-unwind-tables], [CFLAGS="$CFLAGS -fasynchronous-unwind-tables"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-pipe], [CFLAGS="$CFLAGS -pipe"],,[-Werror])
AX_CHECK_COMPILE_FLAG([-fexceptions], [CFLAGS="$CFLAGS -fexceptions"],,[-Werror])

CFLAGS="$CFLAGS -fvisibility=hidden -Wvla -std=gnu11"
AX_CHECK_LINK_FLAG([-z relro], [LDFLAGS="$LDFLAGS -z relro"],,[])
AX_CHECK_LINK_FLAG([-z now], [LDFLAGS="$LDFLAGS -z now"],,[])

# Build with ASAN commands
AC_ARG_ENABLE([asan],
	[AS_HELP_STRING([--enable-asan], [build with address sanitizer enabled [default=no]])],
	[enable_asan=$enableval], [enable_asan=no])
AM_CONDITIONAL([ENABLE_ASAN], [test "x$enable_asan" = "xyes"])

# Build with UBSAN commands
AC_ARG_ENABLE([ubsan],
	[AS_HELP_STRING([--enable-ubsan], [build with ubsan sanitizer enabled [default=no]])],
	[enable_asan=$enableval], [enable_ubsan=no])
AM_CONDITIONAL([ENABLE_UBSAN], [test "x$enable_ubsan" = "xyes"])

AC_OUTPUT

# Configuration overview
cat << EOF

----------------------------
Environment:
 - compiler: $CC

Debugging:
 - tests: $enable_tests
 - ASAN: $enable_asan
 - mutex debugging: $enable_mutex_debugging
EOF
