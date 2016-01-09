# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([lxcfs], [0.16], [lxc-devel@lists.linuxcontainers.org])
AC_SUBST(ACLOCAL_AMFLAGS, "-I m4")
AC_CONFIG_MACRO_DIR([m4])

AC_GNU_SOURCE
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
	Makefile
	share/Makefile
	share/00-lxcfs.conf
	share/lxc.mount.hook
	share/lxc.reboot.hook
	tests/Makefile ])

AM_INIT_AUTOMAKE

LT_INIT
AC_PROG_CC

AC_PROG_CC_C99

AC_CHECK_LIB(pthread, main)

PKG_CHECK_MODULES(FUSE, fuse)

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

AC_OUTPUT
