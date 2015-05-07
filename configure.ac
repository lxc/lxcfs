# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([lxcfs], [0.8], [lxc-devel@lists.linuxcontainers.org])
AC_SUBST(ACLOCAL_AMFLAGS, "-I m4")
AC_CONFIG_MACRO_DIR([m4])

AC_GNU_SOURCE
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
	Makefile
	share/Makefile
	share/00-lxcfs.conf
	share/lxc.mount.hook
	tests/Makefile ])

AM_INIT_AUTOMAKE

LT_INIT
AC_PROG_CC

AC_PROG_CC_C99

PKG_CHECK_MODULES([NIH], [libnih >= 1.0.2])
PKG_CHECK_MODULES([NIH_DBUS], [libnih-dbus >= 1.0.0])
PKG_CHECK_MODULES([DBUS], [dbus-1 >= 1.2.16])
PKG_CHECK_MODULES([CGMANAGER], [libcgmanager >= 0.0.0])
PKG_CHECK_MODULES(FUSE, fuse)
AC_CHECK_LIB(cgmanager, cgmanager_list_controllers_sync, [], AC_MSG_ERROR(["cgmanager 0.35 or higher is required"]))
AC_CHECK_LIB(cgmanager, cgmanager_list_keys_sync, [], AC_MSG_ERROR(["cgmanager 0.35 or higher is required"]))

AC_PATH_PROG(HELP2MAN, help2man, false // No help2man //)
AM_CONDITIONAL([HAVE_HELP2MAN], [test "x$HELP2MAN" != "xfalse // No help2man //" ])

AS_AC_EXPAND(LXCFSSHAREDIR, "$datarootdir/lxcfs")
AS_AC_EXPAND(LXCCONFDIR, "$datarootdir/lxc/config/common.conf.d")
AS_AC_EXPAND(LXCFSTARGETDIR, "$localstatedir/lib/lxcfs")

AC_OUTPUT
