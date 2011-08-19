AC_PREREQ([2.60])
AC_INIT([sw-notify-send], [0.2])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.6 foreign dist-bzip2 no-dependencies])

AC_PROG_CC_C89
AC_USE_SYSTEM_EXTENSIONS

AC_CHECK_FUNCS([chroot])
AC_CHECK_FUNCS([setresuid strdup],,
	[AC_MSG_ERROR([One of required system library functions was not found!])])
AC_CHECK_HEADERS([sysexits.h])
AC_CHECK_LIB([proc], [readproc],,
	[AC_MSG_ERROR([Error: required library proc not found! Please install procps.])])

PKG_CHECK_MODULES([LIBTINYNOTIFY], [libtinynotify libtinynotify-cli])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
