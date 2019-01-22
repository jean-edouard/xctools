AC_INIT([rpc-broker], [1.0], [bug-automake@gnu.org])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
PKG_CHECK_MODULES([DBUS], [dbus-1])
PKG_CHECK_MODULES([LIBV4V], [libv4v],
   [AC_DEFINE([HAVE_V4V], [1], [Use V4V])],
   [AC_MSG_WARN([libv4v not found, building without it])])
PKG_CHECK_MODULES([XENSTORE], [xenstore],
   [AC_DEFINE([HAVE_XENSTORE], [1], [Use xenstore])],
   [AC_MSG_WARN([xenstore not found, building without it])])
PKG_CHECK_MODULES([LIBWEBSOCKETS], [libwebsockets])
PKG_CHECK_MODULES([JSON_C], [json-c])
PKG_CHECK_MODULES([LIBXML], [libxml-2.0])
AC_PROG_CC
##AC_CONFIG_FILES([Makefile])
AC_OUTPUT([Makefile])
