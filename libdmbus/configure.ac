#
# Copyright (c) 2011 Citrix Systems, Inc.
# 
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#

# Prelude.
AC_PREREQ(2.13)
AC_INIT(src/dmbus.c.in)

LT_INIT

LIBDMBUS_MAJOR_VERSION=`cat $srcdir/version-major`
LIBDMBUS_MINOR_VERSION=`cat $srcdir/version-minor`
LIBDMBUS_MICRO_VERSION=`cat $srcdir/version-micro`

LIBDMBUS_INTERFACE_VERSION_MIN=$LIBDMBUS_MINOR_VERSION
LIBDMBUS_INTERFACE_VERSION_MAX=$LIBDMBUS_MINOR_VERSION
LIBDMBUS_INTERFACE_REVISION=1

LIBDMBUS_VERSION=$LIBDMBUS_MAJOR_VERSION.$LIBDMBUS_MINOR_VERSION.$LIBDMBUS_MICRO_VERSION

AC_SUBST(LIBDMBUS_MAJOR_VERSION)
AC_SUBST(LIBDMBUS_MINOR_VERSION)
AC_SUBST(LIBDMBUS_MICRO_VERSION)
AC_SUBST(LIBDMBUS_VERSION)

AC_SUBST(LIBDMBUS_INTERFACE_VERSION_MIN)
AC_SUBST(LIBDMBUS_INTERFACE_VERSION_MAX)
AC_SUBST(LIBDMBUS_INTERFACE_REVISION)

LT_RELEASE=$LIBDMBUS_MAJOR_VERSION.$LIBDMBUS_MINOR_VERSION
LT_CURRENT=$LIBDMBUS_INTERFACE_VERSION_MAX
LT_REVISION=$LIBDMBUS_MICRO_VERSION
LT_AGE=`expr $LIBDMBUS_INTERFACE_VERSION_MAX - $LIBDMBUS_INTERFACE_VERSION_MIN`

AC_SUBST(LT_RELEASE)
AC_SUBST(LT_CURRENT)
AC_SUBST(LT_REVISION)
AC_SUBST(LT_AGE)

VERSION=$LIBDMBUS_VERSION
PACKAGE=libdmbus

AM_INIT_AUTOMAKE($PACKAGE,$VERSION)

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
PKG_PROG_PKG_CONFIG([0.22])
AC_PROG_AWK
AC_CHECK_PROG(MD5SUM, md5sum, md5sum)
AC_CHECK_PROG(GREP, grep, grep)
AC_CHECK_PROG(SED, sed, sed)

# Checks for header files.
AC_CHECK_HEADERS([unistd.h fcntl.h errno.h stdlib.h stdint.h stropts.h syslog.h string.h stdio.h stdarg.h])
AC_CHECK_HEADERS([sys/types.h sys/stat.h sys/mman.h])
#AC_CHECK_HEADERS([pthread.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_C_CONST
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for libargo

AC_ARG_WITH([libargo],
            AC_HELP_STRING([--with-libargo=PATH], [Path to prefix where libargo is installed]),
            [LIBARGO_PREFIX=$with_libargo], [])

case "x$LIBARGO_PREFIX" in
        x|xno|xyes)
                LIBARGO_INC=""
                LIBARGO_LIB="-largo"
                ;;
        *)
                LIBARGO_INC="-I${LIBARGO_PREFIX}/include"
                LIBARGO_LIB="-L${LIBARGO_PREFIX}/lib -largo"
                ;;
esac

AC_SUBST(LIBARGO_INC)
AC_SUBST(LIBARGO_LIB)

have_libargo=true

ORIG_LDFLAGS="${LDFLAGS}"
ORIG_CPPFLAGS="${CPPFLAGS}"
        LDFLAGS="${LDFLAGS} ${LIBARGO_LIB}"
        CPPFLAGS="${CPPFLAGS} ${LIBARGO_INC}"
        AC_CHECK_HEADERS([libargo.h], [], [have_libargo=false])
        AC_CHECK_FUNC([argo_socket], [], [have_libargo=false])
LDFLAGS="${ORIG_LDFLAGS}"
CPPFLAGS="${ORIG_CPPFLAGS}"

if test "x$have_libargo" = "xfalse"; then
        AC_MSG_ERROR([
*** libargo is required.
])
fi

AC_PATH_PROG([SHA1SUM], sha1sum, [])
if test "x${SHA1SUM}" = "x"; then
        AC_MSG_ERROR([
*** sha1sum is required.                
])
fi

# Output files.
AC_CONFIG_MACRO_DIR([m4])
AM_CONFIG_HEADER(src/config.h)

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 app/Makefile
                 libdmbus.pc.src])
AC_CONFIG_FILES([libdmbus-config.src],
                [chmod +x libdmbus-config.src])

AC_OUTPUT
