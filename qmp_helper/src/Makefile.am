#
# Copyright (c) 2016 Assured Information Security, Ross Philipson <philipsonr@ainfosec.com>
# Copyright (c) 2011 Citrix Systems, Inc.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

CFLAGS = -Wall -Werror
CPROTO=cproto
INCLUDES = ${X_CFLAGS}

noinst_HEADERS=project.h prototypes.h

bin_PROGRAMS = qmp_helper

SRCS=qmp_helper.c version.c
qmp_helper_SOURCES = ${SRCS}
qmp_helper_LDADD =  ${X_LIBS} -largo

AM_CFLAGS=-g

qmp_helper_LDFLAGS = 

BUILT_SOURCES = version.h


VFD=${srcdir}/..
VF=${shell cat ${VFD}/version-files}
VFS=${VF:%=${VFD}/%}
VCHK=${shell cat ${VFS} | @MD5SUM@ | @AWK@ '{print $$1 }' }
VNUM=${shell @GREP@ ${VCHK} ${VFD}/version-md5sums | @AWK@ '{ print $$2 }'  }
VDEF=${shell echo `cat ${VFD}/version-major`.`cat ${VFD}/version-minor`.`cat ${VFD}/version-micro` }

protos:
	echo > prototypes.h
	${CPROTO} -v ${INCLUDES} ${SRCS} > prototypes.tmp
	mv -f prototypes.tmp prototypes.h



version.h: $(VFD)/version-files $(VFD)/version-major \
	$(VFD)/version-minor $(VFD)/version-micro \
	$(VFD)/version-md5sums ${VFS} Makefile
	if [ .${VNUM} = . ]; then \
		echo "#define VERSION \"qmp_helper Version ${VDEF} + Edits\"" > version.h; \
		echo ${VDEF}-E > version-num; \
	else \
		echo "#define VERSION \"qmp_helper Version ${VNUM}\"" > version.h; \
		echo ${VNUM} > version-num; \
	fi

