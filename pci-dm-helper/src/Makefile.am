#
#
# Makefile.am:
#
#
# $Id: Makefile.am,v 1.2 2009/07/31 12:59:40 jamesmck Exp $
#
# $Log: Makefile.am,v $
# Revision 1.2  2009/07/31 12:59:40  jamesmck
# *** empty log message ***
#
# Revision 1.1  2009/07/31 11:58:28  jamesmck
# *** empty log message ***
#
#
#
#

#
# Copyright (c) 2012 Citrix Systems, Inc.
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


CPROTO=cproto

noinst_HEADERS=

bin_PROGRAMS = pci-dm-helper

SRCS=pci-dm-helper.c util.c
pci_dm_helper_SOURCES = ${SRCS}
pci_dm_helper_LDADD =  ${LIBARGO_LIB} ${PCI_LIBS} ${LIBXCXENSTORE_LIBS} \
					   ${LIBEVENT_LIB} ${LIBXC_LIB}
pci_dm_helper_CFLAGS = ${LIBXCXENSTORE_CFLAGS} ${LIBEVENT_INC} \
					   ${LIBXC_INC} \
					   -W -Wall -Werror -D_GNU_SOURCE

AM_CFLAGS=-g

BUILT_SOURCES = version.h

noinst_HEADERS =				\
					util.h


VFD=${srcdir}/..
VF=${shell cat ${VFD}/version-files}
VFS=${VF:%=${VFD}/%}
VCHK=${shell cat ${VFS} | @MD5SUM@ | @AWK@ '{print $$1 }' }
VNUM=${shell @GREP@ ${VCHK} ${VFD}/version-md5sums | @AWK@ '{ print $$2 }'  }
VDEF=${shell echo `cat ${VFD}/version-major`.`cat ${VFD}/version-minor`.`cat ${VFD}/version-micro` }

version.h: $(VFD)/version-files $(VFD)/version-major \
	$(VFD)/version-minor $(VFD)/version-micro \
	$(VFD)/version-md5sums ${VFS} Makefile
	if [ .${VNUM} = . ]; then \
		echo "#define VERSION \"pci-dm-helper Version ${VDEF} + Edits\"" > version.h; \
		echo ${VDEF}-E > version-num; \
	else \
		echo "#define VERSION \"pci-dm-helper Version ${VNUM}\"" > version.h; \
		echo ${VNUM} > version-num; \
	fi

