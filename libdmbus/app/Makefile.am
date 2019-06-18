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

INCLUDES = -I$(srcdir)/../src  ${LIBARGO_INC}

AM_CFLAGS=-g -W -Wall

bin_PROGRAMS =
noinst_PROGRAMS = server server_static client client_static


server_SOURCES = server.c
server_LDADD =../src/libdmbus.la ${LIBARGO_LIB}

server_static_SOURCES = server.c
server_static_LDADD =../src/libdmbus.la ${LIBARGO_LIB}
server_static_LDFLAGS = -all-static

client_SOURCES = client.c
client_LDADD = ${LIBARGO_LIB}

client_static_SOURCES = client.c
client_static_LDADD = ${LIBARGO_LIB}
client_static_LDFLAGS = -all-static
