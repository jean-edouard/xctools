//
// Copyright (c) 2015 Assured Information Security, Inc
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

#ifndef OPENXT_ARGO_H
#define OPENXT_ARGO_H

#include <libargo.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include "openxtsettings.h"

typedef struct ArgoConnection {

    int fd;
    bool connected;
    xen_argo_addr_t local_addr;
    xen_argo_addr_t remote_addr;

} ArgoConnection;

ArgoConnection *openxt_argo_open(int32_t lport, int32_t ldomid, int32_t rport, int32_t rdomid);
int openxt_argo_close_internal(ArgoConnection *conn);
int openxt_argo_close(ArgoConnection *conn);
bool openxt_argo_isconnected(ArgoConnection *conn);

typedef struct ArgoPacketHeader {

    int32_t opcode;
    int32_t length;

} ArgoPacketHeader;

typedef struct ArgoPacketBody {

    char buffer[ARGO_MAX_PACKET_BODY_SIZE];

} ArgoPacketBody;

typedef struct ArgoPacket {

    ArgoPacketHeader header;
    ArgoPacketBody body;

} ArgoPacket;

bool openxt_argo_validate(int32_t size);

int openxt_argo_set_opcode(ArgoPacket *packet, int32_t opcode);
int openxt_argo_set_length(ArgoPacket *packet, int32_t length);
int32_t openxt_argo_get_opcode(ArgoPacket *packet);
int32_t openxt_argo_get_length(ArgoPacket *packet);
void *openxt_argo_get_body(ArgoPacket *packet);

int openxt_argo_send(ArgoConnection *conn, ArgoPacket *packet);
int openxt_argo_recv(ArgoConnection *conn, ArgoPacket *packet);

#endif // OPENXT_ARGO_H
