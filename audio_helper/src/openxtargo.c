//
// Copyright (c) 2015 Assured Information Security, Inc
//
// Dates Modified:
//  - 4/8/2015: Initial commit
//    Rian Quinn <quinnr@ainfosec.com>
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

#include "openxtargo.h"
#include "openxtdebug.h"

///
/// This is the main function to setup your Argo connection to another domain.
/// The following provides suggested arguments for this function:
///
/// Clients
/// - local port = XEN_ARGO_PORT_NONE
/// - local domid = XEN_ARGO_DOMID_ANY
/// - remote port = <port #>
/// - remote domid = <server domid, likely == 0>
///
/// Servers
/// - local port = <port #>
/// - local domid = XEN_ARGO_DOMID_ANY
/// - remote port = XEN_ARGO_PORT_NONE
/// - remote domid = <client domid>
///
/// @param lport local port
/// @param ldomid local domid
/// @param rport remote port
/// @param rdomid remote domid
///
/// @return NULL on failure, valid pointer on success
///
ArgoConnection *openxt_argo_open(int32_t lport, int32_t ldomid, int32_t rport, int32_t rdomid)
{
    // Create a new connection structure
    ArgoConnection *conn = calloc(1, sizeof(ArgoConnection));
    openxt_checkp(conn, NULL);

    // Initialize the connection for safety.
    conn->fd = -1;
    conn->connected = false;
    conn->local_addr.aport = lport;
    conn->local_addr.domain_id = ldomid;
    conn->remote_addr.aport = rport;
    conn->remote_addr.domain_id = rdomid;

    // Attempt to open a Argo socket
    if((conn->fd = argo_socket(SOCK_DGRAM)) <= 0)
        goto failure;

    // Bind to Argo
    if(argo_bind(conn->fd, &conn->local_addr, conn->remote_addr.domain_id) != 0)
        goto failure;

    // We are now connected
    conn->connected = true;

done:

    // Success
    return conn;

failure:

    // Cleanup memory
    free(conn);

    // Failure
    return NULL;
}

///
/// The following is for internal use only.
///
int openxt_argo_close_internal(ArgoConnection *conn)
{
    int ret = 0;

    // Sanity checks
    openxt_checkp(conn, -EINVAL);

    // Close Argo
    if (conn->fd >= 0)
        ret = argo_close(conn->fd);

    // We are no longer connected
    conn->fd = -1;
    conn->connected = false;

    // Success
    return ret;
}

///
/// Once you are done with Argo, run this function. Note that this function
/// could be called by this API if something bad happens.
///
/// Note that this free's conn, so don't call it twice :)
///
/// @return -EINVAL if conn == NULL,
///          negative error code on failure of argo_close,
///          0 on success
///
int openxt_argo_close(ArgoConnection *conn)
{
    int ret = openxt_argo_close_internal(conn);

    // Sanity checks
    openxt_checkp(conn, -EINVAL);

    // Cleanup
    free(conn);

    // Success
    return ret;
}

///
/// The following function will tell you if the Argo socket is open and
/// connected
///
/// @return true = connected, false = disconnected or conn == NULL
///
bool openxt_argo_isconnected(ArgoConnection *conn)
{
    // Sanity checks
    openxt_checkp(conn, false);

    // Return connection status
    return conn->connected;
}

///
/// The following can be used as a safety to make sure that your packets are
/// not bigger than a Argo packet. This way you can use the packet structures
/// all you want later without fear of buffer overflows.
///
/// @param size the size of your packet
/// @return true = safe, false = unsafe (likely will overflow)
///
bool openxt_argo_validate(int32_t size)
{
    return size <= ARGO_MAX_PACKET_BODY_SIZE;
}

///
/// The following will set the opcode of a packet.
///
/// @param packet the packet that you want to set the opcode for
/// @param opcode the opcode that you want to set
///
/// @return -EINVAL if packet == NULL, 0 on success
///
int openxt_argo_set_opcode(ArgoPacket *packet, int32_t opcode)
{
    // Sanity checks
    openxt_checkp(packet, -EINVAL);

    // Set the opcode of the packet
    packet->header.opcode = opcode;

    // Success
    return 0;
}

///
/// The following will set the length of a packet.
///
/// @param packet the packet that you want to set the length for
/// @param length the length that you want to set
///
/// @return -EINVAL if packet == NULL, -EOVERFLOW if the length is too large, 0 on success
///
int openxt_argo_set_length(ArgoPacket *packet, int32_t length)
{
    // Sanity checks
    openxt_checkp(packet, -EINVAL);
    openxt_assert(length <= ARGO_MAX_PACKET_BODY_SIZE, -EOVERFLOW);

    // Set the opcode of the packet
    packet->header.length = length + sizeof(ArgoPacketHeader);

    // Success
    return 0;
}

///
/// The following will get the opcode of a packet.
///
/// @param packet the packet that you want to get the opcode for
///
/// @return -EINVAL if packet == NULL, opcode on success
///
int openxt_argo_get_opcode(ArgoPacket *packet)
{
    // Sanity checks
    openxt_checkp(packet, -EINVAL);

    // Success
    return packet->header.opcode;
}

///
/// The following will get the length of a packet.
///
/// @param packet the packet that you want to get the length for
///
/// @return -EINVAL if packet == NULL, length on success
///
int openxt_argo_get_length(ArgoPacket *packet)
{
    // Sanity checks
    openxt_checkp(packet, -EINVAL);

    // Success
    return packet->header.length - sizeof(ArgoPacketHeader);
}

///
/// The following gets the body of a packet. This is basically where you would
/// put the contents of your packet.
///
/// @code
///
/// ArgoPacket snd_packet;
/// MyPacket *packet = openxt_argo_get_body(&snd_packet);
///
/// packet->data1 = data1;
/// packet->data2 = data2;
///
/// openxt_argo_set_opcode(&snd_packet, opcode);
/// openxt_argo_set_length(&snd_packet, sizeof(MyPacket));
///
/// openxt_argo_send(conn, &snd_packet);
///
/// @endcode
///
/// @param packet the packet that you want body access to
/// @return NULL = packet == NULL, valid pointer on success
///
void *openxt_argo_get_body(ArgoPacket *packet)
{
    // Sanity checks
    openxt_checkp(packet, NULL);

    // Success
    return packet->body.buffer;
}

///
/// The following function will send a Argo packet.
///
/// @param conn the Argo connection created using openxt_argo_open.
/// @param packet the packet to send
///
/// @return -EINVAL if conn or packet == NULL,
///         -EOVERFLOW if the packet length is too large,
///         -ENODEV if conn is closed,
///          negative errno if argo_sendto fails,
///          ret >= 0 on success representing number of bytes sent
///
int openxt_argo_send(ArgoConnection *conn, ArgoPacket *packet)
{
    // Local variables
    int ret;

    // Sanity checks
    openxt_checkp(conn, -EINVAL);
    openxt_checkp(packet, -EINVAL);
    openxt_assert(openxt_argo_get_length(packet) <= ARGO_MAX_PACKET_BODY_SIZE, -EOVERFLOW);

    // Make sure that we are actually connected. Note that we make this a
    // quite failure because if a problem happens, we will close the connection
    // and it's possible that the code might continue attempting to send, and
    // we do not want to kill performance by logging a ton of error messages
    openxt_assert_quiet(openxt_argo_isconnected(conn) == true, -ENODEV);

    // Send the packet. Note that we handle printing useful error messages
    // here. All the user should have to do, is validate that the send was
    // successful
    ret = argo_sendto(conn->fd, (char *)packet, packet->header.length, 0, &conn->remote_addr);
    if (ret <= 0) {

        switch (ret) {

            // Failed to send anything
            case 0:
                openxt_warn("failed openxt_argo_send, wrote 0 bytes: %d - %s\n", errno, strerror(errno));
                openxt_argo_close_internal(conn);
                return -errno;

            // Error
            default:
                openxt_warn("failed openxt_argo_send: %d - %s\n", errno, strerror(errno));
                openxt_argo_close_internal(conn);
                return -errno;
        }
    }

    // Success
    return ret - sizeof(ArgoPacketHeader);
}

///
/// The following function will send a Argo packet.
///
/// @param conn the Argo connection created using openxt_argo_open.
/// @param packet the packet to send
///
/// @return -EINVAL if conn or packet == NULL,
///         -EIO if the received packet length != length in header,
///         -ENODEV if conn is closed,
///          negative errno if argo_recvfrom fails,
///          ret >= 0 on success representing number of bytes received
///
int openxt_argo_recv(ArgoConnection *conn, ArgoPacket *packet)
{
    // Local variables
    int ret;

    // Sanity checks
    openxt_checkp(conn, -EINVAL);
    openxt_checkp(packet, -EINVAL);

    // Make sure that we are actually connected. Note that we make this a
    // quite failure because if a problem happens, we will close the connection
    // and it's possible that the code might continue attempting to send, and
    // we do not want to kill performance by logging a ton of error messages
    openxt_assert_quiet(openxt_argo_isconnected(conn) == true, -ENODEV);

    // Send the packet. Note that we handle printing useful error messages
    // here. All the user should have to do, is validate that the send was
    // successful
    ret = argo_recvfrom(conn->fd, (char *)packet, sizeof(ArgoPacket), 0, &conn->remote_addr);
    if (ret <= 0) {

        switch (ret) {

            // Failed to receive anything
            case 0:
                openxt_warn("failed openxt_argo_recv, read 0 bytes: %d - %s\n", errno, strerror(errno));
                openxt_argo_close_internal(conn);
                return -errno;

            // Error
            default:
                openxt_warn("failed openxt_argo_recv: %d - %s\n", errno, strerror(errno));
                openxt_argo_close_internal(conn);
                return -errno;
        }
    }

    // Before we return the packet, we need to check to make sure that the
    // amount of data that we read, is equal to the amount of data that the
    // packet should have returned. If it is not, we have an error
    if (packet->header.length != ret) {
        openxt_warn("failed openxt_argo_recv: length mismatch %d - %d\n", packet->header.length, ret);
        openxt_argo_close_internal(conn);
        return -EIO;
    }

    // Success
    return ret - sizeof(ArgoPacketHeader);
}
