/*
 Copyright (c) 2018 AIS, Inc.

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "rpc-broker.h"


char *prepare_json_reply(struct json_response *jrsp)
{
    struct json_object *jobj = convert_dbus_response(jrsp);

    if (!jobj)
        return NULL;

    char *reply = malloc(WS_RING_BUFFER_MEMBER_SIZE);

    snprintf(reply, WS_RING_BUFFER_MEMBER_SIZE - 1, "%s",
             json_object_to_json_string(jobj));

    json_object_put(jobj);

    return reply;
}

static int ws_server_callback(struct lws *wsi, enum lws_callback_reasons reason,
                              void *user, void *in, size_t len)
{
    switch (reason) {

        case LWS_CALLBACK_RECEIVE: {
            memset(user, '\0', WS_USER_MEM_SIZE);
            memcpy(user, in, len);
            if (ws_request_handler(wsi, user) == 0)
                lws_callback_on_writable(wsi);

            break;
        }

        case LWS_CALLBACK_SERVER_WRITEABLE: {
            if (lws_ring_get_count_waiting_elements(ring, NULL) > 0) {
                char *rsp = (char *) lws_ring_get_element(ring, NULL);
                lws_ring_consume(ring, NULL, NULL, 1);
                memcpy(user + LWS_SEND_BUFFER_PRE_PADDING, rsp, strlen(rsp));
                lws_write(wsi, user + LWS_SEND_BUFFER_PRE_PADDING,
                          strlen(rsp), LWS_WRITE_TEXT);
                lws_callback_on_writable(wsi);
            }

            break;
        }

        case LWS_CALLBACK_PROTOCOL_INIT:
            DBUS_BROKER_EVENT("<WS client request> %s", "");
            break;

        case LWS_CALLBACK_CLOSED:
        case LWS_CALLBACK_WSI_DESTROY:
            DBUS_BROKER_WARNING("WS client session closed %s", "");
            free_dlinks();
            break;

        default:
            break;
    }

    return 0;
}

static struct lws_protocols server_protos[] = {

    { "server-callback", ws_server_callback, 0, 0 },
    { NULL, NULL, 0, 0 }

};

struct lws_context *create_ws_context(int port)
{
    struct lws_context_creation_info info;
    ring = lws_ring_create(WS_RING_BUFFER_MEMBER_SIZE,
                           WS_RING_BUFFER_MEMBER_NUM, NULL);
    server_protos[0].per_session_data_size = WS_USER_MEM_SIZE;
    memset(&info, 0, sizeof(info));
    info.port = port;
    info.protocols = server_protos;

    struct lws_context *context = NULL;
    context = lws_create_context(&info);

    return context;
}

int ws_request_handler(struct lws *wsi, char *raw_req)
{
    int client = lws_get_socket_fd(wsi);
    if (client < 0)
        return -1;

    struct json_request *jreq = convert_json_request(raw_req);

    if (!jreq)
        return -1;

    jreq->wsi = wsi;
    struct json_response *jrsp = make_json_request(jreq);

    if (!jrsp)
        goto free_req;

    char *reply = prepare_json_reply(jrsp);
    if (!reply)
        goto free_resp;

    lws_ring_insert(ring, reply, 1);
    free(reply);

    if (strcmp("AddMatch", jreq->dmsg.member) == 0) {
        add_ws_signal(jreq->conn, wsi);
        // add an interface field (jreq->dmsg.args[0])
    }

free_req:
    free_json_request(jreq);

free_resp:
    free(jrsp);

    return 0;
}

