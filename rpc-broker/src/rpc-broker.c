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

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <uv.h>

#include "rpc-broker.h"

/*
 * Whenever clients connect to port 5555, this function will then connect
 * directly to the DBus system bus socket (/var/run/dbus/system_bus_socket).
 *
 * Polling on the client & server file-descriptors until the connection
 * communication is finished.
 */
void broker_message(struct raw_dbus_conn *rdconn)
{
    int srv = rdconn->server;
    int domid = rdconn->client_domain;
    int client = rdconn->client;
    int sret = 1, cret = 1;

    while (sret > 0 || cret > 0) {
        cret = exchange(client, srv, domid, recv, send);
        if (cret < 0)
            break;
        sret = exchange(srv, client, domid, recv, send);
    }
}

signed int is_stubdom(uint16_t domid)
{
    size_t len = 0;
#ifdef HAVE_XENSTORE
    struct xs_handle *xsh = xs_open(XS_OPEN_READONLY);

    if (!xsh)
        return -1;

    char *path = xs_get_domain_path(xsh, domid);
    path = realloc(path, strlen(path) + XENSTORE_TARGET_LEN);
    strcat(path, XENSTORE_TARGET);

    void *ret = xs_read(xsh, XBT_NULL, path, &len);

    if (ret)
       free(ret);

    free(path);
    xs_close(xsh);
#endif
    return len;
}

static char *get_domain(void)
{
    char *domain = "";

#ifdef HAVE_XENSTORE

    size_t len = 0;
    struct xs_handle *xsh = xs_open(XS_OPEN_READONLY);

    if (!xsh)
        return "";

    domain = xs_read(xsh, XBT_NULL, "domid", &len);
    xs_close(xsh);

#endif

    return domain;
}

void print_usage(void)
{
    printf("rpc-broker <flag> <argument>\n");
    printf("\t-b  [--bus-name=BUS]                    ");
    printf("A dbus bus name to make the connection to.\n");
    printf("\t-h  [--help]                            ");
    printf("Prints this usage description.\n");
    printf("\t-l  [--logging[=optional FILENAME]      ");
    printf("Enables logging to a default path, optionally set.\n");
    printf("\t-p  [--policy-file=FILENAME]            ");
    printf("Provide a policy file to run against.\n");
    printf("\t-r  [--raw-dbus=PORT]                   ");
    printf("Sets rpc-broker to run on given port as raw DBus.\n");
    printf("\t-v  [--verbose]                         ");
    printf("Adds extra information (run with logging).\n");
    printf("\t-w  [--websockets=PORT]                 ");
    printf("Sets rpc-broker to run on given address/port as websockets.\n");
}

void sigint_handler(int signal)
{
    DBUS_BROKER_WARNING("<received signal interrupt> %s", "");
    free_dlinks();
    free_policy();
    // handle cleanup of the uv handles
    if (ring)
        lws_ring_destroy(ring);

    exit(0);
}

void sighup_handler(int signal)
{
    reload_policy = true;
    DBUS_BROKER_EVENT("Re-loading policy %s", "");
}

/*
 * Cycle through linked-list of current dbus-signals being subscribed to.
 * If there are any signals queued up, start the exchange of communication.
 */
static void service_ws_signals(void)
{
    struct dbus_link *curr = dlinks;

    while (curr) {

        DBusMessage *msg = NULL;

        if (curr->dconn && dbus_connection_get_is_connected(curr->dconn)) {
            dbus_connection_read_write(curr->dconn, 0);
            msg = dbus_connection_pop_message(curr->dconn);
        }

        if (!msg)
            goto next_link;

        if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
            goto unref_msg;

        struct json_response *jrsp = init_jrsp();
        jrsp->response_to[0] = '\0';
        snprintf(jrsp->type, JSON_REQ_ID_MAX - 1, "%s", JSON_SIG);

        load_json_response(msg, jrsp);

        jrsp->interface = dbus_message_get_interface(msg);
        jrsp->member = dbus_message_get_member(msg);
        jrsp->path = dbus_message_get_path(msg);

        char *reply = prepare_json_reply(jrsp);

        if (!reply)
            goto free_msg;

        lws_callback_on_writable(curr->wsi);
        lws_ring_insert(ring, reply, 1);
        free(reply);

free_msg:
        free(jrsp);

unref_msg:
        dbus_message_unref(msg);

next_link:
        curr = curr->next;
    }
}

static void run_websockets(struct dbus_broker_args *args)
{
    struct lws_context *ws_context = NULL;
    ws_context = create_ws_context(args->port);
    if (dom0)
        dbus_broker_policy = build_policy(args->rule_file);

    if (!ws_context)
        DBUS_BROKER_ERROR("WebSockets-Server");

    DBUS_BROKER_EVENT("<WebSockets-Server has started listening> [Port: %d]",
                        args->port);

    while (dbus_broker_running) {

        lws_service(ws_context, WS_LOOP_TIMEOUT);
        service_ws_signals();

        if (reload_policy) {
            free_policy();
            dbus_broker_policy = build_policy(args->rule_file);
            reload_policy = false;
        }
    }

    lws_ring_destroy(ring);
    lws_context_destroy(ws_context);
}

static void close_connection(uv_handle_t *handle)
{
    struct raw_dbus_conn *rdconn = (struct raw_dbus_conn *) handle->data;
    free(rdconn);
}

void service_rdconn_cb(uv_poll_t *handle, int status, int events)
{
    struct raw_dbus_conn *rdconn = (struct raw_dbus_conn *) handle->data;

    if (events & UV_READABLE)
        broker_message(rdconn);
    else if (events & UV_DISCONNECT)
        uv_close((uv_handle_t *) handle, close_connection);
}

void run_rawdbus(struct dbus_broker_args *args)
{
    struct dbus_broker_server *server = start_server(args->port);
    DBUS_BROKER_EVENT("<Server has started listening> [Port: %d]", args->port);

    int default_socket = server->dbus_socket;
    if (dom0)
        dbus_broker_policy = build_policy(args->rule_file);

    fd_set server_set;
    uv_loop_t loop;
    uv_loop_init(&loop);

    while (dbus_broker_running) {

        FD_ZERO(&server_set);
        FD_SET(default_socket, &server_set);

        struct timeval tv = { .tv_sec=0, .tv_usec=DBUS_BROKER_CLIENT_TIMEOUT };
        int ret = select(default_socket + 1, &server_set, NULL, NULL, &tv);

        if (ret > 0) {
	        socklen_t clilen = sizeof(server->peer);
	        int client = accept(default_socket,
                               (struct sockaddr *) &server->peer, &clilen);
            if (args->verbose) {
                DBUS_BROKER_EVENT("<Client> [Port: %d Addr: %d Client: %d]",
                                    args->port, server->peer.sin_addr.s_addr,
                                                                     client);
            }

            struct raw_dbus_conn *rdconn = malloc(sizeof *rdconn);
            struct raw_dbus_conn *sdconn = malloc(sizeof *sdconn);

            rdconn->server = connect_to_system_bus();
            rdconn->client = client;
            rdconn->client_domain = 0;
    	    /*
             * When using rpc-broker over V4V, we want to be able to
             * firewall against domids. The V4V interposer stores the
             * domid as follows:
             * sin.sin_addr.s_addr = htonl ((uint32_t) peer->domain | 0x1000000);
             * If we're not using V4V, just return 0 for the domid.
             */
#ifdef HAVE_V4V
            struct sockaddr_in client_addr;
            socklen_t client_addr_len = sizeof(client_addr);

            if (getpeername(client, &client_addr, &client_addr_len) < 0)
                DBUS_BROKER_WARNING("getpeername call failed <%s>", strerror(errno));
            else
                rdconn->client_domain = ntohl(client_addr.sin_addr.s_addr) & ~0x1000000;
#endif
            rdconn->handle.data = rdconn;

            uv_poll_init(&loop, &rdconn->handle, rdconn->client);
            memcpy(sdconn, rdconn, sizeof *rdconn);
            uv_poll_init(&loop, &sdconn->handle, sdconn->server);

            uv_poll_start(&rdconn->handle, UV_READABLE | UV_DISCONNECT,
                           service_rdconn_cb);
            uv_poll_start(&sdconn->handle, UV_READABLE | UV_DISCONNECT,
                           service_rdconn_cb);
        }

        uv_run(&loop, UV_RUN_NOWAIT);

        if (reload_policy) {
            free_policy();
            dbus_broker_policy = build_policy(args->rule_file);
            reload_policy = false;
        }
    }

    free(server);
    close(default_socket);
}

int main(int argc, char *argv[])
{
    const char *dbus_broker_opt_str = "b:hl::p:r:vw:";

    struct option dbus_broker_opts[] = {
        { "bus-name",    required_argument,   0, 'b' },
        { "help",        no_argument,         0, 'h' },
        { "logging",     optional_argument,   0, 'l' },
        { "policy-file", required_argument,   0, 'p' },
        { "raw-dbus",    required_argument,   0, 'r' },
        { "verbose",     no_argument,         0, 'v' },
        { "websockets",  required_argument,   0, 'w' },
        {  0,            0,        0,         0      }
    };

    int opt;
    int option_index;

    uint32_t port;

    bool logging = false;
    verbose_logging = false;
    void (*mainloop)(struct dbus_broker_args *args);

    char *bus_file = NULL;
    char *raw_dbus = NULL;
    char *websockets = NULL;
    char *logging_file = "";
    char *policy_file  = RULES_FILENAME;
    dbus_broker_policy = calloc(1, sizeof *dbus_broker_policy);

    bool proto = false;

    while ((opt = getopt_long(argc, argv, dbus_broker_opt_str,
                              dbus_broker_opts, &option_index)) != -1) {

        switch (opt) {

            case ('b'):
                bus_file = optarg;
                break;

            case ('l'):
                logging = true;
                if (optarg)
                    logging_file = optarg;
                break;

            case ('p'):
                policy_file = optarg;
                break;

            case ('r'):
                if (proto)
                    goto conn_type_error;
                raw_dbus = optarg;
                proto = true;
                break;

            case ('v'):
                verbose_logging = true;
                break;

            case ('w'):
                if (proto)
                    goto conn_type_error;
                websockets = optarg;
                proto = true;
                break;

            case ('h'):
            case ('?'):
                print_usage();
                exit(0);
                break;
        }
    }

    errno = 0;
    if (raw_dbus) {
        port = strtol(raw_dbus, NULL, 0);
        if (errno != 0)
            DBUS_BROKER_ERROR("Invalid raw-dbus port");
        mainloop = run_rawdbus;
    } else if (websockets) {
        port = strtol(websockets, NULL, 0);
        if (errno != 0)
            DBUS_BROKER_ERROR("Invalid websockets port");
        mainloop = run_websockets;
    } else
        goto conn_type_error;

    struct dbus_broker_args args = {
        .logging=logging,
        .verbose=verbose_logging,
        .bus_name=bus_file,
        .logging_file=logging_file,
        .rule_file=policy_file,
        .port=port,
    };

    struct sigaction sa = { .sa_handler=sigint_handler };

    if (sigaction(SIGINT, &sa, NULL) < 0)
        DBUS_BROKER_ERROR("sigaction");

    dbus_broker_running = 1;
    dlinks = NULL;
    ring = NULL;
    reload_policy = false;

    // XXX rm and use dbus-message-get-serial
    char *domain = get_domain();
    dom0 = strcmp(domain, "0") ? false : true;
    DBUS_BROKER_EVENT("Domain: %s", domain);

    srand48(time(NULL));

    mainloop(&args);

    free_policy();
    free_dlinks();

    return 0;

conn_type_error:

    printf("Must supply at least one (and no more than one) connection type.\n");
    print_usage();

    return 0;
}

