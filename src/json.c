#include "../rpc-broker.h"


struct json_response *init_jrsp(void)
{
    // pass type-of, with its string to load?
    struct json_response *jrsp = calloc(sizeof *jrsp + 
                                       (sizeof(char *) * JSON_REQ_MAX), 1); 
    jrsp->args = json_object_new_array();
    // buffer
    jrsp->response_to = malloc(sizeof(char) * JSON_REQ_ID_MAX);
    // buffer
    jrsp->type = malloc(sizeof(char) * JSON_REQ_ID_MAX);
    jrsp->id = rand() % 4096;
    snprintf(jrsp->type, JSON_REQ_ID_MAX, JSON_RESP_TYPE);

    return jrsp;
}

struct json_response *make_json_request(struct json_request *jreq)
{
    struct json_response *jrsp = init_jrsp();

    DBusConnection *conn = jreq->conn;
    dbus_connection_flush(conn);

    if (jreq->id == 1) {
        const char *busname = dbus_bus_get_unique_name(conn);
        jrsp->id = jreq->id;

        snprintf(jrsp->response_to, JSON_REQ_ID_MAX, JSON_RESP_ID);
        jrsp->arg_sig = "s";
        json_object_array_add(jrsp->args, json_object_new_string(busname));
        return jrsp;
    }
    
    snprintf(jrsp->response_to, JSON_REQ_ID_MAX - 1, "%d", jreq->id);
    DBusMessage *msg = make_dbus_call(conn, jreq->dmsg);

    if (!msg || dbus_message_get_type(msg) == DBUS_MESSAGE_TYPE_ERROR) { 
        DBUS_BROKER_WARNING("response to <%d> request failed", jreq->id); 
        free_json_response(jrsp);
        return NULL;
    }

    load_json_response(msg, jrsp);

    if (strcmp("AddMatch", jreq->dmsg->member) == 0) { 
        pthread_t signal_thr;
        struct broker_signal *bsig = malloc(sizeof *bsig);
        bsig->conn = conn;
        bsig->wsi = jreq->wsi;
        pthread_create(&signal_thr, NULL, dbus_signal, bsig);
    } 

    return jrsp;
}

char *get_json_str_obj(struct json_object *jobj, char *field)
{
    struct json_object *jfield;
    json_object_object_get_ex(jobj, field, &jfield);
    return json_object_get_string(jfield);
}

void load_json_response(DBusMessage *msg, struct json_response *jrsp)
{
    DBusMessageIter iter, sub;
    dbus_message_iter_init(msg, &iter);

    jrsp->arg_sig = dbus_message_iter_get_signature(&iter);

    struct json_object *args = jrsp->args;

    if (jrsp->arg_sig && jrsp->arg_sig[0] == 'a') {

        dbus_message_iter_recurse(&iter, &sub);
        iter = sub;

        if (jrsp->arg_sig[1] == 'a' || 
            jrsp->arg_sig[1] == 'o' || 
            jrsp->arg_sig[1] == 's' ||
            jrsp->arg_sig[1] == 'i') {
            struct json_object *array = json_object_new_array();
            json_object_array_add(jrsp->args, array);
            args = array;
        }
    }

    parse_signature(args, NULL, &iter);
}

struct json_request *convert_json_request(char *raw_json_req)
{
    struct json_object *jobj = json_tokener_parse(raw_json_req);
    struct json_request *jreq = malloc(sizeof *jreq);
    // un-needed alloc
    jreq->dmsg = malloc(sizeof *jreq->dmsg);
    jreq->dmsg->dest = get_json_str_obj(jobj, "destination");
    jreq->dmsg->interface = get_json_str_obj(jobj, "interface");
    jreq->dmsg->path = get_json_str_obj(jobj, "path");
    jreq->dmsg->member = get_json_str_obj(jobj, "method");
    jreq->conn = create_dbus_connection();

    if (!jobj) {
        DBUS_BROKER_WARNING("<Error parsing json-request> %s", raw_json_req);
        return NULL;
    }

    struct json_object *jarray;
    json_object_object_get_ex(jobj, "args", &jarray);

    if (!jarray) {
        json_object_put(jobj);
        DBUS_BROKER_WARNING("<Error json-request> %s", raw_json_req);
        return NULL;
    }

    if (parse_json_args(jarray, jreq) < 0)
        return NULL;

    struct json_object *jint;
    json_object_object_get_ex(jobj, "id", &jint);
    jreq->id = json_object_get_int(jint);
    json_object_put(jint);
    
    return jreq;
}

struct json_object *convert_dbus_response(struct json_response *jrsp)
{
    struct json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "id", json_object_new_int(jrsp->id));
    json_object_object_add(jobj, "type", json_object_new_string(jrsp->type));

    if (jrsp->response_to != NULL) {
        json_object_object_add(jobj, "response-to", 
                               json_object_new_string(jrsp->response_to));
    } else {
        json_object_object_add(jobj, "interface", 
                               json_object_new_string(jrsp->interface));
        json_object_object_add(jobj, "path", 
                               json_object_new_string(jrsp->path));
        json_object_object_add(jobj, "member", 
                               json_object_new_string(jrsp->member));
    }

    json_object_object_add(jobj, "args", jrsp->args);
    return jobj;
}

void add_jobj(struct json_object *args, char *key, struct json_object *jobj)
{
    if (!key)
        json_object_array_add(args, jobj);
    else
        json_object_object_add(args, key, jobj);
}

static inline char json_arg_to_dbus_type(int jtype)
{
    char dbus_type;

    switch (jtype) {

        case (json_type_boolean):
            dbus_type = 'b';
            break;

        case (json_type_int):
            dbus_type = 'i';
            break;

        case (json_type_string):
            dbus_type = 's';
            break;

        case (json_type_double):
            dbus_type = 'd';
            break;

        default:
            printf("Missed setting jtype\n");
            dbus_type = 'z';
            break;
    }

    return dbus_type;
}

static inline void append_dbus_message_arg(int type, int idx, void **args,
                                                 struct json_object *jarg)
{
    // The "argument" array -> `void **args` will be set-up as an array of 
    // `struct arg` and these types won't need to be declared;
    // (possibly add union-type in the `struct arg`)

    switch (type) {        

        case ('b'): {
            int json_bool = json_object_get_boolean(jarg);
            args[idx] = malloc(sizeof(int));
            memcpy(args[idx], (void *) &json_bool, sizeof(int));
            break;
        }

        case ('u'):
        case ('i'): {
            int json_int = json_object_get_int(jarg);
            args[idx] = malloc(sizeof(int));
            memcpy(args[idx], (void *) &json_int, sizeof(int));
            break;
        }

        case ('s'): {
            char *json_str = json_object_get_string(jarg);
            args[idx] = malloc(sizeof(char) * strlen(json_str) + 1);
            if (json_str)
                memcpy(args[idx], (void *) json_str, strlen(json_str) + 1);
            else
                ((char *) args[idx])[0] = '\0';

            break;
        }

        case ('v'): {
            int jtype = json_object_get_type(jarg);
            type = json_arg_to_dbus_type(jtype);
            append_dbus_message_arg(type, idx, args, jarg);
            break;
        }

        default:
            break;
    }
}

int parse_json_args(struct json_object *jarray, struct json_request *jreq)
{
    struct dbus_message *dmsg = jreq->dmsg;
    char *signature = dbus_introspect(jreq);

    if (!signature) {
        DBUS_BROKER_WARNING("dbus-introspect %s", "");
        return -1;
    }

    memcpy(dmsg->arg_sig, signature, strlen(signature) + 1);
    size_t array_length = json_object_array_length(jarray);
    dmsg->arg_number = array_length;

    for (int i=0; i < array_length; i++) {

        struct json_object *jarg = json_object_array_get_idx(jarray, i);
        int jtype = json_object_get_type(jarg);

        if (jtype == json_type_null) {
            dmsg->args[i] = malloc(sizeof(char) * 2);
            ((char *) dmsg->args[i])[0] = '\0';
            continue;
        }
        
        dmsg->json_sig[i] = json_arg_to_dbus_type(jtype);       
        append_dbus_message_arg(*signature, i, dmsg->args, jarg);
        signature++;
    }

    return 0;
}

void free_json_response(struct json_response *jrsp)
{
    if (jrsp->response_to)
        free(jrsp->response_to);

    if (jrsp->arg_sig) {
        struct json_object *array = jrsp->args;
        for (int i=0; i < strlen(jrsp->arg_sig); i++) {
            struct json_object *arg = json_object_array_get_idx(array, i);
            json_object_put(arg);            
        }

        json_object_put(array);
    }

    free(jrsp);
}

