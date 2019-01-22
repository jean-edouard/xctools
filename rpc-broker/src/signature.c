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


/*
 * Recursively traverse the XML DocTree of a given dbus destination to find the
 * target property.  This function is arranged in a generic/opaque manner where
 * you can use it for any xml-property you want.
 */
xmlNodePtr find_xml_property(const char *target, const xmlChar *property,
                             xmlNodePtr node)
{
    if (node == NULL)
        return NULL;

    const xmlChar *name = NULL;
    name = xmlGetProp(node, property);

    if (name && !strcmp((const char *) name, target)) {
        xmlFree((xmlChar *) name);
        return xmlFirstElementChild(node);
    }

    if (name)
        xmlFree((xmlChar *) name);

    node = find_xml_property(target, property, xmlNextElementSibling(node));

    return node;
}

/*
 * The main function for handling the dbus XML signature parsing.  Parsing XML
 * schema for each dbus request is necessary because there is no way to rely
 * on the JSON object returning the correct argument type required for each
 * request.  The libjson-c doesn't handle signedness, thus dbus will fail if
 * adding a request argument based solely on `json_object_get_type`
 */
int retrieve_xml_signature(const xmlChar *xml_dump, char *args,
                           const char *interface, const char *member)
{
    int idx = 0;
    char *error = NULL;
    const xmlChar *name = NULL;
    const xmlChar *type = NULL;

    xmlDocPtr doc = xmlParseDoc(xml_dump);

    if (doc == NULL) {
        error = "doc";
        goto xml_error;
    }

    xmlNodePtr root = xmlDocGetRootElement(doc);

    if (root == NULL) {
        error = "doc";
        goto xml_error;
    }

    /* Find the interface for the request */
    xmlNodePtr interface_node = find_xml_property(interface, XML_NAME_PROPERTY,
                                                   xmlFirstElementChild(root));
    if (interface_node == NULL) {
        error = "interface";
        goto xml_error;
    }

    /* Find the method being requested */
    xmlNodePtr member_node = find_xml_property(member, XML_NAME_PROPERTY,
                                               interface_node);
    if (member_node == NULL) {
        error = "member";
        goto xml_error;
    }

    name = xmlGetProp(member_node, XML_DIRECTION_PROPERTY);

    /* Loop over method properties looking for "in" (holds the signature) */
    while (name && !strcmp((const char *) name, XML_IN_FIELD)) {
        xmlFree((xmlChar *) name);
        name = NULL;
        type = xmlGetProp(member_node, (const xmlChar *) XML_TYPE_FIELD);

        if (type) {
            args[idx++] = type[0];
            xmlFree((xmlChar *) type);
            type = NULL;
        }

        member_node = xmlNextElementSibling(member_node);
        name = xmlGetProp(member_node, XML_DIRECTION_PROPERTY);
    }

xml_error:

    if (error)
        DBUS_BROKER_WARNING("Invalid xml-%s <Inteface:%s and Member:%s>",
                             error, interface, member);

    if (name)
        xmlFree((xmlChar *) name);

    if (type)
        xmlFree((xmlChar *) type);

    args[idx] = '\0';
    xmlFreeDoc(doc);

    return idx;
}

static inline void add_json_array(struct json_object *args, char *key,
                                     DBusMessageIter *iter)
{
    DBusMessageIter sub;
    dbus_message_iter_recurse(iter, &sub);

    if (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_INVALID && key) {
        struct json_object *empty_array = json_object_new_object();
        add_jobj(args, key, empty_array);
        return;
    }

    parse_signature(args, key, &sub);
}

void parse_dbus_dict(struct json_object *args, char *key, DBusMessageIter *iter)
{
    struct json_object *dbus_dict = json_object_new_object();
    add_jobj(args, key, dbus_dict);

    while (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_INVALID) {
        char *new_key;
        DBusMessageIter sub;
        dbus_message_iter_recurse(iter, &sub);
        dbus_message_iter_get_basic(&sub, &new_key);
        dbus_message_iter_next(&sub);
        parse_signature(dbus_dict, new_key, &sub);
        dbus_message_iter_next(iter);
    }
}

void parse_signature(struct json_object *args, char *key, DBusMessageIter *iter)
{
    int type;
    DBusMessageIter sub;

    while ((type = dbus_message_iter_get_arg_type(iter)) != DBUS_TYPE_INVALID) {

        struct json_object *obj = NULL;

        switch (type) {

            case (DBUS_TYPE_ARRAY):
                add_json_array(args, key, iter);
                break;

            case (DBUS_TYPE_DICT_ENTRY):
                parse_dbus_dict(args, key, iter);
                break;

            case (DBUS_TYPE_OBJECT_PATH):
            case (DBUS_TYPE_STRING): {
                char *dbus_string;
                dbus_message_iter_get_basic(iter, &dbus_string);
                obj = json_object_new_string(dbus_string);
                break;
            }

            case (DBUS_TYPE_INT32):
            case (DBUS_TYPE_UINT32): {
                int dbus_int;
                dbus_message_iter_get_basic(iter, &dbus_int);
                obj = json_object_new_int(dbus_int);
                break;
            }

            case (DBUS_TYPE_DOUBLE): {
                double dbus_double;
                dbus_message_iter_get_basic(iter, &dbus_double);
                obj = json_object_new_double(dbus_double);
                break;
            }

            case (DBUS_TYPE_BOOLEAN): {
                int dbus_bool;
                dbus_message_iter_get_basic(iter, &dbus_bool);
                obj = json_object_new_boolean(dbus_bool);
                break;
            }

            case (DBUS_TYPE_VARIANT): {
                dbus_message_iter_recurse(iter, &sub);
                parse_signature(args, key, &sub);
                break;
            }

            case (DBUS_TYPE_INT64): {
                uint64_t dbus_long;
                dbus_message_iter_get_basic(iter, &dbus_long);
                obj = json_object_new_int64(dbus_long);
                break;
            }

            default:
                DBUS_BROKER_WARNING("<dbus signature unrecognized> [Type: %d]",
                                      type);
                break;
        }

        if (obj != NULL)
            add_jobj(args, key, obj);

        dbus_message_iter_next(iter);
    }
}

