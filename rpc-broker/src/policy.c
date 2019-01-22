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


static int create_rule(struct rule *current, char *rule)
{
    if (!rule || rule[0] == '\0')
        return -1;

    current->rule_string = strdup(rule);

    char *ruleptr;
    const char *delimiter = " ";
    char *token = strtok_r(rule, delimiter, &ruleptr);

    if (!token)
        return -1;

    current->policy = token[0] == 'a';
    token = strtok_r(NULL, delimiter, &ruleptr);

    while (token) {

        char *field = strtok_r(NULL, delimiter, &ruleptr);

        if (!field && token[0] != 's') {
            return -1;
        } else if (!strcmp("destination", token)) {
            current->destination = strdup(field);
        } else if (!strcmp("dom-type", token)) {
            current->domtype = strdup(field);
        } else if (!strcmp("interface", token)) {
            current->interface = strdup(field);
        } else if (!strcmp("if-boolean", token)) {
            current->if_bool = strdup(field);
            token = strtok_r(NULL, delimiter, &ruleptr);
            current->if_bool_flag = strcmp("true", token) == 0 ? 1 : 0;
        } else if (!strcmp("stubdom", token)) {
            current->stubdom = 1;
        } else if (!strcmp("path", token)) {
            current->path = strdup(field);
        } else if (!strcmp("member", token)) {
            current->member = strdup(field);
        } else if (!strcmp("out-any", token)) {
            current->out = 1;
        } else {
            DBUS_BROKER_WARNING("Unrecognized Rule-Token: %s", token);
            free_rule(*current);
            current = NULL;
            return -1;
        }

        token = strtok_r(NULL, delimiter, &ruleptr);
    }

    return 0;
}

static inline void get_rules(DBusConnection *conn, struct domain_policy *dom)
{
    int rule_idx;

    for (rule_idx=0; rule_idx < MAX_RULES; rule_idx++) {
        char *arg;
        DBUS_REQ_ARG(arg, "/vm/%s/rpc-firewall-rules/%d",
                     dom->uuid, rule_idx);

        char *rulestring = db_query(conn, arg);

        free(arg);

        if (!rulestring)
            break;

        struct rule *policy_rule = &(dom->rules[rule_idx]);

        if (create_rule(policy_rule, rulestring) < 0)
            free_rule(*policy_rule);
        else
            dom->count++;

        free(rulestring);
    }

}

static void build_etc_policy(struct etc_policy *etc, const char *rule_filepath)
{
    struct stat policy_stat;
    etc->count = 0;

    if (stat(rule_filepath, &policy_stat) < 0) {
        DBUS_BROKER_WARNING("/etc policy stat of file <%s> failed %s",
                             rule_filepath, strerror(errno));
        return;
    }

    char *filename = basename(rule_filepath);

    if (filename[0] == '\0') {
        DBUS_BROKER_WARNING("/etc policy invalid file <%s>", rule_filepath);
        return;
    }

    etc->filename = filename;

    size_t policy_size = policy_stat.st_size;

    // There is no officially defined limit on policy file size.
    // Rpc-broker defines a buffer size and for now limit based on that size.
    if (policy_size > ETC_MAX_FILE) {
        DBUS_BROKER_WARNING("/etc policy file %s exceeds buffer size <%zu>",
                             rule_filepath, policy_size);
        return;
    }

    int policy_fd = open(rule_filepath, O_RDONLY);

    if (policy_fd < 0) {
        DBUS_BROKER_WARNING("/etc policy file %s failed to open %s",
                              rule_filepath, strerror(errno));
        return;
    }

    int rbytes = read(policy_fd, etc->etc_file, policy_size);

    if (rbytes < 0) {
        close(policy_fd);
        DBUS_BROKER_WARNING("/etc policy file %s invalid read %s",
                              rule_filepath, strerror(errno));
        return;
    }

    etc->etc_file[rbytes] = '\0';

    const char *newline = "\n";
    char *fileptr;
    char *rule_token = strtok_r(etc->etc_file, newline, &fileptr);
    int idx = 0;

    while (rule_token &&  idx < MAX_RULES) {
        if (isalpha(rule_token[0])) {
            char *line = strdup(rule_token);
            struct rule *current = &(etc->rules[idx]);
            create_rule(current, line) < 0 ? free_rule(*current) : idx++;
            free(line);
        }

        rule_token = strtok_r(NULL, newline, &fileptr);
    }

    etc->count = idx;
    close(policy_fd);
}

DBusMessage *db_list(void)
{
    DBusConnection *conn = create_dbus_connection();

    if (!conn)
        return NULL;

    struct dbus_message dmsg;

    dbus_default(&dmsg);
    dmsg.member = DBUS_LIST;
    dmsg.args[0] = (void *) DBUS_VM_PATH;

    DBusMessage *vms = make_dbus_call(conn, &dmsg);

    if (!vms && verbose_logging) {
        DBUS_BROKER_WARNING("DBus message return error <db-list> %s", "");
    } else if (vms && dbus_message_get_type(vms) == DBUS_MESSAGE_TYPE_ERROR) {
        if (verbose_logging)
            DBUS_BROKER_WARNING("DBus message return error <db-list> %s", "");
        dbus_message_unref(vms);
        vms = NULL;
    }

    dbus_connection_unref(conn);

    return vms;
}

struct policy *build_policy(const char *rule_filename)
{
    DBusMessage *vms = db_list();
    if (!vms)
        return NULL;
    DBusConnection *conn = create_dbus_connection();
    struct policy *dbus_policy = calloc(1, sizeof *dbus_policy);

    DBusMessageIter iter, sub;
    dbus_message_iter_init(vms, &iter);
    dbus_message_iter_recurse(&iter, &sub);

    int dom_idx = 0;

    while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {

        void *arg;
        dbus_message_iter_get_basic(&sub, &arg);

        struct domain_policy *current = &(dbus_policy->domains[dom_idx]);
        strcpy(current->uuid, arg);

        errno = 0;
        // XXX domain ID's set?
        current->domid = strtol(arg + DOMID_SECTION, NULL, 10);

        if (errno != 0) {
            DBUS_BROKER_WARNING("Domain ID error <%s>", strerror(errno));
            continue;
        }

        get_rules(conn, current);

        dbus_message_iter_next(&sub);
        dom_idx++;
    }

    dbus_policy->domain_number = dom_idx;
    struct etc_policy *etc = &(dbus_policy->etc);
    build_etc_policy(etc, rule_filename);
    dbus_message_unref(vms);

    return dbus_policy;
}

void free_rule(struct rule r)
{
    if (r.destination)
        free((char *) (r.destination));

    if (r.path)
        free((char *) (r.path));

    if (r.interface)
        free((char *) (r.interface));

    if (r.member)
        free((char *) (r.member));

    if (r.if_bool)
        free((char *) (r.if_bool));

    if (r.domtype)
        free((char *) (r.domtype));

    if (r.rule_string)
        free((char *) (r.rule_string));
}

void free_policy(void)
{
    int count = dbus_broker_policy->domain_number;

    int i, j;
    for (i=0; i < count; i++) {

        struct domain_policy domain = dbus_broker_policy->domains[i];
        for (j=0; j < domain.count; j++)
            free_rule(domain.rules[j]);
    }

    struct etc_policy etc = dbus_broker_policy->etc;

    for (i=0; i < etc.count; i++)
        free_rule(etc.rules[i]);

    free(dbus_broker_policy);
}

