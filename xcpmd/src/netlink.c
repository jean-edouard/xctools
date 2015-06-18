/*
 * netlink.c
 *
 * Register for and monitor ACPI events from Netlink kernel messages
 * and communicate relevant event to ioemu by triggering xenstore events
 *
 * Copyright (c) 2012 Aurelien Chartier <aurelien.chartier@citrix.com>
 * Copyright (c) 2012 Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

#include "project.h"
#include "xcpmd.h"

#include "netlink.h"
#include "acpi-events.h"

struct s_acpi_netlink
{
    struct event event;
    struct nl_sock *sk;

    uint32_t family_id;
    uint32_t multicast_group_id;
};

static struct s_acpi_netlink acpi_netlink =
{
    .sk = NULL,
    .family_id = -1,
    .multicast_group_id = -1
};


static int
netlink_cb(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct nlattr *attrs[ACPI_GENL_ATTR_MAX + 1];
    struct acpi_genl_event *event;

    /* Check it is an ACPI message */
    if (nlh->nlmsg_type != acpi_netlink.family_id)
    {
        xcpmd_log(LOG_ERR, "Netlink message have wrong netlink family id (was %d, expecting %d",
                  nlh->nlmsg_type, acpi_netlink.family_id);
        return 0;
    }

    genlmsg_parse(nlh, 0, attrs, ACPI_GENL_ATTR_MAX, NULL);

    if (!attrs[ACPI_GENL_ATTR_EVENT])
    {
        xcpmd_log(LOG_WARNING, "No event found in Netlink message, dropping it...\n");
        return 0;
    }

    event =(struct acpi_genl_event *) nla_data(attrs[ACPI_GENL_ATTR_EVENT]);

    if (strcmp(event->device_class, ACPI_AC_CLASS) == 0)
        handle_ac_adapter_event(event->type, event->data);
    else if (strcmp(event->device_class, ACPI_BATTERY_CLASS) == 0)
        handle_battery_event(event->type);
    else if (strcmp(event->device_class, ACPI_BUTTON_CLASS) == 0)
        handle_button_event(event->type, event->data);

    return 0;
}


static void
netlink_cb_wrapper(int fd, short event, void *opaque)
{
    nl_recvmsgs_default(acpi_netlink.sk);
}


static int
netlink_get_ids_cb(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct nlattr *attrs[CTRL_ATTR_MAX + 1];
    struct nl_data *data;
    int *cb_result = arg;

    genlmsg_parse(nlh, 0, attrs, CTRL_ATTR_MAX, NULL);

    if (!attrs[CTRL_ATTR_FAMILY_ID])
    {
        *cb_result = 1;
        return 0;
    }

    acpi_netlink.family_id = nla_get_u32(attrs[CTRL_ATTR_FAMILY_ID]);

    if (!attrs[CTRL_ATTR_MCAST_GROUPS])
    {
        *cb_result = 2;
        return 0;
    }

    struct nlattr *multicast_group;
    int unused;

    nla_for_each_nested(multicast_group, attrs[CTRL_ATTR_MCAST_GROUPS], unused)
    {
        struct nlattr *group_attrs[CTRL_ATTR_MCAST_GRP_MAX + 1];

        nla_parse(group_attrs, CTRL_ATTR_MCAST_GRP_MAX,
                  nla_data(multicast_group),
                  nla_len(multicast_group), NULL);

        if (!group_attrs[CTRL_ATTR_MCAST_GRP_NAME] ||
            !group_attrs[CTRL_ATTR_MCAST_GRP_ID])
            continue;

        if (strcmp(nla_data(group_attrs[CTRL_ATTR_MCAST_GRP_NAME]),
                   ACPI_EVENT_MCAST_GROUP_NAME))
            continue;

        acpi_netlink.multicast_group_id =
            nla_get_u32(group_attrs[CTRL_ATTR_MCAST_GRP_ID]);

        return 0;
    }

    *cb_result = 3;
    return 0;;
}


static int
netlink_acpi_ids_init(struct nl_sock *sk)
{
    struct nl_msg *msg;
    int cb_result = 0;

    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, netlink_get_ids_cb, &cb_result);

    msg = nlmsg_alloc();
    genlmsg_put(msg, getpid(), 0, GENL_ID_CTRL, 0, 0, CTRL_CMD_GETFAMILY, 0);
    nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, ACPI_EVENT_FAMILY_NAME);
    nl_send_auto_complete(sk, msg);

    nl_recvmsgs_default(sk);

    nlmsg_free(msg);
    return cb_result;
}


int
netlink_init(void)
{
    int fd, ret;

    acpi_netlink.sk = nl_socket_alloc();
    nl_socket_disable_seq_check(acpi_netlink.sk);

    genl_connect(acpi_netlink.sk);

    ret = netlink_acpi_ids_init(acpi_netlink.sk);
    if (ret != 0)
    {
        xcpmd_log(LOG_ERR, "Netlink ACPI IDs init failed with error code %d\n", ret);
        return 1;
    }

    nl_socket_modify_cb(acpi_netlink.sk, NL_CB_VALID, NL_CB_CUSTOM, netlink_cb, NULL);
    nl_socket_add_membership(acpi_netlink.sk, acpi_netlink.multicast_group_id);

    fd = nl_socket_get_fd(acpi_netlink.sk);

    event_set(&acpi_netlink.event, fd, EV_READ | EV_PERSIST,
              netlink_cb_wrapper, NULL);
    event_add(&acpi_netlink.event, NULL);

    return 0;
}

void
netlink_cleanup(void)
{
    if (acpi_netlink.sk)
    {
        nl_close(acpi_netlink.sk);
        nl_socket_free(acpi_netlink.sk);
    }
}
