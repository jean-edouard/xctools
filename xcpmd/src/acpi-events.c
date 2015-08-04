/*
 * acpi-events.c
 *
 * Register for and monitor acpi events and communicate relevant
 * events to ioemu by triggering xenstore events.
 *
 * Copyright (c) 2008 Kamala Narasimhan <kamala.narasimhan@citrix.com>
 * Copyright (c) 2011 Ross Philipson <ross.philipson@citrix.com>
 * Copyright (c) 2011 Citrix Systems, Inc.
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

#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include "project.h"
#include "xcpmd.h"
#include "acpi-events.h"

static int acpi_events_fd = -1;
static struct event acpi_event;

static void write_state_info_in_xenstore(FILE *file, char *xenstore_path,
             char *search_str, char *default_value, char *alternate_value)
{
    char file_data[1024];

    if ( file == NULL )
        return;

    xenstore_write(default_value, xenstore_path);

    memset(file_data, 0, 1024);
    fgets(file_data, 1024, file);
    if (strstr(file_data, search_str))
        xenstore_write(alternate_value, xenstore_path);
}

void initialize_system_state_info(void)
{
    FILE *file;

    file = get_ac_adpater_state_file();
    write_state_info_in_xenstore(file,
                                XS_AC_ADAPTER_STATE_PATH, "0", "1", "0");
    if ( file != NULL )
        fclose(file);
}

static void handle_battery_info_change_event(void)
{
    xcpmd_log(LOG_INFO, "Battery info change event\n");

    if (write_battery_info(NULL) > 0)
        xenstore_write("1", XS_BATTERY_PRESENT);
    else
        xenstore_write("0", XS_BATTERY_PRESENT);

    notify_com_citrix_xenclient_xcpmd_battery_info_changed(xcdbus_conn, XCPMD_SERVICE, XCPMD_PATH);
}

static void handle_pbtn_pressed_event(void)
{
    xcpmd_log(LOG_INFO, "Power button pressed event\n");
    xenstore_write("1", XS_PBTN_EVENT_PATH);
    notify_com_citrix_xenclient_xcpmd_power_button_pressed(xcdbus_conn, XCPMD_SERVICE, XCPMD_PATH);
}

static void handle_sbtn_pressed_event(void)
{
    xcpmd_log(LOG_INFO, "Sleep button pressed event\n");
    xenstore_write("1", XS_SBTN_EVENT_PATH);
    notify_com_citrix_xenclient_xcpmd_sleep_button_pressed(xcdbus_conn, XCPMD_SERVICE, XCPMD_PATH);
}

static void handle_bcl_event(enum BCL_CMD cmd)
{
    int ret, err;

    if ( cmd == BCL_UP )
    {
        xenstore_write("1", XS_BCL_CMD);
	adjust_brightness(1, 0);
    }
    else if ( cmd == BCL_DOWN )
    {
        xenstore_write("2", XS_BCL_CMD);
	adjust_brightness(0, 0);
    }

    xenstore_write("1", XS_BCL_EVENT_PATH);
    notify_com_citrix_xenclient_xcpmd_bcl_key_pressed(xcdbus_conn, XCPMD_SERVICE, XCPMD_PATH);
}

static void process_acpi_message(char *acpi_buffer, ssize_t len)
{
    /* todo this code may be unsafe; account for the actual length read? */

    if ( (strstr(acpi_buffer, "PBTN")) ||
         (strstr(acpi_buffer, "PWRF")) )
    {
        handle_pbtn_pressed_event();
        return;
    }

    if ( (strstr(acpi_buffer, "SBTN")) ||
         (strstr(acpi_buffer, "SLPB")) ) /* On Lenovos */
    {
        handle_sbtn_pressed_event();
        return;
    }

    if ( strstr(acpi_buffer, "video") )
    {
        /* Special HP case, check the device the notification is for */
        if ( (pm_quirks & PM_QUIRK_SW_ASSIST_BCL_HP_SB) &&
             (strstr(acpi_buffer, "DD02") == NULL) )
            return;

        if ( strstr(acpi_buffer, "00000086") )
        {
            handle_bcl_event(BCL_UP);
        }
        else if ( strstr(acpi_buffer, "00000087") )
        {
            handle_bcl_event(BCL_DOWN);
        }
    }
}

void acpi_events_read(void)
{
    char acpi_buffer[1024];
    ssize_t len;

    while ( 1 )
    {
        memset(acpi_buffer, 0, sizeof(acpi_buffer));
        len = recv(acpi_events_fd, acpi_buffer, sizeof(acpi_buffer), 0);

        if ( len == 0 )
            break;

        if ( len == -1 )
        {
            if ( errno != EAGAIN )
                xcpmd_log(LOG_ERR, "Error returned while reading ACPI event - %d\n", errno);
            /* else nothing to read */
            break;
        }

        process_acpi_message(acpi_buffer, len);
#ifdef XCPMD_DEBUG
        acpi_buffer[len] = '\0';
        xcpmd_log(LOG_DEBUG, "~ACPI-event: %s\n", acpi_buffer);
#endif
    }
}

static void
wrapper_acpi_event(int fd, short event, void *opaque)
{
    acpi_events_read();
}


void
handle_ac_adapter_event(uint32_t type, uint32_t data)
{
    if (type != ACPI_AC_NOTIFY_STATUS)
        return;

    xcpmd_log(LOG_INFO, "AC adapter state change event\n");
    xenstore_write_int(data, XS_AC_ADAPTER_STATE_PATH);
    notify_com_citrix_xenclient_xcpmd_ac_adapter_state_changed(xcdbus_conn, XCPMD_SERVICE, XCPMD_PATH);
}


void
handle_battery_event(uint32_t type)
{
    switch (type)
    {
        case ACPI_BATTERY_NOTIFY_STATUS: /* status change */
            /* get_battery_status() will send the dbus signal once the
             * sys nodes actually changed */
            break;
        case ACPI_BATTERY_NOTIFY_INFO: /* add/remove */
            handle_battery_info_change_event();
            break;
        default:
            xcpmd_log(LOG_WARNING, "Unknown battery event code %d\n", type);
    }
}


int acpi_events_initialize(void)
{
    int ret, i, err;
    struct sockaddr_un addr;

    acpi_events_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if ( acpi_events_fd == -1 )
    {
        xcpmd_log(LOG_ERR, "Socket function failed with error - %d\n", errno);
        acpi_events_cleanup();
        return -1;
    }

    ret = file_set_nonblocking(acpi_events_fd);
    if ( ret == -1 )
    {
        xcpmd_log(LOG_ERR, "Set non-blocking failed with error - %d\n", errno);
        acpi_events_cleanup();
        return -1;
    }

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, ACPID_SOCKET_PATH, strlen(ACPID_SOCKET_PATH));
    addr.sun_path[strlen(ACPID_SOCKET_PATH)] = '\0';

    for ( i = 0; ; i++ )
    {
        ret = connect(acpi_events_fd, (struct sockaddr *)&addr, sizeof(addr));

        if ( ret != -1 )
            break;

        if ( i == 5 )
        {
            xcpmd_log(LOG_INFO, "ACPI events initialization failed!\n");
            acpi_events_cleanup();
            return -1;
        }

        xcpmd_log(LOG_ERR, "Socket connection function failed with error - %d, on attempt %d\n",
                  errno, i + 1);

        sleep(5);
    }

    /* register event on acpi socket */
    event_set(&acpi_event, acpi_events_fd, EV_READ | EV_PERSIST,
              wrapper_acpi_event, NULL);
    event_add(&acpi_event, NULL);

    xcpmd_log(LOG_INFO, "ACPI events initialized.\n");

    return 0;
}

void acpi_events_cleanup(void)
{
    xcpmd_log(LOG_INFO, "ACPI events cleanup\n");

    if ( acpi_events_fd != -1 )
        close(acpi_events_fd);

    acpi_events_fd = -1;
}

