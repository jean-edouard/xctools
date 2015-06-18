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
            xenstore_write("1", XS_BATTERY_STATUS_CHANGE_EVENT_PATH);
            notify_com_citrix_xenclient_xcpmd_battery_status_changed(xcdbus_conn, XCPMD_SERVICE, XCPMD_PATH);
            break;
        case ACPI_BATTERY_NOTIFY_INFO: /* add/remove */
            handle_battery_info_change_event();
            break;
        default:
            xcpmd_log(LOG_WARNING, "Unknown battery event code %d\n", type);
    }
}

void
handle_button_event(uint32_t type, uint32_t data)
{
    switch (type)
    {
        case ACPI_BUTTON_TYPE_POWER: /* power button pressed */
            handle_pbtn_pressed_event();
            break;
        case ACPI_BUTTON_TYPE_SLEEP: /* sleep button pressed */
            handle_sbtn_pressed_event();
            break;
        case ACPI_BUTTON_TYPE_LID:   /* lid closed */
            xcpmd_log(LOG_WARNING, "Lid event happened, with data=%d. Doing nothing.\n", data);
	    /* handle_lid_state_change(); */
            break;
        default:
            xcpmd_log(LOG_WARNING, "Unknown button event code %d\n", type);
    }
}
