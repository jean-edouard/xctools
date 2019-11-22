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
#include "modules.h"
#include "rules.h"
#include "acpi-module.h"
#include "battery.h"

static int acpi_events_fd = -1;
static struct event acpi_event;

static struct ev_wrapper ** acpi_event_table;

void adjust_brightness(int increase, int force) {

    if ( force || (pm_quirks & PM_QUIRK_SW_ASSIST_BCL) || (pm_quirks & PM_QUIRK_HP_HOTKEY_INPUT)) {
        if (increase)
            com_citrix_xenclient_surfman_increase_brightness_(xcdbus_conn, SURFMAN_SERVICE, SURFMAN_PATH);
        else
            com_citrix_xenclient_surfman_decrease_brightness_(xcdbus_conn, SURFMAN_SERVICE, SURFMAN_PATH);
    }
}


int get_ac_adapter_status(void) {

    char data[128];
    FILE *file;
    file = fopen(AC_ADAPTER_STATE_FILE_PATH, "r");

    //If the file doesn't exist, we're not a laptop.
    if (file == NULL && errno == ENOENT)
        return NO_AC;
    else if (file == NULL)
        return AC_UNKNOWN;

    if (fgets(data, sizeof(data), file) == NULL) {
        xcpmd_log(LOG_ERR, "Failed to read " AC_ADAPTER_STATE_FILE_PATH);
    }

    fclose(file);

    if (strstr(data, "0"))
        return ON_BATT;
    else
        return ON_AC;
}


int get_lid_status(void) {

    char data[128];
    const char *state_file;
    FILE * file;

    //Try both lid state paths.
    state_file = LID_STATE_FILE_PATH;
    file = fopen(state_file, "r");

    if (file == NULL && errno == ENOENT) {
        state_file = LID_STATE_FILE_PATH2;
        file = fopen(state_file, "r");
    }

    //If we still don't have a lid, then we're not a laptop.
    if (file == NULL && errno == ENOENT) {
        return NO_LID;
    }
    else if (file == NULL) {
        return LID_UNKNOWN;
    }

    if (fgets(data, sizeof(data), file) == NULL) {
        xcpmd_log(LOG_ERR, "Failed to read %s", state_file);
    }

    fclose(file);

    if (strstr(data, "open"))
        return LID_OPEN;
    else if (strstr(data, "closed"))
        return LID_CLOSED;
    else
        return LID_UNKNOWN;
}


int get_tablet_status(void) {

    //For now, this is a stub.
    return NORMAL_MODE;

}

/*
static void handle_battery_info_event(int battery_index) {

    char path[256];

    struct ev_wrapper * e = battery_info_events[battery_index];
    //xcpmd_log(LOG_DEBUG, "Info change event on battery %d\n", battery_index);

    update_battery_info(battery_index);
    write_battery_info_to_xenstore(battery_index);

    snprintf(path, 255, "%s%i/%s", XS_BATTERY_EVENT_PATH, battery_index, XS_BATTERY_INFO_EVENT_LEAF);
    xenstore_write("1", path);

    notify_com_citrix_xenclient_xcpmd_battery_info_changed(xcdbus_conn, XCPMD_SERVICE, XCPMD_PATH);

    handle_events(e);
}


static void handle_battery_status_event(int battery_index) {

    char path[256];

    struct ev_wrapper * e = battery_status_events[battery_index];
    //xcpmd_log(LOG_DEBUG, "Status change event on battery %d\n", battery_index);

    update_battery_status(battery_index);
    write_battery_status_to_xenstore(battery_index);

    snprintf(path, 255, "%s%i/%s", XS_BATTERY_EVENT_PATH, battery_index, XS_BATTERY_STATUS_EVENT_LEAF);
    xenstore_write("1", path);

    //Here for compatibility--should eventually be removed
    xenstore_write("1", XS_BATTERY_STATUS_CHANGE_EVENT_PATH);

    notify_com_citrix_xenclient_xcpmd_battery_status_changed(xcdbus_conn, XCPMD_SERVICE, XCPMD_PATH);

    handle_events(e);
}
*/


static void handle_lid_event(int status) {

    int lid_status;
    char * lid_status_string;

    struct ev_wrapper * e = acpi_event_table[EVENT_LID];

    //We may have to check the sysfs if the ACPI string didn't tell us the status.
    if (status == LID_UNKNOWN)
        lid_status = get_lid_status();
    else
        lid_status = status;

    switch (lid_status) {
        case LID_OPEN:
            lid_status_string = "open";
            break;
        case LID_CLOSED:
            lid_status_string = "closed";
            break;
        case LID_UNKNOWN:
            lid_status_string = "unknown";
            break;
        case NO_LID:
        default:
            lid_status_string = "no lid";
    }

    xcpmd_log(LOG_INFO, "Lid change event: %s\n", lid_status_string);

    xenstore_write_int(lid_status == LID_CLOSED ? 0 : 1, XS_LID_STATE_PATH);
    xenstore_write("1", XS_LID_EVENT_PATH);
    //notify_com_citrix_xenclient_xcpmd_lid_changed(xcdbus_conn, XCPMD_SERVICE, XCPMD_PATH);

    e->value.i = lid_status;
    handle_events(e);
}


static void handle_power_button_event(void) {

    struct ev_wrapper * e = acpi_event_table[EVENT_PWR_BTN];

    xcpmd_log(LOG_INFO, "Power button pressed event\n");

    xenstore_write("1", XS_PWRBTN_EVENT_PATH);
    notify_com_citrix_xenclient_xcpmd_power_button_pressed(xcdbus_conn, XCPMD_SERVICE, XCPMD_PATH);

    e->value.b = true;
    handle_events(e);

}


static void handle_sleep_button_event(void) {

    struct ev_wrapper * e = acpi_event_table[EVENT_SLP_BTN];

    xcpmd_log(LOG_INFO, "Sleep button pressed event\n");
    xenstore_write("1", XS_SLPBTN_EVENT_PATH);
    notify_com_citrix_xenclient_xcpmd_sleep_button_pressed(xcdbus_conn, XCPMD_SERVICE, XCPMD_PATH);

    e->value.b = true;
    handle_events(e);

}


static void handle_suspend_button_event(void) {

    struct ev_wrapper * e = acpi_event_table[EVENT_SUSP_BTN];

    xcpmd_log(LOG_INFO, "Suspend button pressed event\n");
    xenstore_write("1", XS_SUSPBTN_EVENT_PATH);
    //notify_com_citrix_xenclient_xcpmd_suspend_button_pressed(xcdbus_conn, XCPMD_SERVICE, XCPMD_PATH);

    e->value.b = true;
    handle_events(e);
}


static void handle_bcl_event(enum BCL_CMD cmd) {

    struct ev_wrapper * e = acpi_event_table[EVENT_BCL];

    if (cmd == BCL_UP) {
        xcpmd_log(LOG_INFO, "Brightness up button pressed event\n");
        xenstore_write("1", XS_BCL_CMD);
        xenstore_write("1", XS_BCL_EVENT_PATH);
        adjust_brightness(1, 0);
    }
    else if (cmd == BCL_DOWN) {
        xcpmd_log(LOG_INFO, "Brightness down button pressed event\n");
        xenstore_write("2", XS_BCL_CMD);
        xenstore_write("1", XS_BCL_EVENT_PATH);
        adjust_brightness(0, 0);
    }
    else if (cmd == BCL_CYCLE) {
        //Qemu doesn't currently support this key, but these can be uncommented
        //should this ever be implemented.
        //xenstore_write("3", XS_BCL_CMD);
        //xenstore_write("1", XS_BCL_EVENT_PATH);
    }

    notify_com_citrix_xenclient_xcpmd_bcl_key_pressed(xcdbus_conn, XCPMD_SERVICE, XCPMD_PATH);

    e->value.i = cmd;
    handle_events(e);
}


static void handle_ac_adapter_event(uint32_t data) {

    struct ev_wrapper * e = acpi_event_table[EVENT_ON_AC];

    xenstore_write_int(data, XS_AC_ADAPTER_STATE_PATH);
    notify_com_citrix_xenclient_xcpmd_ac_adapter_state_changed(xcdbus_conn, XCPMD_SERVICE, XCPMD_PATH);

    switch(data) {
        case ACPI_AC_STATUS_OFFLINE:
            e->value.b = ON_BATT;
            xcpmd_log(LOG_INFO, "AC adapter state change event: on battery");
            break;
        case ACPI_AC_STATUS_ONLINE:
            e->value.b = ON_AC;
            xcpmd_log(LOG_INFO, "AC adapter state change event: on AC");
            break;
        case ACPI_AC_STATUS_UNKNOWN:
        default:
            e->value.b = AC_UNKNOWN;
            xcpmd_log(LOG_INFO, "AC adapter state change event: unknown state");
    }

    handle_events(e);
}


static void handle_video_event(void) {

    //For now, this is a stub.
    //xcpmd_log(LOG_DEBUG, "Uncategorized ACPI video event\n");
    return;
}


static void handle_tablet_mode_event(uint32_t data) {

    //Until this can be tested on a convertible device, this is a stub.
    xcpmd_log(LOG_DEBUG, "Tablet mode change event data: %d\n", data);
    return;
}


//Writes the AC adapter state, lid state, and battery information to xenstore
//and initializes stateful evwrappers.
void acpi_initialize_state(void) {

    int ac_adapter_status = get_ac_adapter_status();
    int lid_status = get_lid_status();
    int tablet_status = get_tablet_status();
    char * acpi_status_string = NULL;

    acpi_event_table[EVENT_ON_AC]->value.i = ac_adapter_status;
    acpi_event_table[EVENT_LID]->value.i = lid_status;
    acpi_event_table[EVENT_TABLET_MODE]->value.i = tablet_status;

    switch (ac_adapter_status) {
        case ON_AC:
            xenstore_write_int(1, XS_AC_ADAPTER_STATE_PATH);
            safe_str_append(&acpi_status_string, "System is on AC");
            break;
        case ON_BATT:
        case AC_UNKNOWN:
            xenstore_write_int(0, XS_AC_ADAPTER_STATE_PATH);
            safe_str_append(&acpi_status_string, "System is on battery");
            break;
        case NO_AC:
            xenstore_rm(XS_AC_ADAPTER_STATE_PATH);
            safe_str_append(&acpi_status_string, "System has no removable AC adapter");
    }

    switch (lid_status) {
        case LID_CLOSED:
            xenstore_write_int(0, XS_LID_STATE_PATH);
            safe_str_append(&acpi_status_string, " and the lid is closed.");
            break;
        case LID_OPEN:
        case LID_UNKNOWN:
            xenstore_write_int(1, XS_LID_STATE_PATH);
            safe_str_append(&acpi_status_string, " and the lid is open.");
            break;
        case NO_LID:
            xenstore_rm(XS_LID_STATE_PATH);
            safe_str_append(&acpi_status_string, " and no lid.");
    }
    xcpmd_log(LOG_INFO, "%s\n", acpi_status_string);

    update_batteries();
}


//Calls the appropriate handler for ACPI events.
static void process_acpi_message(char *acpi_buffer, ssize_t len) {

    unsigned int i;
    char *class, *subclass;
    uint32_t type, data;
    char * token;
    char buffer[len + 1];
    char * tokens[16]; //We really shouldn't need this many, but let's be safe.

    //Make a null-terminated copy of acpi_buffer that we can modify with strsplit().
    strncpy(buffer, acpi_buffer, len);
    buffer[len] = '\0';

    //Tokenize the string.
    token = strsplit(buffer, ' ');
    for (i = 0; i < 16; ++i) {
        tokens[i] = token;
        token = strsplit(NULL, ' ');
    }

    //Start parsing those tokens.
    class = tokens[0];
    if (class == NULL) {
        xcpmd_log(LOG_DEBUG, "Received null ACPI message\n");
        return;
    }

    //Get the subclass, if there is one.
    class = strsplit(class, '/');
    subclass = strsplit(NULL, '/');

    //Handle events by device class, with most common events first.
    if (!strcmp(class, ACPI_BATTERY_CLASS)) {

        //Since notifications are not reliable on some platforms, rely on polling for now.

        /*
        if (tokens[1] == NULL) {
            xcpmd_log(LOG_DEBUG, "Battery event with null device\n");
            return;
        }
        if (tokens[2] == NULL) {
            xcpmd_log(LOG_DEBUG, "Battery event with null type\n");
            return;
        }

        device_num = get_terminal_number(tokens[1]);
        if (device_num < 0) {
            xcpmd_log(LOG_DEBUG, "Couldn't find number at end of %s\n", tokens[1]);
            return;
        } else if (device_num > (MAX_BATTERY_SUPPORTED - 1)) {
            xcpmd_log(LOG_DEBUG, "Received battery numbering past MAX_BATTERY_SUPPORTED: %s\n", tokens[1]);
            return;
        }

        if (sscanf(tokens[2], "%x", &type) != 1) {
            xcpmd_log(LOG_DEBUG, "ACPI type field doesn't look like a hex integer: %s\n", tokens[2]);
            return;
        }

        switch(type) {
            case ACPI_BATTERY_NOTIFY_INFO:
                handle_battery_info_event(device_num);
                break;
            case ACPI_BATTERY_NOTIFY_STATUS:
                handle_battery_status_event(device_num);
                break;
            default:
                xcpmd_log(LOG_DEBUG, "Received unhandled battery notify type: %x\n", type);
        }
        */

        return;

    }
    else if (!strcmp(class, ACPI_AC_CLASS)) {

        if (tokens[2] == NULL || tokens[3] == NULL) {
            xcpmd_log(LOG_DEBUG, "Received AC event with null type or data\n");
            return;
        }

        if (sscanf(tokens[2], "%x", &type) != 1) {
            xcpmd_log(LOG_DEBUG, "ACPI type field doesn't look like a hex integer: %s\n", tokens[2]);
            return;
        }
        if (sscanf(tokens[3], "%x", &data) != 1) {
            xcpmd_log(LOG_DEBUG, "ACPI data field doesn't look like a hex integer: %s\n", tokens[3]);
            return;
        }

        if (type == ACPI_AC_NOTIFY_STATUS)
            handle_ac_adapter_event(data);

    }
    else if (!strcmp(class, ACPI_BUTTON_CLASS)) {

        if (subclass == NULL) {
            xcpmd_log(LOG_DEBUG, "Button event with null subclass\n");
            return;
        }

        if (!strcmp(subclass, ACPI_BUTTON_SUBCLASS_LID)) {

            if (tokens[2] == NULL)
                data = LID_UNKNOWN;
            else if (!strcmp(tokens[2], "open"))
                data = LID_OPEN;
            else if (!strcmp(tokens[2], "close"))
                data = LID_CLOSED;
            else
                data = LID_UNKNOWN;

            handle_lid_event(data);
        }
        else if (!strcmp(subclass, ACPI_BUTTON_SUBCLASS_POWER)) {
            handle_power_button_event();
        }
        else if (!strcmp(subclass, ACPI_BUTTON_SUBCLASS_SLEEP)) {
            handle_sleep_button_event();
        }
        else if (!strcmp(subclass, ACPI_BUTTON_SUBCLASS_SUSPEND)) {
            handle_suspend_button_event();
        }
        else
            xcpmd_log(LOG_DEBUG, "Received unknown button subclass: %s\n", subclass);
    }
    else if (!strcmp(class, ACPI_VIDEO_CLASS)) {

        if (subclass == NULL) {
            handle_video_event();
        }
        else if (!strcmp(subclass, ACPI_VIDEO_SUBCLASS_BRTUP)) {
            handle_bcl_event(BCL_UP);
        }
        else if (!strcmp(subclass, ACPI_VIDEO_SUBCLASS_BRTDN)) {
            handle_bcl_event(BCL_DOWN);
        }
        else if (!strcmp(subclass, ACPI_VIDEO_SUBCLASS_BRTCYCLE)) {
            handle_bcl_event(BCL_CYCLE);
        }
        else if (!strcmp(subclass, ACPI_VIDEO_SUBCLASS_TABLETMODE)) {

            if (tokens[3] == NULL) {
                xcpmd_log(LOG_DEBUG, "Tablet mode event with null data field\n");
                return;
            }
            if (sscanf(tokens[3], "%x", &data) != 1) {
                xcpmd_log(LOG_DEBUG, "Tablet mode data field doesn't look like a hex integer: %s\n", tokens[3]);
                return;
            }
            handle_tablet_mode_event(data);
        }
    }
}


static void acpi_events_read(void) {

    char acpi_buffer[1024];
    ssize_t len;

    while ( 1 ) {

        memset(acpi_buffer, 0, sizeof(acpi_buffer));
        len = recv(acpi_events_fd, acpi_buffer, sizeof(acpi_buffer), 0);

        if ( len == 0 )
            break;

        if ( len == -1 ) {
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


static void wrapper_acpi_event(int fd, short event, void *opaque) {
    acpi_events_read();
}


int xcpmd_process_input(int input_value) {

    switch (input_value) {
        case XCPMD_INPUT_SLEEP:
            handle_sleep_button_event();
            break;
        case XCPMD_INPUT_BRIGHTNESSUP:
        case XCPMD_INPUT_BRIGHTNESSDOWN:
            /* Some laptops use input events for brightness */
            if (pm_quirks & (PM_QUIRK_HP_HOTKEY_INPUT | PM_QUIRK_SW_ASSIST_BCL))
                handle_bcl_event(input_value == XCPMD_INPUT_BRIGHTNESSUP ? BCL_UP : BCL_DOWN);
            break;
        default:
            xcpmd_log(LOG_WARNING, "Input invalid value %d\n", input_value);
            break;
    };

#ifdef XCPMD_DEBUG
    xcpmd_log(LOG_DEBUG, "Input value %d processed\n", input_value);
#endif

    return 0;
}


int acpi_events_initialize(void) {

    int ret, i;
    struct sockaddr_un addr;

    acpi_events_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if ( acpi_events_fd == -1 ) {
        xcpmd_log(LOG_ERR, "Socket function failed with error - %d\n", errno);
        acpi_events_cleanup();
        return -1;
    }

    ret = file_set_nonblocking(acpi_events_fd);
    if ( ret == -1 ) {
        xcpmd_log(LOG_ERR, "Set non-blocking failed with error - %d\n", errno);
        acpi_events_cleanup();
        return -1;
    }

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, ACPID_SOCKET_PATH, strlen(ACPID_SOCKET_PATH));
    addr.sun_path[strlen(ACPID_SOCKET_PATH)] = '\0';

    for (i = 0; ; i++) {
        ret = connect(acpi_events_fd, (struct sockaddr *)&addr, sizeof(addr));

        if (ret != -1)
            break;

        if (i == 5) {
            xcpmd_log(LOG_DEBUG, "ACPI events initialization failed!\n");
            acpi_events_cleanup();
            return -1;
        }

        xcpmd_log(LOG_ERR, "Socket connection function failed with error %d, on attempt %d\n", errno, i + 1);
        sleep(5);
    }

    //Register event on acpi socket.
    event_set(&acpi_event, acpi_events_fd, EV_READ | EV_PERSIST, wrapper_acpi_event, NULL);
    event_add(&acpi_event, NULL);


    //Pull in ACPI event tables.
    acpi_event_table = get_event_table(ACPI_EVENTS, MODULE_PATH ACPI_MODULE_SONAME);
    if (acpi_event_table == NULL) {
        xcpmd_log(LOG_ERR, "ACPI events init failed: couldn't load ACPI event table.\n");
        return -1;
    }


    //Set up battery polling.
    //Ideally, we'd use battery status notifications, but several platforms emit
    //notifications before data is ready on a hardware level. If a quirk is added
    //to the battery driver for these platforms, we can move to an event-driven
    //model.
    event_set(&refresh_battery_event, -1, EV_TIMEOUT | EV_PERSIST, wrapper_refresh_battery_event, NULL);
    wrapper_refresh_battery_event(0, 0, NULL);

    //State must be initialized after acpi-module is loaded--call it from main().

    xcpmd_log(LOG_DEBUG, "ACPI events initialized.\n");

    return 0;
}


void acpi_events_cleanup(void) {

    xcpmd_log(LOG_DEBUG, "ACPI events cleanup\n");

    if (acpi_events_fd != -1)
        close(acpi_events_fd);

    acpi_events_fd = -1;
}


void handle_battery_events(void) {

    unsigned int i;
    struct ev_wrapper * info_e   = acpi_event_table[EVENT_BATT_INFO];
    struct ev_wrapper * status_e = acpi_event_table[EVENT_BATT_STATUS];

    for (i=0; i < num_battery_structs_allocd; ++i) {

        info_e->value.i = i;
        status_e->value.i = i;
        handle_events(info_e);
        handle_events(status_e);
    }
}

