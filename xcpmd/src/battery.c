/*
 * battery.c
 *
 * Functions for monitoring system battery state
 *
 * Copyright (c) 2011 Citrix Systems, Inc.
 * Copyright (c) 2015 Assured Information Security, Inc.
 *
 * Authors:
 * Kamala Narasimhan <kamala.narasimhan@citrix.com>
 * Ross Philipson <philipsonr@ainfosec.com>
 * Jennifer Temkin <temkinj@ainfosec.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
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

#include "project.h"
#include "xcpmd.h"
#include "battery.h"
#include "modules.h"
#include <stdlib.h>


//Battery info for consumption by dbus and others
struct battery_info * last_info;
struct battery_status * last_status;
unsigned int num_battery_structs_allocd = 0;

//Event struct for libevent
struct event refresh_battery_event;

static void cleanup_removed_battery(unsigned int battery_index);
static DIR * get_battery_dir(unsigned int battery_index);
static void set_battery_status_attribute(char * attrib_name, char * attrib_value, struct battery_status * status);
static void set_battery_info_attribute(char *attrib_name, char *attrib_value, struct battery_info *info);
static int get_max_battery_index(void);
static unsigned long get_total_charge(void);
static unsigned long get_total_max_charge(void);
static long get_total_charge_rate(void);


//Get the overall warning level of all batteries in the system.
int get_current_battery_level(void) {

    int percentage;

    percentage = get_overall_battery_percentage();

    if (percentage <= BATTERY_CRITICAL_PERCENT)
        return CRITICAL;
    else if (percentage <= BATTERY_LOW_PERCENT)
        return LOW;
    else if (percentage <= BATTERY_WARNING_PERCENT)
        return WARNING;
    else
        return NORMAL;
}


//Returns whether a battery is charging, discharging, full, etc.
int get_battery_charge_state(unsigned int battery_index) {

    unsigned int percent, i;

    if (last_status[battery_index].state & 0x1)
        return BATT_DISCHARGING;
    else if (last_status[battery_index].state & 0x2) {
        // The Dell Venue 11 Pro 7140 reports state = BATT_CHARGING even when it's full.
        if (last_status[battery_index].charge_now == last_info[battery_index].design_capacity) {
            return BATT_FULL;
        }
        else {
            return BATT_CHARGING;
        }
    }
    else {
        /* We're not charging nor discharging... */
        percent = get_battery_percentage(battery_index);
        /* Are we full or empty? */
        if (percent > 90)
            return BATT_FULL;
        else if (percent < 10)
             return BATT_EMPTY;
        else {
            /* Is anybody else (dis)charging? */
            for (i = 0; i < num_battery_structs_allocd; ++i) {
                if (i != battery_index &&
                    last_status[i].present == YES &&
                    (last_status[i].state & 0x1 || last_status[i].state & 0x2)) {
                    break;
                }
            }
            if (i < num_battery_structs_allocd) {
                /* Yes! */
                /* If the other battery is charging, we're pending charge */
                if (last_status[i].state & 0x2)
                    return BATT_PENDING_CHARGE;
                /* If the other battery is discharging, we're pending discharge */
                else if (last_status[i].state & 0x1)
                    return BATT_PENDING_DISCHARGE;
            }
            /* We tried everything, the state is unknown... */
            return BATT_STATE_UNKNOWN;
        }
    }

    return BATT_STATE_UNKNOWN;
}


//Returns whether the system as a whole is charging, discharging, full, or empty.
int get_system_charge_state(void) {

    int percentage = get_overall_battery_percentage();
    long charge_rate = get_total_charge_rate();

    if (get_ac_adapter_status() == ON_AC) {
        if (percentage > 90 || charge_rate == 0) {
            return BATT_FULL;
        }
        else {
            return BATT_CHARGING;
        }
    }
    else {
        if (percentage < 10) {
            return BATT_EMPTY;
        }
        else {
            return BATT_DISCHARGING;
        }
    }
}


//Returns the overall energy flowing in/out of all batteries per hour.
//Positive return values signify that the batteries are charging; negative
//values indicate the batteries are discharging.
static long get_total_charge_rate(void) {

    unsigned int i;
    int state;
    unsigned long rate;
    long total_charge_rate;

    total_charge_rate = 0;

    for (i = 0; i < num_battery_structs_allocd; ++i) {
        if (last_status[i].present == YES) {

            rate = last_status[i].present_rate;
            state = get_battery_charge_state(i);

            if (state == BATT_CHARGING) {
                total_charge_rate += rate;
            }
            else if (state == BATT_DISCHARGING) {
                total_charge_rate -= rate;
            }
        }
    }

    return total_charge_rate;
}


//Returns the total charge of all batteries in the system.
static unsigned long get_total_charge(void) {

    unsigned int i;
    unsigned long charge;
    unsigned long total_charge = 0;

    for (i = 0; i < num_battery_structs_allocd; ++i) {
        if (last_status[i].present == YES) {

            charge = last_status[i].remaining_capacity;

            total_charge += charge;
        }
    }

    return total_charge;
}


//Returns the sum of the maximum charge of all batteries in the system.
static unsigned long get_total_max_charge(void) {

    unsigned int i;
    unsigned long charge;
    unsigned long total_charge = 0;

    for (i = 0; i < num_battery_structs_allocd; ++i) {
        if (last_status[i].present == YES) {

            if (last_info[i].last_full_capacity != 0) {
                charge = last_info[i].last_full_capacity;
            }
            else {
                charge = last_info[i].design_capacity;
            }

            total_charge += charge;
        }
    }

    return total_charge;
}


//Returns an estimate of the time to fully charge the system, in seconds, or
//0 if the system isn't charging.
unsigned int time_to_full(void) {

    long charge_rate;
    unsigned long max_charge, current_charge;
    int charge_time;

    charge_rate = get_total_charge_rate();

    //Return 0 if the system isn't charging.
    if (charge_rate <= 0) {
        return 0;
    }

    max_charge = get_total_max_charge();
    current_charge = get_total_charge();
    charge_time = ((max_charge - current_charge) * 3600) / charge_rate;

    //Correct for systems that report current charge greater than max charge.
    if (charge_time < 0) {
        charge_time = 0;
    }

    return charge_time;
}


//Returns an estimate of the time to fully discharge the system, in seconds, or
//0 if the system isn't discharging.
unsigned int time_to_empty(void) {

    long discharge_rate;
    unsigned long current_charge;
    int discharge_time;

    discharge_rate = -get_total_charge_rate();

    //Return 0 if the system isn't charging.
    if (discharge_rate <= 0) {
        return 0;
    }

    current_charge = get_total_charge();
    discharge_time = (current_charge * 3600) / discharge_rate;

    return discharge_time;
}


//Get the overall battery percentage of the system.
//May return weird values if one battery is mA and the other is mW.
int get_overall_battery_percentage(void) {

    unsigned int percentage;
    unsigned long capacity_left, capacity_total;

    capacity_left = get_total_charge();
    capacity_total = get_total_max_charge();

    //Don't divide by zero.
    if (capacity_total == 0) {
        return 0;
    }
    percentage = ((100 * capacity_left) / capacity_total);

    //Don't report greater than 100% charge.
    if (percentage > 100) {
        percentage = 100;
    }

    return (int)percentage;
}


//Get the specified battery's current charge in percent.
int get_battery_percentage(unsigned int battery_index) {

    unsigned int percentage;
    struct battery_status * status;
    struct battery_info * info;
    unsigned long capacity;

    if (battery_index >= num_battery_structs_allocd)
        return 0;

    if (battery_is_present(battery_index) == NO)
        return 0;

    status = &last_status[battery_index];
    info = &last_info[battery_index];

    //If last_full_capacity isn't available, use design_capacity.
    if (info->last_full_capacity != 0) {
        capacity = info->last_full_capacity;
    }
    else {
        capacity = info->design_capacity;
    }

    //Avoid dividing by zero
    if (capacity == 0) {
        percentage = 0;
    }
    else {
        percentage = status->remaining_capacity * 100 / capacity;
    }

    //Don't report greater than 100% charge.
    if (percentage > 100) {
        percentage = 100;
    }

    return (int)percentage;
}


//Creates a xenstore battery dir with the specified index if it doesn't already exist.
static void make_xenstore_battery_dir(unsigned int battery_index) {

    char xenstore_path[256];
    char ** dir_entries;
    unsigned int num_entries, i;
    bool flag;

    dir_entries = xenstore_ls(&num_entries, "/pm");
    if (!dir_entries) {
        xcpmd_log(LOG_WARNING,
            "Listing directory /pm failed with error `%s'\n", strerror(errno));
        return;
    }

    snprintf(xenstore_path, 255, "%s%i", XS_BATTERY_PATH, battery_index);

    flag = false;
    for (i = 0; i < num_entries; ++i) {
        if (!strcmp(dir_entries[i], xenstore_path)) {
            flag = true;
            break;
        }
    }
    if (!flag)
        xenstore_mkdir("%s", xenstore_path);

    //xenstore_ls() calls malloc(), so be sure to free().
    free(dir_entries);

}


//Returns the directory of a battery at a particular index.
static DIR * get_battery_dir(unsigned int battery_index) {

    DIR *dir = NULL;
    char path[256];

    snprintf(path, 255, "%s/BAT%i", BATTERY_DIR_PATH, battery_index);
    dir = opendir(path);

    return dir;
}


//Returns YES if this battery slot exists and a battery is present in it.
int battery_is_present(unsigned int battery_index) {

    if (battery_index >= num_battery_structs_allocd) {
        return NO;
    }

    if ((battery_slot_exists(battery_index) == YES) &&
       (battery_index < num_battery_structs_allocd) &&
       (last_status[battery_index].present == YES)) {
        return YES;
    }
    else {
        return NO;
    }
}


//Given an attribute name and value, sets the appropriate member of a battery_status struct.
static void set_battery_status_attribute(char * attrib_name, char * attrib_value, struct battery_status * status) {

    if (!strcmp(attrib_name, "status")) {
        //The spec says bit 0 and bit 1 are mutually exclusive
        if ( strstr(attrib_value, "Discharging") )
            status->state |= 0x1;
        else if ( strstr(attrib_value, "Charging") )
            status->state |= 0x2;
    }
    else if (!strcmp(attrib_name, "capacity_level")) {
        if (strstr(attrib_value, "critical"))
            status->state |= 4;
    }
    else if (!strcmp(attrib_name, "current_now")) {
        status->current_now = strtoull(attrib_value, NULL, 10) / 1000;
    }
    else if (!strcmp(attrib_name, "charge_now")) {
        status->charge_now = strtoull(attrib_value, NULL, 10) / 1000;
    }
    else if (!strcmp(attrib_name, "power_now")) {
        status->power_now = strtoull(attrib_value, NULL, 10) / 1000;
    }
    else if (!strcmp(attrib_name, "energy_now")) {
        status->energy_now = strtoull(attrib_value, NULL, 10) / 1000;
    }
    else if (!strcmp(attrib_name, "voltage_now")) {
        status->present_voltage = strtoull(attrib_value, NULL, 10) / 1000;
    }
    else if (!strcmp(attrib_name, "present")) {
        if (strstr(attrib_value, "1"))
            status->present = YES;
    }
}


//Given an attribute name and value, sets the appropriate member of a battery_info struct.
static void set_battery_info_attribute(char *attrib_name, char *attrib_value, struct battery_info *info) {

    if (!strcmp(attrib_name, "present")) {
        if (strstr(attrib_value, "1"))
            info->present = YES;
    }
    else if (!strcmp(attrib_name, "charge_full_design")) {
        info->charge_full_design = strtoull(attrib_value, NULL, 10) / 1000;
    }
    else if (!strcmp(attrib_name, "charge_full")) {
        info->charge_full = strtoull(attrib_value, NULL, 10) / 1000;
    }
    else if (!strcmp(attrib_name, "energy_full_design")) {
        info->energy_full_design = strtoull(attrib_value, NULL, 10) / 1000;
    }
    else if (!strcmp(attrib_name, "energy_full")) {
        info->energy_full = strtoull(attrib_value, NULL, 10) / 1000;
    }
    else if (!strcmp(attrib_name, "voltage_min_design")) {
        info->design_voltage = strtoull(attrib_value, NULL, 10) / 1000;
    }
    else if (!strcmp(attrib_name, "model_name")) {
        pstrcpy(info->model_number, sizeof (info->model_number), attrib_value);
    }
    else if (!strcmp(attrib_name, "serial_number")) {
        pstrcpy(info->serial_number, sizeof (info->serial_number), attrib_value);
    }
    else if (!strcmp(attrib_name, "technology")) {
        if (strstr(attrib_value, "Li-ion"))
            pstrcpy(info->battery_type, sizeof (info->battery_type), "LION\n");
        else if (strstr(attrib_value, "Li-poly"))
            pstrcpy(info->battery_type, sizeof (info->battery_type), "LiP\n");
        else
            pstrcpy(info->battery_type, sizeof (info->battery_type), attrib_value);
        info->battery_technology = RECHARGEABLE;
    }
    else if (!strcmp(attrib_name, "manufacturer")) {
      pstrcpy(info->oem_info, sizeof (info->oem_info), attrib_value);
    }
}


//Gets a battery's status from the sysfs and stores it in last_status.
int update_battery_status(unsigned int battery_index) {

    DIR *battery_dir;
    struct dirent * dp;
    FILE *file;
    char filename[295];
    char data[128];
    char *ptr;

    struct battery_status status;
    memset(&status, 0, sizeof(struct battery_status));

    if (battery_index >= num_battery_structs_allocd)
        return -1;

    if (battery_slot_exists(battery_index) == NO) {
        status.present = NO;
        memcpy(&last_status[battery_index], &status, sizeof(struct battery_status));
        return 1;
    }

    battery_dir = get_battery_dir(battery_index);
    if (!battery_dir) {
        //Battery directory does not exist--this normally occurs when a battery slot is removed
        if (errno == ENOENT) {
            status.present = NO;
            memcpy(&last_status[battery_index], &status, sizeof(struct battery_status));
            return 1;
        }
        else {
            xcpmd_log(LOG_ERR, "opendir in update_battery_status for directory %s/BAT%d failed with error %d\n", BATTERY_DIR_PATH, battery_index, errno);
            return 0;
        }
    }

    //Loop over the files in the directory.
    while ((dp = readdir(battery_dir)) != NULL) {

        //Convert from dirent to file and read out the data.
        if (dp->d_type == DT_REG) {

            snprintf(filename, sizeof (filename), "%s/BAT%u/%s", BATTERY_DIR_PATH, battery_index, dp->d_name);

            file = fopen(filename, "r");
            if (file == NULL)
                continue;

            memset(data, 0, sizeof(data));
            if (fgets(data, sizeof(data), file) == NULL) {
                xcpmd_log(LOG_ERR, "Failed to read %s", filename);
                continue;
            }

            fclose(file);

            //Trim off leading spaces.
            ptr = data;
            while(*ptr == ' ')
                ptr += sizeof(char);

            //Set the attribute represented by this file.
            set_battery_status_attribute(dp->d_name, ptr, &status);
        }
    }

    // This check handles both cases for mA batteries: if are not charging
    // (current_now == 0) but have capacity or the battery is totally dead
    // (charge_now == 0) but it is charging. If both are zero, they will
    // both be zero in the end.
    if (status.charge_now != 0 || status.current_now != 0) {
        // Rate in mA, remaining in mAh
        status.present_rate = status.current_now;
        status.remaining_capacity = status.charge_now;
    }
    else {
        // Rate in mW, remaining in mWh
        status.present_rate = status.power_now;
        status.remaining_capacity = status.energy_now;
    }

    closedir(battery_dir);
    memcpy(&last_status[battery_index], &status, sizeof(struct battery_status));
#ifdef XCPMD_DEBUG
    print_battery_status(battery_index);
#endif
    return 1;
}


//Gets a battery's info from the sysfs and stores it in last_info.
int update_battery_info(unsigned int battery_index) {

    DIR *battery_dir;
    struct dirent * dp;
    FILE *file;
    char filename[295];
    char data[128];
    char *ptr;

    struct battery_info info;
    memset(&info, 0, sizeof(struct battery_info));

    if (battery_index >= num_battery_structs_allocd)
        return 0;

    if (battery_slot_exists(battery_index) == NO) {
        memcpy(&last_info[battery_index], &info, sizeof(struct battery_info));
        return 0;
    }

    battery_dir = get_battery_dir(battery_index);
    if (!battery_dir) {
        xcpmd_log(LOG_ERR, "opendir in update_battery_info() for directory %s/BAT%d failed with error %d\n", BATTERY_DIR_PATH, battery_index, errno);
        return 0;
    }

    //Loop over the files in the directory.
    while ((dp = readdir(battery_dir)) != NULL) {

        //Convert from dirent to file and read out the data.
        if (dp->d_type == DT_REG) {

            memset(filename, 0, sizeof(filename));
            snprintf(filename, sizeof (filename), "%s/BAT%u/%s", BATTERY_DIR_PATH, battery_index, dp->d_name);

            file = fopen(filename, "r");
            if (file == NULL)
                continue;

            memset(data, 0, sizeof(data));
            if (fgets(data, sizeof(data), file) == NULL) {
                xcpmd_log(LOG_ERR, "Failed to read %s", filename);
                continue;
            }

            fclose(file);

            //Trim off leading spaces.
            ptr = data;
            while(*ptr == ' ')
                ptr += sizeof(char);

            //Set the attribute represented by this file.
            set_battery_info_attribute(dp->d_name, ptr, &info);

        }
    }

    //In sysfs, the charge nodes are for batteries reporting in mA and
    //the energy nodes are for mW.
    if (info.charge_full_design != 0) {
        info.power_unit = mA;
        info.design_capacity = info.charge_full_design;
        info.last_full_capacity = info.charge_full;
    }
    else {
        info.power_unit = mW;
        info.design_capacity = info.energy_full_design;
        info.last_full_capacity = info.energy_full;
    }

    //Unlike the old procfs files, sysfs does not report some values like the
    //warn and low levels. These values are generally ignored anyway. The
    //various OS's decide what to do at different depletion levels through
    //their own policies. These are just some approximate values to pass.
    //TODO govern these by policy
    info.design_capacity_warning = info.last_full_capacity * (BATTERY_WARNING_PERCENT / 100);
    info.design_capacity_low = info.last_full_capacity * (BATTERY_LOW_PERCENT / 100);

    info.capacity_granularity_1 = 1;
    info.capacity_granularity_2 = 1;

    closedir(battery_dir);
    memcpy(&last_info[battery_index], &info, sizeof(struct battery_info));

    return 1;
}


//Exactly what it says on the tin.
void write_battery_info_to_xenstore(unsigned int battery_index) {

    if (battery_slot_exists(battery_index) == NO || battery_index >= num_battery_structs_allocd) {
        xcpmd_log(LOG_INFO, "Detected removal of battery slot %d in info.\n", battery_index);
        cleanup_removed_battery(battery_index);
        return;
    }

    struct battery_info * info;
    char bif[1024], string_info[256];

    info = &last_info[battery_index];

    memset(bif, 0, 1024);
    memset(string_info, 0, 256);
    // write 9 dwords (so 9*4) + length of 4 strings + 4 null terminators
    snprintf(bif, 3, "%02x",
             (unsigned int)(9*4 +
                            strlen(info->model_number) +
                            strlen(info->serial_number) +
                            strlen(info->battery_type) +
                            strlen(info->oem_info) + 4));
    write_ulong_lsb_first(bif+2, info->power_unit);
    write_ulong_lsb_first(bif+10, info->design_capacity);
    write_ulong_lsb_first(bif+18, info->last_full_capacity);
    write_ulong_lsb_first(bif+26, info->battery_technology);
    write_ulong_lsb_first(bif+34, info->design_voltage);
    write_ulong_lsb_first(bif+42, info->design_capacity_warning);
    write_ulong_lsb_first(bif+50, info->design_capacity_low);
    write_ulong_lsb_first(bif+58, info->capacity_granularity_1);
    write_ulong_lsb_first(bif+66, info->capacity_granularity_2);

    snprintf(string_info, 256, "%02x%s%02x%s%02x%s%02x%s",
             (unsigned int)strlen(info->model_number), info->model_number,
             (unsigned int)strlen(info->serial_number), info->serial_number,
             (unsigned int)strlen(info->battery_type), info->battery_type,
             (unsigned int)strlen(info->oem_info), info->oem_info);
    strncat(bif+73, string_info, 1024-73-1);

    //Ensure the directory exists before trying to write the leaves
    make_xenstore_battery_dir(battery_index);

    //Now write the leaves.
    xenstore_write(bif, "%s%i/%s", XS_BATTERY_PATH, battery_index, XS_BIF_LEAF);


    //Here for compatibility--will be removed eventually
    if (battery_index == 0)
        xenstore_write(bif, XS_BIF);
    else
        xenstore_write(bif, XS_BIF1);
}


//Exactly what it says on the tin.
void write_battery_status_to_xenstore(unsigned int battery_index) {

    struct battery_status * status;
    char bst[35];
    int num_batteries, current_battery_level;

    if (battery_index >= num_battery_structs_allocd) {
        cleanup_removed_battery(battery_index);
    }

    num_batteries = get_num_batteries_present();
    if (num_batteries == 0) {
        xenstore_write("0", XS_BATTERY_PRESENT);
        return;
    }
    else {
        xenstore_write("1", XS_BATTERY_PRESENT);
    }

    status = &last_status[battery_index];

    //Delete the BST and reset the "present" flag if the battery is not currently present.
    if (status->present != YES) {

        xenstore_rm("%s%i/%s", XS_BATTERY_PATH, battery_index, XS_BST_LEAF);

        xenstore_write("0", "%s%i/%s", XS_BATTERY_PATH, battery_index, XS_BATTERY_PRESENT_LEAF);
        return;
    }

    //Build the BST structure.
    memset(bst, 0, 35);
    snprintf(bst, 3, "%02x", 16);
    write_ulong_lsb_first(bst+2, status->state);
    write_ulong_lsb_first(bst+10, status->present_rate);
    write_ulong_lsb_first(bst+18, status->remaining_capacity);
    write_ulong_lsb_first(bst+26, status->present_voltage);

    //Ensure the directory exists before trying to write the leaves
    make_xenstore_battery_dir(battery_index);

    //Now write the leaves.
    xenstore_write(bst, XS_BATTERY_PATH "%i/" XS_BST_LEAF, battery_index);

    xenstore_write("1", "%s%i/%s", XS_BATTERY_PATH, battery_index, XS_BATTERY_PRESENT_LEAF);

    //Here for compatibility--will be removed eventually
    if (battery_index == 0)
        xenstore_write(bst, XS_BST);
    else
        xenstore_write(bst, XS_BST1);

    current_battery_level = get_current_battery_level();
    if (current_battery_level == NORMAL || get_ac_adapter_status() == ON_AC)
        xenstore_rm(XS_CURRENT_BATTERY_LEVEL);
    else {
        xenstore_write_int(current_battery_level, XS_CURRENT_BATTERY_LEVEL);
        notify_com_citrix_xenclient_xcpmd_battery_level_notification(xcdbus_conn, XCPMD_SERVICE, XCPMD_PATH);
        xcpmd_log(LOG_ALERT, "Battery level below normal - %d!\n", current_battery_level);
    }

#ifdef XCPMD_DEBUG
    xcpmd_log(LOG_DEBUG, "~Updated battery information in xenstore\n");
#endif
}


//Updates status and info of all batteries locally and in the xenstore.
void update_batteries(void) {

    struct battery_status *old_status = NULL;
    struct battery_info *old_info = NULL;
    unsigned int old_num_batteries = 0;
    unsigned int num_batteries = 0;
    unsigned int i, new_array_size, old_array_size, num_batteries_to_update;
    bool present_batteries_changed = false;

    if ( pm_specs & PM_SPEC_NO_BATTERIES )
        return;

    //Keep a copy of what the battery status/info used to be.
    old_status = (struct battery_status *)malloc(num_battery_structs_allocd * sizeof(struct battery_status));
    old_info = (struct battery_info *)malloc(num_battery_structs_allocd * sizeof(struct battery_info));

    if (last_status != NULL)
        memcpy(old_status, last_status, num_battery_structs_allocd * sizeof(struct battery_status));
    else
        memset(old_status, 0, num_battery_structs_allocd * sizeof(struct battery_status));

    if (last_info != NULL)
        memcpy(old_info, last_info, num_battery_structs_allocd * sizeof(struct battery_info));
    else
        memset(old_info, 0, num_battery_structs_allocd * sizeof(struct battery_info));

    old_array_size = num_battery_structs_allocd;


    //Resize the arrays if necessary.
    new_array_size = (unsigned int)(get_max_battery_index() + 1);
    if (new_array_size != old_array_size) {
        if (new_array_size == 0) {
            xcpmd_log(LOG_INFO, "All batteries removed.\n");
            free(last_info);
            free(last_status);
        }
        else {
            last_info = (struct battery_info *)realloc(last_info, new_array_size * sizeof(struct battery_info));
            last_status = (struct battery_status *)realloc(last_status, new_array_size * sizeof(struct battery_status));
            memset(last_info, 0, new_array_size * sizeof(struct battery_info));
            memset(last_status, 0, new_array_size * sizeof(struct battery_status));
        }
        num_battery_structs_allocd = new_array_size;
    }

    num_batteries_to_update = (new_array_size > old_array_size) ? new_array_size : old_array_size;

    //Updating all status/info before writing to the xenstore prevents bad
    //calculations of aggregate data (e.g., warning level).
    for (i=0; i < num_batteries_to_update; ++i) {
        update_battery_status(i);
        update_battery_info(i);
    }

    //Write back to the xenstore and only send notifications if things have changed.
    for (i=0; i < num_batteries_to_update; ++i) {

        //No need to update status/info in Xenstore if there was no battery to begin with.
        //   On some latops, batteries index are not contiguous. It is not a big
        //   deal to have one or two empty array slot, but it should not be
        //   reported as a removed battery (OXT-614).
        if (last_status[i].present || old_status[i].present) {
            write_battery_status_to_xenstore(i);
            write_battery_info_to_xenstore(i);
        }

        if (i < old_array_size && i < new_array_size) {
            if (memcmp(&old_info[i], &last_info[i], sizeof(struct battery_info))) {
                xenstore_write("1", "%s%i/%s", XS_BATTERY_EVENT_PATH, i, XS_BATTERY_INFO_EVENT_LEAF);
            }

            if (memcmp(&old_status[i], &last_status[i], sizeof(struct battery_status))) {
                xenstore_write("1", "%s%i/%s", XS_BATTERY_EVENT_PATH, i, XS_BATTERY_STATUS_EVENT_LEAF);
            }

            if (old_status[i].present == YES)
                ++old_num_batteries;

            if (last_status[i].present == YES)
                ++num_batteries;

            if (old_status[i].present != last_status[i].present)
                present_batteries_changed = true;

        }
        else if (new_array_size > old_array_size) {
            //a battery has been added
            xenstore_write("1", "%s%i/%s", XS_BATTERY_EVENT_PATH, i, XS_BATTERY_INFO_EVENT_LEAF);
            xenstore_write("1", "%s%i/%s", XS_BATTERY_EVENT_PATH, i, XS_BATTERY_STATUS_EVENT_LEAF);

            if (last_status[i].present == YES)
                ++num_batteries;

            if (i < old_array_size) {
                if (old_status[i].present != last_status[i].present)
                    present_batteries_changed = true;
            }
            else {
                if (last_status[i].present == YES)
                    present_batteries_changed = true;
            }
        }
        else if (new_array_size < old_array_size) {
            //a battery has been removed
            xenstore_write("1", "%s%i/%s", XS_BATTERY_EVENT_PATH, i, XS_BATTERY_INFO_EVENT_LEAF);
            xenstore_write("1", "%s%i/%s", XS_BATTERY_EVENT_PATH, i, XS_BATTERY_STATUS_EVENT_LEAF);

            if (old_status[i].present == YES)
                ++old_num_batteries;

            if (i < new_array_size) {
                if (old_status[i].present != last_status[i].present)
                    present_batteries_changed = true;
            }
            else {
                if (old_status[i].present == YES)
                    present_batteries_changed = true;
            }
        }
    }

    if ((old_array_size != new_array_size) || (memcmp(old_info, last_info, new_array_size * sizeof(struct battery_info)))) {
        notify_com_citrix_xenclient_xcpmd_battery_info_changed(xcdbus_conn, XCPMD_SERVICE, XCPMD_PATH);
    }

    if ((old_array_size != new_array_size) || (memcmp(old_status, last_status, new_array_size * sizeof(struct battery_status)))) {
        //Here for compatibility--should eventually be removed
        xenstore_write("1", XS_BATTERY_STATUS_CHANGE_EVENT_PATH);
        notify_com_citrix_xenclient_xcpmd_battery_status_changed(xcdbus_conn, XCPMD_SERVICE, XCPMD_PATH);
    }

    if (present_batteries_changed) {
        notify_com_citrix_xenclient_xcpmd_num_batteries_changed(xcdbus_conn, XCPMD_SERVICE, XCPMD_PATH);
    }

    free(old_info);
    free(old_status);
}


//Counts the number of battery slots in the sysfs.
int get_num_batteries(void) {

    int count = 0;
    DIR * dir;
    struct dirent * dp;

    dir = opendir(BATTERY_DIR_PATH);
    if (!dir) {
        xcpmd_log(LOG_ERR, "opendir in get_num_batteries failed for directory %s with error %d\n", BATTERY_DIR_PATH, errno);
        return 0;
    }

    //Count all entries whose names start with BAT.
    while ((dp = readdir(dir)) != NULL) {
        if (!strncmp(dp->d_name, "BAT", 3)) {
            ++count;
        }
    }

    closedir(dir);

    return count;
}


//Finds the maximum battery index that exists in the sysfs.
static int get_max_battery_index(void) {

    int max_index, index;
    DIR * dir;
    struct dirent * dp;

    dir = opendir(BATTERY_DIR_PATH);
    if (!dir) {
        xcpmd_log(LOG_ERR, "opendir in get_max_battery_index failed for directory %s with error %d\n", BATTERY_DIR_PATH, errno);
        return -1;
    }

    max_index = -1;
    while ((dp = readdir(dir)) != NULL) {
        if (!strncmp(dp->d_name, "BAT", 3)) {
            index = get_terminal_number(dp->d_name);
            if (index > -1 && index > max_index) {
                max_index = index;
            }
        }
    }

    closedir(dir);

    return max_index;
}


//Counts the number of batteries present in the sysfs.
int get_num_batteries_present(void) {

    int count;
    DIR * dir;
    struct dirent * dp;
    FILE * file;
    char data[128];
    char filename[289];

    dir = opendir(BATTERY_DIR_PATH);
    if (!dir) {
        xcpmd_log(LOG_ERR, "opendir in get_num_batteries_present() failed for directory %s with error %d\n", BATTERY_DIR_PATH, errno);
        return 0;
    }

    //Check all /sys/class/power_supply/BAT*/present.
    count = 0;
    while ((dp = readdir(dir)) != NULL) {

        if (!strncmp(dp->d_name, "BAT", 3)) {
            snprintf(filename, sizeof (filename), "%s/%s/present", BATTERY_DIR_PATH, dp->d_name);
            file = fopen(filename, "r");
            if (file == NULL)
                continue;

            if (fgets(data, sizeof(data), file) == NULL) {
                xcpmd_log(LOG_ERR, "Failed to read %s", filename);
                continue;
            }

            fclose(file);

            if (strstr(data, "1")) {
                ++count;
            }
        }
    }

    closedir(dir);

    return count;
}


//Remove a battery's entries from the xenstore.
static void cleanup_removed_battery(unsigned int battery_index) {

    xenstore_rm("%s%d", XS_BATTERY_PATH, battery_index);

    if (battery_index > 0) {
        xenstore_rm(XS_BST1);
        xenstore_rm(XS_BIF1);
    }
    else {
        xenstore_rm(XS_BST);
        xenstore_rm(XS_BIF);
    }

    if (get_num_batteries_present() == 0)
        xenstore_write("0", XS_BATTERY_PRESENT);
    else
        xenstore_write("1", XS_BATTERY_PRESENT);
}


//Checks the sysfs to see if a battery slot exists in the sysfs at the specified index.
int battery_slot_exists(unsigned int battery_index) {

    DIR * dir;
    char path[256];

    snprintf(path, 255, "%s/BAT%d", BATTERY_DIR_PATH, battery_index);
    dir = opendir(path);
    if (!dir) {
        return NO;
    }
    closedir(dir);

    return YES;
}


//Updates battery info/status and schedules itself to run again in 4 seconds.
void wrapper_refresh_battery_event(int fd, short event, void *opaque) {

    struct timeval tv;
    memset(&tv, 0, sizeof(tv));

    update_batteries();

    tv.tv_sec = 4;
    evtimer_add(&refresh_battery_event, &tv);
}
