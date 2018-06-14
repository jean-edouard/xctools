/*
 * xcpmd.c
 *
 * XenClient platform management daemon
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

/*
 * $Log:$
 */

/* Xen extended power management support provides HVM guest power management
 * features beyond S3, S4, S5.  For example, it helps expose system level
 * battery status and battery meter information and in future will be extended
 * to include more power management support.  This extended power management
 * support is enabled by setting xen_extended_power_mgmt to 1 or 2 in the HVM
 * config file.  When set to 2, non-pass through mode is enabled which heavily
 * relies on this power management daemon to glean battery information from
 * dom0 and store it xenstore which would then be queries and used by qemu and
 * passed to the guest when appropriate battery ports are read/written to.
 */

#include "project.h"
#include "xcpmd.h"
#include "modules.h"
#include "rules.h"


void sighandler_term(int signal, short event, void *base)
{
    (void) signal;
    (void) event;
    event_base_loopbreak(base);
}

int main(int argc, char *argv[]) {

    int ret = 0;
    struct event ev_sigterm;
    struct event_base *ev_base;

#ifndef RUN_STANDALONE
    openlog("xcpmd", 0, LOG_DAEMON);
    daemonize();
#endif

    xcpmd_log(LOG_INFO, "Starting XenClient power management daemon.\n");

    //Initialize libevent library
    ev_base = event_init();

    //SIGTERM handler.
    evsignal_set(&ev_sigterm, SIGTERM, sighandler_term, ev_base);
    evsignal_add(&ev_sigterm, NULL);

    //Initialize xenstore.
    if (xenstore_init() == -1) {
        xcpmd_log(LOG_ERR, "Unable to init xenstore\n");
        return -1;
    }

    // Allow everyone to read from /pm/ in xenstore
    xenstore_rm("/pm");
    xenstore_mkdir("/pm");
    xenstore_chmod("r0", 1, "/pm");

    initialize_platform_info();


    xcpmd_log(LOG_INFO, "Starting DBUS server.\n");
    if (xcpmd_dbus_initialize() == -1) {
        xcpmd_log(LOG_ERR, "Failed to initialize DBUS server\n");
        goto xcpmd_err;
    }

    xcpmd_log(LOG_INFO, "Starting ACPI events monitor.\n");
    if (acpi_events_initialize() == -1) {
        xcpmd_log(LOG_ERR, "Failed to initialize ACPI events monitor\n");
        goto xcpmd_err;
    }

    // Load modules
    xcpmd_log(LOG_INFO, "Loading modules.\n");
    if (init_modules() == -1) {
        xcpmd_log(LOG_ERR, "Failed to load all modules\n");
        goto xcpmd_err;
    }

    //This relies on both acpi-events and acpi-module having been initialized
    xcpmd_log(LOG_INFO, "Initializing ACPI state.\n");
    acpi_initialize_state();

    // Load policy
    xcpmd_log(LOG_INFO, "Loading policy.\n");
    if (load_policy_from_db() == -1) {
        xcpmd_log(LOG_WARNING, "Error loading policy from DB; continuing...\n");
    }

#ifdef POLICY_FILE_PATH
    if (!policy_exists()) {
        xcpmd_log(LOG_INFO, "No DB policy found; loading default policy from %s.\n", POLICY_FILE_PATH);
        if (load_policy_from_file(POLICY_FILE_PATH) == -1) {
            xcpmd_log(LOG_WARNING, "Error loading policy from file %s; continuing...\n", POLICY_FILE_PATH);
        }
    }
#endif

#ifdef XCPMD_DEBUG
    xcpmd_log(LOG_DEBUG, "Rules loaded:\n");
    print_rules();
#endif

    //Initial rule evaluation
    evaluate_policy();

    xcpmd_log(LOG_INFO, "Entering event loop.\n");
    event_dispatch();

    goto xcpmd_out;

xcpmd_err:
    ret = -1;
xcpmd_out:
    uninit_modules();
    acpi_events_cleanup();
    xcpmd_dbus_cleanup();
#ifndef RUN_STANDALONE
    closelog();
#endif
    unlink(XCPMD_PID_FILE);

    return ret;
}
