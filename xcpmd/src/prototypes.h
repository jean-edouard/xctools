/*
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

/* xcpmd.c */

/* acpi-events.c */
int xcpmd_process_input(int input_value);
void adjust_brightness(int increase, int force);
int get_ac_adapter_status(void);
int get_lid_status(void);
int acpi_events_initialize(void);
void acpi_events_cleanup(void);
void acpi_initialize_state(void);

/* platform.c */
extern uint32_t pm_quirks;
extern uint32_t pm_specs;
void initialize_platform_info(void);

/* version.c */

/* rpcgen/xcpmd_server_obj.c */
XcpmdObject *xcpmd_create_glib_obj(void);
XcpmdObject *xcpmd_export_dbus(DBusGConnection *conn, const char *path);

/* xcpmd-dbus-server.c */
gboolean xcpmd_battery_time_to_empty(XcpmdObject *this, guint IN_bat_n, guint *OUT_time_to_empty, GError **error);
gboolean xcpmd_battery_time_to_full(XcpmdObject *this, guint IN_bat_n, guint *OUT_time_to_full, GError **error);
gboolean xcpmd_battery_percentage(XcpmdObject *this, guint IN_bat_n, guint *OUT_percentage, GError **error);
gboolean xcpmd_battery_is_present(XcpmdObject *this, guint IN_bat_n, gboolean *OUT_is_present, GError **error);
gboolean xcpmd_battery_state(XcpmdObject *this, guint IN_bat_n, guint *OUT_state, GError **error);
gboolean xcpmd_get_ac_adapter_state(XcpmdObject *this, guint *ac_ret, GError **);
gboolean xcpmd_get_current_battery_level(XcpmdObject *this, guint *battery_level, GError **);
gboolean xcpmd_get_current_temperature(XcpmdObject *this, guint *cur_temp_ret, GError **);
gboolean xcpmd_get_critical_temperature(XcpmdObject *this, guint *crit_temp_ret, GError **);
gboolean xcpmd_get_bif(XcpmdObject *this, char **bif_ret, GError **);
gboolean xcpmd_get_bst(XcpmdObject *this, char **bst_ret, GError **);
gboolean xcpmd_indicate_input(XcpmdObject *this, gint input_value, GError **);
gboolean xcpmd_hotkey_switch(XcpmdObject *this, const gboolean reset, GError **);
int xcpmd_dbus_initialize(void);
void xcpmd_dbus_cleanup(void);

/* utils.c */
int strnicmp(const char *s1, const char *s2, size_t len);
int get_terminal_number(char * str);
char * strsplit(char * str, char delim);
char * clone_string(char * str);
char * safe_sprintf(char * format, ...);
void safe_str_append(char ** str1, char * format, ...);
void pstrcpy(char *dst, int size, const char *src);
void write_ulong_lsb_first(char *temp_val, unsigned long val);
int file_set_blocking(int fd);
int file_set_nonblocking(int fd);
int find_efi_entry_location(const char *efi_entry, uint32_t length, size_t *location);
int pci_lib_init(void);
uint32_t pci_host_read_dword(int bus, int dev, int fn, uint32_t addr);
void pci_lib_cleanup(void);
uint8_t *map_phys_mem(size_t phys_addr, size_t length);
void unmap_phys_mem(uint8_t *addr, size_t length);
unsigned int xenstore_read_uint(char *path);
void daemonize(void);
