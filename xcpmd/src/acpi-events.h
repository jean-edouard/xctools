/*
 * acpi-events.h
 *
 * Various ACPI values from kernel code
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

#ifndef ACPI_EVENTS_H_
#define ACPI_EVENTS_H_

/* From drivers/acpi/ac.c */
#define ACPI_AC_CLASS                   "ac_adapter"
#define ACPI_AC_NOTIFY_STATUS           0x80

/* From drivers/acpi/battery.c */
#define ACPI_BATTERY_CLASS              "battery"
#define ACPI_BATTERY_NOTIFY_STATUS      0x80
#define ACPI_BATTERY_NOTIFY_INFO        0x81

/* From drivers/acpi/button.c */
#define ACPI_BUTTON_CLASS               "button"
#define ACPI_BUTTON_TYPE_POWER          0x01
#define ACPI_BUTTON_TYPE_SLEEP          0x03
#define ACPI_BUTTON_TYPE_LID            0x05

#endif

