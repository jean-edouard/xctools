/*
 *
 * Copyright (C) 2015 Assured Information Security, Chris Patterson <pattersonc@ainfosec.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _ATAPI_PT_ARGO_H_
#define _ATAPI_PT_ARGO_H_

typedef enum {
    ATAPI_PT_LOCK_STATE_UNLOCKED         = 0x00,
    ATAPI_PT_LOCK_STATE_LOCKED_BY_ME     = 0x01,
    ATAPI_PT_LOCK_STATE_LOCKED_BY_OTHER  = 0x02,
} atapi_pt_lock_state_t;

typedef enum {
    ATAPI_PTARGO_OPEN                     = 0x00,
    ATAPI_PTARGO_SG_IO                    = 0x01,
    ATAPI_PTARGO_SG_GET_RESERVED_SIZE     = 0x02,
    ATAPI_PTARGO_ACQUIRE_LOCK             = 0x03,
    ATAPI_PTARGO_RELEASE_LOCK             = 0x04,
} atapi_ptargo_cmd_t;

typedef struct {
    uint8_t cmd; /* ATAPI_PTARGO_OPEN */
    uint8_t device_id;
    char device_path[256];
} __attribute__((packed)) pt_argocmd_open_request_t;

typedef struct {
    uint8_t cmd; /* ATAPI_PTARGO_OPEN */
    uint8_t device_id;
} __attribute__((packed)) pt_argocmd_open_response_t;

typedef struct {
    uint8_t cmd; /* ATAPI_PTARGO_ACQUIRE_LOCK */
    uint8_t device_id;
} __attribute__((packed)) pt_argocmd_acquire_lock_request_t;

typedef struct {
    uint8_t cmd; /* ATAPI_PTARGO_ACQUIRE_LOCK */
    uint8_t device_id;
    uint8_t lock_state; /* atapi_pt_lock_state_t */
} __attribute__((packed)) pt_argocmd_acquire_lock_response_t;

typedef struct {
    uint8_t cmd; /* ATAPI_PTARGO_RELEASE_LOCK */
    uint8_t device_id;
} __attribute__((packed)) pt_argocmd_release_lock_request_t;

typedef struct {
    uint8_t cmd; /* ATAPI_PTARGO_SG_GET_RESERVED_SIZE */
    uint8_t device_id;
} __attribute__((packed)) pt_argocmd_sg_get_reserved_size_request_t;

typedef struct {
    uint8_t cmd; /* ATAPI_PTARGO_SG_GET_RESERVED_SIZE */
    uint8_t device_id;
    uint32_t size;
} __attribute__((packed)) pt_argocmd_sg_get_reserved_size_response_t;

typedef struct {
    uint8_t cmd; /* ATAPI_PTARGO_SG_IO */
    uint8_t device_id;
    struct sg_io_v4 sgio;
    uint8_t request_data[12]; /* ATAPI_PACKET_SIZE */
    uint32_t dout_data_len;
    uint8_t dout_data[];
} __attribute__((packed)) pt_argocmd_sg_io_request_t;

typedef struct {
    uint8_t cmd; /* ATAPI_PTARGO_SG_IO */
    uint8_t device_id;
    struct sg_io_v4 sgio;
    uint8_t sense_data[64]; /* struct request_sense */
    uint32_t din_data_len;
    uint8_t din_data[];
} __attribute__((packed)) pt_argocmd_sg_io_response_t;

#endif /* !_ATAPI_PT_ARGO_H_ */
