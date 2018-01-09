/*
 * Copyright (c) 2015 Assured Information Security, Chris Patterson <pattersonc@ainfosec.com>
 * Copyright (c) 2014 Citrix Systems, Inc.
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


#include "project.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <linux/cdrom.h>
#include <linux/fd.h>
#include <linux/fs.h>
#include <linux/cdrom.h>
#include <linux/bsg.h>
#include <scsi/sg.h>
#include <syslog.h>

#include "atapi_pt_v4v.h"

static int pt_log_level = 0;

/**
 * PT_LOG: information to always log (errors & important low-volume events)
 * @param fmt,... printf style arguments
 */
#define PT_LOG(fmt, ...)                                           \
do {                                                               \
        syslog(LOG_NOTICE, "[%s:%s:%d] (stubdom-%d) " fmt,          \
               __FILE__, __FUNCTION__, __LINE__, g_hs.stubdom_id,  \
                 ##__VA_ARGS__);                                   \
    } while (0)

/**
 * PT_VERBOSE: verbose level
 * @param fmt,... printf style arguments
 */
#define PT_VERBOSE(fmt, ...)                                             \
    do {                                                               \
        if (pt_log_level >= 1)                                       \
            PT_LOG(fmt, ## __VA_ARGS__);                                  \
    } while (0)

/**
 * PT_DEBUG: debug level
 * @param fmt,... printf style arguments
 */
#define PT_DEBUG(fmt, ...)                                             \
    do {                                                               \
        if (pt_log_level >= 2)                                       \
            PT_LOG(fmt, ## __VA_ARGS__);                                  \
    } while (0)

#define V4V_TYPE 'W'
#define V4VIOCSETRINGSIZE       _IOW (V4V_TYPE,  1, uint32_t)

#define ATAPI_CDROM_PORT 5000

#define V4V_ATAPI_PT_RING_SIZE \
  (V4V_ROUNDUP((((4096)*64) - sizeof(v4v_ring_t)-V4V_ROUNDUP(1))))

#define MAX_V4V_MSG_SIZE (V4V_ATAPI_PT_RING_SIZE)

#define MAX_ATAPI_PT_DEVICES 6
typedef struct ATAPIPTDeviceState {
    /* device "slot" for indicating device */
    int device_id;
    int device_fd;
    char device_path[256];
    int device_addr_a;
    int device_addr_b;
    int device_addr_c;
    int device_addr_d;

    char lock_file_path[256];
    int lock_fd;
    uint32_t lock_state;
} ATAPIPTDeviceState;

typedef struct ATAPIPTHelperState {
    int v4v_fd;
    v4v_addr_t remote_addr;
    v4v_addr_t local_addr;
    int stubdom_id;
    ATAPIPTDeviceState devices[MAX_ATAPI_PT_DEVICES];
} ATAPIPTHelperState;

/* global helper state */
static ATAPIPTHelperState g_hs;

#if 0
static void dump_hex(uint8_t* p, size_t len)
{
  int i, j;

  for (i = 0; i < len; i += 16) {
    for (j = 0; (j < 16) && ((i + j) < len); j++) {
      fprintf(stderr, "%02x ", p[i+j]);
    }
    for (; j < 16; j++) {
      fprintf(stderr, "   ");
    }
    fprintf(stderr, " ");
    for (j = 0; (j < 16) && ((i + j) < len); j++) {
      fprintf(stderr, "%c", ((p[i+j] < ' ') || (p[i+j] > 0x7e)) ? '.' : p[i+j]);
    }
    fprintf(stderr, "\n");
  }
}
#endif

static int pending_exit = 0;

/**
 * Time to bail! Will call exit() with exit_code.
 * @param[in] exit_code
 */
static void exit_cleanup(int exit_code)
{
    int i;

    pending_exit = 1;

    /* close all devices */
    for (i = 0; i < MAX_ATAPI_PT_DEVICES; i++) {
        ATAPIPTDeviceState *ds = &g_hs.devices[i];
        if (ds->device_path[0] == 0) {
            /* device_path is blank, this slot is empty */
            continue;
        }
        if (ds->device_fd >= 0) {
            close(ds->device_fd);
            ds->device_fd = -1;
        }
        if (ds->lock_fd >= 0) {
            close(ds->lock_fd);
            ds->lock_fd = -1;
        }
    }

    /* close v4v channel to stubdom */
    v4v_close(g_hs.v4v_fd);
    g_hs.v4v_fd = -1;

    /* close syslog */
    closelog();

    /* time to bail */
    exit(exit_code);
}

/**
 * Grabs global exclusive lock.
 * @param[in] ds
 * @returns 1 if lock held, 0 otherwise
 */
static int acquire_global_lock(ATAPIPTDeviceState *ds)
{
    struct flock lock = {0};

    if (ds->lock_state == ATAPI_PT_LOCK_STATE_LOCKED_BY_ME) {
        /* already have lock */
        return 1;
    }

    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;

    if (fcntl(ds->lock_fd, F_SETLK, &lock) == 0) {
        PT_LOG("locked by me: %s\n", ds->device_path);
        ds->lock_state = ATAPI_PT_LOCK_STATE_LOCKED_BY_ME;
        return 1;
    }

    PT_LOG("locked by other: %s\n", ds->device_path);
    ds->lock_state = ATAPI_PT_LOCK_STATE_LOCKED_BY_OTHER;
    return 0;
}

/**
 * Releases global exclusive lock.
 * @param[in] ds
 */
static void release_global_lock(ATAPIPTDeviceState *ds)
{
    struct flock lock = {0};

    if (ds->lock_state != ATAPI_PT_LOCK_STATE_LOCKED_BY_ME) {
        /* we don't have the lock, nothing to do */
        return;
    }

    lock.l_type = F_UNLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;

    fcntl(ds->lock_fd, F_SETLK, &lock);

    ds->lock_state = ATAPI_PT_LOCK_STATE_UNLOCKED;

    PT_LOG("released lock: %s\n", ds->device_path);
}

/**
 * Initializes device state if device not already opened.
 * @param[in] device_path File path to device (e.g. /dev/bsg/1:0:0:0)
 * @returns Pointer to device state, otherwise NULL on error.
 */
static ATAPIPTDeviceState *init_device_state(ATAPIPTHelperState *hs,
                                             const char *device_path)
{
    ATAPIPTDeviceState *ds = NULL;
    int i;

    if (!device_path) {
        return NULL;
    }

    for (i = 0; i < MAX_ATAPI_PT_DEVICES; i++) {
        ds = &hs->devices[i];
        if (ds->device_path[0] == 0) {
            /* device_path is blank, this slot is free to use */
            break;
        }
        if (strcmp(hs->devices[i].device_path, device_path) == 0) {
            /* found matching device already open */
            return ds;
        }
    }

    if (i == MAX_ATAPI_PT_DEVICES) {
        /* no available slots */
        PT_LOG("error: ran out of slots!\n");
        return NULL;
    }

    /* before we register - parse path & make sure it is legit */
    if (sscanf(device_path, "/dev/bsg/%d:%d:%d:%d", &ds->device_addr_a,
                                                 &ds->device_addr_b,
                                                 &ds->device_addr_c,
                                                 &ds->device_addr_d) != 4) {
        PT_LOG("error: invalid device path: %s!\n", ds->device_path);
        return NULL;
    }

    snprintf(ds->device_path, sizeof(ds->device_path), "/dev/bsg/%d:%d:%d:%d",
             ds->device_addr_a, ds->device_addr_b,
             ds->device_addr_c, ds->device_addr_d);

    /* make sure the device path is what we think it is */
    if (strcmp(device_path, ds->device_path) != 0) {
        PT_LOG("error: bad path: %s vs %s\n", device_path, ds->device_path);
        return NULL;
    }

    /* open descriptor to device */
    ds->device_fd = open(device_path, O_RDWR | O_NONBLOCK);
    if (ds->device_fd < 0) {
        PT_LOG("error: unable to open device path: %s!\n", device_path);
        return NULL;
    }

    /* set device id (index into devices) */
    ds->device_id = i;

    snprintf(ds->lock_file_path, sizeof(ds->lock_file_path),
          "/var/lock/xen-atapi-pt-lock-%d_%d_%d_%d",
          ds->device_addr_a,
          ds->device_addr_b,
          ds->device_addr_c,
          ds->device_addr_d);


    /* open lock file */
    ds->lock_fd = open(ds->lock_file_path, O_RDWR | O_CREAT, 0666);
    if (ds->lock_fd < 0) {
        PT_LOG("error: unable to open lock file: %s!\n", ds->lock_file_path);
        close(ds->device_fd);
        ds->device_fd = -1;
        return NULL;
    }

    /* assume unlocked for init - doesn't have to be true */
    ds->lock_state = ATAPI_PT_LOCK_STATE_UNLOCKED;

    return ds;
}

/**
 * Initializes helper state.
 * @param[in] hs
 * @returns 0 on succes, otherwise -1.
 */
static int init_helper_state(ATAPIPTHelperState *hs)
{
    uint32_t v4v_ring_size = V4V_ATAPI_PT_RING_SIZE;

    hs->v4v_fd = v4v_socket(SOCK_DGRAM);

    if (hs->v4v_fd == -1) {
        PT_LOG("unable to create a v4vsocket");
        return -1;
    }

    hs->local_addr.port = ATAPI_CDROM_PORT;
    hs->local_addr.domain = V4V_DOMID_ANY;

    hs->remote_addr.port = V4V_PORT_NONE;
    hs->remote_addr.domain = hs->stubdom_id;

    ioctl(hs->v4v_fd, V4VIOCSETRINGSIZE, &v4v_ring_size);
    if (v4v_bind(hs->v4v_fd, &hs->local_addr, hs->stubdom_id) == -1) {
        PT_LOG("unable to bind the v4vsocket");
        v4v_close(hs->v4v_fd);
        hs->v4v_fd = -1;
        return -1;
    }

    return 0;
}

/**
 * Sends v4v message to stubdom.
 * @param[in] hs
 * @param[in] buf: message to send
 * @param[in] size: size of buf
 * @returns true if message sent successfully, false otherwise.
 */
static bool pt_v4v_send_message(ATAPIPTHelperState* hs, void *buf, size_t size)
{
    int ret;

    ret = v4v_sendto(hs->v4v_fd, buf, size, 0, &hs->remote_addr);

    if (ret != size) {
        return false;
    }

    return true;
}

/**
 * Provides pointer to device state from a device id.
 * @param[in] device_id: Device ID
 * @returns Pointer to device state if valid device id, NULL otherwise.
 */
static ATAPIPTDeviceState * device_id_to_device_state(ATAPIPTHelperState* hs,
                                                      uint8_t device_id)
{
    ATAPIPTDeviceState *ds;

    if (device_id < 0 || device_id >= MAX_ATAPI_PT_DEVICES) {
        return NULL;
    }

    ds = &hs->devices[device_id];

    if (ds->device_path[0] == 0) {
        /* device_path is blank, this slot is invalid */
        return NULL;
    }

    return ds;
}

/**
 * Handles ATAPI_PTV4V_OPEN command from qemu stubdom.
 * @param[in] hs: Helper state pointer.
 * @param[in] buf: Data packet received from qemu.
 * @param[in] len: Length of data packet received.
 * @returns 0 on success, -1 on errror.
 */
static int atapi_ptv4v_open(ATAPIPTHelperState *hs, uint8_t *buf, size_t len)
{
    pt_v4vcmd_open_request_t *request = (pt_v4vcmd_open_request_t *)buf;
    pt_v4vcmd_open_response_t response;
    ATAPIPTDeviceState *ds;

    if (len != sizeof(*request)) {
        PT_LOG("error: mismatch buffer size %lu vs %lu", len, sizeof(*request));
        return -1;
    }

    ds = init_device_state(hs, request->device_path);
    if (!ds) {
        PT_LOG("error: unable to open device path!\n");
        return -1;
    }

    response.cmd = ATAPI_PTV4V_OPEN;
    response.device_id = ds->device_id;

    PT_LOG("opened %s - id = %d\n", ds->device_path, ds->device_id);

    if (!pt_v4v_send_message(hs, &response, sizeof(response))) {
        PT_LOG("error: failed to send a message to %s", ds->device_path);
        return -1;
    }

    return 0;
}

/**
 * Handles ATAPI_PTV4V_ACQUIRE_LOCK command from qemu stubdom.
 * @param[in] hs: Helper state pointer.
 * @param[in] buf: Data packet received from qemu.
 * @param[in] len: Length of data packet received.
 * @returns 0 on success, -1 on errror.
 */
static int atapi_ptv4v_acquire_lock(ATAPIPTHelperState* hs, uint8_t *buf,
                                    size_t len)
{
    pt_v4vcmd_acquire_lock_request_t *request;
    pt_v4vcmd_acquire_lock_response_t response;
    ATAPIPTDeviceState *ds;

    request = (pt_v4vcmd_acquire_lock_request_t *)buf;

    if (len != sizeof(*request)) {
        PT_LOG("error: mismatch buffer size %lu vs %lu", len, sizeof(*request));
        return -1;
    }

    ds = device_id_to_device_state(hs, request->device_id);
    if (ds == NULL) {
        PT_LOG("error: invalid device id!\n");
        return -1;
    }

    acquire_global_lock(ds);

    response.cmd = ATAPI_PTV4V_ACQUIRE_LOCK;
    response.device_id = ds->device_id;
    response.lock_state = ds->lock_state;

    PT_LOG("acquire lock for %s = %d\n", ds->device_path, ds->lock_state);

    if (!pt_v4v_send_message(hs, &response, sizeof(response))) {
        PT_LOG("error: failed to send a message to %s", ds->device_path);
        return -1;
    }

    return 0;
}

/**
 * Handles ATAPI_PTV4V_RELEASE_LOCK command from qemu stubdom.
 * @param[in] hs: Helper state pointer.
 * @param[in] buf: Data packet received from qemu.
 * @param[in] len: Length of data packet received.
 * @returns 0 on success, -1 on errror.
 */
static int atapi_ptv4v_release_lock(ATAPIPTHelperState* hs, uint8_t *buf,
                                    size_t len)
{
    pt_v4vcmd_release_lock_request_t *request;
    ATAPIPTDeviceState *ds;

    request = (pt_v4vcmd_release_lock_request_t *)buf;

    if (len != sizeof(*request)) {
        PT_LOG("error: mismatch buffer size %lu vs %lu", len, sizeof(*request));
        return -1;
    }

    ds = device_id_to_device_state(hs, request->device_id);
    if (ds == NULL) {
        PT_LOG("error: invalid device id!\n");
        return -1;
    }

    release_global_lock(ds);

    PT_LOG("release lock for %s = %d\n", ds->device_path, ds->lock_state);
    return 0;
}

/**
 * Handles ATAPI_PTV4V_SG_GET_RESERVED_SIZE command from qemu stubdom.
 * @param[in] hs: Helper state pointer.
 * @param[in] buf: Data packet received from qemu.
 * @param[in] len: Length of data packet received.
 * @returns 0 on success, -1 on errror.
 */
static int atapi_ptv4v_sg_get_reserved_size(ATAPIPTHelperState* hs,
                                            uint8_t *buf, size_t len)
{
    pt_v4vcmd_sg_get_reserved_size_request_t *request;
    pt_v4vcmd_sg_get_reserved_size_response_t response;
    ATAPIPTDeviceState *ds;

    request = (pt_v4vcmd_sg_get_reserved_size_request_t *)buf;

    if (len != sizeof(*request)) {
        PT_LOG("error: mismatch buffer size %lu vs %lu", len, sizeof(*request));
        return -1;
    }

    ds = device_id_to_device_state(hs, request->device_id);
    if (ds == NULL) {
        PT_LOG("error: invalid device id!\n");
        return -1;
    }

    response.cmd = ATAPI_PTV4V_SG_GET_RESERVED_SIZE;
    response.device_id = ds->device_id;

    if (ioctl(ds->device_fd, SG_GET_RESERVED_SIZE, &response.size) < 0) {
        PT_LOG("SG_GET_RESERVED_SIZE error %s - %s",
                ds->device_path, strerror(errno));
        return -1;
    }

    PT_LOG("sg get reserved size for %s = %d\n", ds->device_path,
            (int)response.size);

    if (!pt_v4v_send_message(hs, &response, sizeof(response))) {
        PT_LOG("error: failed to send a message to %s", ds->device_path);
        return -1;
    }

    return 0;
}

/**
 * Handles ATAPI_PTV4V_SG_IO command from qemu stubdom.
 * @param[in] hs: Helper state pointer.
 * @param[in] buf: Data packet received from qemu.
 * @param[in] len: Length of data packet received.
 * @returns 0 on success, -1 on errror.
 */
static int atapi_ptv4v_sg_io(ATAPIPTHelperState* hs, uint8_t *buf, size_t len)
{
    pt_v4vcmd_sg_io_request_t *request = (pt_v4vcmd_sg_io_request_t *)buf;

    /* TODO: MAX_V4V_MSG_SIZE :( - din/dout data needs be contrained properly */
    uint8_t buf_out[MAX_V4V_MSG_SIZE] = {0, };
    pt_v4vcmd_sg_io_response_t *response;

    ATAPIPTDeviceState *ds;
    struct sg_io_v4 cmd;

    response = (pt_v4vcmd_sg_io_response_t *)buf_out;

    /* len must at least be size of request */
    if (len < sizeof(*request)) {
        PT_LOG("error: bad buffer size %lu vs %lu", len, sizeof(*request));
        return -1;
    }

    /* now validate true length using data len in request */
    if (len != sizeof(*request) + request->dout_data_len) {
        PT_LOG("error: buffer size %lu vs %lu", len,
                sizeof(*request) + request->dout_data_len);
        return -1;
    }

    ds = device_id_to_device_state(hs, request->device_id);
    if (ds == NULL) {
        PT_LOG("error: invalid device id!\n");
        return -1;
    }

    /* setup sgio cmd struct with incoming copy */
    memcpy(&cmd, &request->sgio, sizeof(cmd));

    /* init the sgio pointers */
    cmd.request = (uintptr_t)&request->request_data[0];
    cmd.response = (uintptr_t)&response->sense_data[0];

    if (cmd.dout_xfer_len > 0) {
        cmd.dout_xferp = (uintptr_t)&request->dout_data[0];
        cmd.din_xferp = (uintptr_t)NULL;
    } else {
        cmd.dout_xferp = (uintptr_t)NULL;
        cmd.din_xferp = (uintptr_t)&response->din_data[0];
    }

    /* validate sense ("response") data len */
    if (cmd.max_response_len > sizeof(response->sense_data)) {
        PT_LOG("error: invalid max_response_len! %d\n", cmd.max_response_len);
        return -1;
    }

    /* make sure din_xfer_len will fit in response */
    if (sizeof(buf_out) < sizeof(response) + cmd.din_xfer_len) {
        PT_LOG("error: bad din_xfer_len %d", cmd.din_xfer_len);
        return -1;
    }

    /* fire off ioctl */
    if (ioctl(ds->device_fd, SG_IO, &cmd) < 0) {
        PT_LOG("SG_IO error %s - %s", ds->device_path, strerror(errno));
        return -1;
    }

    PT_DEBUG("SG_IO complete %s\n", ds->device_path);

    /* scrub outgoing pointers */
    cmd.request = 0;
    cmd.response = 0;
    cmd.dout_xferp = 0;
    cmd.din_xferp = 0;

    /* populate outgoing packet */
    response->cmd = ATAPI_PTV4V_SG_IO;
    response->device_id = ds->device_id;
    memcpy(&response->sgio, &cmd, sizeof(response->sgio));
    response->din_data_len = cmd.din_xfer_len;
    /* response.sense_data is populated by SG_IO */
    /* response.din_data is populated by SG_IO */

    len = sizeof(*response) + cmd.din_xfer_len;
    if (!pt_v4v_send_message(hs, response, len)) {
       PT_LOG("error: failed to send a message to %s", ds->device_path);
       return -1;
    }

    return 0;
}

static void signal_handler(int sig)
{
    PT_LOG("handle signal %d", sig);
    exit_cleanup(0);
}

int main(int const argc, char const* const* argv)
{
    openlog(NULL, LOG_NDELAY, LOG_DAEMON);

    PT_LOG("starting %s\n", argv[0]);

    memset(&g_hs, 0, sizeof(g_hs));

    if (argc != 3) {
        PT_LOG("wrong syntax: should be %s <target_id> <stubdom_id>", argv[0]);
        return -1;
    }

    g_hs.stubdom_id = atoi(argv[2]);

    if (g_hs.stubdom_id <= 0) {
        PT_LOG("bad stubdom id (%d)", g_hs.stubdom_id);
        return -1;
    }

    signal(SIGINT, signal_handler);

    if (init_helper_state(&g_hs) != 0) {
        PT_LOG("failed to init helper!\n");
        return -1;
    }

    while (!pending_exit) {
        int ret;
        uint8_t io_buf[MAX_V4V_MSG_SIZE] = {0,};

        PT_DEBUG("wait for command from stubdom (%d)", g_hs.stubdom_id);

        /* updates global remote_addr on per-packet basis */
        ret = v4v_recvfrom(g_hs.v4v_fd, io_buf, sizeof(io_buf),
                           0, &g_hs.remote_addr);

        if (ret < 0) {
            PT_LOG("v4v_recvfrom failed!\n");
            break;
        }

        switch (io_buf[0]) {
            case ATAPI_PTV4V_OPEN:
                PT_LOG("ATAPI_PTV4V_OPEN\n");
                ret = atapi_ptv4v_open(&g_hs, io_buf, ret);
                break;
            case ATAPI_PTV4V_SG_IO:
                PT_DEBUG("ATAPI_PTV4V_SG_IO\n");
                ret = atapi_ptv4v_sg_io(&g_hs, io_buf, ret);
                break;
            case ATAPI_PTV4V_SG_GET_RESERVED_SIZE:
                PT_LOG("ATAPI_PTV4V_SG_GET_RESERVED_SIZE\n");
                ret = atapi_ptv4v_sg_get_reserved_size(&g_hs, io_buf, ret);
                break;
            case ATAPI_PTV4V_ACQUIRE_LOCK:
                PT_LOG("ATAPI_PTV4V_ACQUIRE_LOCK\n");
                ret = atapi_ptv4v_acquire_lock(&g_hs, io_buf, ret);
                break;
            case ATAPI_PTV4V_RELEASE_LOCK:
                PT_LOG("ATAPI_PTV4V_RELEASE_LOCK\n");
                ret = atapi_ptv4v_release_lock(&g_hs, io_buf, ret);
                break;
            default:
                PT_LOG("bad command = %d", io_buf[0]);
                ret = -1;
                break;
        }

        if (ret < 0) {
            PT_LOG("command failed!\n");
            break;
        }
    }

    PT_LOG("exiting...\n");
    exit_cleanup(0);
    return 0;
}
