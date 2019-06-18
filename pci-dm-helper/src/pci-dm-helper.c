/*
 * Copyright (c) 2013 Citrix Systems, Inc.
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

#include <xenctrl.h>
#include <libargo.h>
#include <pci/pci.h>

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <event.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <xcxenstore.h>

#include "util.h"

//#define DEBUG

#ifdef DEBUG
#define debug(args...) info (args)
#else
#define debug(args...)
#endif


#define RPCI_BYTE 0
#define RPCI_WORD 1
#define RPCI_LONG 2
#define RPCI_BLCK 3

#define RPCI_PORT 5559

struct remotepci_req {
    unsigned read:1;
    unsigned write:1;
    unsigned align:6;
    u_int16_t domain;
    u_int8_t bus, dev, func;
    u_int16_t offset;
    union {
        u_int32_t len;
        u_int32_t v;
    };
} __attribute__((packed));



static
struct pci_access *paccess = NULL;

/* rv = 1 on success, 0 on eof, < 0 on error */
static
int nrecv(int fd, void *buf, size_t n)
{
    while (n) {
        ssize_t r = argo_recv( fd, buf, n, 0 );
        if (r == -1) {
            if (errno == EAGAIN) continue;
            perror("argo_recv");
            return r;
        } else if (r == 0) {
            warning("nrecv: EOF\n");
            return 0;
        } else {
            n -= r; buf += r;
        }
        
    }
    return 1;
}

/* rv = 1 on success */
static
int nsend(int fd, void *buf, size_t n)
{
    while (n) {
        ssize_t r = argo_send( fd, buf, n, 0 );
        if (r == -1) {
            if (errno == EAGAIN) continue;
            perror("argo_send");
            return r;
        } else {
            n -= r; buf += r;
        }
    }
    return 1;
}

static
int pull(int fd, struct remotepci_req *req)
{
    if (nrecv( fd, req, sizeof(struct remotepci_req) )) {
        return 0;
    }
    return -1;
}

static
int push(int fd, void *buf, size_t n)
{
    if (nsend( fd, buf, n )) {
        return 0;
    }
    return -1;
}

static int push_8(int fd, u_int8_t x) { return push(fd, &x, sizeof(x)); }
static int push_16(int fd, u_int16_t x) { return push(fd, &x, sizeof(x)); }
static int push_32(int fd, u_int32_t x) { return push(fd, &x, sizeof(x)); }

static int nack(int fd) { return push_8(fd, 0x1); }
static int ack(int fd) { return push_8(fd, 0x0); }

static
struct pci_dev *match( struct remotepci_req *req )
{
    struct pci_dev *dev = paccess->devices;
    while (dev && !(dev->domain == req->domain &&
                    dev->bus    == req->bus &&
                    dev->dev    == req->dev &&
                    dev->func   == req->func))
        dev = dev->next;
    return dev;
}

/* rv = 0 on success */
static
int process(int fd, struct remotepci_req *req)
{
    int rv;
    u_int8_t *bytes = NULL;
    struct pci_dev *dev = match( req );
    if (!dev) {
        nack(fd);
        return 0;
    }

    if (req->read) {
        switch (req->align) {
        case RPCI_BYTE:
            debug("read byte %02x:%02x:%02x off=%d\n",  req->bus, req->dev, req->func, req->offset);
            return push_8(fd, pci_read_byte(dev, req->offset));
        case RPCI_WORD:
            debug("read word %02x:%02x:%02x off=%d\n",  req->bus, req->dev, req->func, req->offset);
            return push_16(fd, pci_read_word(dev, req->offset));
        case RPCI_LONG:
            debug("read long %02x:%02x:%02x off=%d\n",  req->bus, req->dev, req->func, req->offset);
            return push_32(fd, pci_read_long(dev, req->offset));
        case RPCI_BLCK:
            debug("read block %02x:%02x:%02x off=%d len=%d\n",  req->bus, req->dev, req->func, req->offset, req->len);
            if ( req->len <= 0x1000 ) {
                bytes = malloc( req->len );
                if (!pci_read_block(dev, req->offset, bytes, req->len)) {
                    warning ("pci_read_block failed %02x:%02x:%02x len=%d addr=%d\n", req->bus, req->dev, req->func, req->len, req->offset);
                    free(bytes);
                    return nack(fd);
                }
                if ( -1 == ack(fd) ) {
                    free(bytes);
                    return -1;
                }

                rv = nsend(fd, bytes, req->len);
                if (!rv) {
                    warning ("error sending %d bytes\n", req->len);
                }
                free(bytes);
                return rv ? 0:-1;
            } else {
                // too long
                return nack(fd);
            }
        }
    } else if (req->write) {
        switch (req->align) {
        case RPCI_BYTE:
            debug("write byte %02x:%02x:%02x off=%d\n",  req->bus, req->dev, req->func, req->offset);
            if (!pci_write_byte(dev, req->offset, req->v)) {
                warning ("pci_write_byte failed %02x:%02x:%02x addr=%d\n", req->bus, req->dev, req->func, req->offset);
            }
            return 0;
        case RPCI_WORD:
            debug("write word %02x:%02x:%02x off=%d\n",  req->bus, req->dev, req->func, req->offset);
            if (!pci_write_word(dev, req->offset, req->v)) {
                warning ("pci_write_word failed %02x:%02x:%02x addr=%d\n", req->bus, req->dev, req->func, req->offset);
            }
            return 0;
        case RPCI_LONG:
            debug("write long %02x:%02x:%02x off=%d\n",  req->bus, req->dev, req->func, req->offset);
            if (!pci_write_long(dev, req->offset, req->v)) {
                warning ("pci_write_long failed %02x:%02x:%02x addr=%d\n", req->bus, req->dev, req->func, req->offset);
            }
            return 0;
        case RPCI_BLCK:
            debug("write block %02x:%02x:%02x off=%d len=%d\n",  req->bus, req->dev, req->func, req->offset, req->len);
            if ( req->len <= 0x1000 ) {
                bytes = malloc( req->len );
                if (nrecv(fd, bytes, req->len)) {
                    rv = 0;
                    if (!pci_write_block(dev, req->offset, bytes, req->len)) {
                        warning ("pci_write_block failed %02x:%02x:%02x len=%d addr=%d\n", req->bus, req->dev, req->func, req->len, req->offset);
                        rv = nack(fd);
                    } else {
                        rv = ack(fd);
                    }
                } else {
                    rv = -1;
                    warning ("error receiving %d byes", req->len);
                }
                free(bytes);
                return rv;
            } else {
                // too long
                return nack(fd);
            }
        }
    } else {
        fatal("bad request");
        return -1;
    }

    return 0;
}

static
int shakehands(int domid, int *ssock)
{
    xen_argo_addr_t addr, raddr;
    int fd = argo_socket(SOCK_STREAM);

    *ssock = fd;
    if (fd<0) {
        perror("argo_socket");
        return fd;
    }
    memset(&addr, 0, sizeof(addr));
    addr.aport = RPCI_PORT;
    addr.domain_id = XEN_ARGO_DOMID_ANY;
    if (-1 == argo_bind(fd, &addr, domid)) {
        perror("argo_bind");
        return -1;
    }
    if (-1 == argo_listen(fd, 1)) {
        perror("argo_listen");
        return -1;
    }
    info("listening..\n");
    for (;;) {
        int talkfd = argo_accept(fd, &raddr);
        if (talkfd == -1) {
            perror("argo_accept");
            return -1;
        }
        info("connection from domain %d\n", raddr.domain_id);
        if (raddr.domain_id != domid) {
            warning ("unexpected remote domain, have %d, expecting %d\n", raddr.domain_id, domid);
            close(talkfd);
        } else {
            return talkfd;
        }
    }
}

static
int go(int domid)

{
    int fd, rv, ssock;
    struct remotepci_req req;

    fd = shakehands(domid, &ssock);
    if (fd < 0) return fd;

    for (;;) {
        rv = pull(fd, &req);
        if (rv < 0) goto out;
        rv = process(fd, &req);
        if (rv < 0) goto out;
    }

out:
    close(fd);
    close(ssock);
    return rv;
}


/* FIXME: need to check if the BDF is valid */
static int parse_bdf (char *str, uint16_t *seg, uint8_t *bus, uint8_t *dev,
                      uint8_t *func)
{
    char *token;
    const char *delim = ":.";

    if (!str || (!strchr (str, ':') && (!strchr(str, '.'))))
        return -1;

    token = strsep (&str, delim);
    *seg = atoi (token);

    token = strsep (&str, delim);
    *bus = atoi (token);

    token = strsep (&str, delim);
    *dev = atoi (token);

    token = strsep (&str, delim);
    *func = atoi (token);

    strsep (&str, "@");

    return 0;
}

static int get_vgabios (unsigned char *buf)
{
    int fd;
    uint32_t bios_size = 0;
    uint32_t start = 0xc0000;
    uint16_t magic = 0;

    if ((fd = open ("/dev/mem", O_RDONLY)) < 0)
    {
        error ("can't open /dev/mem: %s", strerror (errno));
        return 0;
    }

    /*
     * Check if it a real bios extension.
     * The magic number is 0xAA55.
     */
    if (start != (uint32_t)lseek (fd, start, SEEK_SET))
        goto out;
    if (read (fd, &magic, 2) != 2)
        goto out;
    if (magic != 0xAA55)
        goto out;

    /* Find the size of the rom extension */
    if (start != (uint32_t)lseek (fd, start, SEEK_SET))
        goto out;
    if ((uint32_t)lseek (fd, 2, SEEK_CUR) != (start + 2))
        goto out;
    if (read (fd, &bios_size, 1) != 1)
        goto out;

    /* This size is in 512 bytes */
    bios_size *= 512;

    if (bios_size > (64 * 1024))
    {
        error ("bios size is to high (%d)", bios_size);
        bios_size = 0;
        goto out;
    }

    /*
     * Set the file to the begining of the rombios,
     * to start the copy.
     */
    if (start != (uint32_t)lseek (fd, start, SEEK_SET))
        goto out;

    if (bios_size != (uint32_t)read (fd, buf, bios_size))
        bios_size = 0;

out:
    close (fd);
    return bios_size;
}

static int copy_vgabios (xc_interface *xch,
                         unsigned int target_domid)
{
    unsigned char *bios = NULL;
    int bios_size = 0;
    char *c = NULL;
    char checksum = 0;
    int rc = 0;
    void *addr;
    uint32_t align;

    /* Allocated 64K for the vga bios */
    if (!(bios = malloc (64 * 1024)))
        return -1;

    bios_size = get_vgabios(bios);
    if (bios_size == 0 || bios_size > 64 * 1024)
    {
        error("vga bios size (0x%x) is invalid!\n", bios_size);
        rc = -1;
        goto out;
    }

    /* Adjust the bios checksum */
    for (c = (char*)bios; c < ((char*)bios + bios_size); c++)
        checksum += *c;
    if (checksum)
    {
        bios[bios_size - 1] -= checksum;
        info ("vga bios checksum is adjusted!");
    }

    align = (bios_size + XC_PAGE_SIZE - 1) & ~(XC_PAGE_SIZE - 1);
    info ("bios_size = 0x%x align = 0x%x", bios_size, align);

    addr = xc_map_foreign_range (xch, target_domid, align,
                                 PROT_READ | PROT_WRITE,
                                 (0xc0000) >> XC_PAGE_SHIFT);

    if (!addr)
    {
        error ("Unable to map vga bios region of the domain %d", target_domid);
        goto out;
    }

    info ("copy bios");
    memcpy (addr, bios, bios_size);

    munmap (addr, align);
out:
    free (bios);
    return rc;

}

#define CHECK_STATUS(func, fmt, ...)      \
    {                                     \
        int r;                            \
        r = (func);                       \
        if (r)                            \
        {                                 \
            error ("ret = %d" fmt,        \
                   r, ## __VA_ARGS__);    \
            goto permission_err;          \
        }                                 \
    }

/* Process permission for graphic card */
static int process_permission_graphic (unsigned int stubdom_domid,
                                       unsigned int target_domid,
                                       struct pci_dev *pci_dev)
{
    xc_interface *xch;
    int ret = -1;

    if (pci_dev->device_class != 0x0300)
        return 0;

    (void) stubdom_domid;
    (void) target_domid;

    xch = xc_interface_open (NULL, NULL, 0);

    if (!xch)
    {
        error ("Unable to open xc interface");
        return -1;
    }

    info ("It's a graphic card !!!");

    CHECK_STATUS(xc_domain_ioport_permission (xch, stubdom_domid,
                                              0x3b0, 0xc, 1),
                 "perm vga ioport");

    CHECK_STATUS(xc_domain_iomem_permission (xch, stubdom_domid,
                                             0xa0000 >> XC_PAGE_SHIFT,
                                             0x20, 1),
                 "perm part of frame buffer");

    if (pci_dev->vendor_id == 0x8086)
    {
        uint32_t igd_opregion;

        info ("intel graphic card");

        CHECK_STATUS(xc_domain_ioport_permission (xch, stubdom_domid,
                                                  0x3c0, 0x20, 1),
                     "perm vga ioport (2)");

        igd_opregion = pci_read_long (pci_dev, 0xfc);

        if (igd_opregion)
        {
            CHECK_STATUS(xc_domain_iomem_permission (xch, stubdom_domid,
                                                     igd_opregion >> XC_PAGE_SHIFT,
                                                     8, 1),
                         "perm opregion");
        }
    }
    else if (pci_dev->vendor_id == 0x1002)
    {
        CHECK_STATUS(xc_domain_ioport_permission (xch, stubdom_domid,
                                                  0x3c0, 3, 1),
                     "perm ati ioport (1)");
        CHECK_STATUS(xc_domain_ioport_permission (xch, stubdom_domid,
                                                  0x3c4, 0x1c, 1),
                     "perm ati ioport (2)");
    }

    /* Copy vga bios */
    CHECK_STATUS(copy_vgabios (xch, target_domid), "copy vga bios");

    ret = 0;

permission_err:
    xc_interface_close (xch);

    return ret;
}

static struct pci_dev *find_dev (uint16_t seg, uint8_t bus, uint8_t dev,
                                 uint8_t func)
{
    struct pci_dev *pci_dev = paccess->devices;

    while (pci_dev && !(pci_dev->domain == seg &&
                        pci_dev->bus == bus &&
                        pci_dev->dev == dev &&
                        pci_dev->func == func))
        pci_dev = pci_dev->next;

    return pci_dev;
}

/* Give the right permissions to stubdomain for pass-through */
static int process_permission (unsigned int stubdom_domid,
                               unsigned int target_domid)
{
    unsigned int num_devs = 0;
    unsigned int i;
    char *res = NULL;
    uint16_t seg;
    uint8_t bus, dev, func;
    struct pci_dev *pci_dev;

    (void) stubdom_domid;
    (void) target_domid;

    res = xenstore_read ("/local/domain/0/backend/pci/%u/0/num_devs",
                         stubdom_domid);

    if (!res)
    {
        info ("There is no pass-through devices");
        return 0;
    }

    num_devs = atoi (res);
    free (res);

    for (i = 0; i < num_devs; i++)
    {
        res = xenstore_read ("/local/domain/0/backend/pci/%u/0/dev-%u",
                             stubdom_domid, i);
        if (!res)
        {
            error ("can't read pci pass-through device information %u", i);
            continue;
        }

        info ("device %s", res);

        if (parse_bdf (res, &seg, &bus, &dev, &func))
        {
            error ("Unable to parse bdf");
            free (res);

            continue;
        }

        free (res);

        info ("%x:%x:%x.%d", seg, bus, dev, func);

        pci_dev = find_dev (seg, bus, dev, func);

        if (!pci_dev)
        {
            error ("Unable to retrieve device %x:%x:%x.%d",
                   seg, bus, dev, func);
            continue;
        }

        if (process_permission_graphic (stubdom_domid, target_domid,
                                         pci_dev))
        {
            error ("Unable to give permission on device %x:%x:%x.%d",
                   seg, bus, dev, func);
            continue;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    int ret = 0;
    unsigned int stubdom_domid, target_domid;
    char *prefix = NULL;

    if (argc != 3) {
        fatal("Usage: %s target_domid stubdom_domid\n", argv[0]);
    }

    stubdom_domid = atoi (argv[2]);
    target_domid = atoi (argv[1]);

    if ((asprintf (&prefix, "pci-dm-helper-%u", target_domid)) == -1)
        fatal ("Unable to set prefix");

    prefix_set (prefix);
    free (prefix);

    /* Initialize libpci */
    paccess = pci_alloc();
    pci_init(paccess);
    pci_scan_bus(paccess);

    event_init (); // Useful for XenStore, will be used in all the daemon in the future
    xenstore_init ();

    if ((ret = process_permission (stubdom_domid, target_domid)))
    {
        error ("Unable to give the right permission to the stubdomain");

        return ret;
    }

    ret = go(stubdom_domid);

    return ret;
}
