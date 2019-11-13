/*
 * utils.c
 *
 * XenClient platform management daemon common utilities
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

#include <sys/mman.h>
#include <ctype.h>
#include <fcntl.h>
#include <pci/header.h>
#include <pci/pci.h>
#include "project.h"
#include "xcpmd.h"

int strnicmp(const char *s1, const char *s2, size_t len)
{
    unsigned char c1, c2;

    c1 = c2 = 0;
    if ( len == 0 )
        return 0;

    do
    {
        c1 = *s1;
        c2 = *s2;
        s1++;
        s2++;

        if ( (c1 == 0) || (c2 == 0) )
            break;
        if ( c1 == c2 )
            continue;

        c1 = tolower(c1);
        c2 = tolower(c2);
        if ( c1 != c2 )
            break;
    } while ( --len );

    return (int)c1 - (int)c2;
}


//Extracts a number from the end of a string, e.g. BAT1 returns 1.
//Returns -1 on failure.
int get_terminal_number(char * str) {

    char * ptr;
    int ret;

    if (str == NULL)
        return -1;

    //Find the end of the string and walk backwards until you see a non-digit.
    ptr = strchr(str, '\0');

    ptr -= sizeof(char);
    if (ptr < str || *ptr < '0' || *ptr > '9')
        return -1;

    while (*ptr >= '0' && *ptr <= '9' && ptr >= str) {
        ptr -= sizeof(char);
    }

    //Move forward to the digit we just walked off of.
    ptr += sizeof(char);
    sscanf(ptr, "%d", &ret);

    return ret;
}


//Splits a string at a delimiter, similar to strtok().
//Unlike strtok(), returns empty strings for consecutive delimiters (like
//Ruby's String.split). To receive a complete set of tokens, call once with a
//string, then with NULL until a null pointer is returned.
char * strsplit(char * str, char delim) {
    static char * last_found;
    static char * str_end;
    char * token_end;
    char * search;

    //Check if this is the first call to this function.
    if (str != NULL) {
        str_end = strchr(str, '\0');
        search = str;
    }
    else {
        //Return a null pointer if we've reached the end of the string.
        if (last_found == str_end)
            return NULL;

        //Otherwise, start searching from the next character in the string.
        search = last_found + sizeof(char);
    }

    //Find the next delimiter and replace it with null.
    token_end = strchr(search, delim);
    if (token_end == NULL)
        token_end = str_end;
    else
        *token_end = '\0';

    //Save the location of the delimiter most recently found.
    last_found = token_end;

    //Then return the pointer to the beginning of the token.
    return search;
}


//Allocates memory!
//Deep clones a string. Don't forget to free() later.
char * clone_string(char * string) {

    char * clone;
    int length;

    length = strlen(string) + 1;
    clone = (char *)malloc(length * sizeof(char));
    if (clone == NULL) {
        xcpmd_log(LOG_ERR, "Couldn't allocate memory\n");
        return NULL;
    }
    strcpy(clone, string);

    return clone;
}

//Allocates memory!
//Allocates an appropriately sized string and prints to it.
char * safe_sprintf(char * format, ...) {

    int length;
    char * string;
    va_list args;

    va_start(args, format);
    length = vsnprintf(NULL, 0, format, args) + 1;
    va_end(args);
    string = (char *)malloc(length * sizeof(char));
    if (string == NULL) {
        xcpmd_log(LOG_ERR, "Couldn't allocate memory\n");
        return NULL;
    }
    va_start(args, format);
    vsnprintf(string, length, format, args);
    va_end(args);

    return string;
}


//Allocates memory! Frees *str1 if it's not null!
//Places a pointer to the concatenation of *str1 and the sprintf of the
//remaining args into str1.
void safe_str_append(char ** str1, char * format, ...) {

    if (str1 == NULL || format == NULL)
        return;

    int length;
    char *formatted, *concatted;
    va_list args;

    va_start(args, format);
    length = vsnprintf(NULL, 0, format, args) + 1;
    va_end(args);
    formatted = (char *)malloc(length * sizeof(char));
    if (formatted == NULL) {
        xcpmd_log(LOG_ERR, "Couldn't allocate memory\n");
        return;
    }
    va_start(args, format);
    vsnprintf(formatted, length, format, args);
    va_end(args);

    if (*str1 == NULL) {
        *str1 = formatted;
    }
    else {
        concatted = safe_sprintf("%s%s", *str1, formatted);
        free(*str1);
        free(formatted);

        *str1 = concatted;
    }
}

/* Copy at most @size bytes from @src in @dst, including the trailing NUL. If
 * @src is larger than @size, @size-1 bytes are copied and NUL is appended as
 * the last byte of @dst.
 * Nothing is copied if @dst or @src is NULL, or if @size is 0 or less.
 */
void pstrcpy(char *dst, int size, const char *src)
{
    int i;

    if (!dst || !src || size <= 0)
        return;

    for (i = 0; (i < size - 1) && src[i]; ++i)
        dst[i] = src[i];
    dst[i] = '\0';
}


void write_ulong_lsb_first(char *temp_val, unsigned long val)
{
    snprintf(temp_val, 9, "%02x%02x%02x%02x", (unsigned int)val & 0xff,
    (unsigned int)(val & 0xff00) >> 8, (unsigned int)(val & 0xff0000) >> 16,
    (unsigned int)(val & 0xff000000) >> 24);
}

int file_set_blocking(int fd)
{
    long arg = 0;

    arg = (long)fcntl(fd, F_GETFL, arg);
    arg &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, arg);
}

int file_set_nonblocking(int fd)
{
    long arg = 0;

    arg = (long)fcntl(fd, F_GETFL, arg);
    arg |= O_NONBLOCK;
    return fcntl(fd, F_SETFL, arg);
}


int find_efi_entry_location(const char *efi_entry, uint32_t length, size_t *location)
{
    FILE *systab = NULL;
    char efiline[EFI_LINE_SIZE];
    char *val;
    unsigned long loc = 0;

    *location = 0;

    systab = fopen("/sys/firmware/efi/systab", "r");
    if ( systab != NULL )
    {
        while( (fgets(efiline, EFI_LINE_SIZE - 1, systab)) != NULL )
        {
            if ( strncmp(efiline, efi_entry, 6) == 0 )
            {
                val = memchr(efiline, '=', strlen(efiline)) + 1;
                loc = strtoul(val, NULL, 0);
                break;
            }
        }
        fclose(systab);

        if ( loc != 0 )
        {
            *location = loc;
            return 0;
        }
    }

    return -1;
}

static struct pci_access *pci_acc = NULL;

int pci_lib_init(void)
{
    pci_acc = pci_alloc();
    if ( !pci_acc )
        return 0;
    pci_init(pci_acc);
    pci_scan_bus(pci_acc);

    return 1;
}

uint32_t pci_host_read_dword(int bus, int dev, int fn, uint32_t addr)
{
    struct pci_dev *pci_dev;
    uint32_t val = -1;
    uint32_t ret = 0;

    pci_dev = pci_get_dev(pci_acc, 0, bus, dev, fn);
    if ( !pci_dev )
        return 0;

    pci_read_block(pci_dev, addr, (uint8_t*)&val, 4);
    memcpy((uint8_t*)&ret, (uint8_t*)&val, 4);
    pci_free_dev(pci_dev);

    return ret;
}

void pci_lib_cleanup(void)
{
    pci_cleanup(pci_acc);
    pci_acc = NULL;
}

uint8_t *map_phys_mem(size_t phys_addr, size_t length)
{
    uint32_t page_offset = phys_addr % sysconf(_SC_PAGESIZE);
    uint8_t *addr;
    int fd;

    fd = open("/dev/mem", O_RDONLY);
    if ( fd == -1 )
        return NULL;

    addr = (uint8_t*)mmap(0, page_offset + length, PROT_READ, MAP_PRIVATE, fd, phys_addr - page_offset);
    close(fd);

    if ( addr == MAP_FAILED )
        return NULL;

    return addr + page_offset;
}

void unmap_phys_mem(uint8_t *addr, size_t length)
{
    uint32_t page_offset = (size_t)addr % sysconf(_SC_PAGESIZE);

    munmap(addr - page_offset, length + page_offset);
}

unsigned int xenstore_read_uint(char *path)
{
    char *buf;
    int ret;

    buf = xenstore_read("%s", path);
    if ( buf == NULL)
        return 0;

    ret  = atoi(buf);
    free(buf);
    return ret;
}

static void write_pid(pid_t pid)
{
    FILE *f;

    f = fopen(XCPMD_PID_FILE, "w+");
    if (!f)
    {
        xcpmd_log(LOG_ERR, "Failed to open %s\n", XCPMD_PID_FILE);
        return;
    }

    if (!fprintf(f, "%d\n", pid))
        xcpmd_log(LOG_ERR, "Failed to write pid to file\n");

    fclose(f);
}

/* Borrowed daemonize from xenstored - Initially written by Stevens. */
void daemonize(void)
{
    pid_t pid;

    if ( (pid = fork()) < 0 )
    {
        xcpmd_log(LOG_ERR, "Failed to fork - %d\n", errno);
        exit(1);
    }

    if ( pid != 0 )
        exit(0);

    setsid();

    if ( (pid = fork()) < 0 )
    {
        xcpmd_log(LOG_ERR, "Failed to fork - %d\n", errno);
        exit(1);
    }

    if ( pid != 0 )
    {
        write_pid(pid);
        exit(0);
    }

    if ( chdir("/") == -1 )
    {
        xcpmd_log(LOG_ERR, "chdir failed with error - %d\n", errno);
        exit(1);
    }

    umask(0);
}

#ifdef XCPMD_DEBUG_DETAILS

void print_battery_info(struct battery_info *info) {
    xcpmd_log(LOG_DEBUG, "present:                %d\n", info->present);
    xcpmd_log(LOG_DEBUG, "design capacity:        %d\n", (int) info->design_capacity);
    xcpmd_log(LOG_DEBUG, "last full capacity:     %d\n", (int) info->last_full_capacity);
    xcpmd_log(LOG_DEBUG, "battery technology:     %d\n", info->battery_technology);
    xcpmd_log(LOG_DEBUG, "design voltage:         %d\n", (int) info->design_voltage);
    xcpmd_log(LOG_DEBUG, "design capacity warning:%d\n", (int) info->design_capacity_warning);
    xcpmd_log(LOG_DEBUG, "design capacity low:    %d\n", (int) info->design_capacity_low);
    xcpmd_log(LOG_DEBUG, "capacity granularity 1: %d\n", (int) info->capacity_granularity_1);
    xcpmd_log(LOG_DEBUG, "capacity granularity 2: %d\n", (int) info->capacity_granularity_2);
    xcpmd_log(LOG_DEBUG, "model number:           %s\n", info->model_number);
    xcpmd_log(LOG_DEBUG, "serial number:          %s\n", info->serial_number);
    xcpmd_log(LOG_DEBUG, "battery type:           %s\n", info->battery_type);
    xcpmd_log(LOG_DEBUG, "OEM info:               %s\n", info->oem_info);
}

void print_battery_status(struct battery_status *status) {
    xcpmd_log(LOG_DEBUG, "present:                     %d\n", status->present);
    xcpmd_log(LOG_DEBUG, "Battery state                %d\n", (int) status->state);
    xcpmd_log(LOG_DEBUG, "Battery present rate         %d\n", (int) status->present_rate);
    xcpmd_log(LOG_DEBUG, "Battery remining capacity    %d\n", (int) status->remaining_capacity);
    xcpmd_log(LOG_DEBUG, "Battery present voltage      %d\n", (int) status->present_voltage);
}

#endif /*XCPMD_DEBUG_DETAILS*/
