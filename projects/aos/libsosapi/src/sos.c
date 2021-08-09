/*
 * Copyright 2019, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(DATA61_GPL)
 */
#include <stdarg.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sos.h>

#include <sel4/sel4.h>
#include <ttyout.h>
#include <stdbool.h>

#define SOS_WRITE 10
#define SOS_READ 11
#define SOS_SLEEP 12
#define SOS_TIME_STAMP 13
#define SOS_OPEN 14
#define SOS_CLOSE 15
#define SOS_STAT 17
#define SOS_GET_DIRENT 18
#define SOS_MY_PID 19
#define SOS_PROCESS_CREAT 20
#define SOS_PROCESS_STATUS 21
#define SOS_PROCESS_DELETE 22
#define SOS_PROCESS_WAIT 23

#define HEADER_SIZE 3

// Max data size a msg can send
// The longger part will be ignore
#define DATA_SIZE (seL4_MsgMaxLength - HEADER_SIZE)


int sos_sys_open(const char *path, fmode_t mode) {

//    printf("sos_sys_open(%s,%d), strlen = %lu\n",path,mode, strlen(path));
    seL4_MessageInfo_t tag;
    tag = seL4_MessageInfo_new(0, 0, 0, 4);
    seL4_SetMR(0, SOS_OPEN);
    seL4_SetMR(1,mode);
    seL4_SetMR(2,strlen(path));
    seL4_SetMR(3, path);

    seL4_Call(SYSCALL_ENDPOINT_SLOT, tag);

    int fd = seL4_GetMR(0);
    if(fd < 0){
        printf("error open %s, fd = %d\n", path, fd);
        return -1;
    }
    return fd;
}

int sos_sys_close(int file) {

    seL4_MessageInfo_t tag;
    tag = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, SOS_CLOSE);
    seL4_SetMR(1,file);
    seL4_Call(SYSCALL_ENDPOINT_SLOT, tag);

    int error = seL4_GetMR(0);
    if(error){
        printf("error when close fd = %d\n", file);
    }
    return error;
}

int sos_sys_read(int file, char *buf, size_t nbyte) {

    seL4_MessageInfo_t tag;

//    printf("[sos_sys_read] buf = 0x%016lx\n", buf);

    tag = seL4_MessageInfo_new(0, 0, 0, 4);
    seL4_SetMR(0, SOS_READ);
    seL4_SetMR(1, file);
    seL4_SetMR(2, nbyte);
    seL4_SetMR(3, buf);
    seL4_Call(SYSCALL_ENDPOINT_SLOT, tag);

    size_t len = seL4_GetMR(0);
//    printf("sys_read len = %d, nbyte = %d\n", len, nbyte);

    return len;
}

int sos_sys_write(int file, const char *buf, size_t nbyte) {
    seL4_MessageInfo_t tag;

    // No any printf here!
    // Will cause infinity recur!

    tag = seL4_MessageInfo_new(0, 0, 0, 4);
    seL4_SetMR(0, SOS_WRITE);
    seL4_SetMR(1, file);
    seL4_SetMR(2, nbyte);
    seL4_SetMR(3, buf);

    seL4_Call(SYSCALL_ENDPOINT_SLOT, tag);

    size_t len = seL4_GetMR(0);

    return len;
}

int sos_getdirent(int pos, char *name, size_t nbyte) {
    seL4_MessageInfo_t tag;

    tag = seL4_MessageInfo_new(0, 0, 0, 4);
    seL4_SetMR(0, SOS_GET_DIRENT);
    seL4_SetMR(1, pos);
    seL4_SetMR(2, name);
    seL4_SetMR(3, nbyte);
    seL4_Call(SYSCALL_ENDPOINT_SLOT, tag);

    int left = seL4_GetMR(0);


    return left;
}

int sos_stat(const char *path, sos_stat_t *buf) {

    seL4_MessageInfo_t tag;

    tag = seL4_MessageInfo_new(0, 0, 0, 4);
    seL4_SetMR(0, SOS_STAT);
    seL4_SetMR(1, strlen(path));
    seL4_SetMR(2, path);
    seL4_SetMR(3, buf);
    seL4_Call(SYSCALL_ENDPOINT_SLOT, tag);

    int error = seL4_GetMR(0);
//    printf("sys_read buf = %s\n", buf);

    return error;
}

pid_t sos_process_create(const char *path) {

    int len = strlen(path);

    seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, 2 + len);
    seL4_SetMR(0, SOS_PROCESS_CREAT);
    seL4_SetMR(1, len);
    for (int i = 0; i < len; i ++){
        seL4_SetMR(i + 2, path[i]);
    }
    seL4_Call(SYSCALL_ENDPOINT_SLOT, tag);

    return seL4_GetMR(0);
}

int sos_process_delete(pid_t pid) {

    seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, SOS_PROCESS_DELETE);
    seL4_SetMR(1, pid);
    seL4_Call(SYSCALL_ENDPOINT_SLOT, tag);

    return seL4_GetMR(0);
}

pid_t sos_my_id(void) {

    seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, SOS_MY_PID);
    seL4_Call(SYSCALL_ENDPOINT_SLOT, tag);

    return seL4_GetMR(0);
}

int sos_process_status(sos_process_t *processes, unsigned max) {

    seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, 3);
    seL4_SetMR(0, SOS_PROCESS_STATUS);
    seL4_SetMR(1, processes);
    seL4_SetMR(2, max);
    seL4_Call(SYSCALL_ENDPOINT_SLOT, tag);

    return seL4_GetMR(0);
}

pid_t sos_process_wait(pid_t pid) {

    seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, SOS_PROCESS_WAIT);
    seL4_SetMR(1, pid);
    seL4_Call(SYSCALL_ENDPOINT_SLOT, tag);

    return seL4_GetMR(0);

}

void sos_sys_usleep(int msec) {
    seL4_MessageInfo_t tag;
    tag = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, SOS_SLEEP);
    seL4_SetMR(1, msec);
    seL4_Call(SYSCALL_ENDPOINT_SLOT, tag);
    return;
}

int64_t sos_sys_time_stamp(void) {
    seL4_MessageInfo_t tag;
    tag = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(0, SOS_TIME_STAMP);
    seL4_Call(SYSCALL_ENDPOINT_SLOT, tag);
    int64_t now = seL4_GetMR(0);
    return now;
}
