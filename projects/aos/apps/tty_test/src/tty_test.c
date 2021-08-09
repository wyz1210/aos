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
/****************************************************************************
 *
 *      $Id:  $
 *
 *      Description: Simple milestone 0 test.
 *
 *      Author:         Godfrey van der Linden
 *      Original Author:    Ben Leslie
 *
 ****************************************************************************/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sel4/sel4.h>
#include <syscalls.h>
#include <string.h>
#include <utils/page.h>
#include <sos.h>
#include <stdio.h>
#include <unistd.h>
#include <sos.h>
#include <fcntl.h>


#include "ttyout.h"

#define NBLOCKS 9
#define NPAGES_PER_BLOCK 28
#define TEST_ADDRESS 0x8000000000

/* called from pt_test */

static void
do_pt_test(char **buf)
{
    int i;

    /* set */
    for (int b = 0; b < NBLOCKS; b++) {
        for (int p = 0; p < NPAGES_PER_BLOCK; p++) {
            buf[b][p * PAGE_SIZE_4K] = p;
        }
    }

    /* check */
    for (int b = 0; b < NBLOCKS; b++) {
        for (int p = 0; p < NPAGES_PER_BLOCK; p++) {
            if (buf[b][p * PAGE_SIZE_4K] != p){
                printf("buf[%d][%lu] = %d, p = %d\n",b, p * PAGE_SIZE_4K, buf[b][p * PAGE_SIZE_4K], p);
                assert(buf[b][p * PAGE_SIZE_4K] == p);
            }
        }
    }
}


static void pt_test( void )
{
    pid_t pid = sos_my_id();
    printf("\n=== pt_test - %d ===\n", pid);

    /* need a decent sized stack */
    char buf1[NBLOCKS][NPAGES_PER_BLOCK * PAGE_SIZE_4K];
    char *buf1_ptrs[NBLOCKS];
    char *buf2[NBLOCKS];


    char contents[4096];
    memset(contents, 0, sizeof(char) * 4096);
    char file_name[4096];
    memset(file_name, 0, sizeof(char) * 4096);
    char buf[4096];
    memset(buf, 0, 4096);

    sprintf(contents, "[tty_test - %d]", pid);

    sprintf(file_name, "tmp_tty_test-%d.txt", pid);
    int fd = open(file_name, O_WRONLY);

    int i = 0, write_size = 0;
    while (i < 5){
        printf("%s\n", contents);
        sos_sys_write(fd, contents, strlen(contents));
        write_size += strlen(contents);
        sos_sys_usleep(1000);
        i ++;
    }
    printf("[tty_test - %d] write\t%d to\t%s\n", pid, write_size, file_name);
    close(fd);

    int rfd = open(file_name, O_RDONLY);
    if (rfd < 0 ){
        printf("[tty_test - %d] error open %s\n", pid, file_name);
        return;
    }
    int read_size = read(rfd, buf, 4096);
    printf("[tty_test - %d] read\t%d from\t%s\n", pid, read_size, file_name);
    close(rfd);


    printf("[tty_test - %d] exit!\n", pid);
}

// Block a thread forever
// we do this by making an unimplemented system call.
static void thread_block(void)
{
    /* construct some info about the IPC message tty_test will send
     * to sos -- it's 1 word long */
    seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, 1);
    /* Set the first word in the message to 1 */
    seL4_SetMR(0, 1);
    /* Now send the ipc -- call will send the ipc, then block until a reply
     * message is received */
    seL4_Call(SYSCALL_ENDPOINT_SLOT, tag);
    /* Currently SOS does not reply -- so we never come back here */
}


int main(void)
{
    /* initialise communication */
    sosapi_init_syscall_table();
    ttyout_init();

    pt_test();

//    thread_block();
    // sleep(1);    // Implement this as a syscall

    return 0;
}
