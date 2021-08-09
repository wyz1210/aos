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


#include <stdio.h>
#include <syscalls.h>
#include <string.h>
#include <sos.h>
#include <unistd.h>
#include <fcntl.h>

size_t sos_write(void *vData, size_t count)
{

    return sos_sys_write(0, vData,count);
}


int main(void)
{
    /* initialise communication */
    sosapi_init_syscall_table();

    printf("[while true] is running\n");

    while (1){
        sos_sys_usleep(2000);
    }

    return 0;
}
