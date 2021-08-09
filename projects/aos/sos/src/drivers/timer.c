//
// Created by Rui on 2021/6/18.
//

#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <sel4runtime.h>
#include "timer.h"
#include "../utils.h"


void sleep_callback(uint32_t id, void *data){

    TimerTask *task = data;

//    printf("[sleep_callback - %lu] id = %d, task_id = %zu\n", task->pid, id, task->task_id);

    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, task->task_id);

    seL4_Send(task->reply, reply_msg);
    free_reply(task->reply, task->reply_ut);
    free(task);
}

