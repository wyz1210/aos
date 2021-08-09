//
// Created by Rui on 2021/6/18.
//
#include "../ut.h"

#ifndef SEL4_APPLICATION_TIMER_H
#define SEL4_APPLICATION_TIMER_H

typedef struct {
    size_t task_id;
    seL4_CPtr reply;
    ut_t *reply_ut;
    seL4_Word pid;
} TimerTask;

void sleep_callback(uint32_t id, void *data);

#endif //SEL4_APPLICATION_TIMER_H
