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
#include <stdlib.h>
#include <stdint.h>
#include <clock/clock.h>
#include <string.h>

/* The functions in src/device.h should help you interact with the timer
 * to set registers and configure timeouts. */
#include "device.h"

#define MAX_EVENT_SIZE 100

unsigned int LAST_USED_ID = 0;

typedef struct {
    timer_callback_t callback;
    void *data;
    uint64_t id;
    uint64_t actTime;
} Event;

static struct {
    volatile meson_timer_reg_t *regs;
    /* Add fields as you see necessary */
    Event events[MAX_EVENT_SIZE];
} clock;

int event_size = 0;

bool STARTED = false;

int start_timer(unsigned char *timer_vaddr)
{
    int err = stop_timer();
    if (err != 0) {
        return err;
    }

    clock.regs = (meson_timer_reg_t *)(timer_vaddr + TIMER_REG_START);
    event_size = 0;
    memset(clock.events, 0 ,sizeof(Event) * MAX_EVENT_SIZE);

    configure_timestamp(clock.regs,TIMESTAMP_TIMEBASE_1_MS);

    configure_timeout(clock.regs, MESON_TIMER_A, true, true, TIMEOUT_TIMEBASE_1_MS, 10);

    STARTED = true;
    return CLOCK_R_OK;
}

timestamp_t get_time(void){
    return read_timestamp(clock.regs);
}

void copy_event(Event *before, Event *after){
    after->callback = before->callback;
    after->data = before->data;
    after->id = before->id;
    after->actTime = before->actTime;
}


int insert_event(uint64_t delay, timer_callback_t callback, void *data){

    if (event_size >= MAX_EVENT_SIZE){
//        printf("event list is full! size = %d\n", event_size);
        return -1;
    }

    uint64_t actTime = delay + read_timestamp(clock.regs);

    int index = 0;
    while (index < event_size && clock.events[index].actTime <= actTime){
        index++;
    }

    for (int i = event_size; i > index; i--){
        Event *before = &clock.events[i - 1];
        Event *after = &clock.events[i];
        copy_event(before, after);
    }

    Event *e = &clock.events[index];
    e->callback = callback;
    e->data = data;
    e->actTime = actTime;
    e->id = ++LAST_USED_ID;
    if (e->id == 0){
        e->id = ++LAST_USED_ID;
    }

    event_size ++;

    return e->id;
}

int delete_first_n(int n){
//    printf("delete first n = %d\n",n);

    if (event_size <= 0){
//        printf("events is empty\n");
        return -1;
    }

    if (n > event_size){
//        printf("events only contains %d items, can't delete first n = %d\n", event_size, n);
        return -1;
    }

    Event temp_events[MAX_EVENT_SIZE];

    event_size -= n;
    memset(&clock.events[0], 0 , sizeof(Event) * n);
    memcpy(temp_events, &clock.events[n], sizeof(Event) * event_size);
    memcpy(clock.events, &temp_events, sizeof(Event) * event_size);

    return 0;
}


int delete_event(uint64_t id){

//    printf("delete id = %lu\n", id);

    int index = 0;
    while (index < event_size && clock.events[index].id != id){
        index++;
    }

    if(clock.events[index].id != id){
//        printf("can't find id = %lu", id);
        return -1;
    }

    for (int i = index; i < event_size - 1; i++){
        Event *before = &clock.events[i];
        Event *after = &clock.events[i+1];
        copy_event(after, before);
    }

    event_size --;

    return 0;
}

void _print_event_id(){
    for(int i=0; i < event_size; i++){
//        printf("%lu ", clock.events[i].id);
    }
//    printf("\n");
}

uint32_t register_timer(uint64_t delay, timer_callback_t callback, void *data)
{

    int id = insert_event(delay, callback, data);
    if (id < 0){
        return 0;
    }else{
        return id;
    }
}

int remove_timer(uint32_t id)
{
    int err = delete_event(id);
    if (err < 0){
        return CLOCK_R_FAIL;
    }
    return CLOCK_R_FAIL;
}

int timer_irq(
    void *data,
    seL4_Word irq,
    seL4_IRQHandler irq_handler
)
{
    /* Handle the IRQ */
    uint64_t now = read_timestamp(clock.regs);
    // time bias [-5,+4]
    int delete_num = 0;
    Event * e = clock.events;
    while(event_size > 0 && e->actTime < now + 5 && e->actTime != 0 && delete_num < event_size){
//        printf("[timer_irq] intterrupt id = %lu, actTime = %lu, now = %lu, event_size = %d\n", e->id, e->actTime, now, event_size);
        e->callback(e->id,e->data);

        delete_num ++;
        e ++;
    }

    if(delete_num > 0) {
        delete_first_n(delete_num);
    }

    /* Acknowledge that the IRQ has been handled */
    seL4_IRQHandler_Ack(irq_handler);

    return CLOCK_R_OK;
}

int stop_timer(void)
{
    /* Stop the timer from producing further interrupts and remove all
     * existing timeouts */
    if(STARTED == true) {
        event_size = 0;
        memset(clock.events, 0, MAX_EVENT_SIZE * sizeof(Event));
        LAST_USED_ID = 0;

        configure_timeout(clock.regs, MESON_TIMER_A, false, false, TIMEOUT_TIMEBASE_1_MS, 10);
    }

    return CLOCK_R_OK;
}

void test_caller(uint32_t id, void *data){
    printf("test_caller id=%d, data=[%s]\n", id, (char *)data);
    id = register_timer(100, test_caller, data);
    if (id != 0) {
        printf("register_timer return id = %d\n", id);
    }else{
        printf("register_timer error!\n");
    }
}

void test_timer(void)
{
    // TODO 新建线程来跑 100ms timer tick
    // TODO 可能存在并发问题

    printf("event size = %d\n", event_size);

    uint32_t id = register_timer(100, test_caller, "test timer 1");
    if (id != 0) {
        printf("register_timer return id = %d\n", id);
    }else{
        printf("register_timer error!\n");
    }

    id = register_timer(90, test_caller, "test timer 2");
    if (id != 0) {
        printf("register_timer return id = %d\n", id);
    }else{
        printf("register_timer error!\n");
    }

    id = register_timer(80, test_caller, "test timer 3");
    if (id != 0) {
        printf("register_timer return id = %d\n", id);
    }else{
        printf("register_timer error!\n");
    }

    id = register_timer(200, test_caller, "test timer 4");
    if (id != 0) {
        printf("register_timer return id = %d\n", id);
    }else{
        printf("register_timer error!\n");
    }
}