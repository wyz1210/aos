//
// Created by Rui on 2021/6/17.
//

#include <stdio.h>
#include <serial/serial.h>
#include <sel4runtime.h>
#include "console.h"
#include "fdtable.h"
#include "read_task.h"
#include "../vm/app_mapping.h"
#include "../utils.h"


ReadTaskList console_read_tasks;

struct serial * global_serial;

int console_write(WriteTask *task);

void console_write_cb(WriteTask *task){
//    printf("[console_write_cb] cur = %zu\n", task->cur);
    serial_send(global_serial, (char*) (*task->user_pages[task->cur].data_pointer), task->user_pages[task->cur].size);
    task->send_data_size += task->user_pages[task->cur].size;
    finish_use_user_pointer(task->pid, task->user_pages[task->cur].user_pointer);

    task->cur ++;
    console_write(task);
}

int console_write(WriteTask *task){

//    printf("[console_write] cur = %zu, page_size = %zu\n", task->cur, task->pages_size);

    if (task->cur < task->pages_size){
        AsyncTask *async = malloc(sizeof(AsyncTask));
        if (async == NULL){
//            printf("[console_write] cannot allocate\n");
            return 1;
        }
        async->call_back = (void (*)(void *)) console_write_cb;
        async->args = task;

        get_user_pointer_async(task->pid, task->user_pages[task->cur].user_pointer, task->user_pages[task->cur].data_pointer, async);
    }else{
        seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, task->send_data_size);
        seL4_Send(task->reply, reply_msg1);

        free_reply(task->reply,task->reply_ut);
        free(task->user_pages);
//        free(task);
    }

    return 0;
}

int console_read(ReadTask *task){
    insert_read_tasks(task, &console_read_tasks);
    return 0;
}


int console_open(const char * name, int mode){
    return 0;
}

int console_close(int fd){
    return 0;
}

void console_read_reply(ReadTask *task);

void console_read_cb(ReadTask *task){
//    printf("[console_read_cb] cur = %zu\n", task->cursor);

    char *buf = *(task->user_pages[task->cursor].data_pointer);

    size_t i;
    for (i = 0;i < task->user_pages[task->cursor].size && (i + task->send_data_size) < (size_t)task->data_len; i++) {
        buf[i] = task->data[i + task->send_data_size];
//        printf("buf[%d] = %c\n",i , buf[i]);
    }
    task->send_data_size += i;
    finish_use_user_pointer(task->pid, task->user_pages[task->cursor].user_pointer);

    task->cursor ++;

    console_read_reply(task);
}

void console_read_reply(ReadTask *task){

    if (task->cursor < task->pages_size){
        AsyncTask *async = malloc(sizeof(AsyncTask));
        async->call_back = (void (*)(void *)) console_read_cb;
        async->args = task;

        get_user_pointer_async(task->pid, task->user_pages[task->cursor].user_pointer, task->user_pages[task->cursor].data_pointer, async);
    }else{

//        printf("[console_read_reply - %lu] cur = %zu, page_size = %zu\n", task->pid, task->cursor, task->pages_size);

        seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, task->data_len);
        seL4_Send(task->reply, reply_msg1);

        free_reply(task->reply,task->reply_ut);
        free(task->user_pages);
//        free(task);

        delete_read_task_by_id(&console_read_tasks, task->task_id);
    }

}

void console_reply_read_task(size_t task_id) {

    ReadTask *task;
    int error = get_read_task_by_id(&console_read_tasks, &task, task_id);
    if (error){
//        printf("error when first task\n");
    }

    if (task->finished == false){
//        printf("[reply_read_task]task id = %zu not finished\n", task_id);
        return;
    }

    console_read_reply(task);
}

void console_serial_read_handler(struct serial *s, char c){

//    printf("serial read = %c\n", c);

    ReadTask *task;
    int error = first_unfinished_read_task(&console_read_tasks, &task);
    if (error){
//        printf("no read task now\n");
        return;
    }

    if (task-> data_len < MAX_TASK_DATA_SIZE){
        task->data[task->data_len++] = c;
    }else{
//        printf("serial read data over size\n");
        task->finished = true;
        console_reply_read_task(task->task_id);
    }

    if(c == '\n'){
        task->finished = true;
        console_reply_read_task(task->task_id);
    }

}

void init_console(seL4_Word pid, struct serial * serial){
    global_serial = serial;

    file_opts_t opts;
    opts.write = console_write;
    opts.read = console_read;
    opts.open = console_open;
    opts.close = console_close;
    add_fd(pid, "stdin", 0, 0, 0,opts, 1, NULL);
    add_fd(pid, "stdout", 0, 0, 0, opts, 1, NULL);
    add_fd(pid, "stderr", 0, 0,0, opts, 1, NULL);
    add_fd(pid, "console", 0, 0, 0,opts, 1, NULL);

    serial_register_handler(global_serial, console_serial_read_handler);
}