//
// Created by Rui on 2021/6/17.
//


#include <stdio.h>
#include <string.h>
#include <cspace/cspace.h>
#include <clock/clock.h>

#include "irq.h"
#include "drivers/uart.h"
#include "ut.h"
#include "fs/fdtable.h"
#include "fs/read_task.h"
#include "drivers/timer.h"
#include "vm/addrspace.h"
#include "vm/app_mapping.h"
#include "utils.h"
#include "network.h"
#include "fs/nfs_api.h"
#include "process.h"

size_t next_task_id = 1;


bool new_read_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut) {

    seL4_MessageInfo_t reply_msg;

    int fd = seL4_GetMR(1);
    size_t len = seL4_GetMR(2);
    seL4_Word user_pointer = seL4_GetMR(3);
//    printf("[new_read_task - %lu] buf = 0x%016lx\n", badge, user_pointer);

    UserPage *data_list;
    int pages_size = copy_user_pointer_list(user_pointer, len, &data_list);
    assert(pages_size <= 100);

    struct file * f = get_by_FD(badge, fd);
    if(f == NULL){
//        printf("[read] can't find fd = %d\n", fd);
        reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, -1);
        seL4_Send(reply, reply_msg);
        return false;
    }

    ReadTask *task = malloc(sizeof(ReadTask));
    memset(task, 0, sizeof(ReadTask));
    task->task_id = next_task_id++;
    task->reply = reply;
    task->reply_ut = reply_ut;
    task->data_len = 0;
    task->cursor = 0;
    task->finished = false;

    task->user_pages = data_list;

    task->pages_size = pages_size;
    task->user_data_size = len;
    task->file = f;
    task->send_data_size = 0;
    task->pid = badge;

//    printf("[new_read_task - %lu] fd = %d, insert task_id = %zu reply = %zu\n",badge, fd, task->task_id, reply);
    f->opts.read(task);

    return true;
}

bool new_write_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut){
    seL4_MessageInfo_t reply_msg;

    int fd = seL4_GetMR(1);
    size_t dataSize = seL4_GetMR(2);
    seL4_Word user_pointer = seL4_GetMR(3);

//    printf("[new_write_task - %lu] fd = %d,  user_pointer = 0x%016lx, dataSize = %zu\n",badge, fd, user_pointer, dataSize);
    UserPage *data_list;
    int pages_size = copy_user_pointer_list(user_pointer, dataSize, &data_list);

    struct file * f = get_by_FD(badge, fd);
    if(f == NULL){
//        printf("[new_write_task - %lu] can't find fd = %d\n", badge, fd);
        reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, -1);
        seL4_Send(reply, reply_msg);
        return false;
    }

    WriteTask *task = malloc(sizeof(WriteTask));
    task->task_id = next_task_id++;
    task->reply = reply;
    task->reply_ut = reply_ut;
    task->user_pages = data_list;
    task->pages_size = pages_size;
    task->data_size = dataSize;
    task->send_data_size = 0;
    task->cur = 0;
    task->nfsfh = f->nfsfh;
    task->file = f;
    task->pid = badge;

    int error = f->opts.write(task);
    if (!error) {
//        printf("[new_write_task] insert task_id = %zu reply = %zu\n", task->task_id, reply);
        return true;
    }

//    printf("[new_write_task - %d] error = %d\n", fd, error);
    reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, -1);
    seL4_Send(reply, reply_msg);
    return false;
}

bool new_sleep_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut){

    size_t dlay = seL4_GetMR(1);

    TimerTask *task = malloc(sizeof(TimerTask));
    task->task_id = next_task_id++;
    task->reply = reply;
    task->reply_ut = reply_ut;
    task->pid = badge;

    int id = register_timer(dlay, sleep_callback, task);
//    printf("[sleep - %lu] insert, id = %d, task_id = %zu\n",badge, id, task->task_id);

    return true;
}

bool new_time_stamp_task(seL4_CPtr reply, ut_t *reply_ut){

    timestamp_t now = get_time();

    seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, now);
    seL4_Send(reply, reply_msg1);
    return false;
}


typedef struct{
    int len;
    fmode_t mode;
    seL4_CPtr reply;
    ut_t *reply_ut;
    seL4_Word user_pointer;
    unsigned char ** data_pointer;

    seL4_Word pid;
}NewOpenArgs;

void new_open_task_finish(NewOpenArgs *args){
//    printf("[open_task_finish]\n");
    finish_use_user_pointer(args->pid, args->user_pointer);
}

void new_open_task_continue(NewOpenArgs *args){

//    printf("[open] path = ");
    char path[100];
    for(int i = 0; i < args->len; i++){
//        printf("%c", (*args->data_pointer)[i]);
        path[i] = (*args->data_pointer)[i];
    }
    path[args->len] = '\0';
//    printf("\n");


    int fd = get_FD_by_name(args->pid, path);
    if (fd < 0){
        OpenTask *task = malloc(sizeof(OpenTask));
        task->task_id = next_task_id++;
        task->reply = args->reply;
        task->reply_ut = args->reply_ut;
        memset(task->path, 0 , 120);
        memcpy(task->path, path, strlen(path) * sizeof(char));
        task->mode = args->mode;
        task->pid = args->pid;
        task->async = malloc(sizeof(AsyncTask));
        task->async->call_back = (void (*)(void *)) new_open_task_finish;
        task->async->args = args;

        int error = nfs_open_file(task);
        if (!error) {
//            printf("[open] insert task_id = %zu reply = %zu\n", task->task_id, args->reply);
            return;
        }

//        printf("[open] error open new file\n");
    }
    struct file *f = get_by_FD(args->pid, fd);
    f->ref ++;

    seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, fd);
    seL4_Send(args->reply, reply_msg1);
}

bool new_open_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut){

    fmode_t mode = seL4_GetMR(1);
    int len = seL4_GetMR(2);
    seL4_Word user_pointer = (seL4_Word) seL4_GetMR(3);

    unsigned char * data = malloc(sizeof(unsigned char *));
    memset(data, 0, sizeof(unsigned char *));

//    printf("[new_open_task] buf = 0x%016lx, len = %d\n", user_pointer, len);

    NewOpenArgs *args = malloc(sizeof(NewOpenArgs));
    if (args == NULL){
//        printf("[new_open_task] - malloc NewOpenArgs failed\n");
    }
    memset(args, 0, sizeof(NewOpenArgs));
    args->len = len;
    args->mode = mode;
    args->reply = reply;
    args->reply_ut = reply_ut;
    args->data_pointer = &data;
    args->user_pointer = user_pointer;
    args->pid = badge;

    AsyncTask *async = malloc(sizeof(AsyncTask));
    if (async == NULL){
//        printf("[new_open_task] - malloc AsyncTask failed\n");
    }
    memset(async, 0, sizeof(AsyncTask));
    async->call_back = (void (*)(void *)) new_open_task_continue;
    async->args = args;

    get_user_pointer_async(args->pid, args->user_pointer, args->data_pointer, async);
    return true;
}

bool new_close_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut){

    int fd = seL4_GetMR(1);

//    printf("[close - %lu] fd = %d\n", badge, fd);

    int error = close_by_FD(badge, fd);
    if (error){
//        printf("[close] fd = %d, close error\n", fd);
    }

    seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, error);
    seL4_Send(reply, reply_msg1);

    return false;
}

bool new_brk_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut){

    seL4_Word ret;
    seL4_Word newbrk = seL4_GetMR(1);

    Process *process = get_process(badge);
    if (process == NULL){
//        printf("[new_brk_task - %lu] process not found\n", badge);
        return false;
    }

    Addrspace *as = process->addrspace;

    /*if the newbrk is 0, return the bottom of the heap*/
    if (!newbrk) {
        ret = as->heap_base;
    } else if ( as->heap_base < newbrk  && newbrk < (as->heap_base + as->heap_max_size)) {
        ret = newbrk;
    } else {
        ret = 0;
    }

//    printf("[new_brk_task - %lu]  newbrk = 0x%016lx, ret = 0x%016lx\n", badge, newbrk,ret);

    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, ret);
    seL4_Send(reply, reply_msg);

    return false;
}

typedef struct{
    int path_len;
    seL4_Word path_user_pointer;
    unsigned char ** path_pointer;
    seL4_Word buf_user_pointer;
    unsigned char ** buffer_pointer;
    seL4_CPtr reply;
    ut_t *reply_ut;

    seL4_Word pid;
}NewStatArgs;

void new_stat_task_finish(NewStatArgs *args){
//    printf("[new_stat_task_finish]\n");
    finish_use_user_pointer(args->pid, args->path_user_pointer);
    finish_use_user_pointer(args->pid, args->buf_user_pointer);
}

void new_stat_task_continue_2(NewStatArgs *args){

    char *path = malloc(sizeof(char) * (args->path_len + 1));
    memcpy(path, *args->path_pointer, sizeof(char) * args->path_len);
    path[args->path_len] = '\0';

//    printf("[stat] path = %s\n", path);
    StatTask *stat_task = malloc(sizeof(StatTask));
    memset(stat_task, 0, sizeof(StatTask));
    stat_task->task_id = next_task_id++;
    stat_task->reply = args->reply;
    stat_task->reply_ut = args->reply_ut;
    stat_task->path = path;
    stat_task->st = (sos_stat_t *) (*args->buffer_pointer);
    stat_task->async = malloc(sizeof(AsyncTask));
    stat_task->async->call_back = (void (*)(void *)) new_stat_task_finish;
    stat_task->async->args = args;

    int error = nfs_stat_path(stat_task);

    if (error){
        seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, error);
        seL4_Send(args->reply, reply_msg1);
        return;
    }
}

void new_stat_task_continue(NewStatArgs *args){

    AsyncTask *async = malloc(sizeof(AsyncTask));
    if (async == NULL){
//        printf("[new_open_task] - malloc AsyncTask failed\n");
    }
    memset(async, 0, sizeof(AsyncTask));
    async->call_back = (void (*)(void *)) new_stat_task_continue_2;
    async->args = args;

    get_user_pointer_async(args->pid, args->buf_user_pointer, args->buffer_pointer, async);

}

bool new_stat_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut){

    int path_len = seL4_GetMR(1);
    seL4_Word path_user_pointer = seL4_GetMR(2);
    seL4_Word buf_user_pointer = seL4_GetMR(3);

    NewStatArgs *args = malloc(sizeof(NewStatArgs));
    if (args == NULL){
//        printf("[new_stat_task] - malloc NewStatArgs failed\n");
    }
    memset(args, 0, sizeof(NewStatArgs));
    args->path_len = path_len;
    args->path_user_pointer = path_user_pointer;
    args->buf_user_pointer = buf_user_pointer;
    args->reply = reply;
    args->reply_ut = reply_ut;
    args->pid = badge;

    unsigned char * path = malloc(sizeof(unsigned char *));
    memset(path, 0, sizeof(unsigned char *));
    args->path_pointer = &path;

    unsigned char * buffer = malloc(sizeof(unsigned char *));
    memset(buffer, 0, sizeof(unsigned char *));
    args->buffer_pointer = &buffer;

    AsyncTask *async = malloc(sizeof(AsyncTask));
    if (async == NULL){
//        printf("[new_open_task] - malloc AsyncTask failed\n");
    }
    memset(async, 0, sizeof(AsyncTask));
    async->call_back = (void (*)(void *)) new_stat_task_continue;
    async->args = args;

    get_user_pointer_async(badge, args->path_user_pointer, args->path_pointer, async);
    return true;
}

bool new_get_dirent_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut){

//    printf("[new_get_dirent_task]\n");

    int pos = seL4_GetMR(1);
    seL4_Word name_user_pointer = seL4_GetMR(2);
    size_t max_data_size = seL4_GetMR(3);

    UserPage *data_list;
    int pages_size = copy_user_pointer_list(name_user_pointer, max_data_size, &data_list);
    assert(pages_size <= 100);

    GetDirentTask *task = malloc(sizeof(GetDirentTask));
    memset(task, 0, sizeof(GetDirentTask));
    task->task_id = next_task_id++;
    task->reply = reply;
    task->reply_ut = reply_ut;
    task->pos = pos;

    task->user_pages = data_list;

    task->pages_size = pages_size;
    task->user_data_size = max_data_size;
    task->pid = badge;

    int error = nfs_getdirent_api(task);

    if (error){
        seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, error);
        seL4_Send(reply, reply_msg1);
        return false;
    }

    return true;
}

bool new_get_my_pid_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut){
    seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, badge);
    seL4_Send(reply, reply_msg1);
    return false;
}

typedef struct {
    seL4_CPtr reply;
    ut_t *reply_ut;
    seL4_Word pid;
}ProcessCreatArg;

void reply_process_creat(ProcessCreatArg *args){

    seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);

    Process *p = get_process(args->pid);
    if (p == NULL || p->is_active == false){
//        printf("[reply_process_creat] failed to created pid = %lu\n", args->pid);
        destroy_process(args->pid);

        seL4_SetMR(0, -1);
        seL4_Send(args->reply, reply_msg1);
    }else{
//        printf("[reply_process_creat] created pid = %lu\n", args->pid);
        seL4_SetMR(0, args->pid);
        seL4_Send(args->reply, reply_msg1);

    }

    free_reply(args->reply, args->reply_ut);
    free(args);

    return;
}

bool new_process_creat_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut){

    int len = seL4_GetMR(1);
    char *path = malloc(sizeof(char) * (len + 1));
    for (int i = 0; i < len; i++){
        path[i] = seL4_GetMR(i + 2);
    }
    path[len] = '\0';

    Process *process = create_new_process();
    if (process == NULL){
//        printf("[new_process_creat_task - %lu] error start process, app_name = %s\n", badge, path);
        seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, -1);
        seL4_Send(reply, reply_msg1);
        return false;
    }
//    printf("[new_process_creat_task - %lu] Start process, pid = %lu, app_name = %s\n", badge, process->badge, path);

    ProcessCreatArg *args = malloc(sizeof(ProcessCreatArg));
    if (args == NULL){
//        printf("[new_process_creat_task - %lu] could not malloc ProcessCreatArg\n", badge);
        seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, -1);
        seL4_Send(reply, reply_msg1);
        return false;
    }
    memset(args, 0, sizeof(ProcessCreatArg));
    args->reply = reply;
    args->reply_ut =reply_ut;
    args-> pid = process->badge;

    AsyncTask *async = malloc(sizeof(AsyncTask));
    if (async == NULL){
//        printf("[new_process_creat_task - %lu] could not malloc AsyncTask\n", badge);
        seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, -1);
        seL4_Send(reply, reply_msg1);
        return false;
    }
    memset(async, 0, sizeof(AsyncTask));
    async->call_back = (void (*)(void *)) reply_process_creat;
    async->args = args;


    bool success = start_process_async(process, path, app_ipc_ep, true, async);
    if (!success) {
//        printf("[new_process_creat_task] Failed to start process %lu\n", process->badge);
        seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, -1);
        seL4_Send(reply, reply_msg1);
        return false;
    }

    return true;
}

bool new_process_status_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut){

//    printf("[new_process_status_task]\n");

    seL4_Word user_process_pointer = seL4_GetMR(1);
    size_t max_len = seL4_GetMR(2);
    size_t max_data_size = max_len * sizeof (sos_process_t);

    UserPage *user_pages;
    int pages_size = copy_user_pointer_list(user_process_pointer, max_data_size, &user_pages);

    int error = get_process_status(badge, user_pages, pages_size, max_len, reply, reply_ut);
    if (error){
        seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, -1);
        seL4_Send(reply, reply_msg1);
        free(user_pages);
        return false;
    }

    return true;
}

bool new_process_delete_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut){

    seL4_Word pid = seL4_GetMR(1);

//    printf("[new_process_delete_task - %lu] kill pid = %lu\n", badge, pid);

    int error = destroy_process(pid);
    if (error){
//        printf("[new_process_delete_task - %lu] kill pid = %lu, fail with error = %d\n", badge, pid, error);
    }

    seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, error);
    seL4_Send(reply, reply_msg1);
    return false;
}

bool new_process_wait_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut){

    seL4_Word pid = seL4_GetMR(1);

//    printf("[new_process_wait_task - %lu] wait pid = %lu\n", badge, pid);

    int error = add_waitee(pid, badge, reply, reply_ut);
    if (error){
//        printf("[new_process_wait_task - %lu] wait pid = %lu, error = %d\n", badge, pid, error);
        seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, error);
        seL4_Send(reply, reply_msg1);
        return false;
    }

    return true;
}

void init_systask(void){

}