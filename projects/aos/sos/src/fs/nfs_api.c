//
// Created by Rui on 2021/6/28.
//

//
// Created by Rui on 2021/6/17.
//
#include <pico_stack.h>
#include <pico_device.h>
#include <pico_config.h>
#include <pico_ipv4.h>
#include <pico_socket.h>
#include <pico_nat.h>
#include <pico_icmp4.h>
#include <pico_dns_client.h>
#include <pico_dev_loop.h>
#include <pico_dhcp_client.h>
#include <pico_dhcp_server.h>
#include <pico_ipfilter.h>
#include "pico_bsd_sockets.h"

#include <ethernet/ethernet.h>

#include <nfsc/libnfs.h>

#include <stdio.h>
#include <serial/serial.h>
#include <sel4runtime.h>
#include <nfsc/libnfs.h>
#include <fcntl.h>
#include "fdtable.h"
#include "read_task.h"
#include "../vm/app_mapping.h"
#include "../utils.h"
#include "../vm/paging.h"
#include "nfs_api.h"
#include "../process.h"


ReadTaskList nfs_read_tasks;
static struct nfs_context *global_nfs_context;

int nfs_write_api(WriteTask *task);
int nfs_read_api(ReadTask *task);

file_opts_t nfs_opts = {
        .read = nfs_read_api,
        .write = nfs_write_api
};

void nfs_read_api_continue(ReadTask *task);

void sos_nfs_read_cb(int status, struct nfs_context *nfs, void *data, void *private_data){

    ReadTask *task = private_data;

    if (status < 0) {
//        printf("[sos_nfs_read_cb] read call failed with \"%s\"\n", (char *)data);
        seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, task->data_len);
        seL4_Send(task->reply, reply_msg1);
        free_reply(task->reply,task->reply_ut);
        free(task->user_pages);
        free(task);
        return;
    }

//    printf("[sos_nfs_read_cb_continue] read %d\n", status);

    task->data_len += status;
    task->file->offset += status;

    memcpy(*task->user_pages[task->cursor].data_pointer, data, sizeof(char) * status);
    finish_use_user_pointer(task->pid, task->user_pages[task->cursor].user_pointer);

    task->cursor ++;

    if (task->data_len >= task->user_data_size || task->cursor >= task->pages_size){
        // finish read
        seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, task->data_len);
        seL4_Send(task->reply, reply_msg1);
//        printf("[sos_nfs_read_cb_continue] data_len = %zu\n", task->data_len);
        free_reply(task->reply,task->reply_ut);
        free(task->user_pages);
        free(task);
        return;
    }

    AsyncTask * async = malloc(sizeof(AsyncTask));
    async->call_back = (void (*)(void *)) nfs_read_api_continue;
    async->args = task;

    get_user_pointer_async(task->pid, task->user_pages[task->cursor].user_pointer, task->user_pages[task->cursor].data_pointer, async);

}

void nfs_read_api_continue(ReadTask *task){

    //    printf("[nfs_read_api] offset = %zu\n", task->file->offset);
    if (nfs_pread_async(global_nfs_context, task->file->nfsfh,task->file->offset, task->user_pages[task->cursor].size, sos_nfs_read_cb, task) != 0) {
//        printf("[nfs_read_api] Failed to start async nfs read, task_id = %zu\n", task->task_id);
        return;
    }
    //    printf("[nfs_read_api] fd = %d, len = %zu\n", nfs_get_fd(global_nfs_context), task->user_data_size);
    return;
}

int nfs_read_api(ReadTask *task){
    AsyncTask * async = malloc(sizeof(AsyncTask));
    async->call_back = (void (*)(void *)) nfs_read_api_continue;
    async->args = task;

    get_user_pointer_async(task->pid, task->user_pages[task->cursor].user_pointer, task->user_pages[task->cursor].data_pointer, async);
}

void sos_nfs_write_cb(int status, struct nfs_context *nfs, void *data, void *private_data);

void nfs_write_api_continue(WriteTask *task){
    if (nfs_pwrite_async(global_nfs_context, task->file->nfsfh,task->file->offset, task->user_pages[task->cur].size, *task->user_pages[task->cur].data_pointer, sos_nfs_write_cb, task) != 0) {
//        printf("[nfs_write_api] Failed to start async nfs write, task_id = %zu\n", task->task_id);

        seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, -1);
        seL4_Send(task->reply, reply_msg1);
//        printf("[sos_nfs_write_cb] send_data_size = %zu\n", task->send_data_size);
        free_reply(task->reply,task->reply_ut);
        free(task->user_pages);
        free(task);

        return;
    }
    //    printf("[nfs_write_api] sos_buf = %s\n", task->sos_buf);
    //    printf("[nfs_write_api] task_id = %zu, write %zu to nfs\n", task->task_id, len);
    return;
}

void sos_nfs_write_cb(int status, struct nfs_context *nfs, void *data, void *private_data){

    struct nfsfh *nfsfh = data;
    WriteTask *task = private_data;

    if (status < 0) {
//        printf("[sos_nfs_write_cb] write call failed with \"%s\"\n", (char *)data);
        seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, task->send_data_size);
        seL4_Send(task->reply, reply_msg1);
        free_reply(task->reply,task->reply_ut);
        free(task->user_pages);
        free(task);
        return;
    }

    task->send_data_size += status;
    finish_use_user_pointer(task->pid, task->user_pages[task->cur].user_pointer);

    task->cur ++;
    task->file->offset += status;
//    printf("[sos_nfs_write_cb] cur = %zu\n", task->cur);

    if (task->send_data_size >= task->data_size || task->cur >= task->pages_size){
        // finish write
        seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, task->send_data_size);
        seL4_Send(task->reply, reply_msg1);
//        printf("[sos_nfs_write_cb] send_data_size = %zu\n", task->send_data_size);
        free_reply(task->reply,task->reply_ut);
        free(task->user_pages);
        free(task);
        return;
    }

    AsyncTask * async = malloc(sizeof(AsyncTask));
    async->call_back = (void (*)(void *)) nfs_write_api_continue;
    async->args = task;

    get_user_pointer_async(task->pid, task->user_pages[task->cur].user_pointer, task->user_pages[task->cur].data_pointer, async);
    return;
}

int nfs_write_api(WriteTask *task){

    AsyncTask * async = malloc(sizeof(AsyncTask));
    async->call_back = (void (*)(void *)) nfs_write_api_continue;
    async->args = task;

    get_user_pointer_async(task->pid, task->user_pages[task->cur].user_pointer, task->user_pages[task->cur].data_pointer, async);
}

void sos_nfs_open_cb(int status, struct nfs_context *nfs, void *data, void *private_data)
{

    struct nfsfh *nfsfh = data;
    OpenTask *task = private_data;

    if (status < 0) {
//        printf("[sos_nfs_open_cb] open call failed with \"%s\"\n", (char *)data);
        seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, -1);
        seL4_Send(task->reply, reply_msg1);

        free_reply(task->reply,task->reply_ut);
        task->async->call_back(task->async->args);
        free(task);
        return;
    }

//    printf("[sos_nfs_open_cb] Got reply from server for open. Handle: path = %s\n", task->path);

    int fd = add_fd(task->pid, task->path, 0 , 0, task->mode,nfs_opts, 1, nfsfh);
    global_nfs_context = nfs;

    seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, fd);
    seL4_Send(task->reply, reply_msg1);

    free_reply(task->reply,task->reply_ut);
    task->async->call_back(task->async->args);
    free(task);
}

int nfs_open_file(OpenTask *task){
    if (nfs_open_async(global_nfs_context, task->path, O_CREAT | task->mode, sos_nfs_open_cb, task) != 0) {
//        printf("[nfs_open_file] Failed to start async nfs open, path = %s\n", task->path);
        return 1;
    }

    return 0;
}

void sos_nfs_stat_cb(int status, struct nfs_context *nfs, void *data, void *private_data){


    StatTask *task = private_data;

    if (status < 0) {
//        printf("stat call failed with \"%s\"\n", (char *)data);
        seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, 1);
        seL4_Send(task->reply, reply_msg1);
        free_reply(task->reply,task->reply_ut);
        task->async->call_back(task->async->args);
        free(task);
        return;
    }

    struct nfs_stat_64 *st = (struct nfs_stat_64 *)data;
//    printf("Mode %04o\n", (unsigned int) st->nfs_mode);
//    printf("Size %d\n", (int)st->nfs_size);
//    printf("Inode %04o\n", (int)st->nfs_ino);

    (task->st)->st_atime = st->nfs_atime;
    (task->st)->st_ctime = st->nfs_ctime;
    (task->st)->st_size = st->nfs_size;
    (task->st)->st_fmode = st->nfs_mode;
    (task->st)->st_type = 1;

    seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, 0);
    seL4_Send(task->reply, reply_msg1);

    free_reply(task->reply,task->reply_ut);
    task->async->call_back(task->async->args);
    free(task);
}

int nfs_stat_path(StatTask *task){
    if (nfs_stat64_async(global_nfs_context, task->path, sos_nfs_stat_cb, task) != 0) {
//        printf("Failed to start async nfs stat\n");
        return 1;
    }

    return 0;
}

void sos_nfs_opendir_cb_continue(GetDirentTask *task){

    size_t i = 0;
    while((task->nfsdirent = nfs_readdir(task->nfs, task->nfsdir)) != NULL) {
        if (i == task->pos){
//            printf("Inode:%d Name:%s\n", (int)task->nfsdirent->inode, task->nfsdirent->name);
            // TODO support long name
            memset(*task->user_pages[0].data_pointer, 0 , task->user_pages[0].size);
            memcpy(*task->user_pages[0].data_pointer, task->nfsdirent->name, strlen(task->nfsdirent->name));
            seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
            seL4_SetMR(0, 1);
            seL4_Send(task->reply, reply_msg1);
            free_reply(task->reply, task->reply_ut);
            nfs_closedir(task->nfs, task->nfsdir);
            finish_use_user_pointer(task->pid, task->user_pages[0].user_pointer);
            free(task->user_pages);
            free(task);
            return ;
        }
        i ++;
    }
    nfs_closedir(task->nfs, task->nfsdir);

    seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, 0);
    seL4_Send(task->reply, reply_msg1);
    free_reply(task->reply, task->reply_ut);
    finish_use_user_pointer(task->pid, task->user_pages[0].user_pointer);
    free(task->user_pages);
    free(task);
}

void sos_nfs_opendir_cb(int status, struct nfs_context *nfs, void *data, void *private_data){

    GetDirentTask *task = private_data;
    task->nfsdir = data;
    task->nfs = nfs;

//    printf("[nfs_opendir_cb]\n");

    if (status < 0) {
//        printf("opendir failed with \"%s\"\n", (char *)data);
        seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, -1);
        seL4_Send(task->reply, reply_msg1);
        free_reply(task->reply, task->reply_ut);
        free(task);
        return;
    }

    AsyncTask * async = malloc(sizeof(AsyncTask));
    async->call_back = (void (*)(void *)) sos_nfs_opendir_cb_continue;
    async->args = task;

    get_user_pointer_async(task->pid, task->user_pages[0].user_pointer, task->user_pages[0].data_pointer, async);

}

int nfs_getdirent_api(GetDirentTask *task){
//    printf("[nfs_getdirent_api] task_id = %zu\n",task->task_id);
    if (nfs_opendir_async(global_nfs_context, "./", sos_nfs_opendir_cb, task) != 0) {
//        printf("Failed to start async nfs close\n");
        return 1;
    }
    return 0;
}

void page_file_open_cb(int status, struct nfs_context *nfs, void *data, void *private_data)
{

    struct nfsfh *nfsfh = data;

    if (status < 0) {
//        printf("[page_file_open_cb] open call failed with \"%s\"\n", (char *)data);
        return;
    }

//    printf("[page_file_open_cb] Got reply from server for open. Handle: path = pagefile\n");

    int fd = add_fd(0, "pagefile", 0 , 0, O_RDWR,nfs_opts, 1, nfsfh);
    global_nfs_context = nfs;

    PAGE_FILE = get_by_FD(0, fd);
    if (PAGE_FILE == NULL){
//        printf("[page_file_open_cb] error get pagefile file\n");
    }

    vm_ready = true;

}

int open_page_file(){
    if (nfs_open_async(global_nfs_context, "pagefile", O_CREAT | O_RDWR, page_file_open_cb, NULL) != 0) {
//        printf("[open_page_file] Failed to start async nfs open, path = pagefile\n");
        return 1;
    }

    return 0;
}

void page_file_write_cb(int status, struct nfs_context *nfs, void *data, void *private_data){

    struct nfsfh *nfsfh = data;
    SwapOutTask *task = private_data;

    if (status < 0) {
//        printf("[page_file_write_cb] write call failed with \"%s\"\n", (char *)data);
        return;
    }

    int err = app_unmap_frame(task->page->frame_cap);
    if (err != 0) {
//        printf("[page_file_write_cb] unmap err = %d\n", err);
        return;
    }

    cspace_delete(&cspace, task->page->frame_cap);
    cspace_free_slot(&cspace, task->page->frame_cap);
    free_frame(task->page->frame);

    task->page->frame_cap = 0;
    task->page->frame = NULL_FRAME;

//    printf("[page_file_write_cb] write finished, slot = %zu\n",task->page->page_file_offset);

    task->call_back(task->args);
    free(task);
}

int write_page_file(struct file *file, void *t){

    SwapOutTask *task = (SwapOutTask *) t;

    if (get_process(task->pid) == NULL){
//        printf("[write_page_file] process pid = %lu is deleted\n", task->pid);
        return 1;
    }

//    printf("[write_page_file] slot = %zu\n", task->page->page_file_offset);
    if (nfs_pwrite_async(global_nfs_context, file->nfsfh, task->page->page_file_offset * PAGE_SIZE, PAGE_SIZE, frame_data(task->page->frame), page_file_write_cb, task) != 0) {
//        printf("[write_page_file] Failed to start async nfs write\n");
        return 1;
    }
    return 0;
}

void page_file_read_cb(int status, struct nfs_context *nfs, void *data, void *private_data){

    char *read_data = data;
    SwapInTask *task = private_data;

    if (status < 0) {
//        printf("[page_file_read_cb] read call failed with \"%s\"\n", (char *)data);
        return;
    }

    if (task->page->frame == NULL_FRAME){
//        printf("[page_file_read_cb - %lu] read null frame, vaddr = 0x%016lx\n", task->page->pid, task->page->vaddr);
        return;
    }
    memcpy(frame_data(task->page->frame), read_data, sizeof(char) * status);

//    printf("[page_file_read_cb] finished\n");
    unuse_slot(task->page->page_file_offset);
    task->page->page_file_offset = 0;
    task->call_back(task->args);
    free(task);

    return;
}

int read_page_file(struct file *file, void *t){

    SwapInTask *task = (SwapInTask *) t;
//    printf("[swap_in] vaddr = 0x%016lx\n", task->page->vaddr);
    if (nfs_pread_async(global_nfs_context, file->nfsfh, task->page->page_file_offset * PAGE_SIZE, PAGE_SIZE, page_file_read_cb, task) != 0) {
//        printf("[read_page_file] Failed to start async nfs read\n");
        return 1;
    }
    return 0;
}

void init_nfs_api(struct nfs_context *nfs){
    // call from network_init
    // mount is done in network.c

    global_nfs_context = nfs;

}


void nfs_load_elf_read_cb(int status, struct nfs_context *nfs, void *data, void *private_data){

    NfsLoadElfArgs *args = private_data;

    if (status < 0) {
//        printf("[sos_nfs_read_cb] read call failed with \"%s\"\n", (char *)data);
        args->async->call_back(args->async->args);
//        printf("[nfs_load_elf_read_cb] free\n");
        free(args->async);
        free(args);
        return;
    }

//    printf("[sos_nfs_read_cb_continue] read %d\n", status);

    memcpy(args->elf_base + args->cur, data, sizeof(char) * status);

    args->cur += status;

    if (args->cur >= *args->size){
        // finish read
        args->async->call_back(args->async->args);
        free(args->async);
        free(args);
        return;
    }

    if (nfs_pread_async(global_nfs_context, args->nfsfh, args->cur, PAGE_SIZE, nfs_load_elf_read_cb, args) != 0) {
//        printf("[nfs_load_elf_open_cb] Failed to start async read\n");
        args->async->call_back(args->async->args);
        free(args->async);
        free(args);
        return;
    }

}


void nfs_load_elf_open_cb(int status, struct nfs_context *nfs, void *data, void *private_data)
{

    NfsLoadElfArgs *args = private_data;

    if (status < 0) {
//        printf("[nfs_load_elf_open_cb] open call failed with \"%s\"\n", (char *)data);
        free(args);
        return;
    }

    struct nfsfh *nfsfh = data;
    global_nfs_context = nfs;

    args->nfsfh = nfsfh;

    if (nfs_pread_async(global_nfs_context, args->nfsfh, 0, PAGE_SIZE, nfs_load_elf_read_cb, args) != 0) {
//        printf("[nfs_load_elf_open_cb] Failed to start async read\n");
        args->async->call_back(args->async->args);
        free(args->async);
        free(args);
        return;
    }

    return;

}

void nfs_load_elf_stat_cb(int status, struct nfs_context *nfs, void *data, void *private_data){

    NfsLoadElfArgs *args = private_data;

    if (status < 0) {
//        printf("[nfs_load_elf_stat_cb] stat call failed with \"%s\"\n", (char *)data);
        if (args->async != NULL){
            args->async->call_back(args->async->args);
            free(args->async);
        }
        free(args);
        return;
    }

    struct nfs_stat_64 *st = (struct nfs_stat_64 *)data;
    *(args->size) = st->nfs_size;

    if (args->elf_base == NULL){
//        printf("[nfs_load_elf_stat_cb] elf_base with NULL ptr, size = %lu\n", st->nfs_size);
        if (args->async != NULL){
            args->async->call_back(args->async->args);
            free(args->async);
        }
        return;
    }

    if (nfs_open_async(global_nfs_context, args->path, O_RDONLY, nfs_load_elf_open_cb, args) != 0) {
//        printf("[nfs_load_elf_stat_cb] Failed to start async nfs open, path = %s\n", args->path);
        if (args->async != NULL){
            args->async->call_back(args->async->args);
            free(args->async);
        }
    }
    return;

}


int nfs_load_elf_async(char *app_name, char *elf_base, unsigned long *elf_size, AsyncTask *async){

    NfsLoadElfArgs *args = malloc(sizeof(NfsLoadElfArgs));
    if (args == NULL){
//        printf("[nfs_load_elf_async][malloc] could not allocate NfsLoadElfArgs\n");
        if (async != NULL){
            async->call_back(async->args);
            free(async);
        }
        return false;
    }
    memset(args, 0, sizeof(NfsLoadElfArgs));
    args->path = app_name;
    args->elf_base = elf_base;

    args->size = elf_size;

    args->async = async;

    if (nfs_stat64_async(global_nfs_context, args->path, nfs_load_elf_stat_cb, args) != 0) {
//        printf("[nfs_load_elf_async ]Failed to start async nfs stat path = %s\n", args->path);
        if (async != NULL){
            async->call_back(async->args);
            free(async);
        }
        return 1;
    }
    return 0;
}

