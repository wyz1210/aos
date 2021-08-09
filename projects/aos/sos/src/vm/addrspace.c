//
// Created by Rui on 2021/6/21.
//

#include <string.h>
#include <stdlib.h>
#include "addrspace.h"
#include "app_mapping.h"
#include "../vmem_layout.h"
#include "paging.h"
#include "../utils.h"
#include "../process.h"

/*
 * Note! If OPT_DUMBVM is set, as is the case until you start the VM
 * assignment, this file is not compiled or linked or in any way
 * used. The cheesy hack versions in dumbvm.c are used instead.
 *
 * UNSW: If you use ASST3 config as required, then this file forms
 * part of the VM subsystem.
 *
 */


void init_addrspace(){
}

int copy_user_pointer_list(seL4_Word user_pointer, size_t len, UserPage ** page_list){

    size_t max_size = len / PAGE_SIZE + 2;
    UserPage *user_page_list = malloc(sizeof(UserPage) * max_size);
    if (user_page_list == NULL){
//        printf("[copy_user_pointer_list] error create user_page_list\n");
        return 0;
    }
    memset(user_page_list, 0 , sizeof(UserPage) * max_size);

    size_t stored_data_size = OFFSET_MASK - (user_pointer & OFFSET_MASK) + 1;

    user_page_list[0].user_pointer = user_pointer;
    user_page_list[0].data_pointer =  &user_page_list[0].data;
    user_page_list[0].size = stored_data_size <= len ? stored_data_size : len;
    int remain_size = len - user_page_list[0].size;

    int pages_size = 1;
    while(remain_size > 0){
        stored_data_size += OFFSET_MASK + 1;
        user_pointer += OFFSET_MASK + 1;
        user_pointer &= ~OFFSET_MASK;

        user_page_list[pages_size].user_pointer = user_pointer;
        user_page_list[pages_size].data_pointer = &user_page_list[pages_size].data;
        user_page_list[pages_size].size = stored_data_size <= len ? OFFSET_MASK + 1 : remain_size % (OFFSET_MASK + 1);
        remain_size -= user_page_list[pages_size].size;

        pages_size ++;
    }

    *page_list = user_page_list;

    return pages_size;
}

typedef struct{
    seL4_Word user_pointer;
    unsigned char ** data_pointer;
    SeL4_Page * page;
    AsyncTask *async;
    seL4_CPtr vspace;
    seL4_Word pid;
}GetUserPointerTask;

void finish_use_user_pointer(seL4_Word pid, seL4_Word user_pointer){

    Process *process = get_process(pid);
    if (process == NULL){
//        printf("[finish_use_user_pointer - %lu] vaddr(0x%016lx) Couldn't get this process\n",pid, user_pointer);
        return;
    }

    SeL4_Page *p = get_page(pid, user_pointer);

    if (p == NULL || p->frame == NULL_FRAME || p->fix == true){
        return;
    }

//    printf("[unpin - %lu] vaddr = 0x%016lx\n", pid, user_pointer & (~OFFSET_MASK));
    p->pin = false;
}

void get_user_pointer_continue_2(GetUserPointerTask * task){

    Process *process = get_process(task->pid);
    if (process == NULL){
//        printf("[get_user_pointer_continue_2 - %lu] vaddr(0x%016lx) Couldn't get this process\n",task->pid, task->user_pointer);
        return;
    }

    SeL4_Page *p = get_page(task->pid, task->user_pointer);
    if(task == NULL){
//        printf("[get_user_pointer_continue_2] has null task\n");
        return;
    }

    if (p == NULL){
//        printf("[get_user_pointer_continue_2] has null page\n");
        return;
    }
    if(p->frame == NULL_FRAME){
//        printf("[get_user_pointer_continue_2] has null frame\n");
        return;
    }
    unsigned char *data = frame_data(p->frame);
    seL4_Word user_address = task->user_pointer & OFFSET_MASK;
    *(task->data_pointer) = &data[user_address];

    task->async->call_back(task->async->args);

    free(task->async);
    free(task);
}

void get_user_pointer_continue(GetUserPointerTask * task){

    Process *process = get_process(task->pid);
    if (process == NULL){
//        printf("[get_user_pointer_continue - %lu] vaddr(0x%016lx) Couldn't get this process\n",task->pid, task->user_pointer);
        return;
    }

    SeL4_Page *p = get_or_create_page(task->pid, task->user_pointer);
    if (p->frame != NULL_FRAME){
        get_user_pointer_continue_2(task);
        return;
    }

//    printf("[get_user_pointer_continue] alloc new frame\n");
    p->frame = alloc_frame();
    frame_lock = false;

    if (p->frame == NULL_FRAME) {
//        printf("[get_user_pointer_continue - %lu] vaddr(0x%016lx) Couldn't allocate frame\n",task->pid, task->user_pointer);
        return;
    }

    seL4_CPtr frame_cptr = cspace_alloc_slot(&cspace);
    seL4_Error err = cspace_copy(&cspace, frame_cptr, &cspace, frame_page(p->frame), seL4_AllRights);
    if (err != seL4_NoError) {
        cspace_free_slot(&cspace, frame_cptr);
        free_frame(p->frame);
        p->frame = NULL_FRAME;
//        printf("Failed to copy cap error = %d\n", err);
        return;
    }

    err = app_map_frame(task->pid, &cspace, frame_cptr, process->vspace, task->user_pointer,
                        seL4_AllRights, seL4_ARM_Default_VMAttributes, p->frame, true, false);
    if (err != 0) {
        cspace_delete(&cspace, frame_cptr);
        cspace_free_slot(&cspace, frame_cptr);
        free_frame(p->frame);
        p->frame = NULL_FRAME;
//        printf("[get_user_pointer_continue - %lu] Unable to map extra frame for user app, vaddr = 0x%016lx, error = %d\n",task->pid, task->user_pointer & (~OFFSET_MASK), err);
        return;
    }

    if (p->page_file_offset != 0) {
//        printf("[get_user_pointer_continue - %lu] has offset = %zu, need to swap in the page\n",task->pid, p->page_file_offset);
        SwapInTask *in_task = malloc(sizeof(SwapInTask));
        if (in_task == NULL){
//            printf("[malloc] SwapInTask failed\n");
        }
        memset(in_task, 0 ,sizeof(SwapInTask));
        in_task->page = p;
        in_task->call_back = (void (*)(void *)) get_user_pointer_continue_2;
        in_task->args = task;

        swap_in_one_page(in_task);
        return;
    }

    get_user_pointer_continue_2(task);
    return;
}

int get_user_pointer_async(seL4_Word pid, seL4_Word user_pointer, unsigned char ** data_pointer, AsyncTask *async){

    SeL4_Page *p = get_or_create_page(pid, user_pointer);
    if (p == NULL){
//        printf("[get_user_pointer] has null page, vaddr = 0x%016lx\n", user_pointer);
        return 1;
    }

    GetUserPointerTask *pointer_task = malloc(sizeof(GetUserPointerTask));
    if (pointer_task == NULL){
//        printf("[malloc] GetUserPointerTask failed\n");
    }
    memset(pointer_task, 0, sizeof(GetUserPointerTask));
    pointer_task->user_pointer = user_pointer;
    pointer_task->data_pointer = data_pointer;
    pointer_task->page = p;
    pointer_task->async = async;
    pointer_task->pid = pid;

    if (p != NULL && p->frame == NULL_FRAME){
        p->frame = alloc_frame();
//        printf("[get_user_pointer - %lu] has null frame, re-alloc a frame, vaddr = 0x%016lx\n", pid, user_pointer);
    }

    if(p == NULL || p->frame == NULL_FRAME){
//        printf("[get_user_pointer - %lu] has null frame, vaddr = 0x%016lx\n", pid, user_pointer);
        SwapOutTask *task = malloc(sizeof(SwapOutTask));
        if (task == NULL){
//            printf("[malloc] SwapOutTask failed\n");
        }
        memset(task, 0, sizeof(SwapOutTask));
        task->call_back = (void (*)(void *)) get_user_pointer_continue;
        task->args = pointer_task;
        task->pid = pid;

        frame_lock = true;
        swap_out_one_page(task);
        return 0;
    }

    get_user_pointer_continue(pointer_task);
    return 0;
}