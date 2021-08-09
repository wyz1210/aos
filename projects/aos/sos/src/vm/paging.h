//
// Created by Rui on 2021/7/13.
//

#ifndef SEL4_APPLICATION_PAGING_H
#define SEL4_APPLICATION_PAGING_H

#include <sos/gen_config.h>
#include "./app_mapping.h"

#define  MAX_PAGE_FILE_LIST_SIZE 200000
#define FRAME_LIMIT (CONFIG_SOS_FRAME_LIMIT == 0ul ? 81920:CONFIG_SOS_FRAME_LIMIT)

bool frame_lock;

typedef struct {
    void (*call_back)(void *args);
    void *args;
} AsyncTask;

typedef struct{
    seL4_CPtr reply;
    ut_t *reply_ut;
    seL4_CPtr vspace;
    seL4_Word vaddr;
    seL4_Word badge;
    frame_ref_t frame;
}VmFaultTask;

typedef struct {
    SeL4_Page *page;
    void (*call_back)(void *args);
    void *args;

    seL4_Word pid;
} SwapOutTask;

typedef struct {
    SeL4_Page *page;
    void (*call_back)(void *args);
    void *args;
} SwapInTask;

typedef struct {
    size_t length;
    SeL4_Page *page_queue[FRAME_LIMIT];
} PageQueue;

bool vm_ready;
struct file *PAGE_FILE;

void init_paging(void);
void unuse_slot(int slot);
int append_page(SeL4_Page *page);
void swap_out_one_page(SwapOutTask *task);
void swap_in_one_page(SwapInTask *task);
void vm_fault_continue(VmFaultTask *task);
void delete_page_from_pagequeue(seL4_Word pid, SeL4_Page *page);

#endif //SEL4_APPLICATION_PAGING_H
