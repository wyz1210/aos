//
// Created by Rui on 2021/7/13.
//

#include "paging.h"
#include "../fs/nfs_api.h"
#include "../utils.h"


PageQueue ROOT_PAGE_QUEUE;
SeL4_Page *temp_page_queue[FRAME_LIMIT];
bool page_file_list[MAX_PAGE_FILE_LIST_SIZE];

void init_paging(){
    memset(&ROOT_PAGE_QUEUE, 0, sizeof(PageQueue));
    memset(&page_file_list, 0, sizeof(bool) * MAX_PAGE_FILE_LIST_SIZE);
}

int get_empty_slot() {
    for (int i = 1; i < MAX_PAGE_FILE_LIST_SIZE; i++) {
        if (page_file_list[i] == false) {
            return i;
        }
    }
//    printf("[get_empty_slot] no empty slots\n");
    return -1;
}

void unuse_slot(int slot) {
    if (slot > 0 && slot < MAX_PAGE_FILE_LIST_SIZE) {
        page_file_list[slot] = false;
    }
}

int use_slot(int slot) {
    if (slot > 0 && slot < MAX_PAGE_FILE_LIST_SIZE && page_file_list[slot] == false) {
        page_file_list[slot] = true;
        return 0;
    }
    return 1;
}

int append_page(SeL4_Page *page) {

    PageQueue *list = &ROOT_PAGE_QUEUE;
    if (list->length < FRAME_LIMIT) {
        list->page_queue[list->length] = page;
        list->length++;
        return 0;
    }
    return 1;
}


void delete_page_from_pagequeue(seL4_Word pid, SeL4_Page *page){
    PageQueue *list = &ROOT_PAGE_QUEUE;
    for (size_t i = 0; i < list->length; i ++){
        if (list->page_queue[i]->vaddr == page->vaddr && list->page_queue[i]->pid == pid){
//            printf("[delete_page_from_pagequeue] pid = %lu, vaddr = 0x%016lx\n", pid, page->vaddr);
            memcpy(&temp_page_queue, &list->page_queue[i + 1], sizeof(SeL4_Page*) * (list->length - i - 1));
            memcpy(&list->page_queue[i], &temp_page_queue, sizeof(SeL4_Page*) * (list->length - i - 1));
            list->page_queue[list->length - 1] = NULL;
            list->length--;
            return;
        }
    }
    return;
}


int pop_available_page(SeL4_Page **page) {

    PageQueue *list = &ROOT_PAGE_QUEUE;
    if (list->length <= 0) {
//        printf("[pop_available_page] empty!\n");
        return 1;
    }

    size_t index = -1;
    for(size_t i = 0; i < list->length; i++){
        if (list->page_queue[i]->pin == false && list->page_queue[i]->fix == false){
            index = i;
            break;
        }
    }

    if (index < 0){
//        printf("[pop_available_page] no unpin page!\n");
        return 1;
    }

    list->length--;
    *page = list->page_queue[index];

    if (list->length > 0 && index < list->length) {
        memcpy(&temp_page_queue, &list->page_queue[index+1], sizeof(SeL4_Page*) * (list->length - index));
        memcpy(&list->page_queue[index], &temp_page_queue, sizeof(SeL4_Page*) * (list->length - index));
    }

    return 0;
}

int second_chance_pop(SeL4_Page **page){

    int error;

    SeL4_Page *p;

    error = pop_available_page(&p);
    if (error != 0){
        return error;
    }

    while (p->visited == true){
        p->visited = false;
        app_unmap_frame(p->frame_cap);
//        printf("[second_chance_pop] unmap vaddr = 0x%016lx\n", p->vaddr);
        append_page(p);
        error = pop_available_page(&p);
        if (error != 0){
            return error;
        }
    }

    *page = p;
    return 0;
}

int first_page(PageQueue *list, SeL4_Page **page) {
    if (list->length <= 0) {
        return 1;
    }

    *page = list->page_queue[0];
    return 0;
}


void swap_out_one_page(SwapOutTask *task) {

    int error = pop_available_page(&task->page);
    if (error != 0) {
//        printf("[swap_out] no page to swap out\n");
        return;
    }

    if (task->page == NULL){
//        printf("[swap_out - %lu] pop out null page\n", task->pid);
        task->call_back(task->args);
        return;
    }

    task->page->page_file_offset = get_empty_slot();
    use_slot(task->page->page_file_offset);

//    printf("[swap_out - %lu] page->vaddr = 0x%016lx, slot = %zu\n", task->pid, task->page->vaddr, task->page->page_file_offset);

    write_page_file(PAGE_FILE, task);
}

typedef struct{
    seL4_CPtr reply;
    ut_t *reply_ut;
    SeL4_Page *page;
}ReplayTask;

void replay_cb(ReplayTask *task){
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, 0);
    seL4_Send(task->reply, reply_msg);

    task->page->pin = false;

    unuse_slot(task->page->page_file_offset);
    free_reply(task->reply, task->reply_ut);
    free(task);
}


void swap_in_one_page(SwapInTask *task) {
    read_page_file(PAGE_FILE, task);
}


void vm_fault_continue(VmFaultTask *task) {

    if (task->frame == NULL_FRAME) {
        task->frame = alloc_frame();
        frame_lock = false;
    }

    if (task->frame == NULL_FRAME) {
//        printf("[vm_fault_continue - %lu] vaddr(0x%016lx) Couldn't allocate frame\n", task->badge, task->vaddr);
        // TODO add reply or kill process?
        return;
    }

    /* allocate a slot to duplicate the frame cap so we can map it into the application */
    seL4_CPtr frame_cptr = cspace_alloc_slot(&cspace);

    /* copy the frame cap into the slot */
    seL4_Error err = cspace_copy(&cspace, frame_cptr, &cspace, frame_page(task->frame), seL4_AllRights);
    if (err != seL4_NoError) {
        cspace_free_slot(&cspace, frame_cptr);
        free_frame(task->frame);
//        printf("[vm_fault_continue - %lu] Failed to copy cap error = %d\n",task->badge, err);
        // TODO add reply or kill process?
        return;
    }

    err = app_map_frame(task->badge, &cspace, frame_cptr, task->vspace, task->vaddr,
                        seL4_AllRights, seL4_ARM_Default_VMAttributes, task->frame, true, false);
    if (err != 0) {
        cspace_delete(&cspace, frame_cptr);
        cspace_free_slot(&cspace, frame_cptr);
        free_frame(task->frame);
//        printf("[vm_fault_continue - %lu] Unable to map extra frame for user app\n", task->badge);
        // TODO add reply or kill process?
        return;
    }

    SeL4_Page *page = get_page(task->badge, task->vaddr);

    ReplayTask *replay_task = malloc(sizeof(ReplayTask));
    if (replay_task == NULL){
//        printf("[malloc] SwapInTask failed\n");
        // TODO add reply or kill process?
        return;
    }
    memset(replay_task, 0 ,sizeof(SwapInTask));
    replay_task->page = page;
    replay_task->reply = task->reply;
    replay_task->reply_ut = task->reply_ut;

    if (page->page_file_offset != 0) {
//        printf("[vm_fault] swap_in vaddr = 0x%016lx, page_file_offset=%zu, frame=%zu\n", task->vaddr, page->page_file_offset, page->frame);
        SwapInTask *in_task = malloc(sizeof(SwapInTask));
        if (in_task == NULL){
//            printf("[malloc] SwapInTask failed\n");
            // TODO add reply or kill process?
            return;
        }
        memset(in_task, 0 ,sizeof(SwapInTask));
        in_task->page = page;
        in_task->call_back = (void (*)(void *)) replay_cb;
        in_task->args = replay_task;

        swap_in_one_page(in_task);
        return;
    }

    replay_cb(replay_task);
    return;
}
