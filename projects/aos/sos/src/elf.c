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
#include <utils/util.h>
#include <stdbool.h>
#include <sel4/sel4.h>
#include <elf/elf.h>
#include <string.h>
#include <assert.h>
#include <cspace/cspace.h>

#include "frame_table.h"
#include "ut.h"
#include "mapping.h"
#include "elfload.h"
#include "vm/app_mapping.h"
#include "vm/paging.h"

/*
 * Convert ELF permissions into seL4 permissions.
 */
static inline seL4_CapRights_t get_sel4_rights_from_elf(unsigned long permissions)
{
    bool canRead = permissions & PF_R || permissions & PF_X;
    bool canWrite = permissions & PF_W;

    if (!canRead && !canWrite) {
        return seL4_AllRights;
    }

    return seL4_CapRights_new(false, false, canRead, canWrite);
}

typedef struct{
    unsigned int pos;
    cspace_t *cspace;
    seL4_CPtr loadee;
    const char *src;
    size_t segment_size;
    size_t file_size;
    uintptr_t dst;
    seL4_CapRights_t permissions;
    uintptr_t loadee_vaddr;
    seL4_CPtr loadee_frame;
    frame_ref_t frame;
    AsyncTask *async;

    seL4_Word pid;
    bool *loading_error;
}Elf_Task;

int load_segment_into_vspace_async(Elf_Task *task);

int do_load_segment_continue(Elf_Task *task){

    if (task->frame == NULL_FRAME) {
        task->frame = alloc_frame();
        frame_lock = false;
//        printf("[do_load_segment_continue] alloc_frame()\n");
    }

    if (task->frame == NULL_FRAME) {
//        printf("[do_load_segment_continue] Couldn't allocate frame\n");
        *(task->loading_error) = true;
        task->async->call_back(task->async->args);
        free(task->async);
        free(task);
        return -1;
    }

    seL4_Error err;

    /* copy it */
    err = cspace_copy(task->cspace, task->loadee_frame, frame_table_cspace(), frame_page(task->frame), seL4_AllRights);
    if (err != seL4_NoError) {
//        printf("Failed to untyped reypte");
        *(task->loading_error) = true;
        task->async->call_back(task->async->args);
        free(task->async);
        free(task);
        return -1;
    }

    /* map the frame into the loadee address space */
    err = app_map_frame(task->pid, task->cspace, task->loadee_frame, task->loadee, task->loadee_vaddr, task->permissions,
                        seL4_ARM_Default_VMAttributes,task->frame,false, false);


    /* A frame has already been mapped at this address. This occurs when segments overlap in
     * the same frame, which is permitted by the standard. That's fine as we
     * leave all the frames mapped in, and this one is already mapped. Give back
     * the ut we allocated and continue on to do the write.
     *
     * Note that while the standard permits segments to overlap, this should not occur if the segments
     * have different permissions - you should check this and return an error if this case is detected. */
    bool already_mapped = (err == seL4_DeleteFirst);

    if (already_mapped) {
        cspace_delete(task->cspace, task->loadee_frame);
        cspace_free_slot(task->cspace, task->loadee_frame);
        free_frame(task->frame);
//        printf("already_mapped! loadee at %p, error %d\n", (void *) task->loadee_vaddr, err);
    } else if (err != seL4_NoError) {
//        printf("Failed to map into loadee at %p, error %d\n", (void *) task->loadee_vaddr, err);
        *(task->loading_error) = true;
        task->async->call_back(task->async->args);
        free(task->async);
        free(task);
        return -1;
    }


    /* finally copy the data */
    unsigned char *loader_data = frame_data(task->frame);

    /* Write any zeroes at the start of the block. */
    size_t leading_zeroes = task->dst % PAGE_SIZE_4K;
    memset(loader_data, 0, leading_zeroes);
    loader_data += leading_zeroes;

    /* Copy the data from the source. */
    size_t segment_bytes = PAGE_SIZE_4K - leading_zeroes;
    size_t file_bytes = MIN(segment_bytes, task->file_size - task->pos);
    if (task->pos < task->file_size) {
        memcpy(loader_data, task->src, file_bytes);
    } else {
        memset(loader_data, 0, file_bytes);
    }
    loader_data += file_bytes;

    /* Fill in the end of the frame with zereos */
    size_t trailing_zeroes = PAGE_SIZE_4K - (leading_zeroes + file_bytes);
    memset(loader_data, 0, trailing_zeroes);

    /* Flush the frame contents from loader caches out to memory. */
    flush_frame(task->frame);

    /* Invalidate the caches in the loadee forcing data to be loaded
     * from memory. */
    if (seL4_CapRights_get_capAllowWrite(task->permissions)) {
        seL4_ARM_Page_Invalidate_Data(task->loadee_frame, 0, PAGE_SIZE_4K);
    }
    seL4_ARM_Page_Unify_Instruction(task->loadee_frame, 0, PAGE_SIZE_4K);

    task->pos += segment_bytes;
    task->dst += segment_bytes;
    task->src += segment_bytes;

    return load_segment_into_vspace_async(task);
}

Elf_Task *build_elf_task(seL4_Word pid, unsigned int pos,cspace_t *cspace, seL4_CPtr loadee, const char *src, size_t segment_size,
                         size_t file_size, uintptr_t dst, seL4_CapRights_t permissions, bool *loading_error, AsyncTask *async){

    Elf_Task *task = malloc(sizeof(Elf_Task));
    if (task == NULL){
//        printf("[malloc] build elf failed\n");
        return NULL;
    }
    memset(task,0,sizeof(Elf_Task));

    task->pos = pos;
    task->cspace = cspace;
    task->loadee = loadee;
    task->src = src;
    task->segment_size = segment_size;
    task->file_size = file_size;
    task->dst = dst;
    task->permissions = permissions;
    task->loadee_vaddr = 0;
    task->loadee_frame = 0;
    task->frame = 0;
    task->async = async;
    task->pid = pid;
    task->loading_error = loading_error;

    return task;
}

/*
 * Load an elf segment into the given vspace.
 *
 * TODO: The current implementation maps the frames into the loader vspace AND the target vspace
 *       and leaves them there. Additionally, if the current implementation fails, it does not
 *       clean up after itself.
 *
 *       This is insufficient, as you will run out of resouces quickly, and will be completely fixed
 *       throughout the duration of the project, as different milestones are completed.
 *
 *       Be *very* careful when editing this code. Most students will experience at least one elf-loading
 *       bug.
 *
 * The content to load is either zeros or the content of the ELF
 * file itself, or both.
 * The split between file content and zeros is a follows.
 *
 * File content: [dst, dst + file_size)
 * Zeros:        [dst + file_size, dst + segment_size)
 *
 * Note: if file_size == segment_size, there is no zero-filled region.
 * Note: if file_size == 0, the whole segment is just zero filled.
 *
 * @param cspace        of the loader, to allocate slots with
 * @param loader        vspace of the loader
 * @param loadee        vspace to load the segment in to
 * @param src           pointer to the content to load
 * @param segment_size  size of segment to load
 * @param file_size     end of section that should be zero'd
 * @param dst           destination base virtual address to load
 * @param permissions   for the mappings in this segment
 * @return
 *
 */
int load_segment_into_vspace_async(Elf_Task *task){

    assert(task->file_size <= task->segment_size);

    if (task->pos < task->segment_size) {
        task->loadee_vaddr = (ROUND_DOWN(task->dst, PAGE_SIZE_4K));

        /* create slot for the frame to load the data into */
        task->loadee_frame = cspace_alloc_slot(task->cspace);
        if (task->loadee_frame == seL4_CapNull) {
//            printf("Failed to alloc slot");
            *(task->loading_error) = true;
            task->async->call_back(task->async->args);
//            free(task->async);
//            free(task);
            return -1;
        }

        /* allocate the untyped for the loadees address space */
        task->frame = alloc_frame();

        if (task->frame == NULL_FRAME) {
            SwapOutTask *out_task = malloc(sizeof(SwapOutTask));
            if (out_task == NULL){
//                printf("error malloc out_task");
                *(task->loading_error) = true;
                task->async->call_back(task->async->args);
//                free(task->async);
//                free(task);
            }
            out_task->page = NULL;
            out_task->call_back = (void (*)(void *)) do_load_segment_continue;
            out_task->args = task;
            out_task->pid = task->pid;

            frame_lock = true;
            swap_out_one_page(out_task);
        }else {
            do_load_segment_continue(task);
        }

    }else{
//        printf("[load_segment_into_vspace_async] task->async->call_back(task->async->args);\n");
        task->async->call_back(task->async->args);
//        free(task->async);
//        free(task);
    }

    return 0;
}

typedef struct{
    int count;
    cspace_t *cspace;
    seL4_CPtr loadee_vspace;
    elf_t *elf_file;
    AsyncTask *asyncTask;

    seL4_Word pid;
    bool *loading_error;
}ElfLoadTask;

int _elf_load_async(ElfLoadTask *load_task){

    int num_headers = elf_getNumProgramHeaders(load_task->elf_file);

    if (load_task->count < num_headers) {

        /* Skip non-loadable segments (such as debugging data). */
        if (elf_getProgramHeaderType(load_task->elf_file, load_task->count) != PT_LOAD) {
//            printf("Skip non-loadable segments (such as debugging data), count = %d, num_headers = %d\n", load_task->count, num_headers);
            load_task->count++;
            _elf_load_async(load_task);
            return 0;
        }

        /* Fetch information about this segment. */
        const char *source_addr = load_task->elf_file->elfFile + elf_getProgramHeaderOffset(load_task->elf_file, load_task->count);
        size_t file_size = elf_getProgramHeaderFileSize(load_task->elf_file, load_task->count);
        size_t segment_size = elf_getProgramHeaderMemorySize(load_task->elf_file, load_task->count);
        uintptr_t vaddr = elf_getProgramHeaderVaddr(load_task->elf_file, load_task->count);
        seL4_Word flags = elf_getProgramHeaderFlags(load_task->elf_file, load_task->count);

        /* Copy it across into the vspace. */
        load_task->count++;
        AsyncTask *async = malloc(sizeof(AsyncTask));
        if (async == NULL){
//            printf("[malloc] AsyncTask failed\n");
            *(load_task->loading_error) = true;
            load_task->asyncTask->call_back(load_task->asyncTask->args);
//            free(load_task->asyncTask);
//            free(load_task);
            return -1;
        }
        async->call_back = (void (*)(void *)) _elf_load_async;
        async->args = load_task;

        Elf_Task *task = build_elf_task(load_task->pid, 0, load_task->cspace, load_task->loadee_vspace, source_addr, segment_size, file_size, vaddr,
                                        get_sel4_rights_from_elf(flags), load_task->loading_error, async);
        if (task == NULL){
//            printf("error: task build failed!\n");
            *(load_task->loading_error) = true;
            load_task->asyncTask->call_back(load_task->asyncTask->args);
//            free(load_task->asyncTask);
//            free(load_task);
            return -1;
        }


//        printf(" * Loading segment %p-->%p, file_size = %zu\n", (void *) vaddr, (void *)(vaddr + segment_size), file_size);
        int err = load_segment_into_vspace_async(task);
        if (err) {
//            printf("error: Elf loading failed!\n");
            *(load_task->loading_error) = true;
            load_task->asyncTask->call_back(load_task->asyncTask->args);
//            free(load_task->asyncTask);
//            free(load_task);
            return -1;
        }
    }else {
//        printf("[_elf_load_async] task->async->call_back(task->async->args);\n");
        load_task->asyncTask->call_back(load_task->asyncTask->args);
//        free(load_task->asyncTask);
//        free(load_task);
        return 0;
    }

    return 0;
}

int elf_load_async(seL4_Word pid, cspace_t *cspace, seL4_CPtr loadee_vspace, elf_t *elf_file, bool *loading_error, AsyncTask *asyncTask)
{

    ElfLoadTask *elf_load_task = malloc(sizeof(ElfLoadTask));
    if (elf_load_task == NULL){
//        printf("[malloc] ElfLoadTask failed\n");
    }
    memset(elf_load_task, 0, sizeof(ElfLoadTask));
    elf_load_task->count = 0;
    elf_load_task->cspace =cspace;
    elf_load_task->loadee_vspace = loadee_vspace;
    elf_load_task->elf_file = elf_file;
    elf_load_task->asyncTask = asyncTask;
    elf_load_task->pid = pid;
    elf_load_task->loading_error = loading_error;

    _elf_load_async(elf_load_task);

    return 0;
}
