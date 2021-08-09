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
#include <autoconf.h>
#include <utils/util.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <cspace/cspace.h>
#include <aos/sel4_zf_logif.h>
#include <aos/debug.h>

#include <clock/clock.h>
#include <cpio/cpio.h>
#include <elf/elf.h>
#include <serial/serial.h>

#include <sel4runtime.h>
#include <sel4runtime/auxv.h>

#include "bootstrap.h"
#include "irq.h"
#include "network.h"
#include "frame_table.h"
#include "drivers/uart.h"
#include "ut.h"
#include "vmem_layout.h"
#include "mapping.h"
#include "elfload.h"
#include "syscalls.h"
#include "tests.h"
#include "utils.h"
#include "threads.h"
#include "../../libclock/src/device.h"
#include "fs/console.h"
#include "systask.h"

#include <aos/vsyscall.h>
#include "fs/fdtable.h"
#include "vm/app_mapping.h"
#include "vm/addrspace.h"
#include "vm/paging.h"
#include "backtrace.h"
#include "process.h"
#include "fs/nfs_api.h"
/*
 * To differentiate between signals from notification objects and and IPC messages,
 * we assign a badge to the notification object. The badge that we receive will
 * be the bitwise 'OR' of the notification object badge and the badges
 * of all pending IPC messages.
 *
 * All badged IRQs set high bet, then we use uniqe bits to
 * distinguish interrupt sources.
 */
#define IRQ_EP_BADGE         BIT(seL4_BadgeBits - 1ul)
#define IRQ_IDENT_BADGE_BITS MASK(seL4_BadgeBits - 1ul)

#define TTY_NAME             "tty_test"
#define TTY_PRIORITY         (0)

#define SOSH_NAME             "sosh"

/* The number of additional stack pages to provide to the initial
 * process */
#define INITIAL_PROCESS_EXTRA_STACK_PAGES 0

/*
 * A dummy starting syscall
 */
#define SOS_SYSCALL0 0
#define SOS_WRITE 10
#define SOS_READ 11
#define SOS_SLEEP 12
#define SOS_TIME_STAMP 13
#define SOS_OPEN 14
#define SOS_CLOSE 15
#define SOS_BRK 16
#define SOS_STAT 17
#define SOS_GET_DIRENT 18
#define SOS_MY_PID 19
#define SOS_PROCESS_CREAT 20
#define SOS_PROCESS_STATUS 21
#define SOS_PROCESS_DELETE 22
#define SOS_PROCESS_WAIT 23

struct serial * serial;

/* The linker will link this symbol to the start address  *
 * of an archive of attached applications.                */
extern char _cpio_archive[];
extern char _cpio_archive_end[];
extern char __eh_frame_start[];
/* provided by gcc */
extern void (__register_frame)(void *);

/* root tasks cspace */
cspace_t cspace;

static seL4_CPtr sched_ctrl_start;
static seL4_CPtr sched_ctrl_end;

bool handle_syscall(UNUSED seL4_Word badge, UNUSED int num_args, seL4_CPtr reply, ut_t *reply_ut)
{

    /* get the first word of the message, which in the SOS protocol is the number
     * of the SOS "syscall". */
    seL4_Word syscall_number = seL4_GetMR(0);

    /* Process system call */
    switch (syscall_number) {
    case SOS_SYSCALL0:
        ZF_LOGV("syscall: thread example made syscall 0!\n");
        /* construct a reply message of length 1 */
        seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
        /* Set the first (and only) word in the message to 0 */
        seL4_SetMR(0, 0);
        /* Send the reply to the saved reply capability. */
        seL4_Send(reply, reply_msg);
        /* in MCS kernel, reply object is meant to be reused rather than freed as the
         * send does not consume the reply object unlike the non-MCS kernel */
        break;

    case SOS_WRITE:
//        printf("in sos_write\n");
        return new_write_task(badge, reply, reply_ut);

    case SOS_READ:
//        printf("in sos_read\n");
        return new_read_task(badge, reply, reply_ut);

    case SOS_SLEEP:
//        printf("in sos_sleep\n");
        return new_sleep_task(badge, reply, reply_ut);

    case SOS_TIME_STAMP:
//        printf("in sos_time_stamp\n");
        return new_time_stamp_task(reply, reply_ut);

    case SOS_OPEN:
//        printf("in sos_open\n");
        return new_open_task(badge, reply, reply_ut);

    case SOS_CLOSE:
//        printf("in sos_close\n");
        return new_close_task(badge, reply, reply_ut);

    case SOS_BRK:
//        printf("in sos_brk, badge = %lu\n", badge);
        return new_brk_task(badge, reply, reply_ut);

    case SOS_STAT:
//        printf("in sos_stat, badge = %lu\n", badge);
        return new_stat_task(badge, reply, reply_ut);

    case SOS_GET_DIRENT:
//        printf("in new_get_dirent_task, badge = %lu\n", badge);
        return new_get_dirent_task(badge, reply, reply_ut);

    case SOS_MY_PID:
//        printf("in new_get_my_pid_task, badge = %lu\n", badge);
        return new_get_my_pid_task(badge, reply, reply_ut);

    case SOS_PROCESS_CREAT:
//        printf("in new_get_my_pid_task, badge = %lu\n", badge);
        return new_process_creat_task(badge, reply, reply_ut);

    case SOS_PROCESS_STATUS:
//        printf("in new_process_status_task, badge = %lu\n", badge);
        return new_process_status_task(badge, reply, reply_ut);

    case SOS_PROCESS_DELETE:
//        printf("in new_process_delete_task, badge = %lu\n", badge);
        return new_process_delete_task(badge, reply, reply_ut);

    case SOS_PROCESS_WAIT:
//        printf("in new_process_wait_task, badge = %lu\n", badge);
        return new_process_wait_task(badge, reply, reply_ut);

    default:
        ZF_LOGE("Unknown syscall %lu\n", syscall_number);
        /* don't reply to an unknown syscall */
    }

    return false;
}

bool handle_vm_fault(seL4_Word badge, seL4_Fault_t fault, seL4_CPtr reply, ut_t *reply_ut){

    Process *process = get_process(badge);

    seL4_Word vaddr = seL4_Fault_VMFault_get_Addr(fault);
    seL4_Word page_vaddr = vaddr & PAGE_FRAME;

    Addrspace *as = process->addrspace;
    if (as == NULL){
        ZF_LOGE("[vm_fault - %lu] cannot found as, vaddr(0x%016lx)\n", badge, vaddr);
        debug_dump_registers(process->tcb);
        return false;
    }

    bool valid = false;
    if(as->stack_top - as->stack_max_size <= page_vaddr && page_vaddr <= as->stack_top){
        valid = true;
    }else if(as->heap_base <= page_vaddr && page_vaddr <= as->heap_base + as->heap_max_size){
        valid = true;
    }else if( 0x0000000000400000 <= page_vaddr){
        valid = true;
    }

    if (! valid){
        ZF_LOGE("[vm_fault - %lu] vaddr(0x%016lx) is not valid",badge, page_vaddr);
        ZF_LOGE("[vm_fault - %lu] valid vaddr shoud be stack[0x%016lx,0x%016lx], heap[0x%016lx,0x%016lx]",badge,
                as->stack_bottom,as->stack_top, as->heap_base, as->heap_base + as->heap_max_size);
        print_backtrace();
        return false;
    }

    if(frame_lock==true){
//        printf("[vm_fault - %lu] vaddr(0x%016lx) frame_lock is true\n",badge, page_vaddr);
        seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, 0);
        seL4_Send(reply, reply_msg);
        return false;
    }

//    printf("[vm_fault - %lu] vaddr(0x%016lx)\n",badge, page_vaddr);

    // second-chance swap: remap
//    SeL4_Page *p = get_page(badge, page_vaddr);
//    if (p != NULL && p->frame != NULL_FRAME){
//        p->visited = true;
//
//        app_remap_frame(p, process->vspace, seL4_AllRights, seL4_ARM_Default_VMAttributes);
//
//        seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
//        seL4_SetMR(0, 0);
//        seL4_Send(reply, reply_msg);
//        return false;
//    }

    VmFaultTask *vm_task = malloc(sizeof(VmFaultTask));
    if (vm_task == NULL){
//        printf("[malloc] VmFaultTask failed\n");
    }
    memset(vm_task, 0, sizeof(VmFaultTask));
    vm_task->reply = reply;
    vm_task->reply_ut = reply_ut;
    vm_task->badge = badge;
    vm_task->vspace = process->vspace;
    vm_task->vaddr = page_vaddr;
    vm_task->frame = alloc_frame();

    // swap out a frame, so we can alloc
    if (vm_task->frame == NULL_FRAME) {

        SwapOutTask *task = malloc(sizeof(SwapOutTask));
        if (task == NULL){
//            printf("[malloc] SwapOutTask failed\n");
        }
        memset(task, 0, sizeof(SwapOutTask));
        task->page = NULL;
        task->call_back = (void (*)(void *)) vm_fault_continue;
        task->args = vm_task;
        task->pid = badge;

        frame_lock = true;

        swap_out_one_page(task);
        return true;
    }

    vm_fault_continue(vm_task);
    return true;
}

NORETURN void syscall_loop(seL4_CPtr ep)
{
    seL4_CPtr reply;
    ut_t *reply_ut = alloc_retype(&reply, seL4_ReplyObject, seL4_ReplyBits);
    if (reply_ut == NULL) {
        ZF_LOGF("Failed to alloc reply object ut");
    }

    bool is_blocked = false;

    while (1) {
        // generate new reply if last syscall was blocked
        if(is_blocked) {
//            printf("[new reply]\n");
            reply_ut = alloc_retype(&reply, seL4_ReplyObject, seL4_ReplyBits);
            if (reply_ut == NULL) {
                ZF_LOGF("Failed to alloc reply object ut");
            }
            is_blocked = false;
        }

        seL4_Word badge = 0;
        /* Block on ep, waiting for an IPC sent over ep, or
         * a notification from our bound notification object */
        seL4_MessageInfo_t message = seL4_Recv(ep, &badge, reply);
        /* Awake! We got a message - check the label and badge to
         * see what the message is about */
        seL4_Word label = seL4_MessageInfo_get_label(message);

        if (badge & IRQ_EP_BADGE) {
            /* It's a notification from our bound notification
             * object! */
            sos_handle_irq_notification(&badge);
        } else if (label == seL4_Fault_NullFault) {
            /* It's not a fault or an interrupt, it must be an IPC
             * message from tty_test! */
            is_blocked = handle_syscall(badge, seL4_MessageInfo_get_length(message) - 1, reply, reply_ut);
        } else {

            seL4_Fault_t fault = seL4_getFault(message);
            if (seL4_Fault_get_seL4_FaultType(fault) == seL4_Fault_VMFault){
                is_blocked = handle_vm_fault(badge, fault, reply,reply_ut);
            }else {
                /* some kind of fault */
                Process *p = get_process(badge);
                if (p == NULL){
                    ZF_LOGF("badge = %lu, with no process", badge);
                }else{
                    debug_print_fault(message, p->app_name);
                    /* dump registers too */
                    debug_dump_registers(p->tcb);
                }

                ZF_LOGF("The SOS skeleton does not know how to handle faults type = %lu!\n", seL4_Fault_get_seL4_FaultType(fault));
            }
        }
    }
}

static int stack_write(seL4_Word *mapped_stack, int index, uintptr_t val)
{
    mapped_stack[index] = val;
    return index - 1;
}

typedef struct{
    Process *process;
    frame_ref_t initial_stack;
    void *local_stack_top;
    uintptr_t local_stack_bottom;
    cspace_t *cspace;
    seL4_CPtr local_vspace;
    uintptr_t sysinfo;
    seL4_Word *sp;
    AsyncTask *async;
}InitProcessStackArg;

void init_process_stack_async_continue(InitProcessStackArg *args){

    /* Map in the stack frame for the user app */
    Process *process = args->process;
    Addrspace  *as = process->addrspace;
    void *local_stack_top = args->local_stack_top;
    uintptr_t local_stack_bottom = args->local_stack_bottom;
    cspace_t *cspace = args->cspace;
    seL4_CPtr local_vspace = args->local_vspace;
    uintptr_t sysinfo = args->sysinfo;

    if (args->initial_stack == NULL_FRAME) {
        args->initial_stack = alloc_frame();
        frame_lock = false;
    }

    if (args->initial_stack == NULL_FRAME) {
//        printf("[init_process_stack_async_continue - %lu] cannot allocate initial_stack\n", process->badge);
        return;
    }

    seL4_Error err = app_map_frame(process->badge, cspace, process->stack, process->vspace, as->stack_bottom,
                                   seL4_AllRights, seL4_ARM_Default_VMAttributes, args->initial_stack, true, true);
    if (err != 0) {
        ZF_LOGE("Unable to map stack for user app");
        return;
    }

    /* allocate a slot to duplicate the stack frame cap so we can map it into our address space */
    seL4_CPtr local_stack_cptr = cspace_alloc_slot(cspace);
    if (local_stack_cptr == seL4_CapNull) {
        ZF_LOGE("Failed to alloc slot for stack");
        return;
    }

    /* copy the stack frame cap into the slot */
    err = cspace_copy(cspace, local_stack_cptr, cspace, process->stack, seL4_AllRights);
    if (err != seL4_NoError) {
        cspace_free_slot(cspace, local_stack_cptr);
        ZF_LOGE("Failed to copy cap");
        return;
    }

    /* map it into the sos address space */
    err = map_frame(cspace, local_stack_cptr, local_vspace, local_stack_bottom, seL4_AllRights,
                    seL4_ARM_Default_VMAttributes);
    if (err != seL4_NoError) {
        cspace_delete(cspace, local_stack_cptr);
        cspace_free_slot(cspace, local_stack_cptr);
        return;
    }

    int index = -2;

    /* null terminate the aux vectors */
    index = stack_write(local_stack_top, index, 0);
    index = stack_write(local_stack_top, index, 0);

    /* write the aux vectors */
    index = stack_write(local_stack_top, index, PAGE_SIZE_4K);
    index = stack_write(local_stack_top, index, AT_PAGESZ);

    index = stack_write(local_stack_top, index, sysinfo);
    index = stack_write(local_stack_top, index, AT_SYSINFO);

    index = stack_write(local_stack_top, index, PROCESS_IPC_BUFFER);
    index = stack_write(local_stack_top, index, AT_SEL4_IPC_BUFFER_PTR);

    /* null terminate the environment pointers */
    index = stack_write(local_stack_top, index, 0);

    /* we don't have any env pointers - skip */

    /* null terminate the argument pointers */
    index = stack_write(local_stack_top, index, 0);

    /* no argpointers - skip */

    /* set argc to 0 */
    stack_write(local_stack_top, index, 0);

    /* adjust the initial stack top */
    as->stack_top += (index * sizeof(seL4_Word));

    /* the stack *must* remain aligned to a double word boundary,
     * as GCC assumes this, and horrible bugs occur if this is wrong */
    assert(index % 2 == 0);
    assert(as->stack_top % (sizeof(seL4_Word) * 2) == 0);

    /* unmap our copy of the stack */
    err = seL4_ARM_Page_Unmap(local_stack_cptr);
    assert(err == seL4_NoError);

    /* delete the copy of the stack frame cap */
    err = cspace_delete(cspace, local_stack_cptr);
    assert(err == seL4_NoError);

    /* mark the slot as free */
    cspace_free_slot(cspace, local_stack_cptr);

    *args->sp = as->stack_top;
    args->async->call_back(args->async->args);

    free(args->async);
    free(args);
}

/* set up System V ABI compliant stack, so that the process can
 * start up and initialise the C library */
void init_process_stack_async(Process *process, cspace_t *cspace, seL4_CPtr local_vspace, elf_t *elf_file,
                                          seL4_Word *sp, AsyncTask *async)
{
    /* Create a stack frame */
    process->stack_ut = alloc_retype(&process->stack, seL4_ARM_SmallPageObject, seL4_PageBits);
    if (process->stack_ut == NULL) {
        ZF_LOGE("Failed to allocate stack");
        return;
    }

    /* virtual addresses in the target process' address space */
    process->addrspace = malloc(sizeof(Addrspace));
    if (process->addrspace == NULL){
        ZF_LOGE("Failed to allocate addrspace");
        return;
    }
    Addrspace  *as = process->addrspace;
    as->stack_top = PROCESS_STACK_TOP;
    as->stack_bottom = PROCESS_STACK_TOP - PAGE_SIZE_4K;
    as->stack_max_size = PROCESS_STACK_MAX_PAGES;
    as->heap_base = PROCESS_HEAP;
    as->heap_max_size = PROCESS_HEAP_SIZE;

    /* virtual addresses in the SOS's address space */
    void *local_stack_top  = (seL4_Word *) SOS_SCRATCH;
    uintptr_t local_stack_bottom = SOS_SCRATCH - PAGE_SIZE_4K;

    /* find the vsyscall table */
    uintptr_t sysinfo = *((uintptr_t *) elf_getSectionNamed(elf_file, "__vsyscall", NULL));
    if (sysinfo == 0) {
        ZF_LOGE("could not find syscall table for c library");
        return;
    }

    InitProcessStackArg *args = malloc(sizeof(InitProcessStackArg));
    if (args == NULL){
        ZF_LOGE("[malloc] InitProcessStackArg error\n");
        return;
    }
    args->process = process;
    args->local_stack_top = local_stack_top;
    args->local_stack_bottom = local_stack_bottom;
    args->cspace = cspace;
    args->local_vspace = local_vspace;
    args->sysinfo = sysinfo;
    args->sp = sp;
    args->async = async;

    args->initial_stack = alloc_frame();
    if(args->initial_stack == NULL_FRAME) {
        // swap out
        SwapOutTask *task = malloc(sizeof(SwapOutTask));
        if (task == NULL){
            ZF_LOGE("[malloc] SwapOutTask failed\n");
            return;
        }
        memset(task, 0, sizeof(SwapOutTask));
        task->page = NULL;
        task->call_back = (void (*)(void *)) init_process_stack_async_continue;
        task->args = args;
        task->pid = process->badge;

        frame_lock = true;
        swap_out_one_page(task);
        return;
    }
    init_process_stack_async_continue(args);

    return;
}

typedef struct{
    seL4_Word sp;
    elf_t *elf_file;
    Process *process;
    char * app_name;
    char *elf_base;
    unsigned long elf_size;

    bool use_nfs;
    AsyncTask *async;
}StartProcessTask;

void start_first_process_continue3(StartProcessTask *task){

//    printf("[start_first_process_continue3 - %lu]\n", task->process->badge);
    seL4_Word err;

//    frame_lock = false;

    if (task->process->loading_error == true){
//        printf("[start_first_process_continue3 - %lu] error when loading\n", task->process->badge);
        if (task->async != NULL){
            task->async->call_back(task->async->args);
            free(task->async);
        }
        if (task->use_nfs) {
            free(task->elf_file);
        }
        free(task);
        return;
    }

    init_console(task->process->badge, serial);

    /* Start the new process */
    seL4_UserContext *context = malloc(sizeof(seL4_UserContext));
    memset(context, 0, sizeof(seL4_UserContext));

    context->pc = elf_getEntryPoint(task->elf_file),
    context->sp = task->sp,

//    printf("Starting process(%lu) %s at %p\n", task->process->badge, task->app_name, (void *) context->pc);
    err = seL4_TCB_WriteRegisters(task->process->tcb, 1, 0, 2, context);
    if (err){
//        printf("[start_first_process_continue3] Failed to write registers\n");
        if (task->async != NULL){
            task->async->call_back(task->async->args);
            free(task->async);
        }
        free(task);
        return;
    }
    task->process->is_active = true;
    task->process->is_loading = false;

    if (task->async != NULL){
        task->async->call_back(task->async->args);
        free(task->async);
    }
    if (task->use_nfs) {
        free(task->elf_file);
    }

    free(task);
}

void start_first_process_continue2(StartProcessTask *task){

    Process *process = task->process;

    /* load the elf image from the cpio file */
    AsyncTask *asyncTask = malloc(sizeof(AsyncTask));
    if (asyncTask == NULL){
//        printf("[malloc] AsyncTask failed\n");
        if (task->async != NULL){
            process->loading_error = true;
            task->async->call_back(task->async->args);
            free(task->async);
        }
        free(task);
        return;
    }
    asyncTask->call_back = (void (*)(void *)) start_first_process_continue3;
    asyncTask->args = task;

    seL4_Error err = elf_load_async(process->badge, &cspace, process->vspace, task->elf_file, &process->loading_error, asyncTask);
    if (err) {
//        printf("Failed to start load elf image async\n");
        if (task->async != NULL){
            process->loading_error = true;
            task->async->call_back(task->async->args);
            free(task->async);
        }
        free(task);
        return;
    }
}

void start_first_process_continue1(StartProcessTask *task) {
    /* Map in the IPC buffer for the thread */
    Process *process = task->process;

    if (process->ipc_buffer_frame == NULL_FRAME) {
//        printf("[start_first_process_continue1 - %lu] try to re-allocate ipc_buffer_frame\n", process->badge);
        process->ipc_buffer_frame = alloc_frame();
        frame_lock = false;
    }

    if (process->ipc_buffer_frame == NULL_FRAME) {
//        printf("[start_first_process_continue1 - %lu] cannot allocate ipc_buffer_frame\n", process->badge);
        if (task->async != NULL){
            process->loading_error = true;
            task->async->call_back(task->async->args);
//            free(task->async);
        }
        return;
    }

    seL4_Error err = app_map_frame(process->badge, &cspace, process->ipc_buffer, process->vspace, PROCESS_IPC_BUFFER,
                        seL4_AllRights, seL4_ARM_Default_VMAttributes, process->ipc_buffer_frame, true, true);
    if (err != 0) {
//        printf("Unable to map IPC buffer for user app\n");
        if (task->async != NULL){
            process->loading_error = true;
            task->async->call_back(task->async->args);
//            free(task->async);
        }
        return ;
    }

    /* set up the stack */
    AsyncTask *asyncTask = malloc(sizeof(AsyncTask));
    if (asyncTask == NULL){
//        printf("[malloc] AsyncTask failed\n");
        if (task->async != NULL){
            process->loading_error = true;
            task->async->call_back(task->async->args);
//            free(task->async);
        }
        return;
    }
    asyncTask->call_back = (void (*)(void *)) start_first_process_continue2;
    asyncTask->args = task;

    init_process_stack_async(process, &cspace, seL4_CapInitThreadVSpace, task->elf_file, &task->sp, asyncTask);

    return;
}

void start_first_process_cb(StartProcessTask *args){

    Process *process = args->process;
    if (process == NULL){
//        printf("[start_first_process_cb] could not find process\n");
        if (args->async != NULL){
            process->loading_error = true;
            args->async->call_back(args->async->args);
            free(args->async);
        }
        return;
    }

    /* parse the cpio image */
    ZF_LOGI("\nStarting \"%s\"...\n", args->app_name);
    elf_t *elf_file = malloc(sizeof(elf_t));
    memset(elf_file, 0, sizeof(elf_t));

//    unsigned long elf_size;
//    size_t cpio_len = _cpio_archive_end - _cpio_archive;
//    args->elf_base = cpio_get_file(_cpio_archive, cpio_len, args->app_name, &elf_size);

    if (args->elf_base == NULL) {
//        printf("Unable to locate elf header for %s\n", args->app_name);
        if (args->async != NULL){
            process->loading_error = true;
            args->async->call_back(args->async->args);
            free(args->async);
        }
        return;
    }

    /* Ensure that the file is an elf file. */
    if (elf_newFile(args->elf_base, args->elf_size, elf_file)) {
//        printf("Invalid elf file\n");
        if (args->async != NULL){
            process->loading_error = true;
            args->async->call_back(args->async->args);
            free(args->async);
        }
        return;
    }

    args->elf_file = elf_file;

    process->ipc_buffer_frame = alloc_frame();
    if (process->ipc_buffer_frame == NULL_FRAME){

        SwapOutTask *task = malloc(sizeof(SwapOutTask));
        if (task == NULL){
//            printf("[malloc] SwapOutTask failed\n");
            if (args->async != NULL){
                process->loading_error = true;
                args->async->call_back(args->async->args);
                free(args->async);
            }
            return;
        }
        memset(task, 0, sizeof(SwapOutTask));
        task->page = NULL;
        task->call_back = (void (*)(void *)) start_first_process_continue1;
        task->args = args;
        task->pid = process->badge;

        frame_lock = true;
        swap_out_one_page(task);
        return;
    }

    start_first_process_continue1(args);
}

void load_elf_from_nfs(Process *process, char * app_name, AsyncTask *asyncTask){
    StartProcessTask *spt = malloc(sizeof(StartProcessTask));
    if (spt == NULL){
//        printf("[malloc] StartProcessTask failed\n");
        if (asyncTask != NULL){
            process->loading_error = true;
            asyncTask->call_back(asyncTask->args);
            free(asyncTask);
        }
        return;
    }
    memset(spt, 0 , sizeof(StartProcessTask));
    spt->process = process;
    spt->app_name = app_name;
    spt->use_nfs = true;
    spt->elf_base = ELF_CACHE;
    spt->async = asyncTask;

    AsyncTask *async = malloc(sizeof(AsyncTask));
    if (async == NULL){
//        printf("[malloc] could not allocate AsyncTask\n");
        if (asyncTask != NULL){
            process->loading_error = true;
            asyncTask->call_back(asyncTask->args);
            free(asyncTask);
        }
        return;
    }
    async->call_back = (void (*)(void *)) start_first_process_cb;
    async->args = spt;

    nfs_load_elf_async(app_name, spt->elf_base, &spt->elf_size, async);
}

void load_elf_from_cpio(Process *process, char * app_name){

    unsigned long elf_size;
    size_t cpio_len = _cpio_archive_end - _cpio_archive;
    const char *elf_base = cpio_get_file(_cpio_archive, cpio_len, app_name, &elf_size);
    if (elf_base == NULL) {
        ZF_LOGE("Unable to locate cpio header for %s", app_name);
        return;
    }

    StartProcessTask *spt = malloc(sizeof(StartProcessTask));
    if (spt == NULL){
//        printf("[malloc] StartProcessTask failed\n");
        return;
    }
    memset(spt, 0 , sizeof(StartProcessTask));
    spt->process = process;
    spt->app_name = app_name;
    spt->elf_size = elf_size;
    spt->elf_base = (char *)elf_base;
    spt->use_nfs = false;

    start_first_process_cb(spt);
}

/* Start the first process, and return true if successful
 *
 * This function will leak memory if the process does not start successfully.
 * avoid leaking memory once you implement real processes, otherwise a user
 * can force your OS to run out of memory by creating lots of failed processes.
 */
bool start_process_async(Process *process, char *app_name, seL4_CPtr ep, bool use_nfs, AsyncTask *async)
{

    if (process == NULL){
//        printf("[start_process_async] process is NULL\n");
        return false;
    }

    process->is_loading = true;

    if (process->badge == INVALID_PID){
//        printf("[start_process_async] process with invalid pid\n");
        return false;
    }

    if (strlen(app_name) > N_NAME){
//        printf("[start_process_async] process with not supported app_name = %s\n", app_name);
        return false;
    }
    memcpy(process->app_name, app_name, strlen(app_name) + 1);

    process->stime = get_time();

    /* Create a VSpace */
    process->vspace_ut = alloc_retype(& process->vspace, seL4_ARM_PageGlobalDirectoryObject,
                                              seL4_PGDBits);
    if ( process->vspace_ut == NULL) {
        return false;
    }

    /* assign the vspace to an asid pool */
    seL4_Word err = seL4_ARM_ASIDPool_Assign(seL4_CapInitThreadASIDPool,  process->vspace);
    if (err != seL4_NoError) {
        ZF_LOGE("Failed to assign asid pool");
        return false;
    }

    /* Create a simple 1 level CSpace */
    err = cspace_create_one_level(&cspace, & process->cspace);
    if (err != CSPACE_NOERROR) {
        ZF_LOGE("Failed to create cspace");
        return false;
    }

    /* Create an IPC buffer */
    process->ipc_buffer_ut = alloc_retype(& process->ipc_buffer, seL4_ARM_SmallPageObject,
                                                  seL4_PageBits);
    if ( process->ipc_buffer_ut == NULL) {
        ZF_LOGE("Failed to alloc ipc buffer ut");
        return false;
    }

    /* allocate a new slot in the target cspace which we will mint a badged endpoint cap into --
     * the badge is used to identify the process, which will come in handy when you have multiple
     * processes. */
    seL4_CPtr user_ep = cspace_alloc_slot(& process->cspace);
    if (user_ep == seL4_CapNull) {
        ZF_LOGE("Failed to alloc user ep slot");
        return false;
    }

    /* now mutate the cap, thereby setting the badge */
    err = cspace_mint(& process->cspace, user_ep, &cspace, ep, seL4_AllRights, process->badge);
    if (err) {
        ZF_LOGE("Failed to mint user ep");
        return false;
    }

    /* Create a new TCB object */
    process->tcb_ut = alloc_retype(& process->tcb, seL4_TCBObject, seL4_TCBBits);
    if ( process->tcb_ut == NULL) {
        ZF_LOGE("Failed to alloc tcb ut");
        return false;
    }

    /* Configure the TCB */
    err = seL4_TCB_Configure(process->tcb,
                             process->cspace.root_cnode, seL4_NilData,
                             process->vspace, seL4_NilData, PROCESS_IPC_BUFFER,
                             process->ipc_buffer);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure new TCB");
        return false;
    }

    /* Create scheduling context */
    process->sched_context_ut = alloc_retype(&process->sched_context, seL4_SchedContextObject,
                                                     seL4_MinSchedContextBits);
    if (process->sched_context_ut == NULL) {
        ZF_LOGE("Failed to alloc sched context ut");
        return false;
    }

    /* Configure the scheduling context to use the first core with budget equal to period */
    err = seL4_SchedControl_Configure(sched_ctrl_start, process->sched_context, US_IN_MS, US_IN_MS, 0, 0);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure scheduling context");
        return false;
    }

    // badged fault endpoint
    process->fault_ep = cspace_alloc_slot(&cspace);
    if(process->fault_ep == seL4_CapNull) {
        ZF_LOGE("Unable to create slot for badged fault endpoint");
        return false;
    }
    err = cspace_mint(&cspace, process->fault_ep, &cspace, ep, seL4_AllRights, process->badge);
    if(err != seL4_NoError) {
        ZF_LOGE("Error minting fault endpoint: %lu", err);
        return false;
    }

    /* bind sched context, set fault endpoint and priority
     * In MCS, fault end point needed here should be in current thread's cspace.
     * NOTE this will use the unbadged ep unlike above, you might want to mint it with a badge
     * so you can identify which thread faulted in your fault handler */
    err = seL4_TCB_SetSchedParams(process->tcb, seL4_CapInitThreadTCB, seL4_MinPrio, TTY_PRIORITY,
                                  process->sched_context, process->fault_ep);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to set scheduling params");
        return false;
    }

    /* Provide a name for the thread -- Helpful for debugging */
    NAME_THREAD(process->tcb, app_name);

    if (use_nfs){
        load_elf_from_nfs(process, app_name, async);
    }else{
        load_elf_from_cpio(process, app_name);
    }

   return true;
}

/* Allocate an endpoint and a notification object for sos.
 * Note that these objects will never be freed, so we do not
 * track the allocated ut objects anywhere
 */
static void sos_ipc_init(seL4_CPtr *ipc_ep, seL4_CPtr *ntfn)
{
    /* Create an notification object for interrupts */
    ut_t *ut = alloc_retype(ntfn, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!ut, "No memory for notification object");

    /* Bind the notification object to our TCB */
    seL4_Error err = seL4_TCB_BindNotification(seL4_CapInitThreadTCB, *ntfn);
    ZF_LOGF_IFERR(err, "Failed to bind notification object to TCB");

    /* Create an endpoint for user application IPC */
    ut = alloc_retype(ipc_ep, seL4_EndpointObject, seL4_EndpointBits);
    ZF_LOGF_IF(!ut, "No memory for endpoint");
}

/* called by crt */
seL4_CPtr get_seL4_CapInitThreadTCB(void)
{
    return seL4_CapInitThreadTCB;
}

/* tell muslc about our "syscalls", which will bve called by muslc on invocations to the c library */
void init_muslc(void)
{
    setbuf(stdout, NULL);

    muslcsys_install_syscall(__NR_set_tid_address, sys_set_tid_address);
    muslcsys_install_syscall(__NR_writev, sys_writev);
    muslcsys_install_syscall(__NR_exit, sys_exit);
    muslcsys_install_syscall(__NR_rt_sigprocmask, sys_rt_sigprocmask);
    muslcsys_install_syscall(__NR_gettid, sys_gettid);
    muslcsys_install_syscall(__NR_getpid, sys_getpid);
    muslcsys_install_syscall(__NR_tgkill, sys_tgkill);
    muslcsys_install_syscall(__NR_tkill, sys_tkill);
    muslcsys_install_syscall(__NR_exit_group, sys_exit_group);
    muslcsys_install_syscall(__NR_ioctl, sys_ioctl);
    muslcsys_install_syscall(__NR_mmap, sys_mmap);
    muslcsys_install_syscall(__NR_brk,  sys_brk);
    muslcsys_install_syscall(__NR_clock_gettime, sys_clock_gettime);
    muslcsys_install_syscall(__NR_nanosleep, sys_nanosleep);
    muslcsys_install_syscall(__NR_getuid, sys_getuid);
    muslcsys_install_syscall(__NR_getgid, sys_getgid);
    muslcsys_install_syscall(__NR_openat, sys_openat);
    muslcsys_install_syscall(__NR_close, sys_close);
    muslcsys_install_syscall(__NR_socket, sys_socket);
    muslcsys_install_syscall(__NR_bind, sys_bind);
    muslcsys_install_syscall(__NR_listen, sys_listen);
    muslcsys_install_syscall(__NR_connect, sys_connect);
    muslcsys_install_syscall(__NR_accept, sys_accept);
    muslcsys_install_syscall(__NR_sendto, sys_sendto);
    muslcsys_install_syscall(__NR_recvfrom, sys_recvfrom);
    muslcsys_install_syscall(__NR_readv, sys_readv);
    muslcsys_install_syscall(__NR_getsockname, sys_getsockname);
    muslcsys_install_syscall(__NR_getpeername, sys_getpeername);
    muslcsys_install_syscall(__NR_fcntl, sys_fcntl);
    muslcsys_install_syscall(__NR_setsockopt, sys_setsockopt);
    muslcsys_install_syscall(__NR_getsockopt, sys_getsockopt);
    muslcsys_install_syscall(__NR_ppoll, sys_ppoll);
    muslcsys_install_syscall(__NR_madvise, sys_madvise);
}

void timer_current_1000(uint32_t id, void *data){

    timestamp_t now = get_time();

    char buf[100];
    sprintf(buf, "=== current_time = %lu ===\n", now);
    serial_send(serial, buf, strlen(buf));

    id = register_timer(1000, timer_current_1000, data);
    if (id != 0) {
        printf("register_timer 1000 return id = %d\n", id);
    }else{
        printf("register_timer 1000 error!\n");
    }
}

void timer_tick_100(uint32_t id, void *data){

    timestamp_t now = get_time();

    char buf[100];
    sprintf(buf, "timer_tick_100 = %lu\n", now);
    serial_send(serial, buf, strlen(buf));

    id = register_timer(100, timer_tick_100, data);
    if (id != 0) {
        printf("register_timer 100 return id = %d\n", id);
    }else{
        printf("register_timer 100 error!\n");
    }
}

void timer_tick_80(uint32_t id, void *data){

    timestamp_t now = get_time();

    char buf[100];
    sprintf(buf, "timer_tick_80 = %lu\n", now);
    serial_send(serial, buf, strlen(buf));

    id = register_timer(80, timer_tick_80, data);
    if (id != 0) {
        printf("register_timer 80 return id = %d\n", id);
    }else{
        printf("register_timer 80 error!\n");
    }
}

void main_continued3(seL4_CPtr ipc_ep){
    /* Start the user application */

    app_ipc_ep = ipc_ep;

    Process *process = create_new_process();
    if (process == NULL){
//        printf("Error starting process\n");
    }
//    printf("Start process, pid = %lu\n", process->badge);
    bool success = start_process_async(process, SOSH_NAME, ipc_ep, false, NULL);
    ZF_LOGF_IF(!success, "Failed to start process %lu", process->badge);

}

void wait_vm_ready(uint32_t id, void *data){

    if (vm_ready){
//        printf("[vm_ready]\n");
        seL4_CPtr ipc_ep = (seL4_CPtr) data;
        main_continued3(ipc_ep);
        return;
    }

    id = register_timer(100, wait_vm_ready, data);
//    printf("[vm_ready] register_timer 100 return id = %d\n", id);
    assert(id != 0);
}

void main_continued2(seL4_CPtr ipc_ep){
    init_page_table();
    wait_vm_ready(0, (void *) ipc_ep);
}

void wait_network_ready(uint32_t id, void *data){

    if (network_ready){
//        printf("[network_ready]\n");
        seL4_CPtr ipc_ep = (seL4_CPtr) data;
        main_continued2(ipc_ep);
        return;
    }

    id = register_timer(100, wait_network_ready, data);
//    printf("[network_ready] register_timer 100 return id = %d\n", id);
    assert(id != 0);
}

NORETURN void *main_continued(UNUSED void *arg)
{
    /* Initialise other system compenents here */
    seL4_CPtr ipc_ep, ntfn;
    sos_ipc_init(&ipc_ep, &ntfn);
    sos_init_irq_dispatch(
        &cspace,
        seL4_CapIRQControl,
        ntfn,
        IRQ_EP_BADGE,
        IRQ_IDENT_BADGE_BITS
    );
    frame_table_init(&cspace, seL4_CapInitThreadVSpace);

    // address spaces init
    init_addrspace();

    /* run sos initialisation tests */
    run_tests(&cspace);

    /* Map the timer device (NOTE: this is the same mapping you will use for your timer driver -
     * sos uses the watchdog timers on this page to implement reset infrastructure & network ticks,
     * so touching the watchdog timers here is not recommended!) */
    void *timer_vaddr = sos_map_device(&cspace, PAGE_ALIGN_4K(TIMER_MAP_BASE), PAGE_SIZE_4K);

    /* Initialise the network hardware. */
//    printf("Network init\n");
    network_init(&cspace, timer_vaddr, ntfn);

    // init FDT
    file_struct_init();

    // init serial at boot
    serial = serial_init();
    init_console(0, serial);

    /* Initialises the timer */
//    printf("Timer init\n");
    start_timer(timer_vaddr);
    /* You will need to register an IRQ handler for the timer here.
     * See "irq.h". */
    seL4_IRQHandler irq_handler = 0;
    int init_irq_err = sos_register_irq_handler(TIMER_A_IRQ, true, timer_irq, NULL, &irq_handler);
    ZF_LOGF_IF(init_irq_err != 0, "Failed to initialise IRQ");
    seL4_IRQHandler_Ack(irq_handler);

//    printf("Timer test init\n");
//    test_timer();
//    timer_tick_100(0, "timer 100");
//    timer_tick_80(0, "timer 80");
//
//    timer_current_1000(0, "current timer 1000");

    wait_network_ready(0, (void *) ipc_ep);

    printf("\nSOS entering syscall loop\n");
    init_systask();
    init_threads(ipc_ep, sched_ctrl_start, sched_ctrl_end);
    syscall_loop(ipc_ep);
}
/*
 * Main entry point - called by crt.
 */
int main(void)
{
    init_muslc();

    /* register the location of the unwind_tables -- this is required for
     * backtrace() to work */
    __register_frame(&__eh_frame_start);

    seL4_BootInfo *boot_info = sel4runtime_bootinfo();

    debug_print_bootinfo(boot_info);

    printf("\nSOS Starting...\n");

    NAME_THREAD(seL4_CapInitThreadTCB, "SOS:root");

    sched_ctrl_start = boot_info->schedcontrol.start;
    sched_ctrl_end = boot_info->schedcontrol.end;

    /* Initialise the cspace manager, ut manager and dma */
    sos_bootstrap(&cspace, boot_info);

    /* switch to the real uart to output (rather than seL4_DebugPutChar, which only works if the
     * kernel is built with support for printing, and is much slower, as each character print
     * goes via the kernel)
     *
     * NOTE we share this uart with the kernel when the kernel is in debug mode. */
    uart_init(&cspace);
    update_vputchar(uart_putchar);

    /* test print */
    printf("SOS Started!\n");

    /* allocate a bigger stack and switch to it -- we'll also have a guard page, which makes it much
     * easier to detect stack overruns */
    seL4_Word vaddr = SOS_STACK;
    for (int i = 0; i < SOS_STACK_PAGES; i++) {
        seL4_CPtr frame_cap;
        ut_t *frame = alloc_retype(&frame_cap, seL4_ARM_SmallPageObject, seL4_PageBits);
        ZF_LOGF_IF(frame == NULL, "Failed to allocate stack page");
        seL4_Error err = map_frame(&cspace, frame_cap, seL4_CapInitThreadVSpace,
                                   vaddr, seL4_AllRights, seL4_ARM_Default_VMAttributes);
        ZF_LOGF_IFERR(err, "Failed to map stack");
        vaddr += PAGE_SIZE_4K;
    }

    utils_run_on_stack((void *) vaddr, main_continued, NULL);

    UNREACHABLE();
}


