//
// Created by Rui on 2021/7/20.
//

#ifndef SEL4_APPLICATION_PROCESS_H
#define SEL4_APPLICATION_PROCESS_H

#include "ut.h"
#include "frame_table.h"
#include "elfload.h"
#include "vm/addrspace.h"
#include "../../libsosapi/include/sos.h"
#include "utils.h"
#include "fs/fdtable.h"

#define INVALID_PID 0
#define MAX_PID 1000
#define MIN_PID 100

#define MAX_PROCESS_SIZE 16
#define MAX_WAITEE 16

seL4_CPtr app_ipc_ep;

typedef struct{
    seL4_Word pid;
    seL4_CPtr reply;
    ut_t *reply_ut;
}Waitee;

/* the one process we start */
typedef struct {
    seL4_Word badge;

    char app_name[N_NAME];
    unsigned  stime;

    ut_t *tcb_ut;
    seL4_CPtr tcb;
    ut_t *vspace_ut;
    seL4_CPtr vspace;

    seL4_CPtr fault_ep;

    ut_t *ipc_buffer_ut;
    seL4_CPtr ipc_buffer;
    frame_ref_t ipc_buffer_frame;

    ut_t *sched_context_ut;
    seL4_CPtr sched_context;

    cspace_t cspace;

    ut_t *stack_ut;
    seL4_CPtr stack;

    Addrspace *addrspace;
    SeL4_Page ** pages;
    size_t pages_max_size;
    size_t pages_len;

    struct file *fdtable[MAX_FILES_NUM];

    Waitee *waitee[MAX_WAITEE];
    size_t waitee_len;

    bool is_active;
    bool is_loading;
    bool loading_error;
} Process;



Process *create_new_process(void);
Process *get_process(seL4_Word badge);
int process_add_page(Process *p, SeL4_Page* page);

bool start_process_async(Process *process, char *app_name, seL4_CPtr ep, bool use_nfs, AsyncTask *async);
int get_process_status(seL4_Word pid, UserPage *user_pages, int pages_size, int max_len, seL4_CPtr reply, ut_t *reply_ut);

int destroy_process(seL4_Word pid);

int add_waitee(seL4_Word pid, seL4_Word waitee_pid, seL4_CPtr reply, ut_t *reply_ut);
void notify_waitee_and_free(Waitee *w);

#endif //SEL4_APPLICATION_PROCESS_H
