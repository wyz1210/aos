
#include "process.h"

Process *process_table[MAX_PROCESS_SIZE];

seL4_Word now_pid = MIN_PID;

seL4_Word get_new_pid() {

    int count = 0;

    do {
        now_pid++;
        if (now_pid > MAX_PID) {
            now_pid = MIN_PID;
        }

        count++;
        if (count > MAX_PROCESS_SIZE + 1) {
            return INVALID_PID;
        }

    }while (process_table[now_pid % MAX_PROCESS_SIZE] != NULL);

    return now_pid;
}

Process *create_new_process(void) {
    Process *p = malloc(sizeof(Process));
    if (p == NULL) {
//        printf("[create process] can't allocate Process\n");
        return NULL;
    }
    memset(p, 0, sizeof(Process));

    p->badge = get_new_pid();
    if (p->badge == INVALID_PID) {
//        printf("[create process] can't allocate pid\n");
        free(p);
        return NULL;
    }

    process_table[p->badge  % MAX_PROCESS_SIZE] = p;

    p->pages = malloc(sizeof(SeL4_Page*) * 100);
    if (p->pages == NULL){
//        printf("[create process] can't allocate pages\n");
        free(p->pages);
        free(p);
        return NULL;
    }
    memset(p->pages, 0, sizeof(SeL4_Page*) * 100);

    p->pages_max_size = 100;

    return p;
}

Process *get_process(seL4_Word badge) {

    if (badge == INVALID_PID) {
//        printf("[get_process] badge is invalid!\n");
        return NULL;
    }
    if (process_table[badge % MAX_PROCESS_SIZE] == NULL) {
//        printf("[get_process] no related process with badge = %lu\n", badge);
        return NULL;
    }
    if (process_table[badge  % MAX_PROCESS_SIZE]->is_active == false &&
            process_table[badge  % MAX_PROCESS_SIZE]->is_loading == false){
//        printf("[get_process] trying to get destroying process pid = %lu\n", badge);
        return NULL;
    }
    return process_table[badge  % MAX_PROCESS_SIZE];
}

int process_add_page(Process *p, SeL4_Page* page) {

    if (p == NULL || p->pages == NULL){
//        printf("[process_add_page] wrong argument\n");
        return 1;
    }

    p->pages[p->pages_len++] = page;
    if (p->pages_len >= p->pages_max_size){
        // double size
        SeL4_Page ** tmp_pages = malloc(sizeof(SeL4_Page*) * p->pages_max_size * 2);
        if (tmp_pages == NULL){
//            printf("[process_add_page] could allocate tmp_pages with size = %lu\n", p->pages_max_size * 2);
            return 1;
        }
        memset(tmp_pages, 0, sizeof(SeL4_Page*) * p->pages_max_size * 2);
        memcpy(tmp_pages, p->pages, sizeof(SeL4_Page*) * p->pages_max_size);
        free(p->pages);
        p->pages = tmp_pages;
        p->pages_max_size = p->pages_max_size * 2;
    }

    return 0;
}

typedef struct{
    UserPage *user_pages;
    int pages_size;
    seL4_CPtr reply;
    ut_t *reply_ut;

    char * data;
    size_t process_count;
    size_t data_len;
    int cur;
    size_t data_offset;

    seL4_Word pid;
}WriteProcessStatusArg;

void write_process_status_async(WriteProcessStatusArg *args){

    int size = MIN(args->user_pages[args->cur].size, args->data_len);
    memcpy(*args->user_pages[args->cur].data_pointer, args->data + args->data_offset, sizeof(char) * size);
    finish_use_user_pointer(args->pid, args->user_pages[args->cur].user_pointer);

    args->cur ++;
    args->data_offset += size;

    if (args->data_offset >= args->data_len || args->cur >= args->pages_size){
        // finish read
        seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, args->process_count);
        seL4_Send(args->reply, reply_msg1);

        free_reply(args->reply,args->reply_ut);
        free(args->user_pages);
        free(args->data);
        free(args);
        return;
    }

    AsyncTask * async = malloc(sizeof(AsyncTask));
    async->call_back = (void (*)(void *)) write_process_status_async;
    async->args = args;

    get_user_pointer_async(args->pid, args->user_pages[args->cur].user_pointer, args->user_pages[args->cur].data_pointer, async);

}

int get_process_status(seL4_Word pid, UserPage *user_pages, int pages_size, int max_len, seL4_CPtr reply, ut_t *reply_ut){

//    printf("[get_process_status]\n");
    sos_process_t *ps = malloc(sizeof(sos_process_t) * max_len);
    if (ps == NULL){
//        printf("[get_process_status] could allocate sos_process_t of size = %d", max_len);
        return 1;
    }
    memset(ps, 0, sizeof(sos_process_t) * max_len);

    int process_count = 0;
    for (int i = 0; i < MAX_PROCESS_SIZE; i++ ){
        if (process_table[i] != NULL && process_table[i]->is_active){
            ps[process_count].pid = process_table[i]->badge;
            memcpy(ps[process_count].command, process_table[i]->app_name, N_NAME);
            ps[process_count].stime = process_table[i]->stime;
            ps[process_count].size = process_table[i]->pages_len;
//            printf("[get_process_status] pid = %lu\n", process_table[i]->badge);
            process_count++;
        }
    }

    WriteProcessStatusArg *args = malloc(sizeof(WriteProcessStatusArg));
    if (args == NULL){
//        printf("[get_process_status] could not allocate WriteProcessStatusArg\n");
        return 1;
    }
    memset(args, 0, sizeof(WriteProcessStatusArg));
    args->user_pages = user_pages;
    args->pages_size = pages_size;
    args->reply = reply;
    args->reply_ut = reply_ut;

    args->data = (char *) ps;
    args->process_count = process_count;
    args->data_len = process_count * sizeof(sos_process_t);
    args->cur = 0;
    args->data_offset = 0;

    args->pid = pid;

    AsyncTask * async = malloc(sizeof(AsyncTask));
    if (async == NULL){
//        printf("[get_process_status] could not allocate AsyncTask\n");
        free(ps);
        free(args);
        return 1;
    }
    async->call_back = (void (*)(void *)) write_process_status_async;
    async->args = args;

    get_user_pointer_async(args->pid, args->user_pages[args->cur].user_pointer, args->user_pages[args->cur].data_pointer, async);

    return 0;
}

int destroy_process(seL4_Word pid){

    Process *p = get_process(pid);
    if (p == NULL){
//        printf("[destroy_process] cannot find pid = %lu\n", pid);
        return 1;
    }
    if (p->is_active == false && p->loading_error == true){
//        printf("[destroy_process] pid = %lu is already in destroying\n", pid);
        return 1;
    }

    p->is_active = false;

    // free ep
    if(p->fault_ep) {
        cspace_delete(&cspace, p->fault_ep);
        cspace_free_slot(&cspace, p->fault_ep);
        p->fault_ep = 0;
    }

    // free scheduling context
    if(p->sched_context){
        cspace_delete(&cspace, p->sched_context);
        cspace_free_slot(&cspace, p->sched_context);
        p->sched_context = 0;
        ut_free(p->sched_context_ut);
        p->sched_context_ut = NULL;
    }

    // free TCB
    if(p->tcb){
        cspace_delete(&cspace, p->tcb);
        cspace_free_slot(&cspace, p->tcb);
        p->tcb = 0;
        ut_free(p->tcb_ut);
        p->tcb_ut = NULL;
    }

    // free cspace
    if(p->cspace.bootstrap) {
        cspace_destroy(&p->cspace);
        memset(&p->cspace, 0, sizeof(p->cspace));
    }

    // free vspace
    if(p->vspace) {
        cspace_delete(&cspace, p->vspace);
        cspace_free_slot(&cspace, p->vspace);
        p->vspace = 0;
        ut_free(p->vspace_ut);
        p->vspace_ut = NULL;
    }

    // free fdt
    for (int i = 0; i < MAX_FILES_NUM; i ++){
        if (p->fdtable[i] != NULL){
            free(p->fdtable[i]);
        }
    }

    // free as
    if (p->addrspace) {
        free(p->addrspace);
    }

    // free pages
    // ipc buffer and stack are all in pages, so only need free once.
    if (p->pages){
        for (size_t i = 0; i < p->pages_len; i++){
            destroy_page(pid, p->pages[i]);
        }
        free(p->pages);
        p->pages = NULL;
    }

//    printf("[destroy_process] try to notify waitees\n");
    // notify waitees
    for(size_t i = 0; i < p->waitee_len; i ++){
        notify_waitee_and_free(p->waitee[i]);
    }

    // free process
    free(process_table[pid % MAX_PROCESS_SIZE]);
    process_table[pid % MAX_PROCESS_SIZE] = NULL;
    p = NULL;

//    printf("[destroy_process] pid = %lu finished\n", pid);

    return 0;
}

int add_waitee(seL4_Word pid, seL4_Word waitee_pid, seL4_CPtr reply, ut_t *reply_ut){

    Process *p = get_process(pid);
    if(p == NULL){
//        printf("[add_waitee] could not wait a none exist process(%lu)\n", pid);
        return 1;
    }

    if (p->waitee_len >= MAX_WAITEE){
//        printf("[add_waitee] waitee list is full for pid = %lu\n", pid);
        return 1;
    }

    Waitee *w = malloc(sizeof(Waitee));
    if (w == NULL){
//        printf("[add_waitee] could not allocate Waitee\n");
        return 1;
    }
    memset(w, 0, sizeof(Waitee));
    w->pid = waitee_pid;
    w->reply = reply;
    w->reply_ut = reply_ut;

    p->waitee[p->waitee_len++] = w;
    return 0;
}

void notify_waitee_and_free(Waitee *w){
    if (w == NULL){
//        printf("[notify_waitee_and_free] waitee is null");
        return;
    }

    if (get_process(w->pid) == NULL){
//        printf("[notify_waitee_and_free] trying to notify a deleted process, pid = %lu\n", w->pid);
        free_reply(w->reply,w->reply_ut);
        free(w);
        return;
    }

    seL4_MessageInfo_t reply_msg1 = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, 0);
    seL4_Send(w->reply, reply_msg1);

    free_reply(w->reply,w->reply_ut);
    free(w);
}