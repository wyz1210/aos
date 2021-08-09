#include "fdtable.h"
#include "../process.h"
#include <stdlib.h>
#include <string.h>

void file_struct_init() {
    for (int i = 0; i < MAX_FILES_NUM; i++){
        fdtable[i] = NULL;
    }
    return;
}

int handle_open(const char name[], int type, int mode){
//    if (strlen(name) > MAX_FILE_NAME){
//        //printf("path name is too long\n");
//        return -1;
//    }
//    //find an empty slot
//    int i;
//    for (i = 0; i < MAX_FILES_NUM; i++){
//        if (fdtable[i] == NULL){
//            fdtable[i] = malloc(sizeof(struct file));
//            break;
//        }
//    }
//    if (i == MAX_FILES_NUM){
//        return -1;
//    }
//    struct file *opened = fdtable[i];
//    //if it is console, call console_open
//    if (!strcmp(name, "console")) {
//        opened->opts.open = console_open;
//        opened->opts.open(name, mode);
//    }
//
//
//    strcpy(opened->name, name);
//    opened->type = type;
//    opened->mode = mode;
//    opened->ref = 0;
//
//    return i;
    return -1;
}

struct file * get_by_FD(seL4_Word pid, int fd){

    struct file ** fdt;

    if (pid == 0) {
        fdt = fdtable;
    }else {
        Process *p = get_process(pid);
        if (p == NULL){
//            printf("[get_by_FD - %lu] no such process!\n", pid);
            return NULL;
        }
        fdt = p->fdtable;
    }

    if (fd < 0 || fd >= MAX_FILES_NUM){
        return NULL;
    }
    if (fdt[fd] == NULL){
        return NULL;
    }
    return fdt[fd];
}

int get_FD_by_name(seL4_Word pid, char name[]){

    struct file ** fdt;

    if (pid == 0) {
        fdt = fdtable;
    }else {
        Process *p = get_process(pid);
        if (p == NULL){
//            printf("[get_FD_by_name - %lu] no such process!\n", pid);
            return -1;
        }
        fdt = p->fdtable;
    }

    for (int i = 0; i < MAX_FILES_NUM; i++){
        if(fdt[i] != NULL && strcmp(fdt[i]->name, name) == 0){
            return i;
        }
    }
    return -1;
}

int close_by_FD(seL4_Word pid, int fd){

    struct file ** fdt;

    if (pid == 0) {
        fdt = fdtable;
    }else {
        Process *p = get_process(pid);
        if (p == NULL){
//            printf("[close_by_FD - %lu] no such process!\n", pid);
            return -1;
        }
        fdt = p->fdtable;
    }

    if (fd < 0 || fd >= MAX_FILES_NUM){
        return -1;
    }    
    if (fdt[fd] == NULL){
        return 0;
    }

    fdt[fd]->ref --;

    if (fdt[fd]->ref <= 0 ){
//        printf("[close_by_FD - %lu] fd = %d\n", pid, fd);
        free(fdt[fd]);
        fdt[fd] = NULL;
    }

    return 0;
}

int add_fd(seL4_Word pid, const char *name, int type,int offset, int mode, file_opts_t opts, size_t ref, struct nfsfh *nfsfh){

    struct file ** fdt;

    if (pid == 0) {
        fdt = fdtable;
    }else {
        Process *p = get_process(pid);
        if (p == NULL){
//            printf("[add_fd - %lu] no such process!\n", pid);
            return -1;
        }
        fdt = p->fdtable;
    }
    
    //find an empty slot
    int i;
    for (i = 0; i < MAX_FILES_NUM; i++){
        if (fdt[i] == NULL){
            fdt[i] = malloc(sizeof(struct file));
            break;
        }
    }
    if (i == MAX_FILES_NUM){
        return -1;
    }
    
    //create a file pointer
    struct file *new_file = malloc(sizeof(struct file));
    new_file->opts = opts;
    new_file->mode = mode;
    strcpy(new_file->name, name);
    new_file->type = type;
    new_file->offset = offset;
    new_file->nfsfh = nfsfh;
    new_file->ref = ref;
    
    //insert the file pointer
    fdt[i] = new_file;
    return i;
}