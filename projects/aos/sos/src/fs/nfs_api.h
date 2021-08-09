//
// Created by Rui on 2021/6/28.
//

#ifndef SEL4_APPLICATION_NFS_API_H
#define SEL4_APPLICATION_NFS_API_H

#include "read_task.h"

typedef struct {
    char *path;
    AsyncTask *async;
    unsigned long *size;
    char * elf_base;

    unsigned long cur;
    struct nfsfh * nfsfh;
}NfsLoadElfArgs;

int nfs_open_file(OpenTask *task);
int nfs_stat_path(StatTask *task);
int nfs_getdirent_api(GetDirentTask *task);
int open_page_file(void);
int write_page_file(struct file *file, void *t);
int read_page_file(struct file *file, void *t);
int nfs_load_elf_async(char *app_name, char *elf_base, size_t *elf_size, AsyncTask *async);

void init_nfs_api(struct nfs_context *nfs);

#endif //SEL4_APPLICATION_NFS_API_H
