#pragma once

#include <stddef.h>
#include <unistd.h>
#include "read_task.h"

#define MAX_FILE_NAME 100
#define MAX_FILES_NUM 128
//#define MAX_OPEN_FILE 128


#ifndef SEL4_APPLICATION_FDTABLE_H
#define SEL4_APPLICATION_FDTABLE_H


typedef struct file_opts {
    int (*read) (ReadTask *task);
    int (*write) (WriteTask *task);
    int (*open) (const char * name, int mode);
    int (*close) (int fd);
} file_opts_t;

struct file {
    char name[MAX_FILE_NAME];
    //size_t size;
    int type;
    size_t offset;
    int mode;
    file_opts_t opts;
    size_t ref;
    struct nfsfh *nfsfh;
};

//build the file descriptor table
struct file *fdtable[MAX_FILES_NUM];

//globol openfile table
//struct file *open_file_table[MAX_OPEN_FILE];


//init the fdtable
void file_struct_init();

//open a file in fdtable
int handle_open(const char name[], int type, int mode);

//get a file by fd
struct file * get_by_FD(seL4_Word pid, int fd);

//close a file by fd
int close_by_FD(seL4_Word pid, int fd);

//add a file
int add_fd(seL4_Word pid, const char *name, int type,int offset, int mode, file_opts_t opts, size_t ref, struct nfsfh *nfsfh);

int get_FD_by_name(seL4_Word pid, char name[]);

#endif //SEL4_APPLICATION_CONSOLE_H