//
// Created by Rui on 2021/6/18.
//

#include "../ut.h"
#include "../vm/addrspace.h"
#include "../../../libsosapi/include/sos.h"

#define MAX_TASK_SIZE 10
#define MAX_TASK_DATA_SIZE 128
#define MAX_MSG_DATA_SIZE (seL4_MsgMaxLength - 2)

#ifndef SEL4_APPLICATION_READ_TASK_H
#define SEL4_APPLICATION_READ_TASK_H

typedef struct {
    size_t task_id;
    seL4_CPtr reply;
    ut_t *reply_ut;
    size_t data_len;
    size_t cursor;
    bool finished;
    char data[MAX_TASK_DATA_SIZE];
    UserPage *user_pages;
    size_t pages_size;
    size_t user_data_size;
    struct file *file;
    size_t send_data_size;
    seL4_Word pid;
} ReadTask;

typedef struct {
    size_t length;
    ReadTask tasks[MAX_TASK_SIZE];
} ReadTaskList;

int insert_read_tasks(ReadTask *task, ReadTaskList *list);
int pop_read_task(ReadTaskList *list, ReadTask *task);
int delete_first_read_task(ReadTaskList *list);
int first_read_task(ReadTaskList *list, ReadTask **task);
int delete_read_task_by_id(ReadTaskList *list, size_t task_id);
int get_read_task_by_id(ReadTaskList *list, ReadTask ** task, size_t task_id);
int first_unfinished_read_task(ReadTaskList *list, ReadTask ** task);

typedef struct {
    size_t task_id;
    seL4_CPtr reply;
    ut_t *reply_ut;
    UserPage *user_pages;
    size_t pages_size;
    size_t data_size;
    size_t send_data_size;
    size_t cur;
    struct nfsfh *nfsfh;
    struct file *file;
    seL4_Word pid;
} WriteTask;

typedef struct {
    size_t task_id;
    seL4_CPtr reply;
    ut_t *reply_ut;
    char path[120];
    fmode_t mode;
    AsyncTask *async;
    seL4_Word pid;
} OpenTask;

typedef struct {
    size_t task_id;
    seL4_CPtr reply;
    ut_t *reply_ut;
    char *path;
    sos_stat_t *st;
    AsyncTask *async;
} StatTask;

typedef struct {
    size_t task_id;
    seL4_CPtr reply;
    ut_t *reply_ut;
    size_t pos;
    UserPage *user_pages;
    size_t pages_size;
    size_t user_data_size;

    struct nfsdir *nfsdir;
    struct nfsdirent *nfsdirent;
    struct nfs_context *nfs;

    seL4_Word pid;
} GetDirentTask;

typedef struct {
    size_t length;
    OpenTask tasks[MAX_TASK_SIZE];
} OpenTaskList;

#endif //SEL4_APPLICATION_READ_TASK_H
