//
// Created by Rui on 2021/6/18.
//

#include "read_task.h"

ReadTask _temp_task_list[MAX_TASK_SIZE];

int insert_read_tasks(ReadTask *task, ReadTaskList *list) {
    if (list->length < MAX_TASK_SIZE) {
        memcpy(&list->tasks[list->length], task, sizeof(ReadTask) * 1);
        list->length++;
        return 0;
    }
    return 1;
}

int pop_read_task(ReadTaskList *list, ReadTask *task) {
    ReadTask task_list[MAX_TASK_SIZE];

    if (list->length <= 0) {
        return 1;
    }
    list->length--;
    memcpy(task, &list->tasks[0], sizeof(ReadTask) * 1);

    if (list->length > 0) {
        memcpy(&task_list, &list->tasks[1], sizeof(ReadTask) * (list->length));
        memcpy(&list->tasks[0], &task_list, sizeof(ReadTask) * (list->length));
    }

    return 0;
}

int delete_first_read_task(ReadTaskList *list) {
    if (list->length <= 0) {
        return 1;
    }
    list->length--;
//    printf("delete first task id = %zu, size = %zu\n", list->tasks[0].task_id, list->length);
    return 0;
}

int first_read_task(ReadTaskList *list, ReadTask **task) {
    if (list->length <= 0) {
        return 1;
    }

    *task = &list->tasks[0];
    return 0;
}

int delete_read_task_by_id(ReadTaskList *list, size_t task_id){
//    printf("delete_task_by_id, task_id = %zu\n", task_id);

    if (list->length <= 0){
        return 1;
    }

    size_t i;
    bool found = false;
    for (i = 0; i < list->length; i++){
        if (list->tasks[i].task_id == task_id){
            found = true;
            break;
        }
    }

    if (found == false){
        return 1;
    }

    if (i < list->length - 1){
        memcpy(&_temp_task_list, &list->tasks[i + 1], sizeof(ReadTask) * (list->length - i - 1));
        memcpy(&list->tasks[i], &_temp_task_list, sizeof(ReadTask) * (list->length - i - 1));
    }
    list->length --;

    return 0;
}

int get_read_task_by_id(ReadTaskList *list, ReadTask ** task, size_t task_id){
    if (list->length <= 0){
        return 1;
    }

    for (size_t i = 0; i < list->length; i++){
        if (list->tasks[i].task_id == task_id){
            *task = &list->tasks[i];
            return 0;
        }
    }

    return 1;
}

int first_unfinished_read_task(ReadTaskList *list, ReadTask ** task){
    if (list->length <= 0){
        return 1;
    }

    for (size_t i = 0; i < list->length; i++){
        if (list->tasks[i].finished == false){
            *task = &list->tasks[i];
            return 0;
        }
    }

    return 1;
}