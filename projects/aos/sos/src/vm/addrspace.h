//
// Created by Rui on 2021/6/21.
//

#ifndef SEL4_APPLICATION_ADDRSPACE_H
#define SEL4_APPLICATION_ADDRSPACE_H

#include <sel4/sel4.h>
#include "paging.h"

# define MAX_AS_SIZE 128

typedef struct PAGE_TAG{
    seL4_Word vaddr;
    seL4_Word paddr;
    seL4_CapRights_t perms;
    struct PAGE_TAG *next;
} Page;

typedef struct ADDRSPACE_TAG {
    seL4_Word stack_top;
    seL4_Word stack_bottom;
    seL4_Word stack_max_size;
    seL4_Word heap_base;
    seL4_Word heap_max_size;
} Addrspace;

typedef struct {
    seL4_Word user_pointer;
    unsigned char *data;
    unsigned char ** data_pointer;
    size_t size;
} UserPage;

void init_addrspace();

void finish_use_user_pointer(seL4_Word pid, seL4_Word user_pointer);
int get_user_pointer_async(seL4_Word pid, seL4_Word user_pointer, unsigned char ** data_pointer, AsyncTask *async);
int copy_user_pointer_list(seL4_Word user_pointer, size_t len, UserPage ** page_list);


#endif //SEL4_APPLICATION_ADDRSPACE_H
