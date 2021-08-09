//
// Created by Rui on 2021/6/20.
//

#ifndef SEL4_APPLICATION_APP_MAPPING_H
#define SEL4_APPLICATION_APP_MAPPING_H

#include <cspace/cspace.h>
#include "../frame_table.h"


// size of VM page
#define PAGE_SIZE  4096
// mask for getting page number from addr
#define PAGE_FRAME  0x0000fffffffff000

#define PGD_SIZE 512
#define PUD_SIZE 512
#define PD_SIZE 512
#define PT_SIZE 512

#define MAX_PROCESS_SIZE_ 16

typedef struct SeL4_Page_t{
    seL4_CPtr frame_cap;
    frame_ref_t frame;
    size_t page_file_offset;
    seL4_Word vaddr;
    bool pin;
    bool fix;
    bool visited;

    seL4_Word pid;
} SeL4_Page;

typedef struct PT_t{
    SeL4_Page *process_pages[MAX_PROCESS_SIZE_];
    ut_t *ut;
    seL4_CPtr frame_cap;
    frame_ref_t frame;
} PT;

typedef struct PD_t{
    PT *pts[PT_SIZE];
    ut_t *ut;
    seL4_CPtr frame_cap;
    frame_ref_t frame;
} PD;

typedef struct PUD_t{
    PD *pds[PD_SIZE];
    ut_t *ut;
    seL4_CPtr frame_cap;
    frame_ref_t frame;
} PUD;

typedef struct PGD_t{
    PUD *puds[PUD_SIZE];
} PGD;

#define OFFSET_MASK 0x0000000000000fff
#define PGD_MASK    0x0000ff8000000000
#define PUD_MASK    0x0000007fc0000000
#define PD_MASK     0x000000003fe00000
#define PT_MASK     0x00000000001ff000

#define PGD_INDEX(vaddr) (((vaddr)&PGD_MASK)>>39)
#define PUD_INDEX(vaddr) (((vaddr)&PUD_MASK)>>30)
#define PD_INDEX(vaddr) (((vaddr)&PD_MASK)>>21)
#define PT_INDEX(vaddr) (((vaddr)&PT_MASK)>>12)
#define OFFSET_VAL(vaddr) ((vaddr)&OFFSET_MASK)

SeL4_Page* get_page(seL4_Word badge,seL4_Word vaddr);
SeL4_Page* get_or_create_page(seL4_Word badge,seL4_Word vaddr);

seL4_Error app_map_frame(seL4_Word badge,cspace_t *cspace, seL4_CPtr frame_cap, seL4_CPtr vspace, seL4_Word vaddr,
                         seL4_CapRights_t rights, seL4_ARM_VMAttributes attr,frame_ref_t frame, bool pin, bool fix);
seL4_Error app_unmap_frame(seL4_CPtr cap);
seL4_Error app_remap_frame(SeL4_Page *page, seL4_CPtr vspace, seL4_CapRights_t rights, seL4_ARM_VMAttributes attr);

void init_page_table();
void destroy_page(seL4_Word pid, SeL4_Page *page);


#endif //SEL4_APPLICATION_APP_MAPPING_H
