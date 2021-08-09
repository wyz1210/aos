//
// Created by Rui on 2021/6/20.
//

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
#include <sel4/sel4.h>
#include <sel4/sel4_arch/mapping.h>
#include "app_mapping.h"
#include "../ut.h"
#include "../utils.h"
#include "../fs/nfs_api.h"
#include "../fs/fdtable.h"
#include "paging.h"
#include "../process.h"

PGD *ROOT_PGD[PGD_SIZE];

void init_page_table() {
    init_paging();

    int error = open_page_file();
    if (error != 0){
//        printf("[init_page_table] error open pagefile\n");
    }
}

SeL4_Page* get_page(seL4_Word badge, seL4_Word vaddr) {

    int pgdIndex = PGD_INDEX(vaddr);
    int pudIndex = PUD_INDEX(vaddr);
    int pdIndex = PD_INDEX(vaddr);
    int ptIndex = PT_INDEX(vaddr);
//    int offset = OFFSET_VAL(vaddr);

    Process *process = get_process(badge);
    if (process == NULL){
//        printf("[get_page] wrong badge = %lu\n", badge);
        return NULL;
    }

    if (ROOT_PGD[pgdIndex] == NULL) {
        return NULL;
    }

    PUD **puds = ROOT_PGD[pgdIndex]->puds;
    if (puds[pudIndex] == NULL) {
        return NULL;
    }

    PD **pds = puds[pudIndex]->pds;
    if (pds[pdIndex] == NULL) {
        return NULL;
    }

    PT **pts = pds[pdIndex]->pts;
    if (pts[ptIndex] == NULL) {
        return NULL;
    }

    PT *pt = pts[ptIndex];
    SeL4_Page **page_pointer = &pt->process_pages[badge % MAX_PROCESS_SIZE_];
    if (*page_pointer != NULL && (*page_pointer)->pid != badge){
        if (get_process(badge) != NULL){
            // this should not happen
//            printf("[get_page page - %lu] with conflict process %lu\n", badge, (*page_pointer)->pid);
            return NULL;
        }

//        printf("[get_page page - %lu] overwrite process %lu with vaddr = 0x%016lx\n", badge, (*page_pointer)->pid, vaddr);
        memset(*page_pointer, '\0', sizeof(SeL4_Page));
        return *page_pointer;
    }

    return *page_pointer;

}


int store_pud_data(seL4_Word badge,seL4_Word vaddr, ut_t *ut, seL4_CPtr frame_cap, frame_ref_t frame){
    int pgdIndex = PGD_INDEX(vaddr);
    int pudIndex = PUD_INDEX(vaddr);

    Process *process = get_process(badge);
    if (process == NULL){
//        printf("[store_pud_data] wrong badge = %lu\n", badge);
        return -1;
    }


    if (ROOT_PGD[pgdIndex] == NULL) {
//        printf("[store_pud_data] lack pgd structure\n");
        return -1;
    }


    if (ROOT_PGD[pgdIndex]->puds[pudIndex] == NULL) {
//        printf("[store_pud_data] lack pud structure\n");
        return -1;
    }

    PUD *pud = ROOT_PGD[pgdIndex]->puds[pudIndex];
    pud->ut = ut;
    pud->frame = frame;
    pud->frame_cap = frame_cap;

    return 0;
}

int store_pd_data(seL4_Word badge,seL4_Word vaddr, ut_t *ut, seL4_CPtr frame_cap, frame_ref_t frame){
    int pgdIndex = PGD_INDEX(vaddr);
    int pudIndex = PUD_INDEX(vaddr);
    int pdIndex = PD_INDEX(vaddr);

    Process *process = get_process(badge);
    if (process == NULL){
//        printf("[store_pd_data] wrong badge = %lu\n", badge);
        return -1;
    }

    if (ROOT_PGD[pgdIndex] == NULL) {
//        printf("[store_pd_data] lack pgd structure\n");
        return -1;
    }

    if (ROOT_PGD[pgdIndex]->puds[pudIndex] == NULL) {
//        printf("[store_pd_data] lack pud structure\n");
        return -1;
    }

    PUD *pud = ROOT_PGD[pgdIndex]->puds[pudIndex];
    if (pud->pds[pdIndex] == NULL) {
//        printf("[store_pd_data] lack pd structure\n");
        return -1;
    }

    PD *pd = pud->pds[pdIndex];
    pd->ut = ut;
    pd->frame = frame;
    pd->frame_cap = frame_cap;

    return 0;
}

int store_pt_data(seL4_Word badge,seL4_Word vaddr, ut_t *ut, seL4_CPtr frame_cap, frame_ref_t frame){
    int pgdIndex = PGD_INDEX(vaddr);
    int pudIndex = PUD_INDEX(vaddr);
    int pdIndex = PD_INDEX(vaddr);
    int ptIndex = PT_INDEX(vaddr);

    Process *process = get_process(badge);
    if (process == NULL){
//        printf("[store_pt_data] wrong badge = %lu\n", badge);
        return -1;
    }

    if (ROOT_PGD[pgdIndex] == NULL) {
//        printf("[store_pd_data] lack pgd structure\n");
        return -1;
    }

    if (ROOT_PGD[pgdIndex]->puds[pudIndex] == NULL) {
//        printf("[store_pd_data] lack pud structure\n");
        return -1;
    }

    PUD *pud = ROOT_PGD[pgdIndex]->puds[pudIndex];
    if (pud->pds[pdIndex] == NULL) {
//        printf("[store_pd_data] lack pd structure\n");
        return -1;
    }

    PD *pd = pud->pds[pdIndex];
    if (pd->pts[ptIndex] == NULL) {
//        printf("[store_pd_data] lack pt structure\n");
        return -1;
    }

    PT *pt = pd->pts[ptIndex];
    pt->ut = ut;
    pt->frame = frame;
    pt->frame_cap = frame_cap;

    return 0;
}


SeL4_Page* get_or_create_page(seL4_Word badge,seL4_Word vaddr) {

    int pgdIndex = PGD_INDEX(vaddr);
    int pudIndex = PUD_INDEX(vaddr);
    int pdIndex = PD_INDEX(vaddr);
    int ptIndex = PT_INDEX(vaddr);
//    int offset = OFFSET_VAL(vaddr);

    Process *process = get_process(badge);
    if (process == NULL){
//        printf("[get_or_create_page] wrong badge = %lu\n", badge);
        return NULL;
    }


    if (ROOT_PGD[pgdIndex] == NULL) {
        ROOT_PGD[pgdIndex] = malloc(sizeof(PGD));
        if (ROOT_PGD[pgdIndex] == NULL){
//            printf("[create_page pgd] error!\n");
            return NULL;
        }
        memset(ROOT_PGD[pgdIndex], '\0', sizeof(PGD));
//        printf("[create_page pgd]\n");
    }

    if (ROOT_PGD[pgdIndex]->puds[pudIndex] == NULL) {
        ROOT_PGD[pgdIndex]->puds[pudIndex] = malloc(sizeof(PUD));
        if (ROOT_PGD[pgdIndex]->puds[pudIndex] == NULL){
//            printf("[create_page pud] error!\n");
            return NULL;
        }
        memset(ROOT_PGD[pgdIndex]->puds[pudIndex], '\0', sizeof(PUD));
//        printf("[create_page pud]\n");
    }

    PUD *pud = ROOT_PGD[pgdIndex]->puds[pudIndex];
    if (pud->pds[pdIndex] == NULL) {
        pud->pds[pdIndex] = malloc(sizeof(PD));
        if (pud->pds[pdIndex] == NULL){
//            printf("[create_page pd] error!\n");
            return NULL;
        }
        memset(pud->pds[pdIndex], '\0', sizeof(PD));
//        printf("[create_page pd]\n");
    }

    PD *pd = pud->pds[pdIndex];
    if (pd->pts[ptIndex] == NULL) {
        pd->pts[ptIndex] = malloc(sizeof(PT));
        if (pd->pts[ptIndex] == NULL){
//            printf("[create_page pt] error!\n");
            return NULL;
        }
        memset(pd->pts[ptIndex], '\0', sizeof(PT));
//        printf("[create_page pt]\n");
    }

    PT *pt = pd->pts[ptIndex];
    SeL4_Page **page_pointer = &pt->process_pages[badge % MAX_PROCESS_SIZE_];
    if (*page_pointer == NULL){
        *page_pointer = malloc(sizeof(SeL4_Page));
        if (*page_pointer == NULL){
//            printf("[create_page page - %lu] error!\n", badge);
            return NULL;
        }
        memset(*page_pointer, '\0', sizeof(SeL4_Page));
        if (process_add_page(process, *page_pointer) > 0){
//            printf("[create_page page - %lu] error add pages into process!\n", badge);
            free(*page_pointer);
            return NULL;
        }
    }else if ((*page_pointer)->pid != badge){
        if (get_process((*page_pointer)->pid) != NULL){
//            printf("[create_page page - %lu] with conflict process %lu\n", badge, (*page_pointer)->pid);
            return NULL;
        }
//        printf("[create_page page - %lu] overwrite process %lu with vaddr = 0x%016lx\n", badge, (*page_pointer)->pid, vaddr);
        memset(*page_pointer, '\0', sizeof(SeL4_Page));
        if (process_add_page(process, *page_pointer) > 0){
//            printf("[create_page page - %lu] error add pages into process!\n", badge);
            free(*page_pointer);
            return NULL;
        }
    }

    return *page_pointer;

}

static seL4_Error app_retype_map_pt(cspace_t *cspace, seL4_CPtr vspace, seL4_Word vaddr, seL4_CPtr ut, seL4_CPtr empty)
{

    seL4_Error err = cspace_untyped_retype(cspace, ut, empty, seL4_ARM_PageTableObject, seL4_PageBits);
    if (err) {
        return err;
    }

    return seL4_ARM_PageTable_Map(empty, vspace, vaddr, seL4_ARM_Default_VMAttributes);
}


static seL4_Error app_retype_map_pd(cspace_t *cspace, seL4_CPtr vspace, seL4_Word vaddr, seL4_CPtr ut, seL4_CPtr empty)
{

    seL4_Error err = cspace_untyped_retype(cspace, ut, empty, seL4_ARM_PageDirectoryObject, seL4_PageBits);
    if (err) {
        return err;
    }

    return seL4_ARM_PageDirectory_Map(empty, vspace, vaddr, seL4_ARM_Default_VMAttributes);
}


static seL4_Error app_retype_map_pud(cspace_t *cspace, seL4_CPtr vspace, seL4_Word vaddr, seL4_CPtr ut,
                                     seL4_CPtr empty)
{

    seL4_Error err = cspace_untyped_retype(cspace, ut, empty, seL4_ARM_PageUpperDirectoryObject, seL4_PageBits);
    if (err) {
        return err;
    }
    return seL4_ARM_PageUpperDirectory_Map(empty, vspace, vaddr, seL4_ARM_Default_VMAttributes);
}

static seL4_Error app_map_frame_impl(seL4_Word badge, cspace_t *cspace, seL4_CPtr frame_cap, seL4_CPtr vspace, seL4_Word vaddr,
                                     seL4_CapRights_t rights, seL4_ARM_VMAttributes attr,frame_ref_t frame, bool pin, bool fix)
{
    /* Attempt the mapping */

    seL4_Error err = seL4_ARM_Page_Map(frame_cap, vspace, vaddr, rights, attr);
    if(err != seL4_NoError && err != seL4_FailedLookup){
//        printf("[app_map_frame_impl - %lu] seL4_ARM_Page_Map error = %d\n", badge, err);
        return err;
    }

    SeL4_Page *page = get_or_create_page(badge, vaddr);
    if (page == NULL){
//        printf("[app_map_frame_impl - %lu] can't alloc new page\n", badge);
        return -1;
    }

    for (size_t i = 0; i < MAPPING_SLOTS && err == seL4_FailedLookup; i++) {
        /* save this so nothing else trashes the message register value */
        seL4_Word failed = seL4_MappingFailedLookupLevel();

        /* Assume the error was because we are missing a paging structure */
        ut_t *ut = ut_alloc_4k_untyped(NULL);
        if (ut == NULL) {
            ZF_LOGE("Out of 4k untyped");
            return -1;
        }

        seL4_CPtr slot = cspace_alloc_slot(cspace);
        if (slot == seL4_CapNull) {
            ZF_LOGE("No cptr to alloc paging structure");
            return -1;
        }

        switch (failed) {
            case SEL4_MAPPING_LOOKUP_NO_PT:
                err = app_retype_map_pt(cspace, vspace, vaddr, ut->cap, slot);
//                printf("[app_map_frame pt] vaddr = 0x%016lx, slot = 0x%016lx\n", vaddr, slot);
                store_pt_data(badge, vaddr, ut, ut->cap, slot);
                break;
            case SEL4_MAPPING_LOOKUP_NO_PD:
                err = app_retype_map_pd(cspace, vspace, vaddr, ut->cap, slot);
//                printf("[app_map_frame pd] vaddr = 0x%016lx, slot = 0x%016lx\n", vaddr, slot);
                store_pd_data(badge, vaddr, ut, ut->cap, slot);
                break;

            case SEL4_MAPPING_LOOKUP_NO_PUD:
                err = app_retype_map_pud(cspace, vspace, vaddr, ut->cap, slot);
//                printf("[app_map_frame pud] vaddr = 0x%016lx, slot = 0x%016lx\n", vaddr, slot);
                store_pud_data(badge, vaddr, ut, ut->cap, slot);
                break;
        }

        if (!err) {
            /* Try the mapping again */
            err = seL4_ARM_Page_Map(frame_cap, vspace, vaddr, rights, attr);
        }
    }

    page->frame_cap = frame_cap;
    page->frame = frame;
    page->vaddr = vaddr & (~OFFSET_MASK);
    page->pin = pin;
    page->fix = fix;
    page->visited = true;
    page->pid = badge;

    err = append_page(page);
    if (err != 0){
//        printf("append_page error\n");
    }

    seL4_ARM_Page_GetAddress_t _frame = seL4_ARM_Page_GetAddress(frame_cap);
//    printf("[app_map_frame - %lu] vaddr = 0x%016lx, paddr = 0x%016lx\n", badge, vaddr, _frame.paddr);

    return err;
}

int _count = 0;

seL4_Error app_map_frame(seL4_Word badge, cspace_t *cspace, seL4_CPtr frame_cap, seL4_CPtr vspace, seL4_Word vaddr,
                         seL4_CapRights_t rights, seL4_ARM_VMAttributes attr, frame_ref_t frame, bool pin, bool fix)
{
    if (fix == true){
        _count ++;
//        printf("[app_map_frame - %lu] new fix frame, vaddr = 0x%016lx, count = %d\n",badge, vaddr, _count);
    }
    return app_map_frame_impl(badge, cspace, frame_cap, vspace, vaddr & (~OFFSET_MASK), rights, attr, frame, pin, fix);
}

seL4_Error app_unmap_frame(seL4_CPtr cap){
//    printf("[app_unmap_frame]");
    return seL4_ARM_Page_Unmap(cap);
}

seL4_Error app_remap_frame(SeL4_Page *page, seL4_CPtr vspace, seL4_CapRights_t rights, seL4_ARM_VMAttributes attr){

//    printf("[remap] vaddr = 0x%016lx\n", page->vaddr);
    seL4_Error err = seL4_ARM_Page_Map(page->frame_cap, vspace, page->vaddr, rights, attr);
    if (err){
//        printf("[remap] can't remap, vaddr = 0x%016lx, err = %d\n", page->vaddr, err);
    }
    return err;
}

void delete_pud_from_pgd_if_need(seL4_Word vaddr){
    int pgdIndex = PGD_INDEX(vaddr);
    int pudIndex = PUD_INDEX(vaddr);

    if (ROOT_PGD[pgdIndex] == NULL) {
        return;
    }

    PUD **puds = ROOT_PGD[pgdIndex]->puds;
    if (puds[pudIndex] == NULL) {
        return;
    }

    PUD *pud = puds[pudIndex];

    bool found = false;
    for (int i = 0; i < PD_SIZE; i ++){
        if (pud->pds[i] != NULL){
            found = true;
            break;
        }
    }

    if (found == false){
        cspace_delete(&cspace, pud->frame_cap);
        cspace_free_slot(&cspace, pud->frame_cap);
        cspace_delete(&cspace,  pud->frame);
        cspace_free_slot(&cspace, pud->frame);
//        ut_free(pud->ut);

        free(pud);
        puds[pudIndex] = NULL;
    }

    return;
}

void delete_pd_from_pud_if_need(seL4_Word vaddr){
    int pgdIndex = PGD_INDEX(vaddr);
    int pudIndex = PUD_INDEX(vaddr);
    int pdIndex = PD_INDEX(vaddr);

    if (ROOT_PGD[pgdIndex] == NULL) {
        return;
    }

    PUD **puds = ROOT_PGD[pgdIndex]->puds;
    if (puds[pudIndex] == NULL) {
        return;
    }

    PD **pds = puds[pudIndex]->pds;
    if (pds[pdIndex] == NULL) {
        return;
    }

    if (pds[pdIndex] == NULL) {
        return;
    }

    PD *pd = pds[pdIndex];

    bool found = false;
    for (int i = 0; i < PT_SIZE; i ++){
        if (pd->pts[i] != NULL){
            found = true;
            break;
        }
    }

    if (found == false){
        cspace_delete(&cspace, pd->frame_cap);
        cspace_free_slot(&cspace, pd->frame_cap);
        cspace_delete(&cspace,  pd->frame);
        cspace_free_slot(&cspace, pd->frame);
//        ut_free(pd->ut);

        free(pd);
        pds[pdIndex] = NULL;
    }

    return;
}

void delete_pt_from_pd_if_need(seL4_Word vaddr){
    int pgdIndex = PGD_INDEX(vaddr);
    int pudIndex = PUD_INDEX(vaddr);
    int pdIndex = PD_INDEX(vaddr);
    int ptIndex = PT_INDEX(vaddr);


    if (ROOT_PGD[pgdIndex] == NULL) {
        return;
    }

    PUD **puds = ROOT_PGD[pgdIndex]->puds;
    if (puds[pudIndex] == NULL) {
        return;
    }

    PD **pds = puds[pudIndex]->pds;
    if (pds[pdIndex] == NULL) {
        return;
    }

    PT **pts = pds[pdIndex]->pts;
    if (pts[ptIndex] == NULL) {
        return;
    }

    PT *pt = pts[ptIndex];

    bool found = false;
    for (int i = 0; i < MAX_PROCESS_SIZE_; i ++){
        if (pt->process_pages[i] != NULL){
            found = true;
            break;
        }
    }

    if (found == false){
        cspace_delete(&cspace, pt->frame_cap);
        cspace_free_slot(&cspace, pt->frame_cap);
        cspace_delete(&cspace,  pt->frame);
        cspace_free_slot(&cspace, pt->frame);
//        ut_free(pt->ut);

        free(pt);
        pts[ptIndex] = NULL;
    }

    return;
}

void delete_page_from_pt(seL4_Word badge, seL4_Word vaddr){
    int pgdIndex = PGD_INDEX(vaddr);
    int pudIndex = PUD_INDEX(vaddr);
    int pdIndex = PD_INDEX(vaddr);
    int ptIndex = PT_INDEX(vaddr);


    if (ROOT_PGD[pgdIndex] == NULL) {
        return;
    }

    PUD **puds = ROOT_PGD[pgdIndex]->puds;
    if (puds[pudIndex] == NULL) {
        return;
    }

    PD **pds = puds[pudIndex]->pds;
    if (pds[pdIndex] == NULL) {
        return;
    }

    PT **pts = pds[pdIndex]->pts;
    if (pts[ptIndex] == NULL) {
        return;
    }

    PT *pt = pts[ptIndex];
    if (pt->process_pages[badge % MAX_PROCESS_SIZE_] != NULL){
        pt->process_pages[badge % MAX_PROCESS_SIZE_] = NULL;
    }
    return;
}

void destroy_page(seL4_Word pid, SeL4_Page *page){
    if (page == NULL){
        return;
    }

//    printf("[destroy_page] vaddr = 0x%016lx\n", page->vaddr);

    if (page->vaddr == 0){
        return ;
    }

    delete_page_from_pagequeue(pid, page);

    if (page->frame != NULL_FRAME){
        app_unmap_frame(page->frame_cap);

        cspace_delete(&cspace, page->frame_cap);
        cspace_free_slot(&cspace, page->frame_cap);
        free_frame(page->frame);

        page->frame_cap = 0;
        page->frame = 0;
    }

    unuse_slot(page->page_file_offset);

    delete_page_from_pt(pid, page->vaddr);
    delete_pt_from_pd_if_need(page->vaddr);
    delete_pd_from_pud_if_need(page->vaddr);
    delete_pud_from_pgd_if_need(page->vaddr);

//    printf("[destroy_page] vaddr = 0x%016lx, finish\n", page->vaddr);

    free(page);
    page = NULL;
}