//
// Created by Rui on 2021/6/17.
//

#ifndef SEL4_APPLICATION_SYSTASK_H
#define SEL4_APPLICATION_SYSTASK_H

char ELF_CACHE[1000000];

bool new_read_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut);
bool new_write_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut);
bool new_sleep_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut);
bool new_time_stamp_task(seL4_CPtr reply, ut_t *reply_ut);
bool new_open_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut);
bool new_close_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut);
bool new_brk_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut);
bool new_stat_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut);
bool new_get_dirent_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut);
bool new_get_my_pid_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut);
bool new_process_creat_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut);
bool new_process_status_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut);
bool new_process_delete_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut);
bool new_process_wait_task(seL4_Word badge, seL4_CPtr reply, ut_t *reply_ut);

void init_systask(void);

#endif //SEL4_APPLICATION_SYSTASK_H
