#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

typedef int mapid_t; 

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
bool handle_mm_fault(struct sup_page_entry *spte);
bool install_page (void *upage, void *kpage, bool writable);
#endif /* userprog/process.h */
