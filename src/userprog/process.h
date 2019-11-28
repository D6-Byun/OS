#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

#define CLOSE_ALL -1

struct mmap_file{
	struct list_elem melem; //for mmap_list
	int mapid; //mapping ID
	struct sup_page_entry *spte; //Map to virtual address
};


tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
bool install_page(void *upage, void *kpage, bool writable);
#endif /* userprog/process.h */
