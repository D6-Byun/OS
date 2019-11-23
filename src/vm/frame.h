#ifndef VM_FRAME_H
#define VM_FRAME_H

//#include <stdio.h>
#include <list.h>
#include "threads/synch.h"
#include "threads/palloc.h"
#include "vm/page.h"

/* list for swapping algorithm*/
struct list fifo_list;

struct lock frame_lock;


struct frame_entry {

	void * kaddr;
	struct sup_page_entry *spte;
	struct thread * thread;
	struct list_elem fifo;

};
void fifo_init();
void *frame_alloc(enum palloc_flags flags,struct sup_page_entry *spte);
void free_frame_entry(void *kaddr);
void *frmae_evict(void);
#endif
