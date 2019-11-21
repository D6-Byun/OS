#include <stdio.h>
#include <list.h>
#include "vm/page.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"

struct frame_entry {

	void * kaddr;
	struct sup_page_entry *spte;
	struct thread * thread;
	struct list_elem lru;

};

struct frame_entry *alloc_frame(enum palloc_flags flags);
void free_frame_entry(void *kaddr);