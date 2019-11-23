#include "vm/frame.h"
#include <list.h>
//#include "vm/page.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

void fifo_init() {
	list_init(&fifo_list);
	lock_init(&frame_lock);
}

void add_frame_to_fifo_list(struct frame_entry *f_table) {
	lock_acquire(&frame_lock);
	list_push_back(&fifo_list, &f_table->fifo);
	lock_release(&frame_lock);
}
void del_frame_to_fifo_list(struct frame_entry *f_table) {
	if(f_table->fifo.next != NULL && f_table->fifo.prev != NULL)
		list_remove(&f_table->fifo);
}

void *frame_alloc(enum palloc_flags flags,struct sup_page_entry *spte){
	if ((flags & PAL_USER) == 0) {
		return NULL;
	}
	
	void * frame_addr = palloc_get_page(flags);
	if (frame_addr == NULL) {
		/*It means there is not enough physical memory*/
		/*Need eviction*/
	}
	struct frame_entry *frame = (struct frame_entry *)malloc(sizeof(struct frame_entry));
	if (frame == NULL) {
		return NULL;
	}
	frame->thread = thread_current();
	frame->kaddr = frame_addr;
	frame->spte = spte;
	add_frame_to_fifo_list(frame);
	return frame_addr;
}
void free_frame(struct frame_entry *frame) {
	del_frame_to_fifo_list(frame);
	free(frame);
	palloc_free_page(frame->kaddr);

}

void free_frame_entry(void *kaddr) {
	struct list_elem *e;
	lock_acquire(&frame_lock);
	for (e = list_begin(&fifo_list); e != list_end(&fifo_list); e = list_next(e)) {
		struct frame_entry *frame = list_entry(e, struct frame_entry, fifo);
		if (frame->kaddr == kaddr) {
			free_frame(frame);
		}
	}
	lock_release(&frame_lock);
}

void *frame_evict(enum palloc_flags flags) {
	lock_acquire(&frame_lock);
	/*1. Choose a frame to evict, using fifo algorithm*/
	struct list_elem *e = list_begin(&fifo_list);
	struct frame_entry *entry = list_entry(e, struct frame_entry, fifo);
	/*2. remove references to the frame from any page tables*/
	entry->spte->is_loaded = false;
	del_frame_to_fifo_list(entry->kaddr);
	pagedir_clear_page(entry->thread->pagedir, entry->spte->upage);
	palloc_free_page(entry->kaddr);
	free(entry);
	return palloc_get_page(flags);

}
