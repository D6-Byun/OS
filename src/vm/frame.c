#include "vm/frame.h"

/* list for swapping algorithm*/
static struct list lru_list;

void lru_init() {
	list_init(&lru_list);
	struct lock lru_lock;
	lock_init(&lru_lock);
	int lru_clock = NULL;
}

void add_frame_to_lru_list(struct frame_entry *f_table) {
	list_push_back(&lru_list, &f_table->lru);
}

void del_frame_to_lru_list(struct frame_entry *f_table) {
	if(f_table->lru.next != NULL && f_table->lru.prev != NULL)
		list_remove(&f_table->lru);
}

struct frame_entry *alloc_frame(enum palloc_flags flags) {
	void * frame_addr = palloc_get_page(PAL_USER|flags);
	if (frame_addr == NULL) {

	}
	struct frame_entry *frame = (struct frame_entry *)malloc(sizeof(struct frame_entry));
	if (frame == NULL) {
		return NULL;
	}
	frame->thread = thread_current();
	frame->kaddr = frame_addr;
	frame->spte = NULL;
	add_frame_to_lru_list(frame);
	return frame_addr;
}
void free_frame(struct frame_entry *frame) {
	del_frame_to_lru_list(frame);
	free(frame);
	palloc_free_page(frame->kaddr);

}

void free_frame_entry(void *kaddr) {
	struct list_elem *e;
	for (e = list_begin(&lru_list); e != list_end(&lru_list); e = list_next(e)) {
		struct frame_entry *frame = list_entry(e, struct frame_entry, lru);
		if (frame->kaddr == kaddr) {
			free_frame(frame);
		}
	}
}