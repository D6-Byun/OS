#include "vm/frame.h"
#include "vm/page.h"
#include <hash.h>
#include <list.h>
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

static struct hash frame_hash;

static struct lock frame_lock;

static unsigned frame_hash_func(const struct hash_elem *elem, void *aux);
static bool frame_less_func(const struct hash_elem *elema, const struct hash_elem *elemb, void *aux);


struct frame_page_entry{
	void *kpage; //key: mapped to physical addr
	void *upage;

	struct hash_elem helem; //for frame_hash
//	struct list_elem lelem;
	struct thread *t; //thread
	struct sup_page_entry *spte;
	bool pinned; //true: prevent evicting

};

void frame_init(){
	lock_init(&frame_lock);
	hash_init(&frame_hash, frame_hash_func, frame_less_func, NULL);

}


static unsigned
frame_hash_func(const struct hash_elem *elem, void *aux){
	struct frame_page_entry *fpe = hash_entry(elem, struct frame_page_entry, helem);
	return hash_int((int)fpe->kpage);
}
static bool frame_less_func(const struct hash_elem *elema, const struct hash_elem *elemb, void *aux){
	struct frame_page_entry *a = hash_entry(elema, struct frame_page_entry, helem);
	struct frame_page_entry *b = hash_entry(elemb, struct frame_page_entry, helem);
	return a->kpage < b->kpage;

}

void *frame_alloc(enum palloc_flags flags, void *upage){
	lock_acquire(&frame_lock);
	void *frame_page = palloc_get_page(PAL_USER | flags);
	if(frame_page == NULL){
		/*eviction and swapping*/
		PANIC("Swapping Not implemented");
	}
	struct frame_page_entry *frame = malloc(sizeof(struct frame_page_entry));
	if(frame == NULL) {
		lock_release(&frame_lock);
		return NULL;
	}
	frame->kpage = frame_page;
	frame->upage = upage;
	frame->t = thread_current();
	frame->pinned = true;

	hash_insert(&frame_hash, &frame->helem);
	lock_release(&frame_lock);
	return frame_page;
}

struct frame_page_entry * frame_lookup(void *kpage){
	ASSERT(pg_ofs(kpage) == 0);
	
	struct frame_page_entry fpe_temp;
	fpe_temp.kpage = kpage;

	struct hash_elem *hel = hash_find(&frame_hash, &(fpe_temp.helem));
	if(hel == NULL){
		PANIC("There is no such frame");
	}
	return hash_entry(hel, struct frame_page_entry, helem);
}

void frame_free(void *kpage){
	lock_acquire(&frame_lock);
	ASSERT(pg_ofs(kpage) == 0);

	struct frame_page_entry *fpe = frame_lookup(kpage);
	hash_delete(&frame_hash, &fpe->helem);

	palloc_free_page(kpage);
	free(fpe);
	lock_release(&frame_lock);
}
/*set pinned value of frame_page_entry which has KAPGE to PIN*/
static void frame_set_pinned(void *kpage, bool pin){
	lock_acquire(&frame_lock);
	struct frame_page_entry *fpe = frame_lookup(kpage);
	fpe->pinned = pin;

	lock_release(&frame_lock);
}
void frame_pin(void *kpage){
	frame_set_pinned(kpage, true);
}


void frame_unpin(void *kpage){
	frame_set_pinned(kpage, false);
}





