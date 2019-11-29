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

static struct list frame_list;
static struct lock frame_lock;

static unsigned frame_hash_func(const struct hash_elem *elem, void *aux);
static bool frame_less_func(const struct hash_elem *elema, const struct hash_elem *elemb, void *aux);


struct frame_page_entry{
	void *kpage; //key: mapped to physical addr
	void *upage;

	struct hash_elem helem; //for frame_hash
	struct list_elem lelem;
	struct thread *t; //thread
	struct sup_page_entry *spte;
	bool pinned; //true: prevent evicting

};

void frame_init(){
	lock_init(&frame_lock);
	//hash_init(&frame_hash, frame_hash_func, frame_less_func, NULL);
	list_init(&frame_list);
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

void *frame_alloc(enum palloc_flags flags, struct sup_page_entry *spte){
	void *frame_page = palloc_get_page(PAL_USER | flags);
	if(frame_page == NULL){
		/*eviction and swapping*/
		frame_page = frame_evict();
		if(frame_page == NULL){
			PANIC("SWAP IS FULL");
		}
		return frame_page;
	}
	struct frame_page_entry *frame = malloc(sizeof(struct frame_page_entry));
	if(frame == NULL) {
		return NULL;
	}
	frame->kpage = frame_page;
	frame->upage = spte->upage;
	frame->t = thread_current();
	frame->pinned = true;

	lock_acquire(&frame_lock);
	//hash_insert(&frame_hash, &frame->helem);
	list_push_back(&frame_list, &frame->lelem);
	lock_release(&frame_lock);
	return frame_page;
}

struct frame_page_entry * frame_lookup(void *kpage){
	ASSERT(pg_ofs(kpage) == 0);
	
	struct list_elem *elem;
	for(elem = list_begin(&frame_list);elem != list_end(&frame_list); elem = list_next(elem)){
		struct frame_page_entry *fpe = list_entry(elem,struct frame_page_entry, lelem);
		if(fpe->kpage == kpage){
			return fpe;
		}
	
	}
	return NULL;
}

void frame_free(void *kpage){
	lock_acquire(&frame_lock);
	ASSERT(pg_ofs(kpage) == 0);

	struct frame_page_entry *fpe = frame_lookup(kpage);
	if(fpe != NULL){
	//hash_delete(&frame_hash, &fpe->helem);
	list_remove(&fpe->lelem);
	free(fpe);
	}
	lock_release(&frame_lock);
	palloc_free_page(kpage);
}
/*set pinned value of frame_page_entry which has KAPGE to PIN*/
/*static void frame_set_pinned(void *kpage, bool pin){
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
}*/

void *frame_evict(void){
	struct thread *cur = thread_current();
	struct list_elem *elem = list_begin(&frame_list);
	lock_acquire(&frame_lock);
	while(true){
		struct frame_page_entry *fpe = list_entry(elem, struct frame_page_entry, lelem);
		if(pagedir_is_accessed(cur->pagedir,fpe->spte->upage)){
			pagedir_set_accessed(cur->pagedir,fpe->spte->upage, false);
		}else{
			if(pagedir_is_dirty(cur->pagedir, fpe->spte->upage
						||fpe->spte->status == SWAP)){
				struct sup_page_entry *spte = fpe->spte; 
				off_t iswrite = file_write_at(spte->file,spte->upage,spte->read_bytes, spte->ofs);
				if(iswrite != spte->read_bytes){
					printf("frame_evict: write at error:\n");
					lock_release(&frame_lock);
					return NULL;
				}
				spte->swap_index = swap_out(fpe->kpage);
			}
			fpe->spte->is_loaded = false;
			
			list_remove(&fpe->lelem);
			pagedir_clear_page(cur->pagedir, fpe->spte->upage);
			palloc_free_page(fpe->kpage);
			free(fpe);
			lock_release(&frame_lock);
			
			return palloc_get_page(PAL_USER);
		}
		elem = list_next(elem);
		if(elem == list_end(&frame_list)){
			elem = list_begin(&frame_list);
		}
	}
	lock_release(&frame_lock);
	return NULL;
}



