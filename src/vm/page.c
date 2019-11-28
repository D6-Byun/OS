#include <stdio.h>
#include <hash.h>
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "vm/page.h"
#include "vm/frame.h"

bool spt_load_page(struct sup_page_table *spt, void *upage);

static unsigned
spt_hash_func(const struct hash_elem *elem, void *aux)
{
	struct sup_page_entry *spte = hash_entry(elem, struct sup_page_entry, helem);
	return hash_int((int)spte->upage);
}
static bool
spt_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux)
{
	struct sup_page_entry *aentry = hash_entry(a, struct sup_page_entry, helem);
	struct sup_page_entry *bentry = hash_entry(b, struct sup_page_entry, helem);
	return aentry->upage < bentry->upage;
}
static void
spt_destroy_func(struct hash_elem *elem, void *aux)
{
	struct sup_page_entry *spte = hash_entry(elem, struct sup_page_entry, helem);
	if(spte->is_loaded){
		frame_free(pagedir_get_page(thread_current()->pagedir, spte->upage));
		pagedir_clear_page(thread_current()->pagedir,spte->upage);
	}
	free(spte);
}


struct sup_page_table *spt_create(void){
	struct sup_page_table *spt = (struct sup_page_table *)malloc(sizeof(struct sup_page_table));
	hash_init(&spt->hash_brown,spt_hash_func,spt_less_func, NULL);
	return spt;
}

void spt_destroy(struct sup_page_table *spt){
	hash_destroy(&spt->hash_brown, spt_destroy_func);
	free(spt);
}

struct sup_page_entry *spt_lookup(struct sup_page_table *spt, void *upage){
	struct sup_page_entry spte;
	spte.upage = pg_round_down(upage);

	struct hash_elem *elem = hash_find(&spt->hash_brown,&spte.helem);
	if(elem == NULL){
		//printf("spt_lookup: can't find entry.\n");
		return NULL;
	}
	return hash_entry(elem, struct sup_page_entry, helem);
}

bool spt_load_file(struct sup_page_entry *spte){
	//void *addr = pagedir_get_page(thread_current()->pagedir, spte->upage);
	uint8_t *frame = frame_alloc(PAL_USER,spte);
	if(!frame){
		printf("spt_load_file: can't alloc frame\n");
		return false;
	}
	off_t isread = file_read_at(spte->file, frame, spte->read_bytes, spte->ofs);
	if(isread != spte->read_bytes){
		frame_free(frame);
		printf("isread : %d is diff with read_bytes : %d\n",isread,spte->read_bytes);
		return false;
	}
	memset(frame + spte->read_bytes, 0, spte->zero_bytes);
	if(!install_page(spte->upage, frame, spte->writable)){
		frame_free(frame);
		printf("spt_load_file: fail to install\n");
		return false;
	}
	spte->is_loaded = true;
	return true;
}

bool spt_load_swap(struct sup_page_entry *spte){
	void *frame = frame_alloc(PAL_USER,spte);
	if(frame == NULL){
		printf("spt_load_swap: fail to alloc\n");
		return false;
	}
	if(install_page(spte->upage,frame,spte->writable)){
		frame_free(frame);
		return false;
	}
	swap_in(spte->swap_index,spte->upage);
	spte->is_loaded = true;
	return true;
}

bool spt_load_page(struct sup_page_table *spt, void *upage){
	struct sup_page_entry *spte = spt_lookup(spt,upage);
	if(spte == NULL){
		//printf("spt_load_page: can't find entry.\n");
		return false;
	}
	bool success = false;
	if(spte->is_loaded){
		return false;
	}
	switch(spte->status){
		case VMFILE:
			success = spt_load_file(spte);
			break;
		case SWAP:
			success = spt_load_swap(spte);
			break;
		case MMAP:
			success = spt_load_file(spte);
			break;
	}
	return success;
}

bool spt_add_entry(struct sup_page_table *spt, struct file *file, off_t ofs, void *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable){
	struct sup_page_entry *spte = (struct sup_page_entry *)malloc(sizeof(struct sup_page_entry));
	if(spte == NULL){
		return false;
	}
	spte->file = file;
	spte->ofs = ofs;
	spte->upage = upage;
	spte->read_bytes = read_bytes;
	spte->zero_bytes = zero_bytes;
	spte->is_loaded = false;
	spte->status = VMFILE;
	spte->writable = writable;
	return hash_insert(&spt->hash_brown,&spte->helem) == NULL;
}

bool spt_add_mmap(struct sup_page_table *spt, struct file *file, off_t ofs, void *upage, uint32_t read_bytes, uint32_t zero_bytes){
	struct sup_page_entry *spte = (struct sup_page_entry *)malloc(sizeof(struct sup_page_entry));
	spte->file = file;
	spte->ofs = ofs;
	spte->upage = upage;
	spte->read_bytes = read_bytes;
	spte->zero_bytes = zero_bytes;
	spte->writable = true;
	spte->is_loaded = false;
	spte->status = MMAP;
	if(spt_try_add_mmap(spte) == false){
		free(spte);
		return false;
	}
	return hash_insert(&spt->hash_brown,&spte->helem) == NULL;
}

bool spt_try_add_mmap(struct sup_page_entry *spte){
	struct mmap_file *mfile = (struct mmap_file *)malloc(sizeof(struct mmap_file));
	if(mfile == NULL){
		printf("spt_try_add_mmap: fail to malloc mmap_file.\n");
		return false;
	}
	mfile->spte = spte;
	mfile->mapid = thread_current()->mapid;
	list_push_back(&thread_current()->mmap_list, &mfile->melem);
	return true;
}

bool grow_stack(void *upage){
	if(PHYS_BASE - pg_round_down(upage) > MAX_STACK_SIZE){
		printf("Grow stack: stack is full.\n");
		return false;
	}
	struct sup_page_entry *spte = (struct sup_page_entry *)malloc(sizeof(struct sup_page_entry));
	if(spte == NULL){
		printf("spte is not allocated \n");
		return false;
	}
	spte->upage = upage;
	spte->is_loaded = true;
	spte->status = SWAP;
	void *frame = frame_alloc(PAL_USER,spte);
	if(frame == NULL){
		free(spte);
		printf("frame is not allocated\n");
		return false;
	}
	if(!install_page(upage,frame,true)){
		free(spte);
		frame_free(frame);
		printf("frame install is failed\n");
		return false;
	}
	return hash_insert(&(thread_current()->spt->hash_brown),&spte->helem) == NULL;
}





