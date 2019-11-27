#include <hash.h>
#include "vm/page.h"

#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "filesys/file.h"

static unsigned spt_hash_func(const struct hash_elem *e, void* aux) {
	struct sup_page_entry *spe = hash_entry(e, struct sup_page_entry, helem);
	return hash_int((int)spe->upage);
}

static bool spt_less_func(const struct hash_elem *a, const struct hash_elem *b, void* aux) {
	struct sup_page_entry *a_spe = hash_entry(a, struct sup_page_entry, helem);
	struct sup_page_entry *b_spe = hash_entry(b, struct sup_page_entry, helem);
	return a_spe->upage < b_spe->upage;
}

static void spt_destroy_func(const struct hash_elem *e, void *aux) {
	struct sup_page_entry *spte = hash_entry(e, struct sup_page_entry, helem);
	if (!spte->kpage) {
		frame_free(spte->kpage);
	}
	free(spte);
}

struct sup_page_table *spt_create(void) {
	struct sup_page_table *spt = (struct sup_page_table *)malloc(sizeof(struct sup_page_table));
	hash_init(&spt->hash_brown,spt_hash_func,spt_less_func, NULL);
	return spt;

}
void spt_destroy(struct sup_page_table *spt) {
	if (spt != NULL) {
		hash_destroy(&spt->hash_brown, spt_destroy_func);
		free(spt);
	}
}

/*
Lookup the supplemental page table
Return page table entry which has user page addr.
Return NUll if there is no such entry.
*/
struct sup_page_entry *sup_lookup_page(struct sup_page_table *spt, void *page) {
	struct sup_page_entry temp;
	temp.upage = page;
	struct hash_elem *e = hash_find(&spt->hash_brown, &temp.helem);
	if (e == NULL)
		return NULL;
	return hash_entry(e, struct sup_page_entry, helem);
}

bool add_entry(struct sup_page_table *spt, struct file *file, off_t ofs, void *upage, void *kpage, 
	uint32_t read_bytes, uint32_t zero_bytes, bool writable, enum status type) {
	
	struct sup_page_entry *entry = (struct sup_page_entry *)malloc(sizeof(struct sup_page_entry));
	entry->file = file;
	entry->file_ofs = ofs;
	entry->kpage = kpage;
	entry->upage = upage;
	entry->read_bytes = read_bytes;
	entry->zero_bytes = zero_bytes;
	entry->writable = writable;
	entry->dirty = false;
	entry->type = type;
	if (hash_insert(&spt->hash_brown,entry->helem) != NULL) {
		return false;
	}
	return true;
}
/*add entry with UPAGE, KPAGE and WRITABLE which is already in frame to SPT */
bool add_install(struct sup_page_table *spt, void *upage, void *kpage, bool writable) {
	struct sup_page_entry *entry = (struct sup_page_entry *)malloc(sizeof(struct sup_page_entry));
	entry->upage = upage;
	entry->kpage = kpage;
	entry->dirty = false;
	entry->writable = writable;
	entry->type = FRAME;

	if (hash_insert(&spt->hash_brown, entry->helem) != NULL) {
		free(entry);
		printf("add_install: hash_insert failed.\n");
		return false;
	}
	return false;
}
/*Allocate frame and insert to SPT*/
bool spt_load_page(struct sup_page_table *spt, uint32_t *pagedir, void *upage) {
	struct sup_page_entry *spte = sup_lookup_page(spt, upage);
	if (spte == NULL) {
		printf("spt_load_page: lookup failed.\n");
		return false;
	}
	void * frame = frame_alloc(PAL_USER, upage);
	if (frame == NULL) {
		printf("spt_load_page: frame_alloc failed.\n");
		return false;
	}
	switch (spte->type) {
		case FRAME:
			/*is already in frame*/
			return true;
			break;
		case SWAP:
			/*Not implemented yet*/
			PANIC("Not implemented yet");
			break;
		case ZERO:
			memset(frame, 0, PGSIZE);
		default:
			NOT_REACHED();
			break;
	}
	if (!pagedir_set_page(pagedir, upage, frame, true)) {
		frame_free(frame);
		printf("spt_load_page: upage is already mapped.");
		return false;
	}
	spte->kpage = frame;
	spte->type = FRAME:
	pagedir_set_dirty(pagedir, frame, false);
	frame_unpin(frame);

	return true;
}








