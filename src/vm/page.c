#include "vm/page.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include <string.h>
#include "threads/thread.h"

/*For build hash
it get elem e then return upage of entry
*/
static unsigned 
spt_hash_func(const struct hash_elem *e, void* aux) {
	struct sup_page_entry *spe = hash_entry(e, struct sup_page_entry, helem);
	return hash_int((int)spe->upage);
}

static bool 
spt_less_func(const struct hash_elem *a, const struct hash_elem *b, void* aux) {
	struct sup_page_entry *a_spe = hash_entry(a, struct sup_page_entry, helem);
	struct sup_page_entry *b_spe = hash_entry(b, struct sup_page_entry, helem);
	return a_spe->upage < b_spe->upage;
}

static void spt_destroy_func(const struct hash_elem *e, void *aux){
	thread_current()->spt->hash_brown.elem_cnt--;
	list_remove (&e->list_elem);
}

struct sup_page_table *
spt_create(void) {
	struct sup_page_table *spt = (struct sup_page_table *)malloc(sizeof(struct sup_page_table));
	hash_init(&spt ->hash_brown,spt_hash_func,spt_less_func, NULL);
	return spt;
}

void spt_destroy(struct sup_page_table *spt) {
	hash_destroy(&spt ->hash_brown, spt_destroy_func);
	if(spt != NULL)
		free(spt);
}

/*
Lookup the supplemental page table
Return page table entry which has user page addr.
Return NUll if there is no such entry.
*/
struct sup_page_entry *sup_lookup_page(struct sup_page_table *spt, void *page) {
	struct sup_page_entry temp;
	temp.upage = pg_round_down(page);
	struct hash_elem *e = hash_find(&spt->hash_brown, &temp.helem);
	if (e == NULL) 
		return NULL;
	return hash_entry(e, struct sup_page_entry, helem);
}
/*
Find entry which has page as upage
Set dirty if it is not NULL.
#Dirty: no -> yes: O, yes -> no: X
*/
void sup_set_dirty(struct sup_page_table *spt, void *page, bool dirty) {
	struct sup_page_entry *entry = sup_lookup_page(spt, page);
	ASSERT(entry != NULL);
	entry->dirty = entry->dirty || dirty;
}
/*Get dirty, if can't find entry, ASSERT*/
bool sup_get_dirty(struct sup_page_table *spt, void *page) {
	struct sup_page_entry *entry = sup_lookup_page(spt, page);
	ASSERT(entry != NULL);
	return entry->dirty;

}
/*insert SPTE in SPT return TRUE, 
if inserting fails return FALSE*/
bool sup_insert(struct sup_page_table *spt, struct sup_page_entry *spte) {
	struct hash_elem *elem = hash_insert(&spt->hash_brown, &spte->helem);
	if (elem == NULL) {
		return true;
	}
	return false;
}
/*insert SPTE in SPT return TRUE,
if inserting fails return FALSE*/
bool sup_delete(struct sup_page_table *spt, struct sup_page_entry *spte) {
	struct hash_elem *elem = hash_delete(&spt->hash_brown, &spte->helem);
	if (elem == NULL) {
		return false;
	}
	return true;
}

/*load the file to physical page*/
bool load_file(void *kaddr, struct sup_page_entry *spte) {
	void * paddr = palloc_get_page(0);	
	printf("read_bytes: %d\n",(off_t)spte->read_bytes);
	printf("offset: %d\n", spte->file_ofs);
	file_seek(spte->file, spte->file_ofs);
	off_t isread = file_read(spte->file, paddr, (off_t)spte->read_bytes);
	//off_t  isread = file_read_at(spte->file, kaddr, (off_t)spte->read_bytes, spte->file_ofs);
	printf("isread = %d\n",isread);
	printf("Check Page Size: %d\n", spte->zero_bytes + spte->read_bytes);
	if (isread != spte->read_bytes){
		return false;
	}
	memset(kaddr + isread, 0, spte->zero_bytes);
	return true;
}

bool add_entry(struct sup_page_table *spt,struct file *file, off_t ofs,void *upage, void *kpage, uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	struct sup_page_entry *entry = (struct sup_page_entry *)malloc(sizeof(struct sup_page_entry));
	entry->file = file;
	entry->file_ofs = ofs;
	entry->kpage = kpage;
	entry->upage = upage;
	entry->read_bytes = read_bytes;
	entry->zero_bytes = zero_bytes;
	entry->writable = writable;
	entry->dirty = false;
	if(sup_insert(spt, entry) == false){
		return false;
	}
	return true;
}
