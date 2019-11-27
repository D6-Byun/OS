#include <hash.h>
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "vm/page.h"

static unsigned
spt_hash_func(const struct hash_elem *elem, void *aux)
{
	struct sup_page_entry *spte = hash_entry(elem, struct sup_page_entry, elem);
	return hash_int((int)spte->upage);
}
static bool
spt_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux)
{
	struct sup_page_entry *aentry = hash_entry(a, struct sup_page_entry, elem);
	struct sup_page_entry *bentry = hash_entry(b, struct sup_page_entry, elem);
	return aentry->upage < bentry->upage;
}
static void
spt_destroy_func(struct hash_elem *elem, void *aux)
{
	struct sup_page_entry *spte = hash_entry(elem, struct sup_page_entry, elem);
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
