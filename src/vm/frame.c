#include "vm/frame.h"
#include <string.h>
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"

static struct hash frame_table;

static unsigned frame_hash_func(const struct hash_elem, void *);
static bool frame_less_func(const struct hash_elem, const struct hash_elem, void *);

struct frame_table * frame_init(void)
{
	hash_init(&frame_table , frame_hash_func, frame_less_func, NULL);
}

static unsigned frame_hash_func(const struct hash_elem *e, void *aux)
{
	struct frame_entry * target_entry = hash_entry(e, struct frame_entry, helem);
	return hash_int((uint32_t)target_entry->kpage);
}

static bool frame_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux)
{
	struct frame_entry *a_entry = hash_entry(a, struct frame_entry, helem);
	struct frame_entry *b_entry = hash_entry(b, struct frame_entry, helem);
	return (hash_int((uint32_t)a_entry->kpage) < hash_int((uint32_t)b_entry->kpage));
}

bool insert_frame_entry(struct frame_entry *frame_e)
{
	struct hash_elem insert_elem = hash_insert(&frame_table, frame_e->helem);
	if (insert_elem == NULL)
	{
		return false;
	}
	return true;
}

bool delete_frame_entry(struct frame_entry *frame_e)
{
	uint8_t * kpage_ptr = frame_e->kpage;
	struct hash_elem delete_elem = hash_delete(&frame_table, frame_e->helem);
	if (delete_elem == NULL)
	{
		return false;
	}
	palloc_free_page(kpage_ptr);
	free(frame_e);
	return true;
}

struct frame_entry * create_f_entry(enum palloc_flags flag, uint8_t * upage)
{
	struct frame_entry * new_frame_entry = (struct frame_entry *)malloc(sizeof(struct frame_entry));
	new_frame_entry->kpage = palloc_get_page(PAL_USER | flag);
	new_frame_entry->upage = upage;

	return new_frame_entry;
}

void free_frame_table(void)
{
	hash_destroy(&frame_table, free_frame_entry);
	free(frame);
}

void free_frame_entry(struct hash_elem *e, void *aux)
{
	struct frame_entry * target_entry = hash_entry(e, struct frame_entry, helem);
	palloc_free_page(target_entry->kpage);
	free(target_entry);
}

/*
struct frame_entry * search_frame_entry()

::Maybe needed at free::

*/

