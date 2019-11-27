#include "vm/frame.h"
#include <string.h>
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"

static unsigned frame_hash_func(const struct hash_elem, void *)
static bool frame_less_func(const struct hash_elem, const struct hash_elem, void *)

struct frame_table * frame_init(void)
{
	struct frame_table* m_hash = (struct frame_table *)malloc(sizeof(struct frame_table));
	hash_init(&m_hash->frame_hash, frame_hash_func, frame_less_func, NULL);
	return m_hash;
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

bool insert_frame_entry(struct hash *frame_hash, struct frame_entry *frame_e)
{
	struct hash_elem insert_elem = hash_insert(frame_hash, frame_e->helem);
	if (insert_elem == NULL)
	{
		return false;
	}
	return true;
}

bool delete_spt_entry(struct hash *frame_hash, struct frame_entry *frame_e)
{
	struct hash_elem delete_elem = hash_delete(frame_hash, frame_e->helem);
	if (delete_elem == NULL)
	{
		return false;
	}
	return true;
}

struct frame_entry * create_entry(void)
{

}

