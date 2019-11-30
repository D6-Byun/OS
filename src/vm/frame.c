#include "vm/frame.h"
#include <string.h>
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"

static struct hash *frame_table = NULL;

static unsigned frame_hash_func(const struct hash_elem *, void *);
static bool frame_less_func(const struct hash_elem *, const struct hash_elem *, void *);

void frame_init(void)
{
	frame_table = (struct hash *)malloc(sizeof(struct hash));
	hash_init(frame_table , frame_hash_func, frame_less_func, NULL);
	//printf("successfully frame inited\n");
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
	struct hash_elem * insert_elem = hash_insert(frame_table, &frame_e->helem);
	if (insert_elem != NULL)
	{
		//printf("hash_insert failed in insert_frame_entry\n");
		return false;
	}
	//printf("successfully frame_entry inserted\n");
	return true;
}

bool delete_frame_entry(struct frame_entry *frame_e)
{
	uint8_t * kpage_ptr = frame_e->kpage;
	struct hash_elem * delete_elem = hash_delete(frame_table, &frame_e->helem);
	if (delete_elem == NULL)
	{
		//printf("hash_delete failed in delete_frame_entry\n");
		return false;
	}
	palloc_free_page(kpage_ptr);
	free(frame_e);
	//printf("successfully frame_entry deleted\n");
	return true;
}

struct frame_entry * create_f_entry(enum palloc_flags flag, uint8_t * upage)
{
	struct frame_entry * new_frame_entry = (struct frame_entry *)malloc(sizeof(struct frame_entry));
	if (new_frame_entry == NULL)
	{
		//printf("malloc failed in create_f_entry\n");
		return NULL;
	}
	new_frame_entry->kpage = palloc_get_page(PAL_USER | flag);
	if (new_frame_entry->kpage == NULL)
	{
		//swap needed to implement
		PANIC("Swap needed\n");
	}
	new_frame_entry->upage = upage;

	//printf("successfully frame_entry created\n");

	insert_frame_entry(new_frame_entry);

	return new_frame_entry;
}

void free_frame_table(void)
{
	hash_destroy(frame_table, free_frame_entry);
	//free(&frame_table);
}

void free_frame_entry(struct hash_elem *e, void *aux)
{
	//printf("free frame_entry\n");
	struct frame_entry * target_entry = hash_entry(e, struct frame_entry, helem);
	//printf("kpage addr : %x\n", target_entry->kpage);
	hash_delete(frame_table, &target_entry->helem);
	palloc_free_page(target_entry->kpage);
	free(target_entry);


	//printf("chock chock - frame_entry_Destroy\n");
}


struct frame_entry * search_frame_entry(void *kpage) {
	struct frame_entry * tem_entry;
	tem_entry->kpage = pg_round_down(kpage);
	struct hash_elem * target_elem = hash_find(frame_table, &tem_entry->helem);
	if (target_elem == NULL)
	{
		//printf("hash_find failed in find_spt_entry\n");
		return NULL;
	}
	//printf("successfully spt_entry found\n");
	return hash_entry(target_elem, struct frame_entry, helem);
}

