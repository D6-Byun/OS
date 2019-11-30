#include "vm/page.h"
#include <string.h>
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "vm/frame.h"

static unsigned spt_hash_func(const struct hash_elem *, void *);
static bool spt_less_func(const struct hash_elem *, const struct hash_elem *, void *);
static void spt_entry_destroy(struct hash_elem *, void *);

struct spt* spt_init(void)
{
	struct spt* m_hash = (struct spt *)malloc(sizeof(struct spt));
	hash_init(&m_hash->hash_brown, spt_hash_func, spt_less_func, NULL);
	//printf("successfully spt inited\n");
	return m_hash;
}

static unsigned spt_hash_func(const struct hash_elem *e, void *aux)
{
	struct spt_entry * target_entry = hash_entry(e, struct spt_entry, helem);
	return hash_int((uint32_t)target_entry->upage);
}

static bool spt_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux)
{
	struct spt_entry *a_entry = hash_entry(a, struct spt_entry, helem);
	struct spt_entry *b_entry = hash_entry(b, struct spt_entry, helem);
	return (hash_int((uint32_t)a_entry->upage) < hash_int((uint32_t)b_entry->upage));

}

bool insert_spt_entry(struct hash *spt, struct spt_entry *spt_e)
{
	struct hash_elem * insert_elem = hash_insert(spt, &spt_e->helem);
	if (insert_elem != NULL)
	{
		//printf("hash_insert failed in insert_spt_entry\n");
		return false;
	}
	//printf("successfully spt_entry inserted\n");
	return true;
}

bool delete_spt_entry(struct hash *spt, struct spt_entry *spt_e)
{
	//uint8_t *upage_ptr = spt_e->upage;
	//printf("delete_spt_Entry ON\n");
	struct hash_elem * delete_elem = hash_delete(spt, &spt_e->helem);
	if (delete_elem == NULL)
	{
		//printf("hash_delete failed in delete_spt_entry\n");
		return false;
	}
	if (spt_e->is_loaded)
	{
		/*
		struct frame_entry *taget_entry = search_frame_entry(spt_e->kpage);
		free_frame_entry(&taget_entry->helem, NULL);
		*/
	}
	spt_e->is_loaded = false;
	free(spt_e);
	//printf("successfully spt_entry deleted\n");
	return true;
}

struct spt_entry * create_s_entry(uint8_t * upage, uint8_t *kpage, bool writable, struct file * file, off_t offset, uint32_t read_bytes, uint32_t zero_bytes)
{
	struct spt_entry * new_spt_entry = (struct spt_entry *)malloc(sizeof(struct spt_entry));
	if (new_spt_entry == NULL)
	{
		//printf("malloc failed in create_s_entry\n");
		return NULL;
	}
	new_spt_entry->kpage = kpage;
	new_spt_entry->upage = pg_round_down(upage);
	new_spt_entry->writable = writable;
	new_spt_entry->file = file;
	new_spt_entry->offset = offset;
	new_spt_entry->read_bytes = read_bytes;
	new_spt_entry->zero_bytes = zero_bytes;
	new_spt_entry->is_loaded = false;

	//printf("successfully spt_entry created\n");

	return new_spt_entry;
}

struct spt_entry * find_spt_entry(void *upage)
{
	struct spt_entry* tem_entry = (struct spt_entry*)malloc(sizeof(struct spt_entry));
	tem_entry->upage = pg_round_down(upage);
	struct hash_elem * target_elem = hash_find(&thread_current()->spt->hash_brown, &tem_entry->helem);
	if (target_elem == NULL)
	{
		//printf("hash_find failed in find_spt_entry\n");
		return NULL;
	}
	//printf("successfully spt_entry found\n");
	return hash_entry(target_elem, struct spt_entry, helem);
}

void spt_destroy(struct spt *spt)
{
	hash_destroy(&spt->hash_brown, spt_entry_destroy);
	free(spt);
	//printf("OMAWE WA MO SINDAERU\n");
}

static void spt_entry_destroy(struct hash_elem *e, void *aux)
{
	//printf("start spt_entry_destroy\n");
	struct spt_entry * target_entry = hash_entry(e, struct spt_entry, helem);
	//printf("upage addr : %x\n", target_entry->upage);
	//printf("kpage addr : %x\n", target_entry->kpage);
	//printf("right target_entry\n");
	if (target_entry->is_loaded)
	{
		//printf("need to change format of frame entry deletion\n");
		//printf("connected with frame\n");
		//printf("kpage addr : %x\n", target_entry->kpage);
		/*
		struct frame_entry *target_frame = search_frame_entry(target_entry->kpage);
		
		printf("found frame entry\n");
		if (target_frame != NULL)
		{
			free_frame_entry(&target_frame->helem, NULL);
			target_entry->is_loaded = false;
		}
		*/

	}
	//hash_delete(&thread_current()->spt->hash_brown, &target_entry->helem);
	//printf("NANIIIIII - spt_entry_Destroy\n");
	free(target_entry);
	//printf("end\n");
}
