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
	if (insert_elem == NULL)
	{
		return false;
	}
	return true;
}

bool delete_spt_entry(struct hash *spt, struct spt_entry *spt_e)
{
	//uint8_t *upage_ptr = spt_e->upage;
	struct hash_elem * delete_elem = hash_delete(spt, &spt_e->helem);
	if (delete_elem == NULL)
	{
		return false;
	}
	//palloc_free_page(upage_ptr);
	free(spt_e);
	return true;
}

struct spt_entry * create_s_entry(uint8_t * upage, uint8_t *kpage, bool writable, struct file * file, off_t offset, uint32_t read_bytes, uint32_t zero_bytes)
{
	struct spt_entry * new_spt_entry = (struct spt_entry *)malloc(sizeof(struct spt_entry));
	new_spt_entry->kpage = kpage;
	new_spt_entry->upage = upage;
	new_spt_entry->writable = writable;
	new_spt_entry->file = file;
	new_spt_entry->offset = offset;
	new_spt_entry->read_bytes = read_bytes;
	new_spt_entry->zero_bytes = zero_bytes;

	return new_spt_entry;
}

struct spt_entry * find_spt_entry(void *upage)
{
	struct spt_entry tem_entry;
	tem_entry.upage = pg_round_down(upage);
	struct hash_elem * target_elem = hash_find(&thread_current()->spt->hash_brown, &tem_entry.helem);
	if (target_elem == NULL)
	{
		return NULL;
	}
	return hash_entry(target_elem, struct spt_entry, helem);
}

void spt_destroy(struct hash *hash_brown)
{
	hash_destroy(hash_brown, spt_entry_destroy);
}

static void spt_entry_destroy(struct hash_elem *e, void *aux)
{
	struct spt_entry * target_entry = hash_entry(e, struct spt_entry, helem);
	free(target_entry);
}
