#include "vm/page.h"
#include <string.h>

static unsigned spt_hash_func(const struct hash_elem, void *)
static bool spt_less_func(const struct hast_elem, const struct hast_elem, void *)

struct spt* spt_init(void)
{
	struct spt* m_hash = (struct spt *)malloc(sizeof(struct spt));
	hash_init(&m_hash->hash_brown, spt_hash_func, spt_less_func, NULL);
	return m_hash;
}

static unsigned spt_hash_func(const struct hash_elem *e, void *aux)
{
	struct spt_entry * target_entry = hash_entry(e, struct spt_entry, helem);
	return hash_int((uint32_t)target_entry->vaddr);
}

static bool spt_less_func(const struct hast_elem *a, const struct hast_elem *b, void *aux)
{
	struct spt_entry *a_entry = hash_entry(a, struct spt_entry, helem);
	struct spt_entry *b_entry = hash_entry(b, struct spt_entry, helem);
	return (hash_int((uint32_t)a_entry->vaddr) < hash_int((uint32_t)b_entry->vaddr));

}

bool insert_spt_entry(struct hash *spt, struct spt_entry *spt_e)
{
	struct hash_elem insert_elem = hash_insert(spt, spt_e->helem);
	if (insert_elem == NULL)
	{
		return false;
	}
	return true;
}

bool delete_spt_entry(struct hash *spt, struct spt_entry *spt_e)
{
	struct hash_elem delete_elem = hash_delete(spt, spt_e->helem);
	if (delete_elem == NULL)
	{
		return false;
	}
	return true;
}

struct spt_entry * find_spt_elem(void *vaddr)
{
	void * r_vaddr = 
	struct hash_elem * target_elem = hash_find()

}