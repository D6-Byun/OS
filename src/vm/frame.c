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
	hash_init(&m_hash->fried_hash, frame_hash_func, frame_less_func, NULL);
	return m_hash;
}

static unsigned frame_hash_func(const struct hash_elem *e, void *aux)
{

}

static bool frame_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux)
{

}
