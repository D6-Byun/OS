#ifndef FRAME_H
#define FRAME_H

#include <hash.h>
#include "threads/synch.h"
#include "threads/palloc.h"
#include "vm/page.h"

void frame_init(void);
void *frame_alloc(enum palloc_flags flags, struct sup_page_entry *spte);

void frame_free(void *kpage);

void frame_pin(void *kpage);
void frame_unpin(void *kpage);
void *frame_evict(void);
#endif
