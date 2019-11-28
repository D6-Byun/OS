#ifndef FRAME_H
#define FRAME_H

#include <hash.h>
#include "threads/synch.h"
#include "threads/palloc.h"


void frame_init(void);
void *frame_alloc(enum palloc_flags flags, void *upage);

void frame_free(void *kpage);

void frame_pin(void *kpage);
void frame_unpin(void *kpage);

#endif
