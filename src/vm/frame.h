#ifndef VM_FRAME_H

#include <list.h>
#include <stdio.h>
#include <stdint.h>
#include <hash.h>
#include "filesys/off_t.h"

struct frame_table
{
	struct hash fried_hash;
};

struct frame_entry {

	uint8_t * upage;
	uint8_t * kpage;
	struct hash_elem helem;
};

struct frame_table * frame_init(void)

#endif