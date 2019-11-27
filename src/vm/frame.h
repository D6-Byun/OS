#ifndef _FRAME_H_
#define _FRAME_H_

#include <list.h>
#include <stdio.h>
#include <stdint.h>
#include <hash.h>
#include "filesys/off_t.h"



struct frame_table
{
	struct hash frame_hash;
};

struct frame_entry {
	uint8_t * upage; //will be linked after the page creation.
	uint8_t * kpage; //key which indicates physical memory address.
	struct hash_elem helem;
};

struct frame_table * frame_init(void);
bool insert_frame_entry(struct frame_entry*);
bool delete_frame_entry(struct frame_entry*);

struct frame_entry * create_f_entry(enum palloc_flags, uint8_t *);
void free_frame_table(void);
void free_frame_entry(struct hash_elem *, void *);

#endif
