#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <list.h>
#include <stdio.h>
#include <stdint.h>
#include <hash.h>
#include "filesys/off_t.h"

struct spt
{
	struct hash hash_brown;
};

struct spt_entry {
	uint8_t * upage;         //virtual address section
	uint8_t * kpage;     //kernel page
	bool writable;
	bool is_loaded;      //flag indicates connection of physical memory
	struct file* file;

	bool dirty;
	bool accessd;

	off_t offset;       //file offset
	uint32_t read_bytes;   //size of data
	uint32_t zero_bytes;   //remaining 0 bytes

	struct hash_elem helem;

	//struct list_elem mmap_elem;
	//uint32_t swap_slot;


};

struct spt * spt_init(void);
bool insert_spt_entry(struct hash*, struct spt_entry*);
bool delete_spt_entry(struct hash*, struct spt_entry*);

struct spt_entry * find_spt_entry(void *);
void spt_destroy(struct hash *);

struct spt_entry * create_s_entry(uint8_t *, uint8_t *, bool, struct file *, off_t, uint32_t, uint32_t);

#endif // !VM_PAGE_H_