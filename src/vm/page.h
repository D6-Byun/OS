#ifndef VM_PAGE_H

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
	void *vaddr;         //virtual address section
	bool writable;
	bool is_loaded;      //flag indicates connection of physical memory
	struct file* file;

	struct list_elem mmap_elem;

	off_t offset;       //file offset
	uint32_t read_bytes;   //size of data
	uint32_t zero_bytes;   //remaining 0 bytes

	uint32_t swap_slot;

	struct hash_elem helem;

};

struct spt * spt_init(void);
bool insert_spt_entry(struct hash*, struct spt_entry*);
bool delete_spt_entry(struct hash*, struct spt_entry*);

struct spt_entry * find_spt_elem(void *);
void spt_destroy(struct hash *);

#endif // !VM_PAGE_H_