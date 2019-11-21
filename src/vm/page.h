#include "filesys/off_t.h"
#include <stdio.h>
#include <stdint.h>
#include <hash.h>
#include "threads/palloc.h"
#include "threads/malloc.h"

#ifndef _PAGE_H_
#define _PAGE_H_

#include "vm/frame.h"

#define VM_BIN 0
#define VM_FILE 1
#define VM_ANON 2


struct mmap_file {
	int mapid;
	struct file *file;
	struct list_elem elem;
	struct list spte_list;
};


struct sup_page_table {

	struct hash hash_brown;
};

struct sup_page_entry{

	struct hash_elem helem; //virtual page addr

	struct file *file; //file
	off_t file_ofs; //offset
	uint8_t *upage; //user page address
	uint8_t *kpage; //kernel page address
	uint8_t type;
	uint32_t read_bytes, zero_bytes; //read, zero bytes, PGsize - read = zero
	bool writable; //True: can write, False: can't write
	bool dirty; //True: fixed, False: Original

	struct list_elem mmap_elem;

	
};

struct sup_page_table *spt_create(void);
void spt_destroy(struct sup_page_table *spt);
struct sup_page_entry *sup_lookup_page(struct sup_page_table *spt, void *page);
void sup_set_dirty(struct sup_page_table *spt, void *page, bool dirty);
bool sup_get_dirty(struct sup_page_table *spt, void *page);
bool sup_insert(struct sup_page_table *spt, struct sup_page_entry *spte);
bool load_file(void *kaddr, struct sup_page_entry *spte);
bool add_entry(struct sup_page_table * spt, struct file *file, off_t ofs, void *upage, void *kpage, uint32_t read_bytes, uint32_t zero_bytes, bool writable);




#endif
