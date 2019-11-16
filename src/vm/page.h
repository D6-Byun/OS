
#include <stdio.h>
#include <stdint.h>
#include <hash.h>
#include "filesys/off_t.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include <string.h>


struct sup_page_table {

	struct hash hash_brown;
};

struct sup_page_entry{

	struct hash_elem helem; //virtual page addr

	struct file *file; //file
	off_t file_ofs; //offset
	uint8_t *upage; //user page address
	uint8_t *kpage; //kernel page address

	uint32_t read_bytes, zero_bytes; //read, zero bytes, PGsize - read = zero
	bool writable; //True: can write, False: can't write
	bool dirty; //True: fixed, False: Original
	
};

struct sup_page_table *spt_create(void);
void spt_destroy(struct sup_page_table *spt);
struct sup_page_entry *sup_lookup_page(struct sup_page_table *spt, void *page);
void sup_set_dirty(struct sup_page_table *spt, void *page, bool dirty);
bool sup_get_dirty(struct sup_page_table *spt, void *page);
bool sup_insert(struct sup_page_table *spt, struct sup_page_entry *spte);
bool load_file(void *kaddr, struct sup_page_entry *spte);
