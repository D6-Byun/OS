#ifndef PAGE_H
#define PAGE_H

#include "filesys/file.h"
#include <hash.h>
#include "filesys/off_t.h"

enum status {
	FRAME,
	SWAP,
	ZERO
};

struct sup_page_tabe {
	struct hash hash_brown;
};

struct sup_page_entry {
	void *upage; //virtual page addr
	void *kpage; //NULL of frame pointer

	enum status type;
	struct hash_elem helem;

	bool dirty, writable;

	struct file *file;
	off_t file_ofs;
	uint32_t read_bytes, zero_bytes;
};

struct sup_page_table *spt_create(void);
void spt_destroy(struct sup_page_table *spt);
struct sup_page_entry *sup_lookup_page(struct sup_page_table *spt, void *page);
bool add_entry(struct sup_page_table *spt, struct file *file, off_t ofs, void *upage, void *kpage, 
	uint32_t read_bytes, uint32_t zero_bytes, bool writable, enum status type);
bool add_install(struct sup_page_table *spt, void *upage, void *kpage, bool writable);
bool spt_load_page(struct sup_page_table *spt, uint32_t *pagedir, void *upage);

#endif