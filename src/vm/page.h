#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "vm/frame.h"
#include "filesys/off_t.h"
enum status{
	MMAP,
	SWAP, //is swapped
	VMFILE //is file
};

struct sup_page_table{
	struct hash hash_brown;
};

struct sup_page_entry{
	void *upage;

	struct file *file;
	off_t ofs;
	uint32_t read_bytes, zero_bytes;
	bool writable;
	
	bool is_loaded;
	struct hash_elem helem;
	int swap_index;
	enum status status;
};

struct sup_page_table *spt_create(void);
void spt_destroy(struct sup_page_table *spt);
struct sup_page_entry *spt_lookup(struct sup_page_table *spt, void *upage);
bool spt_load_file(struct sup_page_entry *spte);
//bool spt_load_mmap(struct sup_page_entry *spte);
bool spt_load_swap(struct sup_page_entry *spte);
bool spt_load_page(struct sup_page_table *spt, void *upage);
bool spt_add_entry(struct sup_page_table *spt, struct file *file, off_t ofs, void *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable);
bool spt_add_mmap(struct sup_page_table *spt, struct file *file, off_t ofs, void *upage, uint32_t read_bytes, uint32_t zero_bytes);
bool spt_try_add_mmap(struct sup_page_entry *spte);



#endif
