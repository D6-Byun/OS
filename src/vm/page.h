#include <list.h>
#include <stdint.h>

struct spt_entry {
	void *vaddr;         //virtual address section
	bool writable;
	bool is_loaded;      //flag indicates connection of physical memory
	struct file* file;

	struct list_elem mmap_elem;

	size_t offset;       //file offset
	size_t read_bytes;   //size of data
	size_t zero_bytes;   //remaining 0 bytes

	size_t swap_slot;
	
	struct hash_elem elem;

};