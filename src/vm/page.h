#ifndef PAGE_H
#define PAGE_H

#include <hash.h>

struct sup_page_table{
	struct hash hash_brown;
};

struct sup_page_entry{
	void *upage;
	struct hash_elem helem;

};


struct sup_page_table *sup_create(void);
void sup_destroy(struct sup_page_table *);

#endif
