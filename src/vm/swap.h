#ifndef SWAP_H
#define SWAP_H

#include "devices/block.h"
#include "threads/synch.h"
#include <bitmap.h>
//#include "lib/kernel/bitmap.h"
#include "threads/vaddr.h"


#define SWAP_FREE 0
#define SWAP_USE 1

#define SEC_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

void swap_init(void);
void swap_in(size_t used_index, void *frame);
size_t swap_out(void *frame);

#endif
