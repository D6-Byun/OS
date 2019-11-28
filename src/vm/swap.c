#include "vm/swap.h"

struct lock swap_lock;

struct block *swap_block;

struct bitmap *swap_bm;

void swap_init(void){
	lock_init(&swap_lock);
	swap_block = block_get_role(BLOCK_SWAP);
	if(swap_block == NULL){
		PANIC("NO SUCH BLOCK DEVICE");
	}
	swap_bm = bitmap_create(block_size(swap_block)/SEC_PER_PAGE);	
	if(swap_bm == NULL){
		PANIC("bitmap: INITIALIZE FAILED");
	}
	bitmap_set_all(swap_bm, SWAP_FREE);
}
/*swap disk -> physical memory*/
void swap_in(size_t used_index, void *addr){
	lock_acquire(&swap_lock);
	if(bitmap_test(swap_bm,used_index) == SWAP_FREE){
		lock_release(&swap_lock);
		return;
	}
	bitmap_reset(swap_bm,used_index);
	lock_release(&swap_lock);
	for(int i = 0; i < SEC_PER_PAGE; i++){
		block_read(swap_block,used_index * SEC_PER_PAGE + i,(uint8_t *)addr + i * BLOCK_SECTOR_SIZE);
	}
}
/*frame -> swap disk*/
size_t swap_out(void *addr){
	lock_acquire(&swap_lock);
	/*FIRST FIT*/
	size_t free_idx = bitmap_scan_and_flip(swap_bm,0,1,SWAP_FREE);
	if(free_idx == BITMAP_ERROR){
		PANIC("swap_out: bitmap scan error\n");
	}
	for(size_t i = 0; i < SEC_PER_PAGE; i++){
		block_write(swap_block, free_idx * SEC_PER_PAGE + i, (uint8_t *)addr + i * BLOCK_SECTOR_SIZE);
	}
	lock_release(&swap_lock);
	return free_idx;

}
