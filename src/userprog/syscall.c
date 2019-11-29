#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
//#include "lib/user/syscall.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "filesys/off_t.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "vm/frame.h"
struct file 
	{
		struct inode *inode;        /* File's inode. */
		off_t pos;                  /* Current position. */
    	bool deny_write;            /* Has file_deny_write() been called? */
	};

typedef int pid_t;

static void syscall_handler (struct intr_frame *);
void halt(void) NO_RETURN;
void exit(int status) NO_RETURN;
pid_t exec(const char *cmd_line);
int wait(pid_t);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned length);
int write(int fd, const void *buffer, unsigned length);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

struct lock lock_imsi2;
	
void
syscall_init (void) 
{
	lock_init(&lock_imsi2);
  	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void is_valid_addr(void *addr,void *esp) {
	if (addr == NULL || !is_user_vaddr(addr)||(uint32_t)addr < 0x08048000
			||!is_user_vaddr(addr + 3)){
		exit(-1);
	}
	bool isload = false;
	struct sup_page_entry *spte = spt_lookup(thread_current()->spt,addr);
	//printf("is_valid_addr: addr %x, esp %x\n",addr, esp);
	if(spte != NULL){
		//printf("is_valid_addr: cannot found spte.\n");
		spt_load_page(thread_current()->spt,spte);
		isload = spte->is_loaded;
	}else if(addr >= esp - 32){
		isload = grow_stack(addr);
	}
	if(!isload){
		exit(-1);
	}
}

void check_valid_buffer(void *buffer, unsigned size, void *esp){
	char *char_buffer = (char *)buffer;
	for(unsigned i = 0; i < size; i++){
		is_valid_addr(char_buffer + i, esp);
	}
}
void check_valid_string(const void *str, void *esp){
	is_valid_addr(str,esp);
	while(*(char *)str != 0){
		str = (char *)str + 1;
		is_valid_addr(str, esp);
	}
}

static void
syscall_handler (struct intr_frame *f) 
{
	//printf("system call!\n");
	//printf("f->esp: %x\n",f->esp);
	//printf("*f->esp: %d\n",*(int*)f->esp);
	//hex_dump((uintptr_t)f->esp,f->esp,24,true);
	struct thread *cur = thread_current();
	cur->cur_esp = f->esp;
	is_valid_addr(f->esp, f->esp);
	switch (*(uint32_t *)f->esp) {
		case SYS_HALT:
			shutdown_power_off();
			break;
		case SYS_EXIT:
			is_valid_addr(f->esp + 4, f->esp);
			//printf("EXIT!\n");
			exit(*(uint32_t *)(f->esp + 4));
			break;
		case SYS_EXEC:
			is_valid_addr(f->esp + 4, f->esp);
			check_valid_string((const void*)*(uint32_t *)(f->esp + 4), f->esp);
			f->eax = exec((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_WAIT:
			is_valid_addr(f->esp + 4, f->esp);
			f->eax = wait((pid_t)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_CREATE:
			is_valid_addr(f->esp + 4, f->esp);
			is_valid_addr(f->esp + 8, f->esp);
			check_valid_string((const void *)*(uint32_t *)(f->esp + 4), f->esp);
			f->eax = create((const char *)*(uint32_t *)(f->esp + 4),(unsigned)*(uint32_t *)(f->esp + 8));
			break;
		case SYS_REMOVE:
			is_valid_addr(f->esp + 4, f->esp);
			f->eax = remove((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_OPEN:
			is_valid_addr(f->esp + 4, f->esp);
			check_valid_string((const void *)*(uint32_t *)(f->esp +4),f->esp);
			f->eax = open((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_FILESIZE:
			is_valid_addr(f->esp + 4, f->esp);
			f->eax = filesize((int)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_READ:
			is_valid_addr(f->esp + 4, f->esp);
			is_valid_addr(f->esp + 8, f->esp);
			is_valid_addr(f->esp + 12, f->esp);
			check_valid_buffer((void *)*(uint32_t *)(f->esp + 8),(unsigned)*(uint32_t *)(f->esp + 12), f->esp);
			f->eax = read((int)*(uint32_t*)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*(uint32_t *)(f->esp + 12));
			break;
		case SYS_WRITE:
			is_valid_addr(f->esp + 4, f->esp);
			is_valid_addr(f->esp + 8, f->esp);
			is_valid_addr(f->esp + 12, f->esp);
			check_valid_buffer((void *)*(uint32_t *)(f->esp + 8),(unsigned)*(uint32_t *)(f->esp +12),f->esp);
			f->eax = write((int)*(uint32_t *)(f->esp + 4),(void *)*(uint32_t *)(f->esp + 8),(uintptr_t)*(uint32_t *)(f->esp + 12));
			break;
		case SYS_SEEK:
			is_valid_addr(f->esp + 4, f->esp);
			is_valid_addr(f->esp + 8, f->esp);
			seek((int)*(uint32_t *)(f->esp + 4),(unsigned)*(uint32_t *)(f->esp + 8));
			break;
		case SYS_TELL:
			is_valid_addr(f->esp + 4, f->esp);
			f->eax = tell((unsigned)*(uint32_t*)(f->esp + 4));
			break;
		case SYS_CLOSE:
			is_valid_addr(f->esp + 4, f->esp);
			close((int)*(uint32_t*)(f->esp + 4));
			break;
		case SYS_MMAP:
			is_valid_addr(f->esp + 4, f->esp);
			is_valid_addr(f->esp + 8, f->esp);
			f->eax = mmap((int)*(uint32_t *)(f->esp + 4),(void *)*(uint32_t *)(f->esp + 8));
			break;
		case SYS_MUNMAP:
			is_valid_addr(f->esp + 4, f->esp);
			munmap((int)*(uint32_t *)(f->esp + 4));
			break;
	}
}
int mmap(int fd, void *addr){
	uint32_t page_read_bytes;
	uint32_t page_zero_bytes;
	struct thread *cur = thread_current();
	if(addr == NULL|| !is_user_vaddr(addr) ||pg_ofs(addr) != 0){
		return -1;
	}
	struct file *ofile = cur->files[fd];
	if(ofile == NULL){
		return -1;
	}
	struct file *file = file_reopen(ofile);
	if(file == NULL || file_length(ofile) == 0){
		return -1;	
	}
	thread_current()->mapid++;
	off_t ofs = 0;
	uint32_t read_bytes = file_length(file);
	while(read_bytes > 0){
		page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		page_zero_bytes = PGSIZE - page_read_bytes;
		if(!spt_add_mmap(&cur->spt,file,ofs,addr,page_read_bytes,page_zero_bytes)){
			munmap(cur->mapid);
			return -1;
		}
		read_bytes -= page_read_bytes;
		ofs += page_read_bytes;
		addr += PGSIZE;
	}
	return cur->mapid;
}

void munmap(int mapping){
	struct thread *cur = thread_current();
	struct list_elem *next, *elem = list_begin(&cur->mmap_list);

	while(elem != list_end(&cur->mmap_list)){
		next = list_next(elem);
		struct mmap_file *mfile = list_entry(elem,struct mmap_file, melem);
		if(mfile->mapid == mapping ||mapping == CLOSE_ALL){
			if(mfile->spte->is_loaded){
				if(pagedir_is_dirty(cur->pagedir,mfile->spte->upage)){
					file_write_at(mfile->spte->file, mfile->spte->upage, mfile->spte->read_bytes, mfile->spte->ofs);
				}
				frame_free(pagedir_get_page(cur->pagedir, mfile->spte->upage));
				pagedir_clear_page(cur->pagedir, mfile->spte->upage);
			}
			hash_delete(&cur->spt->hash_brown,&mfile->spte->helem);
			list_remove(&mfile->melem);
			free(mfile->spte);
			free(mfile);	
		}

		elem = next;
	}	

}

/*void halt() {
	shutdown_power_off();
}*/
void exit(int status) {
	printf("%s: exit(%d)\n",thread_name(),status);
	thread_current()->exit = status;
	for(int i = 3; i < 128; i++){
		if(thread_current()->files[i] != NULL){
			close(i);
		}
	}
	thread_exit();
}
pid_t exec(const char *cmd_line) {
	//hex_dump((uintptr_t)cmd_line,cmd_line,64,true);
	if(cmd_line == NULL){
		exit(-1);
	}
	return process_execute(cmd_line);
}
int wait(pid_t pid) {
	return process_wait(pid);
}
bool create(const char *file, unsigned initial_size) {
	if(file == NULL){
		exit(-1);
	}
	return filesys_create(file, initial_size);
}
bool remove(const char *file) {
	if(file == NULL){
		exit(-1);
	}
	lock_acquire(&lock_imsi2);
	bool success = filesys_remove(file);
	lock_release(&lock_imsi2);
	return success;
}
int open(const char *file) {
	struct file *openfile;
	int retval;
	if(file == NULL){
		exit(-1);
	}
	//is_valid_addr(file);
	lock_acquire(&lock_imsi2);
	openfile = filesys_open(file);
	if(openfile == NULL){
		retval = -1;
	}else{
	/*0 = STDIN, 1 = STDOUT, 2 = STDERR */
		for (int i = 3; i < 128; i++) {
			if (thread_current()->files[i] == NULL) {
				if(strcmp(thread_current()->name,file) == 0){
					file_deny_write(openfile);	
				}
				thread_current()->files[i] = openfile;
				retval = i;
				break;
			}
		}
	}
	//printf("-1\n");
	lock_release(&lock_imsi2);
	return retval;
}
int filesize(int fd) {
	//printf("filesize start\n");
	if(thread_current()->files[fd] == NULL){
		exit(-1);
	}
	//printf("file length : %d\n",file_length(thread_current()->files[fd]));
	return file_length(thread_current()->files[fd]);
}
int read(int fd, void *buffer, unsigned length) {
	int i = 0;
	//is_valid_addr(buffer);
	lock_acquire(&lock_imsi2);
	if (fd == 0) {
		uint8_t *input_buffer = (uint8_t *) buffer;
		for (i = 0; i < length; i++) {
			input_buffer[i] = input_getc();		
		}
		lock_release(&lock_imsi2);
		return length;
	}
	else if(fd > 2 && fd < 128){
		if (thread_current()->files[fd] == NULL) {
			lock_release(&lock_imsi2);
			exit(-1);
		}
		i = file_read(thread_current()->files[fd], buffer, length);
	}else{
		/*invalid fd*/
		lock_release(&lock_imsi2);
		return -1;
	}

	//printf("%d\n",i);
	lock_release(&lock_imsi2);
	return i;
}
int write(int fd, const void *buffer, unsigned length) {
	int retval;
	//is_valid_addr(buffer);
	lock_acquire(&lock_imsi2);
	if (fd == 1) {
		putbuf(buffer,length);
		//printf("size = %d\n",length);
		retval = length;
	}
	else if(fd > 2 && fd < 128){
		if(thread_current()->files[fd] == NULL){
			lock_release(&lock_imsi2);
			exit(-1);
		}
		if(thread_current()->files[fd]->deny_write){
			file_deny_write(thread_current()->files[fd]);
		}
		//printf("write bytes: %d\n",file_write(thread_current()->files[fd],buffer,length));
		retval = file_write(thread_current()->files[fd], buffer, length);
	}else{
		retval = -1;
	}
	lock_release(&lock_imsi2);
	return retval;	
}
void seek(int fd, unsigned position) {
	if(thread_current()->files[fd] == NULL)
		exit(-1);
	file_seek(thread_current()->files[fd],position);
}
unsigned tell(int fd) {
	if(thread_current()->files[fd] == NULL)
		exit(-1);
	return file_tell(thread_current()->files[fd]);
}
void close(int fd) {
	if(fd < 0 || fd > 127){
		exit(-1);
	}
	if(thread_current()->files[fd] == NULL)
		exit(-1);
	
	file_close(thread_current()->files[fd]);
	thread_current()->files[fd] = NULL;
}

