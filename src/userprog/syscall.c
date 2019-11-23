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
int write(int fd, const void *, unsigned length);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

struct lock file_lock;
	
void
syscall_init (void) 
{
	lock_init(&file_lock);
  	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

struct sup_page_entry* is_valid_addr(void *addr) {
	if (addr == NULL || !is_user_vaddr(addr)||(uint32_t)addr < 0x08048000){
		exit(-10);
	}
	struct sup_page_entry* entry = sup_lookup_page(thread_current()->spt, addr);
	return entry;
}
/*check is buffer is valid for syscall READ*/
void check_valid_buffer(void *buffer, unsigned size, void *esp, bool write) {
	for (int i = 0; i < size; i++) {
		struct sup_page_entry* entry = is_valid_addr(buffer + i);
		if (entry == NULL && write){
			if(!entry->writable) {
			exit(-11);
			}
		}
	}
}
void check_valid_string(const void *str, void *esp) {
	struct sup_page_entry *entry = is_valid_addr(str);
	while (*(char *)str != 0) {
		str = (char *)str + 1;
		if(is_valid_addr(str)){
			exit(-12);
		}
	}
}

static void
syscall_handler (struct intr_frame *f) 
{
	//printf("system call!\n");
	//printf("f->esp: %x\n",f->esp);
	//printf("*f->esp: %d\n",*(int*)f->esp);
	//hex_dump((uintptr_t)f->esp,f->esp,24,true);
	is_valid_addr(f->esp);
	thread_current()->cur_esp = f->esp;
	switch (*(uint32_t *)f->esp) {
		case SYS_HALT:
			shutdown_power_off();
			break;
		case SYS_EXIT:
			is_valid_addr(f->esp + 4);
			//printf("EXIT!\n");
			exit(*(uint32_t *)(f->esp + 4));
			break;
		case SYS_EXEC:
			is_valid_addr(f->esp + 4);
			check_valid_string((const void *)*(uint32_t *)(f->esp + 4),f->esp);
			f->eax = exec((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_WAIT:
			is_valid_addr(f->esp + 4);
			f->eax = wait((pid_t)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_CREATE:
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 8);
			check_valid_string((const void *)*(uint32_t *)(f->esp + 4), f->esp);
			f->eax = create((const char *)*(uint32_t *)(f->esp + 4),(unsigned)*(uint32_t *)(f->esp + 8));
			break;
		case SYS_REMOVE:
			is_valid_addr(f->esp + 4);
			f->eax = remove((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_OPEN:
			is_valid_addr(f->esp + 4);
			check_valid_string((const void *)*(uint32_t *)(f->esp + 4), f->esp);
			f->eax = open((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_FILESIZE:
			is_valid_addr(f->esp + 4);
			f->eax = filesize((int)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_READ:
			is_valid_addr(f->esp + 4);
			check_valid_buffer((void *)*(uint32_t *)f->esp + 8,(unsigned)*(uint32_t *)f->esp + 12,f->esp,true);
			f->eax = read((int)*(uint32_t*)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*(uint32_t *)(f->esp + 12));
			break;
		case SYS_WRITE:
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 8);
			is_valid_addr(f->esp + 12);
			check_valid_buffer((void *)*(uint32_t *)f->esp + 8, (unsigned)*(uint32_t *)f->esp + 12, f->esp, false);
			f->eax = write((int)*(uint32_t *)(f->esp + 4),(void *)*(uint32_t *)(f->esp + 8),(uintptr_t)*(uint32_t *)(f->esp + 12));
			break;
		case SYS_SEEK:
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 8);
			seek((int)*(uint32_t *)(f->esp + 4),(unsigned)*(uint32_t *)(f->esp + 8));
			break;
		case SYS_TELL:
			is_valid_addr(f->esp + 4);
			f->eax = tell((unsigned)*(uint32_t*)(f->esp + 4));
			break;
		case SYS_CLOSE:
			is_valid_addr(f->esp + 4);
			close((int)*(uint32_t*)(f->esp + 4));
			break;
		case SYS_MMAP:
			{
				is_valid_addr(f->esp + 4);
				is_valid_addr(f->esp + 8);
				f->eax = mmap((int)*(uint32_t *)f->esp + 4,(void *)*(uint32_t *)f->esp + 8);
				break;
			}
		/*case SYS_MUNMAP:
			{
				is_valid_addr(f->esp + 4);
				munmap((mapid_t)*(uint32_t *) f->esp + 4);
				break;
			}*/
		default:
			printf("Not implemented system call: %d\n", *(uint32_t *)f->esp);
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
		exit(-13);
	}
	return process_execute(cmd_line);
}
int wait(pid_t pid) {
	return process_wait(pid);
}
bool create(const char *file, unsigned initial_size) {
	if(file == NULL){
		exit(-14);
	}
	return filesys_create(file, initial_size);
}
bool remove(const char *file) {
	if(file == NULL){
		exit(-15);
	}
	return filesys_remove(file);
}
int open(const char *file) {
	struct file *openfile;
	int retval;
	if(file == NULL){
		exit(-16);
	}
	is_valid_addr(file);
	lock_acquire(&file_lock);
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
	lock_release(&file_lock);
	return retval;
}
int filesize(int fd) {
	//printf("filesize start\n");
	if(thread_current()->files[fd] == NULL){
		exit(-17);
	}
	//printf("file length : %d\n",file_length(thread_current()->files[fd]));
	return file_length(thread_current()->files[fd]);
}
int read(int fd, void *buffer, unsigned length) {
	int i = 0;
	is_valid_addr(buffer);
	lock_acquire(&file_lock);
	if (fd == 0) {
		for (i = 0; i < length; i++) {
			if (((char *)buffer)[i] == '\0') {
				break;		
			}
		}
	}
	else if(fd > 2){
		if (thread_current()->files[fd] == NULL) {
			lock_release(&file_lock);
			exit(-18);
		}
		i = file_read(thread_current()->files[fd], buffer, length);
	}

	//printf("%d\n",i);
	lock_release(&file_lock);
	return i;
}
int write(int fd, const void *buffer, unsigned length) {
	int retval;
	is_valid_addr(buffer);
	lock_acquire(&file_lock);
	if (fd == 1) {
		putbuf(buffer,length);
		//printf("size = %d\n",length);
		retval = length;
	}
	else if(fd > 2){
		if(thread_current()->files[fd] == NULL){
			lock_release(&file_lock);
			exit(-19);
		}
		if(thread_current()->files[fd]->deny_write){
			file_deny_write(thread_current()->files[fd]);
		}
		//printf("write bytes: %d\n",file_write(thread_current()->files[fd],buffer,length));
		retval = file_write(thread_current()->files[fd], buffer, length);
	}else{
		retval = -1;
	}
	lock_release(&file_lock);
	return retval;	
}
void seek(int fd, unsigned position) {
	if(thread_current()->files[fd] == NULL)
		exit(-110);
	file_seek(thread_current()->files[fd],position);
}
unsigned tell(int fd) {
	if(thread_current()->files[fd] == NULL)
		exit(-111);
	return file_tell(thread_current()->files[fd]);
}
void close(int fd) {
	if(thread_current()->files[fd] == NULL)
		exit(-112);
	
	file_close(thread_current()->files[fd]);
	thread_current()->files[fd] = NULL;
}

mapid_t mmap(int fd, void * addr) {
	struct mmap_file *mfile;
	int mapid;
	struct thread *cur = thread_current();
	if(addr == NULL || fd < 2){
		return -1;
	}
	struct file *memfiles = thread_current()->files[fd];
	if(memfiles == NULL){
		return -1;
	}
	file_reopen(memfiles);
	/*mapid allocation*/
	if(!list_empty(&cur->mmap_list)){
		mapid = list_entry(list_back(&cur->mmap_list), struct mmap_file, elem)->mapid + 1;
	}else{
		mapid = 1;
	}
	/*mmap_file construct*/
	mfile = (struct mmap_file *)malloc(sizeof(struct mmap_file));
	mfile->mapid = mapid;
	mfile->file = memfiles;
	list_push_back(&cur->mmap_list, &mfile->elem);
	/*sup page table entry construct*/
	for(int ofs = 0; ofs < file_length(memfiles); ofs+= PGSIZE){
		void *upage = addr + ofs;
		uint32_t read_bytes = (ofs + PGSIZE < file_length(memfiles)? PGSIZE: file_length(memfiles) - ofs);
		uint32_t zero_bytes = PGSIZE - read_bytes;
		add_entry(cur->spt, memfiles,ofs,upage,NULL,read_bytes,zero_bytes,true);
	}	
	return mapid;
}/*
void munmap(int mapping) {
	while(thread_current()->mmap)


}*/
