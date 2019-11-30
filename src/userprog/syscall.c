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
#include "vm/frame.h"
#include "vm/page.h"
#include "threads/malloc.h"
#include <list.h>


struct file 
	{
		struct inode *inode;        /* File's inode. */
		off_t pos;                  /* Current position. */
    	bool deny_write;            /* Has file_deny_write() been called? */
	};

typedef int pid_t;

typedef int mapid_t;
//#define MAP_FAILED ((mapid_t) -1)

struct spt_entry * is_valid_addr(void *);
void check_valid_buffer(void*, unsigned, bool);
void check_valid_string(void *);
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

mapid_t mmap(int, void *);
void munmap(mapid_t);

struct lock lock_imsi2;
	
void
syscall_init (void) 
{
	lock_init(&lock_imsi2);
  	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

struct spt_entry * is_valid_addr(void *addr) {
	struct spt_entry * search_entry;
	if (addr == NULL || !is_user_vaddr(addr) || (uint32_t)addr < 0x08048000) {
		//printf("addr not in user section\n");
		exit(-1);
	}
	/*
	search_entry = find_spt_entry(addr);
	if (search_entry != NULL)
	{
		return search_entry;
	}
	else
	{
		//printf("entry not found in is_valid_addr\n");
		return NULL;
	}
	*/
}

void check_valid_buffer(void* buffer, unsigned size, bool to_write)
{
	void * temp_buffer = buffer;
	struct spt_entry * temp_entry;
	//int32_t new_size = (int32_t)size;

	//printf("check_valid_Buffer start \n");

	while (temp_buffer < buffer + size)
	{
		//printf("checking %x addr in check_valid_buffer \n",temp_buffer);
		temp_entry = is_valid_addr(temp_buffer);
		/*
		if (temp_entry == NULL)
		{
			//printf("spt_entry doesn't exist in check_Valid_buffer\n");
			exit(-1);
		}
		*/
		/*
		if (!temp_entry->writable)
		{
			//printf("buffer not writable in check_valid_buffer\n");
			exit(-1);
		}
		*/
		//new_size = new_size - PGSIZE;
		temp_buffer = temp_buffer + PGSIZE;
	}
}

void check_valid_string(void *str)
{
	is_valid_addr(str);
}

static void
syscall_handler (struct intr_frame *f) 
{
	//printf("system call!\n");
	//printf("f->esp: %x\n",f->esp);
	//printf("*f->esp: %d\n",*(int*)f->esp);
	//hex_dump((uintptr_t)f->esp,f->esp,24,true);
	is_valid_addr(f->esp);
	switch (*(uint32_t *)f->esp) {
		case SYS_HALT:
			shutdown_power_off();
			break;
		case SYS_EXIT:
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 7);
			//printf("EXIT!\n");
			exit(*(uint32_t *)(f->esp + 4));
			break;
		case SYS_EXEC:
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 7);
			//printf("EXEC!\n");
			f->eax = exec((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_WAIT:
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 7);
			//printf("WAIT!\n");
			f->eax = wait((pid_t)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_CREATE:
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 7);
			is_valid_addr(f->esp + 8);
			is_valid_addr(f->esp + 11);
			//printf("CREATE!\n");
			f->eax = create((const char *)*(uint32_t *)(f->esp + 4),(unsigned)*(uint32_t *)(f->esp + 8));
			break;
		case SYS_REMOVE:
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 7);
			//printf("REMOVE!\n");
			f->eax = remove((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_OPEN:
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 7);
			//printf("OPEN!\n");
			f->eax = open((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_FILESIZE:
			
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 7);
			//printf("FILESIZE!\n");
			f->eax = filesize((int)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_READ:
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 7);
			is_valid_addr(f->esp + 8);
			is_valid_addr(f->esp + 11);
			is_valid_addr(f->esp + 12);
			is_valid_addr(f->esp + 15);
			//printf("READ!\n");
			f->eax = read((int)*(uint32_t*)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*(uint32_t *)(f->esp + 12));
			break;
		case SYS_WRITE:
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 7);
			is_valid_addr(f->esp + 8);
			is_valid_addr(f->esp + 11);
			is_valid_addr(f->esp + 12);
			is_valid_addr(f->esp + 15);
			//printf("WRITE!\n");
			f->eax = write((int)*(uint32_t *)(f->esp + 4),(void *)*(uint32_t *)(f->esp + 8),(uintptr_t)*(uint32_t *)(f->esp + 12));
			break;
		case SYS_SEEK:
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 7);
			is_valid_addr(f->esp + 8);
			is_valid_addr(f->esp + 11);
			//printf("SEEK!\n");
			seek((int)*(uint32_t *)(f->esp + 4),(unsigned)*(uint32_t *)(f->esp + 8));
			break;
		case SYS_TELL:
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 7);
			f->eax = tell((unsigned)*(uint32_t*)(f->esp + 4));
			break;
		case SYS_CLOSE:
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 7);
			//printf("CLOSE!\n");
			close((int)*(uint32_t*)(f->esp + 4));
			break;
		case SYS_MMAP:
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 7);
			is_valid_addr(f->esp + 8);
			is_valid_addr(f->esp + 11);
			f->eax = mmap((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8));

		case SYS_MUNMAP:
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 7);
			munmap((mapid_t)*(uint32_t *)(f->esp + 4));

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
		//printf("exec failed \n");
		exit(-1);
	}
	return process_execute(cmd_line);
}
int wait(pid_t pid) {
	return process_wait(pid);
}
bool create(const char *file, unsigned initial_size) {
	if(file == NULL){
		//printf("full file in syscall create \n");
		exit(-1);
	}
	return filesys_create(file, initial_size);
}
bool remove(const char *file) {
	if(file == NULL){
		//printf("full file in syscall remove \n");
		exit(-1);
	}
	return filesys_remove(file);
}
int open(const char *file) {
	struct file *openfile;
	int retval;
	if(file == NULL){
		//printf("full file in syscall open \n");
		exit(-1);
	}
	is_valid_addr(file);
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
		//printf("file with fd doesn't exist in syscall filesize \n");
		exit(-1);
	}
	//printf("file length : %d\n",file_length(thread_current()->files[fd]));
	return file_length(thread_current()->files[fd]);
}
int read(int fd, void *buffer, unsigned length) {
	int i = 0;
	//check_valid_buffer(buffer, length, true);
	is_valid_addr(buffer);
	lock_acquire(&lock_imsi2);
	if (fd == 0) {
		for (i = 0; i < length; i++) {
			if (((char *)buffer)[i] == '\0') {
				break;	
			}
		}
	}
	else if(fd > 2){
		if (thread_current()->files[fd] == NULL) {
			lock_release(&lock_imsi2);
			//printf("file with fd doesn't exist in syscall read \n");
			exit(-1);
		}
		i = file_read(thread_current()->files[fd], buffer, length);
	}

	//printf("%d\n",i);
	lock_release(&lock_imsi2);
	return i;
}
int write(int fd, const void *buffer, unsigned length) {
	int retval;
	is_valid_addr(buffer);
	lock_acquire(&lock_imsi2);
	if (fd == 1) {
		putbuf(buffer,length);
		//printf("size = %d\n",length);
		retval = length;
	}
	else if(fd > 2){
		if(thread_current()->files[fd] == NULL){
			lock_release(&lock_imsi2);
			//printf("file with fd doesn't exist in syscall write \n");
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
		//printf("file with fd doesn't exist in syscall seek \n");
		exit(-1);
	file_seek(thread_current()->files[fd],position);
}
unsigned tell(int fd) {
	if(thread_current()->files[fd] == NULL)
		//printf("file with fd doesn't exist in syscall tell \n");
		exit(-1);
	return file_tell(thread_current()->files[fd]);
}
void close(int fd) {
	if(thread_current()->files[fd] == NULL)
		//printf("file with fd doesn't exist in syscall close \n");
		exit(-1);
	
	file_close(thread_current()->files[fd]);
	thread_current()->files[fd] = NULL;
}

mapid_t mmap(int fd, void *addr)
{
	struct file* saved_file = thread_current()->files[fd];
	struct file* target_file = file_reopen(saved_file);
	mapid_t mapid;
	int file_size = file_length(target_file);
	int page_count = (file_size / PGSIZE) + ((file_size % PGSIZE) == 0 ? 0 : 1);
	struct mmap_file * mmap_file1;
	int8_t * upage = (int8_t *) addr;
	bool writable = true;
	struct file* file = target_file;
	off_t ofs = 0;
	uint32_t read_byte = file_size;
	//uint32_t zero_byte = ;
	struct spt_entry* temp_entry;
	struct list_elem* e;

	if (saved_file == NULL)
	{
		//printf("file with fd doesn't exist in mmap\n");
		exit(-1);
	}
	if (list_empty(&thread_current()->mmap_list))
	{
		//printf("list is empty\n");
	}

	is_valid_addr(addr);
	mapid = thread_current()->mmap_index;
	thread_current()->mmap_index++;
	mmap_file1 = (struct mmap_file *)malloc(sizeof(struct mmap_file));
	mmap_file1->file = target_file;
	mmap_file1->mapid = mapid;
	list_init(&mmap_file1->spt_entry_list);


	//printf("list init ended in mmap\n");
	//printf("upage : %x\n", addr);
	//printf("file_size : %d\n", read_byte);
	//printf("mapid : %d\n", thread_current()->mmap_index);
	//printf("now go to while loop\n");


	while (file_size>ofs)
	{
		//printf("upage : %x\n", upage);
		//printf("file_size : %d\n", read_byte);
		size_t page_read_bytes = read_byte < PGSIZE ? read_byte : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;
		//printf("page_read_bytes : %d\n", page_read_bytes);
		//printf("page_zero_bytes : %d\n", page_zero_bytes);
		temp_entry = create_s_entry(upage, NULL, writable, file, ofs, page_read_bytes, page_zero_bytes);
		if (temp_entry == NULL)
		{
			//printf("spt_entry create fail in load_segment\n");
			exit(-1);
		}

		//printf("spt_entry created in mmap\n");
		//printf("spt_entry page_read_bytes : %d\n", temp_entry->read_bytes);

		if (!insert_spt_entry(&thread_current()->spt->hash_brown, temp_entry))
		{
			//printf("spt insert fail in load_segment\n");
			exit(-1);
		}
		//printf("spt_entry inserted in table in mmap\n");
		list_push_back(&mmap_file1->spt_entry_list, &temp_entry->mmap_elem);
		//printf("stp_entry inserted in mmap_list in mmap\n");
		upage = upage + PGSIZE;
		ofs += page_read_bytes;
		read_byte -= page_read_bytes;
	}
	list_push_back(&thread_current()->mmap_list, &mmap_file1->elem);
	//printf("mmap ended\n");
	
	
	for (e = list_begin(&thread_current()->mmap_list); e != list_end(&thread_current()->mmap_list); e = list_next(e))
	{
		//printf("for start \n");
		//printf("e : %x\n", e);
		
		struct mmap_file * temp_mmap = list_entry(e, struct mmap_file, elem);
		
		if (temp_mmap == NULL)
		{
			//printf("mmap_file is null\n");
		}
		
		//printf("mapid == %d\n",(temp_mmap->mapid));
		
	}
	
	return mapid;

}

void munmap(mapid_t mapid)
{
	struct mmap_file * target_mmap = NULL;
	struct list_elem *e;
	//printf("munmap start\n");
	if (!list_empty(&thread_current()->mmap_list))
	{
		for (e = list_begin(&thread_current()->mmap_list); e != list_end(&thread_current()->mmap_list); e = list_next(e))
		{
			struct mmap_file * temp_mmap = list_entry(e, struct mmap_file, elem);
			//printf("mapid : %d\n", temp_mmap->mapid);
			//printf("input mapid : %d\n", mapid);
			if (temp_mmap->mapid == mapid)
			{
				target_mmap = temp_mmap;
				//printf("1!\n");
			}
		}
		if (target_mmap == NULL)
		{
			//printf("target_mmap is null in munmap\n");
			exit(-1);
		}
		free_mmap(target_mmap);
	}
	else
	{
		//printf("mmap_list is empty in munmap\n");
		exit(-1);
	}
	//printf("munmap finish\n");
}

/* delete spt_entry in spt_entry_list, in hash_brown, delete mmap_file in mmap_list, and file_close, and free mmap_file. */
void free_mmap(struct mmap_file * mmap_file)
{
	struct list_elem *e;
	//printf("start free_map\n");
	for (e = list_begin(&mmap_file->spt_entry_list); e != list_end(&mmap_file->spt_entry_list); e = list_next(e))
	{
		//printf("for loop start\n");
		struct spt_entry *temp_entry = list_entry(e, struct spt_entry, mmap_elem);
		if (temp_entry == NULL)
		{
			//printf("it is null\n");
		}
		list_remove(e);
		/*
		if (temp_entry->is_loaded && temp_entry->dirty)
		{
			file_write_at(temp_entry->file, mmap_file->file, temp_entry->read_bytes, temp_entry->offset);
		}
		*/
		//printf("removed from list\n");
		delete_spt_entry(&thread_current()->spt->hash_brown, temp_entry);
	}
	//printf("for loop end\n");
	list_remove(&mmap_file->elem);
	//printf("mmap_file deleted in mmap_list\n");
	file_close(mmap_file->file);
	//printf("file close\n");
	free(mmap_file);
	//printf("free mmap_file\n");
}
