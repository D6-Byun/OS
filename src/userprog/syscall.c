#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "lib/user/syscall.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/vaddr.h"

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

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void is_valid_addr(void *addr) {
	if (!is_user_vaddr(addr)) {
		exit(-1);
	}
}


static void
syscall_handler (struct intr_frame *f) 
{
	//printf("system call!\n");
	//printf("f->esp: %x\n",f->esp);
	//printf("*f->esp: %d\n",*(int*)f->esp);
	//hex_dump((uintptr_t)f->esp,f->esp,100,true);
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
			f->eax = exec((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_WAIT:
			is_valid_addr(f->esp + 4);
			f->eax = wait((pid_t)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_CREATE:
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 8);
			f->eax = create((const char *)*(uint32_t *)(f->esp + 4),(unsigned)*(uint32_t *)(f->esp + 8));
			break;
		case SYS_REMOVE:
			is_valid_addr(f->esp + 4);
			f->eax = remove((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_OPEN:
			is_valid_addr(f->esp + 4);
			f->eax = open((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_FILESIZE:
			is_valid_addr(f->esp + 4);
			f->eax = ((int)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_READ:
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 8);
			is_valid_addr(f->esp + 12);
			f->eax = read((int)*(uint32_t*)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*(uint32_t *)(f->esp + 12));
			break;
		case SYS_WRITE:
			is_valid_addr(f->esp + 4);
			is_valid_addr(f->esp + 8);
			is_valid_addr(f->esp + 12);
			f->eax = write((int)*(uint32_t *)(f->esp + 4),*(uint32_t *)(f->esp + 8),(uintptr_t)*(uint32_t *)(f->esp + 12));
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
	}
	
	//printf ("system call!\n");
	//thread_exit ();
}

/*void halt() {
	shutdown_power_off();
}*/
void exit(int status) {
	printf("%s: exit(%d)\n",thread_name(),status);
	thread_exit();
}
pid_t exec(const char *cmd_line) {
	return process_execute(cmd_line);
}
int wait(pid_t pid) {
	return process_wait(pid);
}
bool create(const char *file, unsigned initial_size) {
	filesys_create(file, initial_size);
}
bool remove(const char *file) {
	filesys_remove(file);
}
int open(const char *file) {
	/*0 = STDIN, 1 = STDOUT, 2 = STDERR */
	for (int i = 3; i < 128; i++) {
		if (thread_current()->files[i] == NULL) {
			thread_current()->files[i] = filesys_open(file);
			return i;
		}
	}
	return -1;
}
int filesize(int fd) {
	file_length(thread_current()->files[fd]);
}
int read(int fd, void *buffer, unsigned length) {
	if (fd == 0) {
		for (int i = 0; i < length; i++) {
			if (((char *)buffer)[i] == '\0') {
				return i;		
			}
		}
	}
	else {
		return file_read(thread_current()->files[fd], buffer, length);
	}
	return -1;
}
int write(int fd, const void *buffer, unsigned length) {
	if (fd == 1) {
		putbuf(buffer,length);
		return length;
	}
	else {
		return file_write(thread_current()->files[fd], buffer, length);
	}
	return -1;	
}
void seek(int fd, unsigned position) {
	file_seek(thread_current()->files[fd],position);
}
unsigned tell(int fd) {
	file_tell(thread_current()->files[fd]);
}
void close(int fd) {
	file_close(thread_current()->files[fd]);
}
