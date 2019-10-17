#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include <kernel/stdio.h>
#include <string.h>
#include <threads/synch.h>

static void syscall_handler (struct intr_frame *);
static void arg_catcher(uint32_t* args[], int num, void *esp);
static void is_pointer_valid(uint32_t* ptr);

struct lock file_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	uint32_t *args[4];

	//printf("system call start!\n");

	is_pointer_valid((uint32_t *)(f->esp));
	is_pointer_valid((uint32_t *)(f->esp + 3));

	switch (*(uint32_t *)(f->esp))
	{
	case SYS_HALT: /* arg 0 */
	{
		//printf("system call 0\n");
		shutdown_power_off();
		break;
	}
	case SYS_EXIT: /* arg 1 */
	{
		//printf("system call 1\n");
		arg_catcher(args, 2, f->esp);
		printf("%s: exit(%d)\n", thread_name(), *args[1]);
		thread_exit();
		break;
	}
	case SYS_EXEC: /* arg 1 */
	{
		int pid;
		//printf("system call 2\n");
		arg_catcher(args, 2, f->esp);
		//is_pointer_valid((uint32_t *)*args[1]);
		//is_pointer_valid((uint32_t *)(*args[1]+3));
		pid = process_execute((const char *)*args[1]);
		if (pid == TID_ERROR)
		{
		}
		f->eax = pid;
		break;
	}
	case SYS_WAIT: /* arg 1 */
	{
		int child_pid;
		//printf("system call 3\n");
		arg_catcher(args, 2, f->esp);
		child_pid = *args[1];
		process_wait(child_pid);
		f->eax = 0; //should be implemented here
		break;
	}
	case SYS_CREATE: /* arg 2 */
	{
		//printf("system call 4\n");
		arg_catcher(args, 3, f->esp);
		is_pointer_valid((uint32_t *)*args[1]);
		is_pointer_valid((uint32_t *)(*args[1] + 3));
		/*
		if (strlen((const char *)*args[1]) > 56)
		{
			printf("%s: exit(%d)\n", thread_name(), -1);
			thread_exit();
			break;
		}
		*/
		if (*(const char *)*args[1] == NULL)
		{
			printf("%s: exit(%d)\n", thread_name(), -1);
			thread_exit();
			break;
		}
		
		if ((int)*args[2] < 0)
		{
			printf("%s: exit(%d)\n", thread_name(), -1);
			thread_exit();
			break;
		}
		
		if (!filesys_create((const char *)*args[1], *args[2]))
		{
			f->eax = 0;
		}
		else
		{
			f->eax = 1;
		}
		break;
	}
	case SYS_REMOVE: /* arg 1 */
	{
		//printf("system call 5\n");
		arg_catcher(args, 2, f->esp);
		is_pointer_valid((uint32_t *)*args[1]);
		is_pointer_valid((uint32_t *)(*args[1] + 3));
		if (*(const char *)*args[1] == NULL)
		{
			printf("%s: exit(%d)\n", thread_name(), -1);
			thread_exit();
			break;
		}
		if (!filesys_remove((const char *) *args[1]))
		{
			f->eax = 0;
		}
		else
		{
			f->eax = 1;
		}
		break;
	}
	case SYS_OPEN: /* arg 1 */
	{
		struct thread * cur = thread_current();
		struct file * target_file;
		//printf("system call 6\n");
		arg_catcher(args, 2, f->esp);
		if (*(const char *)*args[1] == NULL)
		{
			f->eax = -1;
			break;
		}
		is_pointer_valid((uint32_t *)*args[1]);
		is_pointer_valid((uint32_t *)(*args[1] + 3));
		lock_acquire(&file_lock);
		target_file = filesys_open((const char *)*args[1]);
		
		if (target_file == NULL)
		{
			f->eax = -1;
			lock_release(&file_lock);
			break;
		}
		cur->fd_table[cur->fd_num] = target_file;
		f->eax = cur->fd_num;
		cur->fd_num += 1;
		lock_release(&file_lock);
		break;
	}
	case SYS_FILESIZE: /* arg 1 */
	{
		struct thread * cur = thread_current();
		struct file * target_file;
		//printf("system call 7\n");
		arg_catcher(args, 2, f->esp);
		if (thread_current()->fd_table[(int)*args[1]]== NULL)
		{
			printf("%s: exit(%d)\n", thread_name(), -1);
			thread_exit();
			break;
		}
		target_file = cur->fd_table[*args[1]];
		f->eax = file_length(target_file);
		break;
	}
	case SYS_READ: /* arg 3 */
	{
		struct thread * cur = thread_current();
		struct file * target_file;
		//printf("system call 8\n");
		arg_catcher(args, 4, f->esp);
		is_pointer_valid((uint32_t *)*args[2]);
		is_pointer_valid((uint32_t *)(*args[2] + 3));
		lock_acquire(&file_lock);
		if (*args[1] == 0)
		{
			int count = *args[3];
			int32_t buffer = *args[2];
			while (count--)
			{
				*((char *)buffer++) = input_getc();
				f->eax = *args[3];
			}
			lock_release(&file_lock);
			break;
		}
		if (thread_current()->fd_table[(int)*args[1]] == NULL)
		{
			lock_release(&file_lock);
			printf("%s: exit(%d)\n", thread_name(), -1);
			thread_exit();
			break;
		}
		target_file = cur->fd_table[*args[1]];
		f->eax = file_read(target_file, *args[2], *args[3]);
		lock_release(&file_lock);
		break;
	}
	case SYS_WRITE: /* arg 3 */
	{
		struct thread * cur = thread_current();
		struct file * target_file;
		//printf("system call 9\n");
		arg_catcher(args, 4, f->esp);
		//printf("not the problem of arg_catch\n");
		lock_acquire(&file_lock);
		if (*args[1] == 1)
		{
			putbuf(*args[2], *args[3]);
			f->eax = *args[3];
			lock_release(&file_lock);
			break;
		}
		if (thread_current()->fd_table[(int)*args[1]] == NULL)
		{
			printf("%s: exit(%d)\n", thread_name(), -1);
			lock_release(&file_lock);
			thread_exit();
			break;
		}

		is_pointer_valid((uint32_t *)*args[2]);
		is_pointer_valid((uint32_t *)(*args[2] + 3));
		//printf("not the problem of is_pointer_valid\n");
		target_file = cur->fd_table[*args[1]];
		//printf("not the problem of target_file\n");
		f->eax = file_write(target_file, *args[2], *args[3]);
		//printf("not the problem of f->eax\n");
		lock_release(&file_lock);
		break;
	}
	case SYS_SEEK: /* arg 2 */
	{
		struct thread * cur = thread_current();
		struct file * target_file;
		//printf("system call 10\n");
		arg_catcher(args, 3, f->esp);
		if (thread_current()->fd_table[(int)*args[1]] == NULL)
		{
			printf("%s: exit(%d)\n", thread_name(), -1);
			thread_exit();
			break;
		}
		target_file = cur->fd_table[*args[1]];
		file_seek(target_file, *args[2]);
		break;
	}
	case SYS_TELL: /* arg 1 */
	{
		struct thread * cur = thread_current();
		struct file * target_file;
		//printf("system call 11\n");
		arg_catcher(args, 2, f->esp);
		if (thread_current()->fd_table[(int)*args[1]] == NULL)
		{
			printf("%s: exit(%d)\n", thread_name(), -1);
			thread_exit();
			break;
		}
		target_file = cur->fd_table[*args[1]];
		f->eax = file_tell(target_file);
		break;
	}
	case SYS_CLOSE: /* arg 1 */
	{
		struct thread * cur = thread_current();
		struct file * target_file;
		//printf("system call 12\n");
		arg_catcher(args, 2, f->esp);
		if (thread_current()->fd_table[(int)*args[1]] == NULL)
		{
			printf("%s: exit(%d)\n", thread_name(), -1);
			thread_exit();
			break;
		}
		target_file = cur->fd_table[*args[1]];
		file_close(target_file);
		cur->fd_table[*args[1]] = NULL;
		break;
	}
	}
}

static void arg_catcher(uint32_t* args[], int num, void *esp)
{
	for (int i = 0; i < num; i++)
	{
		is_pointer_valid((uint32_t*)(esp + 4 * i));
		is_pointer_valid((uint32_t *)(esp + 4 * i + 3));
		args[i] = (uint32_t*)(esp + 4 * i);
	}
}

static void is_pointer_valid(uint32_t* ptr)
{
	unsigned int casted_ptr = (unsigned int)ptr;
	//printf("pointer invalid? : %x\n", casted_ptr);
	if (casted_ptr < 0x08048000 || is_kernel_vaddr(ptr))
	{
		//printf("invalid pointer %d", casted_ptr);
		printf("%s: exit(%d)\n", thread_name(), -1);
		thread_exit();
	}
}
