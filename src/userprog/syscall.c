#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	uintptr_t *args[4];

	switch (*(uintptr_t *)(f.esp - 4)) 
	{
	case SYS_HALT: /* arg 0 */
	{
		shutdown_power_off();
		break;
	}
	case SYS_EXIT: /* arg 1 */
	{
		arg_catcher(args[4], 2);
		thread_exit();
		break;
	}
	case SYS_EXEC: /* arg 1 */
	{
		int pid;
		arg_catcher(args[4], 2);
		pid = process_execute(*args[1]);
		f->eax = pid;
		break;
	}
	case SYS_WAIT: /* arg 1 */
	{
		int child_pid;
		arg_catcher(args[4], 2);
		child_pid = *args[1];
		process_wait(child_pid);
		f->eax = 0; //should be implemented here
		break;
	}
	case SYS_CREATE: /* arg 2 */
	{
		arg_catcher(args[4], 3);
		if (!filesys_create(*args[1], *arg[2]))
		{
			f->eax = 0;
		}
		f->eax = 1;
		break;
	}
	case SYS_REMOVE: /* arg 1 */
	{
		arg_catcher(args[4], 2);
		if (!filesys_remove(*args[1]))
		{
			f->eax = 0;
		}
		f->eax = 1;
		break;
	}
	case SYS_OPEN: /* arg 1 */
	{
		struct thread * cur = thread_current();
		arg_catcher(args[4], 2);
		cur->fd_table[cur->fd_num] = filesys_open(*args[1]);
		f->eax = cur->fd_num;
		cur->fd_num += 1;
		break;
	}
	case SYS_FILESIZE: /* arg 1 */
	{
		struct thread * cur = thread_current();
		struct file * target_file;
		arg_catcher(args[4], 2);
		target_file = cur->fd_table[*args[1]];
		f->eax = file_length(target_file);
		break;
	}
	case SYS_READ: /* arg 3 */
	{
		struct thread * cur = thread_current();
		struct file * target_file;
		arg_catcher(args[4], 4);
		target_file = cur->fd_table[*args[1]];
		f->eax = file_read(target_file, *arg[2], *arg[3]);
		break;
	}
	case SYS_WRITE: /* arg 3 */
	{
		struct thread * cur = thread_current();
		struct file * target_file;
		arg_catcher(args[4], 4);
		target_file = cur->fd_table[*args[1]];
		f->eax = file_write(target_file, *arg[2], *arg[3]);
		break;
	}
	case SYS_SEEK: /* arg 2 */
	{
		struct thread * cur = thread_current();
		struct file * target_file;
		arg_catcher(args[4], 3);
		target_file = cur->fd_table[*args[1]];
		file_seek(target_file, *arg[2]);
		break;
	}
	case SYS_TELL: /* arg 1 */
	{
		struct thread * cur = thread_current();
		struct file * target_file;
		arg_catcher(args[4], 2);
		target_file = cur->fd_table[*args[1]];
		f->eax = file_tell(target_file);
		break;
	}
	case SYS_CLOSE: /* arg 1 */
	{
		struct thread * cur = thread_current();
		struct file * target_file;
		arg_catcher(args[4], 2);
		target_file = cur->fd_table[*args[1]];
		file_close(target_file);
		break;
	}
	}
  printf ("system call!\n");
}

void arg_catcher(uintptr_t* args[], int num, void *esp)
{
	for (int i = 0; i < num; i++)
	{
		is_pointer_valid((uintptr_t*)(esp + 4 * i));
		arg[i] = (uintptr_t*)(esp + 4 * i));
	}
}

void is_pointer_valid(uintptr_t* ptr)
{
	int casted_ptr = (int)ptr;
	if (casted_ptr < 0x08048000 || is_kernel_vaddr(ptr))
	{
		printf("invalid pointer %d", casted_ptr);
		thread_exit();
	}
}
