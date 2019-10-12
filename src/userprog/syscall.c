#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}



static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	switch (*(uintptr_t *)(f.esp - 4)) 
	{
	case SYS_HALT: /* arg 0 */
	{
		shutdown_power_off();
		break;
	}
	case SYS_EXIT: /* arg 1 */
	{
		break;
	}
	case SYS_EXEC: /* arg 1 */
	{
		
		break;
	}
	case SYS_WAIT: /* arg 1 */
	{
		break;
	}
	case SYS_CREATE: /* arg 2 */
	{
		break;
	}
	case SYS_REMOVE: /* arg 1 */
	{
		break;
	}
	case SYS_OPEN: /* arg 1 */
	{
		break;
	}
	case SYS_FILESIZE: /* arg 1 */
	{
		break;
	}
	case SYS_READ: /* arg 3 */
	{
		break;
	}
	case SYS_WRITE: /* arg 3 */
	{
		break;
	}
	case SYS_SEEK: /* arg 2 */
	{
		break;
	}
	case SYS_TELL: /* arg 1 */
	{
		break;
	}
	case SYS_CLOSE: /* arg 1 */
	{
		break;
	}
	}
  printf ("system call!\n");
  thread_exit ();
}
