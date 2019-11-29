#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/thread.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */


/*parse function for a to b*/
void parse(char *a, char * b){
	int i;
	strlcpy(b, a, strlen(a) + 1);
	for(i = 0; b[i] != '\0' && b[i] != ' '; i++){
	
	}
	b[i] = '\0';
}
	
	
tid_t
process_execute (const char *file_name) 
{
	char *fn_copy, *save_ptr, *save_ptr2;
  	tid_t tid;
	char hongkong[128];	
	struct list_elem *child_e;
	struct thread *child_t;
	/* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  	fn_copy = palloc_get_page (0);
	
  	if (fn_copy == NULL){
		return TID_ERROR;
	}
  	strlcpy (fn_copy, file_name, PGSIZE);

  	parse(file_name, hongkong);
	
	//printf("%s\n",token);
	/*if load failed, return -1 */
	if(filesys_open(hongkong) == NULL){
		printf("file open failed in process_execute\n");
		return -1;
	}
	//printf("check\n");
  	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (hongkong, PRI_DEFAULT, start_process, fn_copy);
	sema_down(&(thread_current()->lock_imsi));  	
	if (tid == TID_ERROR){
    	palloc_free_page (fn_copy);
	}
	/*for(child_e = list_next(list_begin(&(thread_current()->child)));child_e != list_end(&(thread_current()->child));child_e = list_next(&child_e)){
		child_t = list_entry(child_e,struct thread,child_elem);
		if(child_t -> isexit == true){
			return process_wait(tid);
		}
	}*/
	if(thread_current()->isexit){

		printf("isexit in process_execute\n");
		return -1;
	}
	//free(hongkong);
  	return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
	char *save_ptr;
	char *file_name = file_name_;
	struct intr_frame if_;
	bool success;
	struct thread *cur = thread_current();

	cur->spt = spt_init(); /*create spt in current thread*/
	
  	//printf("start_process\n");
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);
  
  /* If load failed, quit. */
  palloc_free_page (file_name);
  sema_up(&(thread_current()->pthread->lock_imsi));
	if (!success){
	  	thread_current()->pthread->isexit = true;
		thread_exit ();
  }
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
	/*for (int i = 0; i < 100000000; i++) {

	}*/
	int exit;
	struct list_elem *elem;
	struct thread *child_t = NULL;
	for (elem = list_begin(&(thread_current()->child)); elem != list_end(&(thread_current()->child)); elem = list_next(elem)) {
		child_t = list_entry(elem, struct thread, child_elem);
		if (child_tid == child_t->tid) {
			sema_down(&(child_t->sema_child));
			exit = child_t->exit;
			list_remove(&(child_t->child_elem));
			sema_up(&(child_t->sema_imsi));
			return exit;
		}
	}
	return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
	struct thread *par;
  struct thread *cur = thread_current ();
  uint32_t *pd;

  spt_destroy(cur->spt);
  cur->spt = NULL;
  
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
  //free_frame_table();
	sema_up(&(cur->sema_child));
	sema_down(&(cur->sema_imsi));
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp,int argc,char *argv[]);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i, argc = 1;
  char *argv[32];
  char *token, *save_ptr;
	//printf("start loading\n");
	//hex_dump((uintptr_t)file_name,file_name,100,true);
	argv[0] = strtok_r(file_name, " ", &save_ptr);
		while (1) {
			argv[argc] = strtok_r(NULL, " ",&save_ptr);	
			if (argv[argc] == NULL)	
				break;
			argc++;
			//printf("%d\n",argc);
  		}
	 /* Allocate and activate page directory. */
  	t->pagedir = pagedir_create ();
    if (t->pagedir == NULL) 
    	goto done;
  	process_activate ();

  /* Open executable file. */
  	file = filesys_open (file_name);
  	if (file == NULL) 
    {
      	printf ("load: %s: open failed\n", file_name);
      	goto done; 
    }

  /* Read and verify executable header. */
  	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      	printf ("load: %s: error loading executable\n", file_name);
      	goto done; 
    }

  /* Read program headers. */
  	file_ofs = ehdr.e_phoff;
  	for (i = 0; i < ehdr.e_phnum; i++) 
    {
    	struct Elf32_Phdr phdr;

      	if (file_ofs < 0 || file_ofs > file_length (file))
        	goto done;
      	file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }
  /* Set up stack. */
  if (!setup_stack (esp,argc,argv))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  printf("now load_segment \n");

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
	  printf("now read_byte is %d",read_bytes);
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE; 
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
	  struct spt_entry * temp_entry;
	  /*
      // Get a page of memory. 
	  struct frame_entry * new_frame = create_f_entry(0, upage);
      //uint8_t *kpage = palloc_get_page (PAL_USER);
	  uint8_t *kpage = new_frame->kpage;
      if (kpage == NULL)
        return false;
	  
      // Load this page.
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      // Add the page to the process's address space.
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }
	  */

	  //not sure about page member initializing
	  temp_entry = create_s_entry(upage, NULL, writable, file, ofs, page_read_bytes, page_zero_bytes);
	  if (temp_entry == NULL)
	  {
		  printf("spt_entry create fail in load_segment\n");
		  return false;
	  }
	  if (!insert_spt_entry(&thread_current()->spt->hash_brown, temp_entry))
	  {
		  printf("spt insert fail in load_segment\n");
		  return false;
	  }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
	  ofs += page_read_bytes;
      upage += PGSIZE;
    }
  printf("end load_segment \n");
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, int argc, char *argv[]) 
{
  uint8_t *kpage, *nullp = (uint8_t)0;
  bool success = false;
  uintptr_t *addr[32];
  struct spt_entry *new_spte;
  struct frame_entry *new_frame = create_f_entry(PAL_ZERO, (uint8_t *)(PHYS_BASE - PGSIZE));
  //kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  kpage = new_frame->kpage;
  printf("start stacking\n");
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
	  if (success) {
		  *esp = PHYS_BASE;
		  /*argv[i][...]*/
		  for (int i = argc - 1; i >= 0; i--) {
			  *esp -= (strlen(argv[i]) + 1);
			 // printf("%d,\n",(strlen(argv[i]+1)));
			  memcpy(*esp, argv[i], strlen(argv[i]) + 1);
			  addr[i] = (uintptr_t*)*esp;
		  }
		  addr[argc] = (uintptr_t*)0;
		  /*word-align*/
		  while ((uintptr_t)*esp % 4 != 0) {
			  *esp = *esp - 1;
			  //printf("%d\n",(uintptr_t)*esp);
			  //memmove(*esp,nullp,sizeof(*nullp));
		  }
			//printf("%d\n",(uintptr_t)*esp);
		  /*argv[i]*/
		  for (int i = argc; i >= 0; i--) {
			  *esp = *esp - 4;
			  *(uintptr_t **)*esp = addr[i];
		  }
		  /*argv*/
		  *esp = *esp - 4;
		  //printf("%d\n",(uintptr_t)*esp);
		  *(uintptr_t **)*esp = *esp + 4;
		  /*argc*/
		  *esp = *esp - 4;
		  	//printf("%d\n",(uintptr_t)*esp);
			*(int *)*esp = argc;
		  /*ret addr*/
		  *esp = *esp - 4;
		  *(int *)*esp = 0;

	  }
	  else
	  {
		  free_frame_entry(&new_frame->helem, NULL);
	  }
    }
  printf("arg_stack end ")
  new_spte = create_s_entry((uint8_t *)(PHYS_BASE - PGSIZE), kpage, true, NULL, 0, 0, PGSIZE);
  if (new_spte == NULL)
  {
	  printf("spt_entry create fail in setup_stack\n");
	  return false;
  }
  if (!insert_spt_entry(&thread_current()->spt->hash_brown, new_spte))
  {
	  printf("spt insert fail in setup_stack\n");
	  return false;
  }
  //not sure
  printf("end setup_stack \n");
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

void load_and_map(struct spt_entry *spt_e)
{
	struct frame_entry * new_frame = create_f_entry(PAL_ZERO, spt_e->upage);
	if (new_frame == NULL)
	{
		//case of swap
		printf("can't alloc frame in load_and_map\n");
		exit(-1);
	}
	spt_e->kpage = new_frame->kpage;
	if (load_file(new_frame, spt_e))
	{
		install_page(spt_e->upage, new_frame, spt_e->writable);
		spt_e->is_loaded = true;
	}
	else
	{
		printf("load error");
		exit(-1);
	}
}

bool load_file(struct frame_entry *kpage, struct spt_entry* spt_e)
{
	off_t indexer = file_read_at(spt_e->file, kpage, spt_e->read_bytes, spt_e->offset);
	if(indexer != spt_e->read_bytes)
	{
		free_frame_entry(&kpage->helem, NULL);
		printf("load_file: fail to install\n");
		return false;
	}
	return true;
}
