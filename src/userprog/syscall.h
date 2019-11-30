#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "vm/page.h"

void syscall_init (void);

void free_mmap(struct mmap_file *);

#endif /* userprog/syscall.h */
