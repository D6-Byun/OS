#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void arg_catcher(uintptr_t* args[], int num, void *esp);
void is_pointer_valid(uintptr_t* ptr);

#endif /* userprog/syscall.h */
