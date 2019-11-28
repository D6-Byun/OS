#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
int mmap(int fd, void *addr);
void munmap(int mapping);

#endif /* userprog/syscall.h */
