#ifndef COSMOPOLITAN_LIBC_SOCK_EPOLL_H_
#define COSMOPOLITAN_LIBC_SOCK_EPOLL_H_
#include "libc/calls/struct/sigset.h"
COSMOPOLITAN_C_START_

typedef union epoll_data {
  void *ptr;
  int fd;
  uint32_t u32;
  uint64_t u64;
} epoll_data_t;

// packed on x86_64 and naturally aligned on aarch64, like the kernel
struct
#ifdef __x86_64__
    thatispacked
#endif
    epoll_event {
  uint32_t events;
  epoll_data_t data;
};

int epoll_create(int) libcesque;
int epoll_create1(int) libcesque;
int epoll_ctl(int, int, int, struct epoll_event *) libcesque;
int epoll_wait(int, struct epoll_event *, int, int) libcesque;
int epoll_pwait(int, struct epoll_event *, int, int, const sigset_t *) libcesque;

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_SOCK_EPOLL_H_ */
