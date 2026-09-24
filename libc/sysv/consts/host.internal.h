#ifndef COSMOPOLITAN_LIBC_SYSV_CONSTS_HOST_INTERNAL_H_
#define COSMOPOLITAN_LIBC_SYSV_CONSTS_HOST_INTERNAL_H_
#include "libc/calls/struct/timespec.h"
#include "libc/sock/struct/sockaddr.h"
COSMOPOLITAN_C_START_

/*
 * Declares the host's value of a constant whose public name is a Linux
 * literal. The number still comes from consts.sh; it's only reachable
 * as __host_NAME now.
 */
#define __HOSTCONST(TYPE, NAME) extern const TYPE __host_##NAME __asm__(#NAME)

int __af2host(int) libcesque;
int __at2host(int) libcesque;
unsigned long __auxv2host(unsigned long) libcesque;
ssize_t __cmsg2bsd(const void *, size_t, void *, size_t);
size_t __cmsg2linux(const void *, size_t, void *, size_t);
int __af2linux(int) libcesque;
int __clock2host(int) libcesque;
int __dirfd2host(int) libcesque;
int __faccessat2host(int) libcesque;
int __iff2linux(int) libcesque;
unsigned long __ioctl2host(unsigned long) libcesque;
int __mmap2host(int) libcesque;
int __msg2host(int) libcesque;
int __msg2linux(int) libcesque;
int __msync2host(int) libcesque;
int __poll2host(int) libcesque;
int __poll2linux(int) libcesque;
int __sched2host(int) libcesque;
int __sched2linux(int) libcesque;
int __sicode2linux(int, int) libcesque;
int __sighow2host(int) libcesque;
int __socktype2host(int) libcesque;
int __sockopt2host(int, int) libcesque;
int __sockopt2linux(int, int) libcesque;
const void *__sockaddr2nt(const void *, uint32_t, struct sockaddr_storage *);
int __sol2host(int) libcesque;
const struct timespec *__utime2host(const struct timespec[2], struct timespec[2]);
int __wait2host(int) libcesque;
int __whence2host(int) libcesque;

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_SYSV_CONSTS_HOST_INTERNAL_H_ */
