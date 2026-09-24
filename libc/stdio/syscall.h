#ifndef COSMOPOLITAN_LIBC_STDIO_SYSCALL_H_
#define COSMOPOLITAN_LIBC_STDIO_SYSCALL_H_
#include "libc/sysv/consts/nrlinux.h"
COSMOPOLITAN_C_START_

#define SYS_gettid    __NR_linux_gettid
#define SYS_getrandom __NR_linux_getrandom
#define SYS_getcpu    __NR_linux_getcpu

long syscall(long, ...) libcesque;

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_STDIO_SYSCALL_H_ */
