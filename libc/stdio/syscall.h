#ifndef COSMOPOLITAN_LIBC_STDIO_SYSCALL_H_
#define COSMOPOLITAN_LIBC_STDIO_SYSCALL_H_
#include "libc/sysv/consts/nrlinux.h"
COSMOPOLITAN_C_START_

#define SYS_gettid          __NR_linux_gettid
#define SYS_getrandom       __NR_linux_getrandom
#define SYS_getcpu          __NR_linux_getcpu
#define SYS_futex           __NR_linux_futex
#define SYS_fchmod          __NR_linux_fchmod
#define SYS_fchown          __NR_linux_fchown
#define SYS_fchmodat        __NR_linux_fchmodat
#define SYS_copy_file_range __NR_linux_copy_file_range
#define SYS_eventfd2        __NR_linux_eventfd2
#define SYS_memfd_create    __NR_linux_memfd_create
#define SYS_renameat2       __NR_linux_renameat2
#define SYS_syncfs          __NR_linux_syncfs
#define SYS_statx           __NR_linux_statx
#ifdef __x86_64__
#define SYS_eventfd         __NR_linux_eventfd
#endif

long syscall(long, ...) libcesque;

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_STDIO_SYSCALL_H_ */
