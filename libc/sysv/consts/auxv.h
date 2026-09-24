#ifndef COSMOPOLITAN_LIBC_CALLS_AUXV_H_
#define COSMOPOLITAN_LIBC_CALLS_AUXV_H_

/*
 * getauxval() keys, numbered the way linux does; __auxv2host() maps
 * them onto the vector a bsd kernel hands out
 */
#define AT_NULL          0
#define AT_IGNORE        1
#define AT_EXECFD        2
#define AT_PHDR          3
#define AT_PHENT         4
#define AT_PHNUM         5
#define AT_PAGESZ        6
#define AT_BASE          7
#define AT_FLAGS         8
#define AT_ENTRY         9
#define AT_NOTELF        10
#define AT_UID           11
#define AT_EUID          12
#define AT_GID           13
#define AT_EGID          14
#define AT_PLATFORM      15
#define AT_HWCAP         16
#define AT_CLKTCK        17
#define AT_DCACHEBSIZE   19
#define AT_ICACHEBSIZE   20
#define AT_UCACHEBSIZE   21
#define AT_SECURE        23
#define AT_BASE_PLATFORM 24
#define AT_RANDOM        25
#define AT_HWCAP2        26
#define AT_EXECFN        31
#define AT_SYSINFO_EHDR  33
#define AT_MINSIGSTKSZ   51

#define AT_EXECPATH AT_EXECFN /* freebsd's name for it */

/* keys only a bsd has, on numbers linux leaves alone */
#define AT_OSRELDATE    0x1000
#define AT_CANARY       0x1001
#define AT_CANARYLEN    0x1002
#define AT_NCPUS        0x1003
#define AT_PAGESIZES    0x1004
#define AT_PAGESIZESLEN 0x1005
#define AT_TIMEKEEP     0x1006
#define AT_STACKPROT    0x1007
#define AT_EHDRFLAGS    0x1008
#define AT_STACKBASE    0x1009

#define AT_FLAGS_PRESERVE_ARGV0_BIT 0
#define AT_FLAGS_PRESERVE_ARGV0     (1 << AT_FLAGS_PRESERVE_ARGV0_BIT)

#endif /* COSMOPOLITAN_LIBC_CALLS_AUXV_H_ */
