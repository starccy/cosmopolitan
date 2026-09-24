#ifndef COSMOPOLITAN_LIBC_SYSV_CONSTS_MAP_H_
#define COSMOPOLITAN_LIBC_SYSV_CONSTS_MAP_H_

#define MAP_FILE            0
#define MAP_SHARED          1
#define MAP_PRIVATE         2
#define MAP_SHARED_VALIDATE 3
#define MAP_TYPE            15
#define MAP_FIXED           16

#define MAP_ANONYMOUS       0x00000020
#define MAP_32BIT           0x00000040
#define MAP_DENYWRITE       0x00000800
#define MAP_EXECUTABLE      0x00001000
#define MAP_LOCKED          0x00002000
#define MAP_NORESERVE       0x00004000
#define MAP_POPULATE        0x00008000
#define MAP_NONBLOCK        0x00010000
#define MAP_STACK           0x00020000
#define MAP_HUGETLB         0x00040000
#define MAP_SYNC            0x00080000
#define MAP_FIXED_NOREPLACE 0x00100000

/* flags linux doesn't have, placed on bits linux leaves alone */
#define MAP_INHERIT      0x00000080
#define MAP_NOSYNC       0x00000200
#define MAP_NOCACHE      0x00000400
#define MAP_JIT          0x00200000
#define MAP_CONCEAL      0x00400000
#define MAP_NOEXTEND     0x00800000
#define MAP_HASSEMAPHORE 0x01000000

#define MAP_ANON   MAP_ANONYMOUS
#define MAP_NOCORE MAP_CONCEAL

#endif /* COSMOPOLITAN_LIBC_SYSV_CONSTS_MAP_H_ */
