#ifndef COSMOPOLITAN_LIBC_SYSV_CONSTS_AT_H_
#define COSMOPOLITAN_LIBC_SYSV_CONSTS_AT_H_

/**
 * @fileoverview AT_xxx constants for fcntl(), fopenat(), etc..
 * @see libc/sysv/consts/auxv.h for getauxval() constants
 */

#define AT_FDCWD            -100
#define AT_SYMLINK_NOFOLLOW 0x0100
#define AT_REMOVEDIR        0x0200
#define AT_EACCESS          0x0200
#define AT_SYMLINK_FOLLOW   0x0400
#define AT_NO_AUTOMOUNT     0x0800
#define AT_EMPTY_PATH       0x1000

#endif /* COSMOPOLITAN_LIBC_SYSV_CONSTS_AT_H_ */
