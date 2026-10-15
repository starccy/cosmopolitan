#ifndef COSMOPOLITAN_LIBC_CALLS_STRUCT_SIGVAL_INTERNAL_H_
#define COSMOPOLITAN_LIBC_CALLS_STRUCT_SIGVAL_INTERNAL_H_
#include "libc/calls/struct/sigval.h"
COSMOPOLITAN_C_START_

int sys_sigqueue(int, int, const union sigval);
int __sigqueue(int, int, const union sigval, int);

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_CALLS_STRUCT_SIGVAL_INTERNAL_H_ */
