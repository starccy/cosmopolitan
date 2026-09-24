#ifndef COSMOPOLITAN_LIBC_CALLS_TERMIOS_INTERNAL_H_
#define COSMOPOLITAN_LIBC_CALLS_TERMIOS_INTERNAL_H_
#include "libc/calls/struct/metatermios.internal.h"
#include "libc/calls/struct/termios.h"
COSMOPOLITAN_C_START_

void *__termios2host(union metatermios *, const struct termios *);
void __termios2linux(struct termios *, const union metatermios *);
uint32_t __baud2rate(uint32_t);
uint32_t __rate2baud(uint32_t);

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_CALLS_TERMIOS_INTERNAL_H_ */
