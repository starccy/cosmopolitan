#ifndef COSMOPOLITAN_LIBC_PROC_XDGOPEN_H_
#define COSMOPOLITAN_LIBC_PROC_XDGOPEN_H_
#include "libc/limits.h"
COSMOPOLITAN_C_START_

struct XdgOpen {
  char arg[PATH_MAX];
  char *argv[4];
};

char *__xdg_open(const char *, char *const[], char *, size_t,
                 struct XdgOpen *) libcesque;

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_PROC_XDGOPEN_H_ */
