// The __isoc99_* names glibc's stdio.h redirects scanf, fscanf and
// sscanf to (and their v* forms). Any object compiled against glibc or
// musl headers on Linux calls these.

#include "libc/stdio/stdio.h"

int __isoc99_vscanf(const char *fmt, va_list va) {
  return vscanf(fmt, va);
}

int __isoc99_vfscanf(FILE *f, const char *fmt, va_list va) {
  return vfscanf(f, fmt, va);
}

int __isoc99_vsscanf(const char *s, const char *fmt, va_list va) {
  return vsscanf(s, fmt, va);
}

int __isoc99_scanf(const char *fmt, ...) {
  va_list va;
  va_start(va, fmt);
  int rc = vscanf(fmt, va);
  va_end(va);
  return rc;
}

int __isoc99_fscanf(FILE *f, const char *fmt, ...) {
  va_list va;
  va_start(va, fmt);
  int rc = vfscanf(f, fmt, va);
  va_end(va);
  return rc;
}

int __isoc99_sscanf(const char *s, const char *fmt, ...) {
  va_list va;
  va_start(va, fmt);
  int rc = vsscanf(s, fmt, va);
  va_end(va);
  return rc;
}
