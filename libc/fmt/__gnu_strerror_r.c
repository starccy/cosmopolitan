#include "libc/fmt/magnumstrs.internal.h"
#include "libc/str/str.h"

/**
 * strerror_r() as glibc declares it under _GNU_SOURCE.
 *
 * libc/str/str.h routes strerror_r() here for code compiled with
 * _GNU_SOURCE (every C++ translation unit, since the compiler predefines
 * it). The XSI strerror_r() stays what code without the macro, and the
 * libc itself, link against.
 *
 * @return the static message of a known errno, else buf
 */
char *__gnu_strerror_r(int err, char *buf, size_t size) {
  const char *msg;
  if (err && (msg = _strerdoc(err)))
    return (char *)msg;
  strerror_r(err, buf, size);
  return buf;
}
