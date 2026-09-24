#include "libc/calls/calls.h"
#include "libc/errno.h"

/**
 * Reserves disk space for a file, POSIX style.
 *
 * Same as fallocate() with mode 0, except the error comes back as the
 * return value and errno is left alone.
 *
 * @return 0 on success, or error number
 */
int posix_fallocate(int fd, int64_t offset, int64_t length) {
  int e = errno;
  int rc = fallocate(fd, 0, offset, length) ? errno : 0;
  errno = e;
  return rc;
}
