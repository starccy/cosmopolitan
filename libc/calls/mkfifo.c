#include "libc/calls/calls.h"
#include "libc/sysv/consts/at.h"
#include "libc/sysv/consts/s.h"

/**
 * Creates named pipe.
 *
 * @return 0 on success, or -1 w/ errno
 * @raise ENOSYS on Windows
 */
int mkfifo(const char *path, unsigned mode) {
  return mknodat(AT_FDCWD, path, S_IFIFO | (mode & ~S_IFMT), 0);
}

int mkfifoat(int dirfd, const char *path, unsigned mode) {
  return mknodat(dirfd, path, S_IFIFO | (mode & ~S_IFMT), 0);
}
