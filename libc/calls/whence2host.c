#include "libc/dce.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/seek.h"

__HOSTCONST(int, SEEK_DATA);
__HOSTCONST(int, SEEK_HOLE);

/**
 * Turns an lseek() whence into what the host kernel expects.
 *
 * Returns -1 for `SEEK_DATA` and `SEEK_HOLE` on a host without them.
 */
int __whence2host(int whence) {
  if (IsLinux() || IsWindows())
    return whence;
  if (whence == SEEK_DATA)
    return __host_SEEK_DATA;
  if (whence == SEEK_HOLE)
    return __host_SEEK_HOLE;
  return whence;
}
