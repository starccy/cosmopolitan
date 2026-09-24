#include "libc/calls/calls.h"
#include "libc/calls/internal.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/intrin/strace.h"
#include "libc/sysv/errfuns.h"

/**
 * Duplicates pipe content.
 *
 * @param flags can have SPLICE_F_{MOVE,NONBLOCK,MORE,GIFT}
 * @return number of bytes duplicated, 0 on input end, or -1 w/ errno
 * @raise ENOSYS if not Linux
 * @see splice()
 */
ssize_t tee(int infd, int outfd, size_t uptobytes, unsigned flags) {
  ssize_t rc;
  if (IsWindows()) {
    rc = enosys();
  } else if (__isfdkind(infd, kFdZip) || __isfdkind(outfd, kFdZip)) {
    rc = enotsup();
  } else {
    rc = sys_tee(infd, outfd, uptobytes, flags);
  }
  STRACE("tee(%d, %d, %'zu, %#x) → %'ld% m", infd, outfd, uptobytes, flags,
         rc);
  return rc;
}
