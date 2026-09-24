#include "libc/calls/calls.h"
#include "libc/calls/internal.h"
#include "libc/calls/struct/iovec.h"
#include "libc/calls/struct/iovec.internal.h"
#include "libc/dce.h"
#include "libc/intrin/strace.h"
#include "libc/sysv/errfuns.h"

/**
 * Splices user pages into pipe.
 *
 * @param flags can have SPLICE_F_{MOVE,NONBLOCK,MORE,GIFT}
 * @return number of bytes transferred, or -1 w/ errno
 * @raise ENOSYS if not Linux
 * @see splice()
 */
ssize_t vmsplice(int fd, const struct iovec *iov, int64_t nr_segs,
                 uint32_t flags) {
  ssize_t rc;
  if (IsWindows()) {
    rc = enosys();
  } else if (__isfdkind(fd, kFdZip)) {
    rc = enotsup();
  } else {
    rc = sys_vmsplice(fd, iov, nr_segs, flags);
  }
  STRACE("vmsplice(%d, %s, %ld, %#x) → %'ld% m", fd,
         DescribeIovec(rc != -1 ? rc : -1, iov, nr_segs), nr_segs, flags, rc);
  return rc;
}
