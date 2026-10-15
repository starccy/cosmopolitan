#include "libc/calls/signalfd.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/intrin/strace.h"
#include "libc/sysv/errfuns.h"

/**
 * Creates or updates a file descriptor that reads signals.
 *
 * Reads return `struct signalfd_siginfo` records for signals in `mask`
 * that are blocked and pending for the calling thread.
 *
 * @param fd is -1 for a new descriptor, or an existing one to re-mask
 * @param flags may have `SFD_CLOEXEC` and `SFD_NONBLOCK`
 * @return file descriptor on success, or -1 w/ errno
 * @raise ENOSYS if not Linux
 */
int signalfd(int fd, const sigset_t *mask, int flags) {
  int rc;
  if (IsLinux()) {
    rc = sys_signalfd4(fd, mask, sizeof(*mask), flags);
  } else {
    rc = enosys();
  }
  STRACE("signalfd(%d, %p, %#x) → %d% m", fd, mask, flags, rc);
  return rc;
}
