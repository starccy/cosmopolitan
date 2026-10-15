#include "libc/calls/struct/iovec.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/intrin/strace.h"
#include "libc/sysv/errfuns.h"

/**
 * Reads memory of another process.
 *
 * @return bytes transferred on success, or -1 w/ errno
 * @raise ENOSYS if not Linux
 */
ssize_t process_vm_readv(int pid, const struct iovec *local,
                         unsigned long liovcnt, const struct iovec *remote,
                         unsigned long riovcnt, unsigned long flags) {
  ssize_t rc;
  if (IsLinux()) {
    rc = sys_process_vm_readv(pid, local, liovcnt, remote, riovcnt, flags);
  } else {
    rc = enosys();
  }
  STRACE("process_vm_readv(%d, %p, %lu, %p, %lu, %#lx) → %ld% m", pid, local,
         liovcnt, remote, riovcnt, flags, rc);
  return rc;
}

/**
 * Writes memory of another process.
 *
 * @return bytes transferred on success, or -1 w/ errno
 * @raise ENOSYS if not Linux
 */
ssize_t process_vm_writev(int pid, const struct iovec *local,
                          unsigned long liovcnt, const struct iovec *remote,
                          unsigned long riovcnt, unsigned long flags) {
  ssize_t rc;
  if (IsLinux()) {
    rc = sys_process_vm_writev(pid, local, liovcnt, remote, riovcnt, flags);
  } else {
    rc = enosys();
  }
  STRACE("process_vm_writev(%d, %p, %lu, %p, %lu, %#lx) → %ld% m", pid, local,
         liovcnt, remote, riovcnt, flags, rc);
  return rc;
}
