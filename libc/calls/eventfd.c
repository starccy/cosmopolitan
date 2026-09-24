#include "libc/calls/calls.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/intrin/strace.h"
#include "libc/sysv/errfuns.h"

/**
 * Creates file descriptor for event notification.
 *
 * @param flags can have EFD_{CLOEXEC,NONBLOCK,SEMAPHORE}
 * @return file descriptor, or -1 w/ errno
 * @raise ENOSYS if not Linux
 */
int eventfd(unsigned initval, int flags) {
  int rc;
  if (IsLinux()) {
    rc = sys_eventfd2(initval, flags);
  } else {
    rc = enosys();
  }
  STRACE("eventfd(%u, %#x) → %d% m", initval, flags, rc);
  return rc;
}

int eventfd_read(int fd, uint64_t *value) {
  return read(fd, value, sizeof(*value)) == sizeof(*value) ? 0 : -1;
}

int eventfd_write(int fd, uint64_t value) {
  return write(fd, &value, sizeof(value)) == sizeof(value) ? 0 : -1;
}
