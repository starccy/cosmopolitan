#include "libc/calls/calls.h"
#include "libc/calls/struct/itimerspec.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/intrin/describeflags.h"
#include "libc/intrin/strace.h"
#include "libc/sysv/errfuns.h"

/**
 * Creates file descriptor that reports timer expirations.
 *
 * @param flags can have TFD_{CLOEXEC,NONBLOCK}
 * @return file descriptor, or -1 w/ errno
 * @raise ENOSYS if not Linux
 */
int timerfd_create(int clock, int flags) {
  int rc;
  if (IsLinux()) {
    rc = sys_timerfd_create(clock, flags);
  } else {
    rc = enosys();
  }
  STRACE("timerfd_create(%s, %#x) → %d% m", DescribeClockName(clock), flags,
         rc);
  return rc;
}

/**
 * Arms or disarms timer file descriptor.
 *
 * @param flags can have TFD_TIMER_{ABSTIME,CANCEL_ON_SET}
 * @return 0 on success, or -1 w/ errno
 * @raise ENOSYS if not Linux
 */
int timerfd_settime(int fd, int flags, const struct itimerspec *neu,
                    struct itimerspec *old) {
  int rc;
  if (IsLinux()) {
    rc = sys_timerfd_settime(fd, flags, neu, old);
  } else {
    rc = enosys();
  }
  STRACE("timerfd_settime(%d, %#x, %p, %p) → %d% m", fd, flags, neu, old, rc);
  return rc;
}

/**
 * Reads how long until timer file descriptor fires.
 *
 * @return 0 on success, or -1 w/ errno
 * @raise ENOSYS if not Linux
 */
int timerfd_gettime(int fd, struct itimerspec *cur) {
  int rc;
  if (IsLinux()) {
    rc = sys_timerfd_gettime(fd, cur);
  } else {
    rc = enosys();
  }
  STRACE("timerfd_gettime(%d, %p) → %d% m", fd, cur, rc);
  return rc;
}
