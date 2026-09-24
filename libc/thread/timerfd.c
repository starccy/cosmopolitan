#include "libc/calls/calls.h"
#include "libc/calls/internal.h"
#include "libc/calls/struct/itimerspec.h"
#include "libc/calls/struct/sigevent.h"
#include "libc/calls/struct/sigval.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/intrin/describeflags.h"
#include "libc/intrin/fds.h"
#include "libc/intrin/strace.h"
#include "libc/sysv/consts/clock.h"
#include "libc/sysv/consts/efd.h"
#include "libc/sysv/consts/tfd.h"
#include "libc/sysv/consts/timer.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"

/**
 * @fileoverview timerfd for every host.
 *
 * Linux has it. Elsewhere it's an eventfd (libc/calls/eventfd.c) fed by
 * a POSIX timer (timer.c): each time the timer fires, the expirations it
 * stands for are added to the counter, which is exactly what a read on a
 * timerfd hands back. The descriptor polls, blocks and takes O_NONBLOCK
 * the way the eventfd does.
 */

static void TimerFdFire(union sigval v) {
  int fd = v.sival_int;
  if (!__isfdkind(fd, kFdEvent))
    return;
  struct Fd *f = __get_pib()->fds.p + fd;
  int overrun = timer_getoverrun(f->tftimer);
  __eventfd_post(fd, 1 + (overrun > 0 ? overrun : 0));
}

static struct Fd *GetTimerFd(int fd) {
  if (!__isfdkind(fd, kFdEvent) ||
      !(__get_pib()->fds.p[fd].evflags & __EFD_TIMERFD)) {
    einval();
    return 0;
  }
  return __get_pib()->fds.p + fd;
}

// called by close() with the entry already taken out of the table
void __timerfd_close(struct Fd *f) {
  if (f->tftimer) {
    timer_delete(f->tftimer);
    f->tftimer = 0;
  }
}

/**
 * Creates file descriptor that reports timer expirations.
 *
 * @param clock is CLOCK_REALTIME, CLOCK_MONOTONIC or CLOCK_BOOTTIME
 * @param flags can have TFD_{CLOEXEC,NONBLOCK}
 * @return file descriptor, or -1 w/ errno
 */
int timerfd_create(int clock, int flags) {
  int rc;
  if (IsLinux()) {
    rc = sys_timerfd_create(clock, flags);
  } else if (flags & ~(TFD_CLOEXEC | TFD_NONBLOCK)) {
    rc = einval();
  } else {
    if (clock == CLOCK_BOOTTIME)
      clock = CLOCK_MONOTONIC;
    if (clock != CLOCK_REALTIME && clock != CLOCK_MONOTONIC) {
      rc = einval();
    } else {
      int eflags = 0;
      if (flags & TFD_CLOEXEC)
        eflags |= EFD_CLOEXEC;
      if (flags & TFD_NONBLOCK)
        eflags |= EFD_NONBLOCK;
      int fd = eventfd(0, eflags);
      if (fd != -1) {
        struct sigevent sev = {0};
        sev.sigev_notify = SIGEV_THREAD;
        sev.sigev_notify_function = TimerFdFire;
        sev.sigev_value.sival_int = fd;
        timer_t t;
        if (timer_create(clock, &sev, &t) == -1) {
          close(fd);
          fd = -1;
        } else {
          struct Fd *f = __get_pib()->fds.p + fd;
          f->tftimer = t;
          f->evflags |= __EFD_TIMERFD;
        }
      }
      rc = fd;
    }
  }
  STRACE("timerfd_create(%s, %#x) → %d% m", DescribeClockName(clock), flags,
         rc);
  return rc;
}

/**
 * Arms or disarms timer file descriptor.
 *
 * Expirations not yet read are forgotten, as on Linux.
 *
 * @param flags can have TFD_TIMER_{ABSTIME,CANCEL_ON_SET}
 * @return 0 on success, or -1 w/ errno
 */
int timerfd_settime(int fd, int flags, const struct itimerspec *neu,
                    struct itimerspec *old) {
  int rc;
  struct Fd *f;
  if (IsLinux()) {
    rc = sys_timerfd_settime(fd, flags, neu, old);
  } else if (flags & ~(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET)) {
    rc = einval();
  } else if (!(f = GetTimerFd(fd))) {
    rc = -1;
  } else {
    __eventfd_drain(fd);
    rc = timer_settime(f->tftimer, (flags & TFD_TIMER_ABSTIME) ? TIMER_ABSTIME : 0,
                       neu, old);
  }
  STRACE("timerfd_settime(%d, %#x, %p, %p) → %d% m", fd, flags, neu, old, rc);
  return rc;
}

/**
 * Reads how long until timer file descriptor fires.
 *
 * @return 0 on success, or -1 w/ errno
 */
int timerfd_gettime(int fd, struct itimerspec *cur) {
  int rc;
  struct Fd *f;
  if (IsLinux()) {
    rc = sys_timerfd_gettime(fd, cur);
  } else if (!(f = GetTimerFd(fd))) {
    rc = -1;
  } else {
    rc = timer_gettime(f->tftimer, cur);
  }
  STRACE("timerfd_gettime(%d, %p) → %d% m", fd, cur, rc);
  return rc;
}
