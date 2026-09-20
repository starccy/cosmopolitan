/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2022 Justine Alexandra Roberts Tunney                              │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/
#include "libc/calls/sigtimedwait.h"
#include "libc/calls/cp.internal.h"
#include "libc/calls/sigtimedwait.internal.h"
#include "libc/calls/struct/siginfo.internal.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/calls/struct/timespec.h"
#include "libc/calls/struct/timespec.internal.h"
#include "libc/calls/syscall_support-sysv.internal.h"
#include "libc/cosmotime.h"
#include "libc/dce.h"
#include "libc/intrin/strace.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/clock.h"
#include "libc/sysv/errfuns.h"

int sys_sigtimedwait_nt(const sigset_t *, siginfo_t *, const struct timespec *);
int sys_sigwait(const uint32_t *, int *);

static int sys_sigtimedwait_xnu(const sigset_t *set, siginfo_t *opt_info,
                                const struct timespec *opt_timeout) {
  int sig;
  uint32_t set2 = __linux2mask(*set);
  if (opt_timeout) {
    long nap = 1000000;
    struct timespec deadline = timespec_add(timespec_mono(), *opt_timeout);
    for (;;) {
      uint64_t pending[2] = {0};
      if (sys_sigpending(pending, 8) == -1)
        return -1;
      if ((uint32_t)pending[0] & set2)
        break;
      struct timespec left = timespec_sub(deadline, timespec_mono());
      if (timespec_cmp(left, timespec_zero) <= 0)
        return eagain();
      struct timespec ts = {0, nap};
      if (timespec_cmp(ts, left) > 0)
        ts = left;
      if (clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, 0))
        return eintr();
      if (nap < 10000000)
        nap *= 2;
    }
  }
  if (sys_sigwait(&set2, &sig) == -1)
    return -1;
  if (opt_info) {
    bzero(opt_info, sizeof(*opt_info));
    opt_info->si_signo = __sig2linux(sig);
  }
  return sig;
}

/**
 * Waits for signal synchronously, w/ timeout.
 *
 * This function does not change the thread signal mask. Signals that
 * aren't masked, which aren't in `set`, will be handled normally, in
 * which case this function will raise `EINTR`.
 *
 * This function silently ignores attempts to synchronously wait for
 * SIGTHR which is used internally by the POSIX threads implementation.
 *
 * @param set is signals for which we'll be waiting
 * @param opt_info if not null shall receive info about signal
 * @param opt_timeout is relative deadline and null means wait forever
 * @return signal number on success, or -1 w/ errno
 * @raise EINTR if an asynchronous signal was delivered instead
 * @raise ECANCELED if thread was cancelled in masked mode
 * @raise EINVAL if nanoseconds parameter was out of range
 * @raise EAGAIN if timeout elapsed
 * @raise ENOSYS on XNU, OpenBSD, and Metal
 * @raise EFAULT if invalid memory was supplied
 * @cancelationpoint
 * @norestart
 */
int sigtimedwait(const sigset_t *set, siginfo_t *opt_info,
                 const struct timespec *opt_timeout) {
  int rc;
  struct timespec ts;
  union siginfo_meta si = {0};
  BEGIN_CANCELATION_POINT;

  // validate timeout
  if (!set) {
    rc = efault();
  } else if (opt_timeout && opt_timeout->tv_nsec >= 1000000000ull) {
    rc = einval();
  } else if (IsLinux() || IsFreebsd() || IsNetbsd()) {
    sigset_t set2 = __linux2mask(*set);
    if (opt_timeout) {
      // 1. Linux needs its size parameter
      // 2. NetBSD modifies timeout argument
      ts = *opt_timeout;
      rc = sys_sigtimedwait(&set2, &si, &ts, 8);
    } else {
      rc = sys_sigtimedwait(&set2, &si, 0, 8);
    }
    if (rc != -1 && opt_info)
      __siginfo2cosmo(opt_info, &si);
  } else if (IsWindows()) {
    rc = sys_sigtimedwait_nt(set, opt_info, opt_timeout);
  } else if (IsXnu()) {
    rc = sys_sigtimedwait_xnu(set, opt_info, opt_timeout);
  } else {
    rc = enosys();
  }
  rc = __sig2linux(rc);

  END_CANCELATION_POINT;
  STRACE("sigtimedwait(%s, [%s], %s) → %s% m", DescribeSigset(0, set),
         DescribeSiginfo(rc, opt_info), DescribeTimespec(0, opt_timeout),
         strsignal(rc));
  return rc;
}
