/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2021 Justine Alexandra Roberts Tunney                              │
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
#include "libc/calls/internal.h"
#include "libc/calls/struct/sigset.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/calls/struct/timespec.h"
#include "libc/calls/struct/timespec.internal.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/cosmotime.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/atomic.h"
#include "libc/macros.h"
#include "libc/nt/ntdll.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/nt/winmm.h"
#if SupportsWindows()

// timeBeginPeriod(1) gets the scheduler tick down to 1ms, and a waitable
// timer only fires on a tick, so a 1ms sleep took 1.9ms on average. The
// kernel can tick twice as fast when asked through ntdll. That is asked
// for while somebody sleeps, and given back when nobody does. Leaving it
// on between sleeps measures worse (1.4ms), so it really is per sleep.
static atomic_int g_sleepers;

static textwindows void sys_clock_nanosleep_nt_fast_tick(bool enter) {
  uint32_t coarsest, finest, current;
  if (enter) {
    atomic_fetch_add(&g_sleepers, 1);
    if (!NtQueryTimerResolution(&coarsest, &finest, &current))
      NtSetTimerResolution(MIN(coarsest, finest), true, &current);
  } else if (atomic_fetch_sub(&g_sleepers, 1) == 1) {
    NtSetTimerResolution(0, false, &current);
  }
}

static textwindows int sys_clock_nanosleep_nt_impl(int clock,
                                                   struct timespec abs,
                                                   sigset_t waitmask) {
  int rc;
  struct timespec now, wall;
  sys_clock_gettime_nt(0, &wall);
  if (sys_clock_gettime_nt(clock, &now))
    return -1;
  if (timespec_cmp(abs, now) > 0)
    wall = timespec_add(wall, timespec_sub(abs, now));
  // not from sys_clock_nanosleep_nt_init(): ntdll imports are bound
  // lazily and WinMain() calls that before they can be
  sys_clock_nanosleep_nt_fast_tick(true);
  rc = _park_norestart(wall, waitmask);
  sys_clock_nanosleep_nt_fast_tick(false);
  return rc;
}

textwindows int sys_clock_nanosleep_nt(int clock, int flags,
                                       const struct timespec *req,
                                       struct timespec *rem) {
  int rc;
  struct timespec abs, now;
  sigset_t m = __sig_block();
  if (flags) {
    abs = *req;
  } else {
    if ((rc = sys_clock_gettime_nt(clock, &now))) {
      rc = _sysret(rc);
      goto BailOut;
    }
    abs = timespec_add(now, *req);
  }
  rc = sys_clock_nanosleep_nt_impl(clock, abs, m);
  if (rc == -1 && !flags && rem && errno == EINTR) {
    sys_clock_gettime_nt(clock, &now);
    *rem = timespec_subz(abs, now);
  }
BailOut:
  __sig_unblock(m);
  return rc;
}

// called by WinMain() if clock_nanosleep() is linked
__msabi textwindows dontinstrument void sys_clock_nanosleep_nt_init(void) {
  __imp_timeBeginPeriod(1);  // make sleep(1ms) not take 15ms
}

#endif /* __x86_64__ */
