/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2023 Justine Alexandra Roberts Tunney                              │
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
#include "libc/stdio/syscall.h"
#include "libc/calls/calls.h"
#include "libc/calls/struct/timespec.h"
#include "libc/cosmotime.h"
#include "libc/cosmo.h"
#include "libc/errno.h"
#include "libc/stdio/rand.h"
#include "libc/sysv/consts/clock.h"
#include "libc/sysv/errfuns.h"

// linux's own numbers, since this emulates its abi
#define FUTEX_WAIT_linux             0
#define FUTEX_WAKE_linux             1
#define FUTEX_WAIT_BITSET_linux      9
#define FUTEX_WAKE_BITSET_linux      10
#define FUTEX_PRIVATE_FLAG_linux     128
#define FUTEX_CLOCK_REALTIME_linux   256
#define FUTEX_BITSET_MATCH_ANY_linux 0xffffffffu

// FUTEX_WAIT takes a relative timeout and FUTEX_WAIT_BITSET an absolute
// one on the clock the flags name; cosmo_futex_wait() wants absolute.
// Only the whole-bitset forms exist, which is what mutexes issue.
static long sys_futex_emul(va_list va) {
  int rc;
  cosmo_futex_t *addr = va_arg(va, void *);
  int op = va_arg(va, int);
  int val = va_arg(va, int);
  const struct timespec *ts = va_arg(va, const struct timespec *);
  va_arg(va, void *);
  unsigned bitset = va_arg(va, unsigned);
  int cmd = op & ~(FUTEX_PRIVATE_FLAG_linux | FUTEX_CLOCK_REALTIME_linux);
  char pshare = !(op & FUTEX_PRIVATE_FLAG_linux);
  int clock =
      (op & FUTEX_CLOCK_REALTIME_linux) ? CLOCK_REALTIME : CLOCK_MONOTONIC;
  switch (cmd) {
    case FUTEX_WAIT_linux: {
      struct timespec abs, *deadline = 0;
      if (ts) {
        clock_gettime(clock, &abs);
        abs = timespec_add(abs, *ts);
        deadline = &abs;
      }
      rc = cosmo_futex_wait(addr, val, pshare, clock, deadline);
      break;
    }
    case FUTEX_WAIT_BITSET_linux:
      if (bitset != FUTEX_BITSET_MATCH_ANY_linux)
        return enosys();
      rc = cosmo_futex_wait(addr, val, pshare, clock, ts);
      break;
    case FUTEX_WAKE_BITSET_linux:
      if (bitset != FUTEX_BITSET_MATCH_ANY_linux)
        return enosys();
      // fallthrough
    case FUTEX_WAKE_linux:
      rc = cosmo_futex_wake(addr, val, pshare);
      break;
    default:
      return enosys();
  }
  if (rc < 0) {
    errno = -rc;
    return -1;
  }
  return rc;
}

/**
 * Translation layer for some Linux system calls:
 *
 * - `SYS_gettid`
 * - `SYS_getrandom`
 * - `SYS_getcpu`
 * - `SYS_futex` (wait, wake and their whole-bitset forms)
 * - `SYS_fchmod`, `SYS_fchown`, `SYS_fchmodat`, `SYS_copy_file_range`
 *
 * @return system call result, or -1 w/ errno
 */
long syscall(long number, ...) {
  switch (number) {
    default:
      errno = ENOSYS;
      return -1;
    case SYS_futex: {
      va_list va;
      va_start(va, number);
      long rc = sys_futex_emul(va);
      va_end(va);
      return rc;
    }
    case SYS_fchmod: {
      va_list va;
      va_start(va, number);
      int fd = va_arg(va, int);
      unsigned mode = va_arg(va, unsigned);
      va_end(va);
      return fchmod(fd, mode);
    }
    case SYS_fchown: {
      va_list va;
      va_start(va, number);
      int fd = va_arg(va, int);
      unsigned uid = va_arg(va, unsigned);
      unsigned gid = va_arg(va, unsigned);
      va_end(va);
      return fchown(fd, uid, gid);
    }
    case SYS_fchmodat: {
      // the three argument form, since the kernel has no flags word here
      va_list va;
      va_start(va, number);
      int dirfd = va_arg(va, int);
      const char *path = va_arg(va, const char *);
      unsigned mode = va_arg(va, unsigned);
      va_end(va);
      return fchmodat(dirfd, path, mode, 0);
    }
    case SYS_copy_file_range: {
      va_list va;
      va_start(va, number);
      int in = va_arg(va, int);
      long *inoff = va_arg(va, long *);
      int out = va_arg(va, int);
      long *outoff = va_arg(va, long *);
      size_t len = va_arg(va, size_t);
      unsigned flags = va_arg(va, unsigned);
      va_end(va);
      return copy_file_range(in, inoff, out, outoff, len, flags);
    }
    case SYS_gettid:
      return gettid();
    case SYS_getrandom: {
      va_list va;
      va_start(va, number);
      void *buf = va_arg(va, void *);
      size_t buflen = va_arg(va, size_t);
      unsigned flags = va_arg(va, unsigned);
      va_end(va);
      return getrandom(buf, buflen, flags);
    }
    case SYS_getcpu: {
      va_list va;
      va_start(va, number);
      unsigned *cpu = va_arg(va, unsigned *);
      unsigned *node = va_arg(va, unsigned *);
      va_end(va);
      return getcpu(cpu, node);
    }
  }
}
