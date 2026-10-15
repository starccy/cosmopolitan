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
#include "libc/calls/calls.h"
#include "libc/calls/internal.h"
#include "libc/calls/state.internal.h"
#include "libc/calls/struct/rlimit.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/intrin/strace.h"
#include "libc/sysv/consts/close.h"
#include "libc/sysv/consts/f.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"

static int close_range_emu(unsigned first, unsigned last, unsigned flags) {
  if (first > last || (flags & ~(CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE)))
    return einval();
  // only windows tracks every descriptor in the table; elsewhere the
  // kernel owns them, so the walk goes up to the descriptor limit
  unsigned n = __get_pib()->fds.n;
  if (!IsWindows()) {
    struct rlimit rl;
    unsigned lim = 1 << 16;
    if (!getrlimit(RLIMIT_NOFILE, &rl) && rl.rlim_cur < lim)
      lim = rl.rlim_cur;
    if (lim > n)
      n = lim;
  }
  if (last >= n)
    last = n ? n - 1 : 0;
  for (unsigned fd = first; n && fd <= last; ++fd) {
    if (IsWindows() && !__isfdopen(fd))
      continue;
    if (flags & CLOSE_RANGE_CLOEXEC) {
      int fl = fcntl(fd, F_GETFD);
      if (fl != -1)
        fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
    } else {
      close(fd);
    }
  }
  return 0;
}

// a zip descriptor goes through close() for its handle; the rest the
// kernel closes, and their table entries forget any index node
static int close_range_bundle(unsigned first, unsigned last) {
  unsigned start = first;
  for (unsigned fd = first; fd < __get_pib()->fds.n && fd <= last; ++fd) {
    if (__isfdkind(fd, kFdZip)) {
      if (start < fd && sys_close_range(start, fd - 1, 0)) return -1;
      close(fd);
      start = fd + 1;
    }
  }
  return start <= last ? sys_close_range(start, last, 0) : 0;
}

static void forget_nodes(unsigned first, unsigned last) {
  for (unsigned fd = first; fd < __get_pib()->fds.n && fd <= last; ++fd)
    __get_pib()->fds.p[fd].zipdir = 0;
}

/**
 * Closes inclusive range of file descriptors.
 *
 * Linux 5.9+ and FreeBSD 13+ have this as a system call. Elsewhere it
 * walks the descriptor table and closes (or marks) each open entry.
 *
 * The following flags are available:
 *
 * - `CLOSE_RANGE_CLOEXEC` to mark file descriptors as close-on-exec
 *   instead of actually closing them.
 *
 * - `CLOSE_RANGE_UNSHARE` (Linux only) can improve performance in
 *   situations where threads are in play.
 *
 * @return 0 on success, or -1 w/ errno
 * @error EINVAL if flags are bad or first is greater than last
 * @error EMFILE if a weird race condition happens on Linux
 * @error ENOMEM on Linux maybe
 */
int close_range(unsigned int first, unsigned int last, unsigned int flags) {
  int rc;
  if (first > last || (flags & ~(CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE)))
    return einval();
  if (IsLinux() || IsFreebsd()) {
    if (__vforked) return sys_close_range(first, last, flags);
    __fds_lock();
    // a zip handle is process state the kernel table can't carry
    if (flags & CLOSE_RANGE_UNSHARE) {
      for (unsigned i = 0; i < __get_pib()->fds.n; ++i) {
        if (__isfdkind(i, kFdZip)) {
          __fds_unlock();
          return einval();
        }
      }
    }
    if (!(flags & CLOSE_RANGE_CLOEXEC)) {
      unsigned end = last < __get_pib()->fds.n ? last : __get_pib()->fds.n - 1;
      for (unsigned i = first; __get_pib()->fds.n && i <= end; ++i) {
        if (__isfdkind(i, kFdZip)) {
          __fds_unlock();
          rc = close_range_bundle(first, last);
          __fds_lock();
          forget_nodes(first, last);
          __fds_unlock();
          return rc;
        }
      }
      forget_nodes(first, last);
    }
    rc = sys_close_range(first, last, flags);
    __fds_unlock();
  } else {
    rc = close_range_emu(first, last, flags);
  }
  STRACE("close_range(%d, %d, %#x) → %d% m", first, last, flags, rc);
  return rc;
}
