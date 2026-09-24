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
#include "libc/assert.h"
#include "libc/calls/calls.h"
#include "libc/errno.h"
#include "libc/intrin/strace.h"
#include "libc/runtime/runtime.h"
#include "libc/runtime/utmp.h"
#include "libc/sysv/consts/termios.h"

/**
 * Prepares terminal for login.
 *
 * After this operation `fd` will be used for all stdio handles.
 *
 * On Windows `fd` must be the slave side of an openpty() pair; the
 * process then becomes a pty child when it execs.
 *
 * @return 0 on success, or -1 w/ errno
 * @raise EPERM if terminal is already controlling another sid?
 * @raise EPERM if pledge() was used without tty
 * @raise ENOTTY if `fd` isn't a teletypewriter
 * @raise EBADF if `fd` isn't open
 */
int login_tty(int fd) {
  int rc;
  if (!isatty(fd)) {
    rc = -1;  // validate before changing the process's state
  } else {
    // become session leader
    // we don't care if it fails due to already being the one
    int e = errno;
    setsid();
    errno = e;
    // take control of teletypewriter (requires being leader)
    if ((rc = ioctl(fd, TIOCSCTTY, 0)) != -1) {
      unassert(dup2(fd, 0) == 0);
      unassert(dup2(fd, 1) == 1);
      unassert(dup2(fd, 2) == 2);
      if (fd > 2) {
        unassert(!close(fd));
      }
      rc = 0;
    }
  }
  STRACE("login_tty(%d) → %d% m", fd, rc);
  return rc;
}
