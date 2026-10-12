/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2020 Justine Alexandra Roberts Tunney                              │
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
#include "libc/calls/fifo.internal.h"
#include "libc/sock/struct/msghdr.h"
#include "libc/calls/internal.h"
#include "libc/calls/pty.internal.h"
#include "libc/calls/sig.internal.h"
#include "libc/calls/struct/iovec.h"
#include "libc/calls/struct/sigset.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/calls/syscall-nt.internal.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/atomic.h"
#include "libc/intrin/fds.h"
#include "libc/intrin/kprintf.h"
#include "libc/intrin/nomultics.h"
#include "libc/intrin/pgrp.h"
#include "libc/intrin/weaken.h"
#include "libc/nt/console.h"
#include "libc/nt/enum/consolemodeflags.h"
#include "libc/nt/errors.h"
#include "libc/nt/runtime.h"
#include "libc/sysv/consts/sicode.h"
#include "libc/sysv/consts/sig.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#include "libc/thread/tls.h"
#if SupportsWindows()

static inline void RaiseSignal(int sig) {
  if (_weaken(__sig_raise)) {
    _weaken(__sig_raise)(sig, SI_KERNEL);
  } else {
    TerminateThisProcess(sig);
  }
}

textwindows static ssize_t sys_write_nt_impl(int fd, void *data, size_t size,
                                             ssize_t offset,
                                             uint64_t waitmask) {
  bool isconsole;
  struct Fd *f = __get_pib()->fds.p + fd;

  switch (f->kind) {
    case kFdFile:
    case kFdDevNull:
      isconsole = false;
      break;
    case kFdConsole:
      isconsole = true;
      break;
    case kFdDevRandom:
      // not implemented, XNU returns eperm();
      return eperm();
    default:
      return ebadf();
  }
  if (f->flags & _O_PATH)
    return ebadf();

  // determine win32 handle for writing
  int64_t handle = f->handle;
  if (isconsole && _weaken(GetConsoleOutputHandle))
    handle = _weaken(GetConsoleOutputHandle)();
  if (f->pty && _weaken(__pty_write_handle))
    handle = _weaken(__pty_write_handle)(f);
  bool fifo = f->kind == kFdFile && f->type == kFifoMark &&
              _weaken(__fifo_write_handle_nt);
  if (fifo)
    handle = _weaken(__fifo_write_handle_nt)(f);
  else if (f->kind == kFdFile && f->fifow)
    handle = f->fifow;

  // a cursor position query is answered here rather than by the host,
  // after what comes before it is written, see read-nt.c
  const char *dsr;
  if (isconsole && _weaken(AnswerCursorPositionQuery) &&
      (dsr = memmem(data, size, "\e[6n", 4))) {
    size_t i = dsr - (const char *)data;
    ssize_t rc = i ? sys_write_nt_impl(fd, data, i, offset, waitmask) : 0;
    if (rc != (ssize_t)i)
      return rc;
    _weaken(AnswerCursorPositionQuery)();
    if (size == i + 4)
      return size;
    rc = sys_write_nt_impl(fd, (char *)data + i + 4, size - i - 4,
                           offset, waitmask);
    return rc == -1 ? (ssize_t)(i + 4) : (ssize_t)(i + 4 + rc);
  }

  // intercept ansi tty configuration sequences
  if (isconsole && _weaken(GetConsoleOutputHandle))
    _weaken(InterceptTerminalCommands)(data, size);

  // perform heavy lifting
  ssize_t rc;
  rc = sys_readwrite_nt(fd, data, size, offset, handle, waitmask,
                        (void *)WriteFile);
  // a fifo whose readers left may have new ones on a later pipe
  if (rc == -2 && fifo &&
      (GetLastError() == kNtErrorBrokenPipe ||
       GetLastError() == kNtErrorNoData) &&
      _weaken(__fifo_write_swap_nt)(f))
    rc = sys_readwrite_nt(fd, data, size, offset,
                          _weaken(__fifo_write_handle_nt)(f), waitmask,
                          (void *)WriteFile);
  if (rc != -2)
    return rc;

  // mops up win32 errors
  switch (GetLastError()) {
    // case kNtErrorInvalidHandle:
    //   return ebadf(); /* handled by consts.sh */
    // case kNtErrorNotEnoughQuota:
    //   return edquot(); /* handled by consts.sh */
    case kNtErrorBrokenPipe:  // broken pipe
    case kNtErrorNoData:      // closing named pipe
      // a SOCK_DGRAM or SOCK_SEQPACKET socketpair end, where linux raises
      // no SIGPIPE
      if ((f->mode & 0170000) == 0140000 && _weaken(__msgpipe_gone_nt))
        return _weaken(__msgpipe_gone_nt)(f);
      RaiseSignal(SIGPIPE);
      return epipe();
    case kNtErrorAccessDenied:  // write doesn't return EACCESS
      return ebadf();
    default:
      return __winerr();
  }
}

textwindows static ssize_t sys_write_nt2(int fd, const struct iovec *iov,
                                         size_t iovlen, ssize_t opt_offset,
                                         uint64_t waitmask) {
  ssize_t rc;
  size_t i, total;
  if (opt_offset < -1)
    return einval();
  while (iovlen && !iov[0].iov_len)
    iov++, iovlen--;
  if (iovlen) {
    for (total = i = 0; i < iovlen; ++i) {
      if (!iov[i].iov_len)
        continue;
      rc = sys_write_nt_impl(fd, iov[i].iov_base, iov[i].iov_len, opt_offset,
                             waitmask);
      if (rc == -1) {
        if (total && errno != ECANCELED) {
          return total;
        } else {
          return -1;
        }
      }
      total += rc;
      if (opt_offset != -1)
        opt_offset += rc;
      if (rc < iov[i].iov_len)
        break;
    }
    return total;
  } else {
    return sys_write_nt_impl(fd, NULL, 0, opt_offset, waitmask);
  }
}

textwindows ssize_t sys_write_nt(int fd, const struct iovec *iov, size_t iovlen,
                                 ssize_t opt_offset) {
  ssize_t rc;
  struct Fd *f = __get_pib()->fds.p + fd;
  // a socketpair message from a process that has to say it sent it
  if (f->kind == kFdFile && (f->mode & 0170000) == 0140000 &&
      f->credpid != __get_pib()->pid && opt_offset == -1 &&
      _weaken(__scm_msgpipe_send_nt))
    return _weaken(__scm_msgpipe_send_nt)(
        fd, &(struct msghdr){.msg_iov = (void *)iov, .msg_iovlen = iovlen}, 0);
  sigset_t m = __sig_block();
  if (__get_pib()->fds.p[fd].kind == kFdConsole && __pgrp_tostop() &&
      __ttystop_nt(SIGTTOU, m) == -1)
    rc = -1;
  else
    rc = sys_write_nt2(fd, iov, iovlen, opt_offset, m);
  __sig_unblock(m);
  if (_weaken(__epoll_rearm_out)) {
    size_t want = 0;
    for (size_t i = 0; i < iovlen; ++i)
      want += iov[i].iov_len;
    if ((rc >= 0 && rc < want) || (rc == -1 && errno == EAGAIN))
      _weaken(__epoll_rearm_out)(fd);
  }
  return rc;
}

#endif /* __x86_64__ */
