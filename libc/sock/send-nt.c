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
#include "libc/calls/internal.h"
#include "libc/calls/sig.internal.h"
#include "libc/calls/struct/iovec.internal.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/weaken.h"
#include "libc/intrin/kprintf.h"
#include "libc/nt/errors.h"
#include "libc/nt/struct/iovec.h"
#include "libc/nt/struct/overlapped.h"
#include "libc/nt/winsock.h"
#include "libc/sock/internal.h"
#include "libc/sysv/consts/fio.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/msg.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/sicode.h"
#include "libc/sysv/consts/sig.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#include "libc/vga/vga.internal.h"
#if SupportsWindows()

struct SendArgs {
  const struct iovec *iov;
  size_t iovlen;
  struct NtIovec iovnt[16];
};

textwindows static int sys_send_nt_start(int64_t handle,
                                         struct NtOverlapped *overlap,
                                         uint32_t *flags, void *arg) {
  struct SendArgs *args = arg;
  return WSASend(handle, args->iovnt,
                 __iovec2nt(args->iovnt, args->iov, args->iovlen), 0, *flags,
                 overlap, 0);
}

__msabi extern typeof(__sys_ioctlsocket_nt) *const __imp_ioctlsocket;

// puts the socket in winsock's nonblocking mode, which only changes
// calls made without an overlapped structure
textwindows int __winsock_fionbio(struct Fd *f) {
  int pid = __get_pib()->pid;
  if (f->fionbio == f->handle && f->fionbio_pid == pid)
    return 0;
  if (__imp_ioctlsocket(f->handle, __ioctl2host(FIONBIO), (uint32_t[]){1}))
    return -1;
  f->fionbio = f->handle;
  f->fionbio_pid = pid;
  return 0;
}

// a send that fails with WSAEWOULDBLOCK when there's no room, rather
// than one that waits. afd tells epoll the socket is writable again only
// after such a failure, so a nonblocking send has to actually try
textwindows ssize_t __winsock_send_nonblock(struct Fd *f,
                                            const struct iovec *iov,
                                            size_t iovlen, uint32_t flags,
                                            const void *addr,
                                            uint32_t addrsize) {
  struct NtIovec iovnt[16];
  uint32_t sent;
  if (__winsock_fionbio(f))
    return __winsockerr();
  if (WSASendTo(f->handle, iovnt, __iovec2nt(iovnt, iov, iovlen), &sent,
                flags, addr, addrsize, 0, 0))
    return __winsockerr();
  return sent;
}

textwindows static ssize_t sys_send_nt_impl(int fd, const struct iovec *iov,
                                            size_t iovlen, uint32_t flags) {

  if (flags & ~(MSG_DONTWAIT | MSG_OOB | MSG_DONTROUTE | MSG_NOSIGNAL))
    return einval();

  if (iovlen) {
    if (kisdangerous(iov))
      return efault();
    for (int i = 0; i < iovlen; ++i)
      if (iov[i].iov_len && kisdangerous(iov[i].iov_base))
        return efault();
  }

  ssize_t rc;
  struct iovec clamped[16];
  struct Fd *f = __get_pib()->fds.p + fd;
  if (__udg_nt(f))
    return __udg_sendto_nt(fd, iov, iovlen, flags, 0, 0, 0);
  uint32_t hostflags = __msg2host(flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL));
  __sockopt_replay(f);
  if (f->flags & O_NONBLOCK) {
    iovlen = __winsock_clamp_send(clamped, iov, iovlen);
    rc = __winsock_send_nonblock(f, clamped, iovlen, hostflags, 0, 0);
  } else {
    // MSG_DONTWAIT on a blocking socket can't change its mode under
    // another thread's blocking call, so it asks WSAPoll instead
    if (flags & MSG_DONTWAIT) {
      if (!__winsock_send_ready(f->handle))
        return eagain();
      iovlen = __winsock_clamp_send(clamped, iov, iovlen);
      iov = clamped;
    }
    sigset_t waitmask = __sig_block();
    rc = __winsock_block(f->handle, hostflags, false, f->sndtimeo, waitmask,
                         sys_send_nt_start, &(struct SendArgs){iov, iovlen});
    __sig_unblock(waitmask);
  }
  rc = __winsock_dgram_rc(f, rc, 0, 0, 0);

  if (rc == -1 && (errno == ESHUTDOWN ||      // WSAESHUTDOWN
                   errno == ECONNABORTED)) {  // WSAECONNABORTED
    errno = EPIPE;
    if (!(flags & MSG_NOSIGNAL))
      __sig_raise(SIGPIPE, SI_KERNEL);
  }

  return rc;
}

textwindows ssize_t sys_send_nt(int fd, const struct iovec *iov, size_t iovlen,
                                uint32_t flags) {
  ssize_t rc = sys_send_nt_impl(fd, iov, iovlen, flags);
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
