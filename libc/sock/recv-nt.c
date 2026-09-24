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
#include "libc/calls/struct/sigset.internal.h"
#include "libc/dce.h"
#include "libc/sysv/consts/af.h"
#include "libc/intrin/kprintf.h"
#include "libc/nt/struct/iovec.h"
#include "libc/nt/struct/overlapped.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/nt/winsock.h"
#include "libc/sock/internal.h"
#include "libc/sock/syscall_fd.internal.h"
#include "libc/sysv/consts/fio.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/msg.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#include "libc/vga/vga.internal.h"
#include "libc/errno.h"
#include "libc/intrin/weaken.h"
#include "libc/nt/errors.h"
#if SupportsWindows()

__msabi extern typeof(__sys_ioctlsocket_nt) *const __imp_ioctlsocket;

struct RecvArgs {
  const struct iovec *iov;
  size_t iovlen;
  struct NtIovec iovnt[16];
};

textwindows static int sys_recv_nt_start(int64_t handle,
                                         struct NtOverlapped *overlap,
                                         uint32_t *flags, void *arg) {
  struct RecvArgs *args = arg;
  return WSARecv(handle, args->iovnt,
                 __iovec2nt(args->iovnt, args->iov, args->iovlen), 0, flags,
                 overlap, 0);
}

textwindows static ssize_t sys_recv_nt_impl(int fd, const struct iovec *iov,
                                            size_t iovlen, uint32_t flags) {

  if (__get_pib()->fds.p[fd].family == AF_PACKET)
    return sys_recv_packet_nt(__get_pib()->fds.p + fd, iov, iovlen, flags, 0,
                              0);

  if (flags & ~(MSG_DONTWAIT | MSG_OOB | MSG_PEEK | MSG_WAITALL))
    return einval();

  if (iovlen) {
    if (kisdangerous(iov))
      return efault();
    for (int i = 0; i < iovlen; ++i)
      if (iov[i].iov_len && kisdangerous(iov[i].iov_base))
        return efault();
  }

  ssize_t rc;
  struct Fd *f = __get_pib()->fds.p + fd;
  sigset_t waitmask = __sig_block();

  // "Be aware that if the underlying transport provider does not
  //  support MSG_WAITALL, or if the socket is in a non-blocking mode,
  //  then this call will fail with WSAEOPNOTSUPP. Also, if MSG_WAITALL
  //  is specified along with MSG_OOB, MSG_PEEK, or MSG_PARTIAL, then
  //  this call will fail with WSAEOPNOTSUPP."
  //                             —Quoth MSDN § WSARecv
  if (flags & MSG_WAITALL)
    __imp_ioctlsocket(f->handle, __ioctl2host(FIONBIO), (uint32_t[]){0});

  bool nonblock = (f->flags & O_NONBLOCK) || (flags & MSG_DONTWAIT);
  if (nonblock && !__winsock_recv_ready(f->handle, flags)) {
    __sig_unblock(waitmask);
    return eagain();
  }

  rc = __winsock_block(f->handle, __msg2host(flags & ~MSG_DONTWAIT), nonblock,
                       f->rcvtimeo, waitmask, sys_recv_nt_start,
                       &(struct RecvArgs){iov, iovlen});

  if (rc == -1 && errno == kNtErrorHandleEof)
    rc = 0;

  __sig_unblock(waitmask);

  return rc;
}

textwindows ssize_t sys_recv_nt(int fd, const struct iovec *iov, size_t iovlen,
                                uint32_t flags) {
  ssize_t rc = sys_recv_nt_impl(fd, iov, iovlen, flags);
  if ((rc > 0 || (rc == -1 && errno == EAGAIN)) && _weaken(__epoll_rearm_in))
    _weaken(__epoll_rearm_in)(fd);
  return rc;
}

#endif /* __x86_64__ */
