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
#include "libc/errno.h"
#include "libc/intrin/weaken.h"
#include "libc/calls/internal.h"
#include "libc/calls/struct/iovec.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/dce.h"
#include "libc/sysv/consts/af.h"
#include "libc/intrin/fds.h"
#include "libc/intrin/kprintf.h"
#include "libc/nt/struct/iovec.h"
#include "libc/nt/winsock.h"
#include "libc/sock/internal.h"
#include "libc/sock/struct/sockaddr.h"
#include "libc/sock/syscall_fd.internal.h"
#include "libc/sysv/consts/msg.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/msg.h"
#if SupportsWindows()

struct RecvFromArgs {
  const struct iovec *iov;
  size_t iovlen;
  void *opt_out_srcaddr;
  uint32_t *opt_inout_srcaddrsize;
  struct NtIovec iovnt[16];
};

textwindows static int sys_recvfrom_nt_start(int64_t handle,
                                             struct NtOverlapped *overlap,
                                             uint32_t *flags, void *arg) {
  struct RecvFromArgs *args = arg;
  return WSARecvFrom(
      handle, args->iovnt, __iovec2nt(args->iovnt, args->iov, args->iovlen), 0,
      flags, args->opt_out_srcaddr, args->opt_inout_srcaddrsize, overlap, 0);
}

textwindows static ssize_t sys_recvfrom_nt_impl(int fd, const struct iovec *iov,
                                                size_t iovlen, uint32_t flags,
                                                void *opt_out_srcaddr,
                                                uint32_t *opt_inout_srcaddrsize) {

  if (__get_pib()->fds.p[fd].family == AF_PACKET)
    return sys_recv_packet_nt(__get_pib()->fds.p + fd, iov, iovlen, flags,
                              opt_out_srcaddr, opt_inout_srcaddrsize);

  if (flags & ~(MSG_DONTWAIT | MSG_OOB | MSG_PEEK))
    return einval();

  ssize_t rc;
  struct Fd *f = __get_pib()->fds.p + fd;
  sigset_t waitmask = __sig_block();
  uint32_t addrcapacity = opt_inout_srcaddrsize ? *opt_inout_srcaddrsize : 0;
  
  bool nonblock = (f->flags & O_NONBLOCK) || (flags & MSG_DONTWAIT);
  if (nonblock && !__winsock_recv_ready(f->handle, flags)) {
    __sig_unblock(waitmask);
    return eagain();
  }
  rc = __winsock_block(f->handle, __msg2host(flags & ~MSG_DONTWAIT), nonblock,
                       f->rcvtimeo, waitmask, sys_recvfrom_nt_start,
                       &(struct RecvFromArgs){iov, iovlen, opt_out_srcaddr,
                                              opt_inout_srcaddrsize});
  if (rc != -1) {
    __unfixsunpath(opt_out_srcaddr, opt_inout_srcaddrsize, addrcapacity);
    if (opt_out_srcaddr && opt_inout_srcaddrsize && *opt_inout_srcaddrsize >= 2)
      ((struct sockaddr *)opt_out_srcaddr)->sa_family =
          __af2linux(((struct sockaddr *)opt_out_srcaddr)->sa_family);
  }
  __sig_unblock(waitmask);
  return rc;
}

textwindows ssize_t sys_recvfrom_nt(int fd, const struct iovec *iov,
                                    size_t iovlen, uint32_t flags,
                                    void *opt_out_srcaddr,
                                    uint32_t *opt_inout_srcaddrsize) {
  ssize_t rc = sys_recvfrom_nt_impl(fd, iov, iovlen, flags, opt_out_srcaddr,
                                    opt_inout_srcaddrsize);
  if ((rc > 0 || (rc == -1 && errno == EAGAIN)) && _weaken(__epoll_rearm_in))
    _weaken(__epoll_rearm_in)(fd);
  return rc;
}

#endif /* __x86_64__ */
