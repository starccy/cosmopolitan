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
#include "libc/calls/internal.h"
#include "libc/calls/sig.internal.h"
#include "libc/calls/struct/iovec.h"
#include "libc/calls/struct/iovec.internal.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/weaken.h"
#include "libc/intrin/fds.h"
#include "libc/intrin/kprintf.h"
#include "libc/nt/errors.h"
#include "libc/nt/struct/iovec.h"
#include "libc/nt/winsock.h"
#include "libc/sock/internal.h"
#include "libc/sock/struct/sockaddr.h"
#include "libc/sock/syscall_fd.internal.h"
#include "libc/sysv/consts/af.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/msg.h"
#include "libc/sysv/consts/sicode.h"
#include "libc/sysv/consts/sig.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#if SupportsWindows()

struct SendToArgs {
  const struct iovec *iov;
  size_t iovlen;
  const void *opt_in_addr;
  uint32_t in_addrsize;
  struct NtIovec iovnt[16];
};

textwindows static int sys_sendto_nt_start(int64_t handle,
                                           struct NtOverlapped *overlap,
                                           uint32_t *flags, void *arg) {
  struct SendToArgs *args = arg;
  return WSASendTo(handle, args->iovnt,
                   __iovec2nt(args->iovnt, args->iov, args->iovlen), 0, *flags,
                   args->opt_in_addr, args->in_addrsize, overlap, 0);
}

textwindows static ssize_t sys_sendto_nt_impl(int fd, const struct iovec *iov,
                                              size_t iovlen, uint32_t flags,
                                              const void *opt_in_addr,
                                              uint32_t in_addrsize) {

  if (flags & ~(MSG_DONTWAIT | MSG_OOB | MSG_DONTROUTE | MSG_NOSIGNAL))
    return einval();

  // normalize unix socket filenames
  struct sockaddr_un sun;
  if (__fixsunpath(&sun, &opt_in_addr, &in_addrsize) == -1)
    return -1;

  // windows has *some* support for AF_UNIX but it might have a
  // different idea about the current directory than cosmo does
  if (in_addrsize >= 2 &&
      ((struct sockaddr *)opt_in_addr)->sa_family == AF_UNIX)
    return eafnosupport();

  struct sockaddr_storage ss;
  opt_in_addr = __sockaddr2nt(opt_in_addr, in_addrsize, &ss);

  ssize_t rc;
  struct iovec clamped[16];
  struct Fd *f = __get_pib()->fds.p + fd;
  __sockopt_replay(f);
  if ((f->flags & O_NONBLOCK) || (flags & MSG_DONTWAIT)) {
    if (!__winsock_send_ready(f->handle))
      return eagain();
    iovlen = __winsock_clamp_send(clamped, iov, iovlen);
    iov = clamped;
  }
  sigset_t waitmask = __sig_block();

  rc = __winsock_block(f->handle, __msg2host(flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL)),
                       false, f->sndtimeo, waitmask, sys_sendto_nt_start,
                       &(struct SendToArgs){iov, iovlen,  //
                                            opt_in_addr, in_addrsize});

  __sig_unblock(waitmask);

  if (rc == -1 && (errno == ESHUTDOWN ||      // WSAESHUTDOWN
                   errno == ECONNABORTED)) {  // WSAECONNABORTED
    errno = EPIPE;
    if (!(flags & MSG_NOSIGNAL))
      __sig_raise(SIGPIPE, SI_KERNEL);
  }

  return rc;
}

textwindows ssize_t sys_sendto_nt(int fd, const struct iovec *iov,
                                  size_t iovlen, uint32_t flags,
                                  const void *opt_in_addr,
                                  uint32_t in_addrsize) {
  ssize_t rc = sys_sendto_nt_impl(fd, iov, iovlen, flags, opt_in_addr,
                                  in_addrsize);
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
