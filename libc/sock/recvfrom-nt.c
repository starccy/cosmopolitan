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
#include "libc/intrin/maps.h"
#include "libc/sock/internal.h"
#include "libc/sock/struct/sockaddr.h"
#include "libc/sock/syscall_fd.internal.h"
#include "libc/sysv/consts/msg.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/msg.h"
#include "libc/atomic.h"
#include "libc/cosmo.h"
#include "libc/nt/enum/wsaid.h"
#include "libc/nt/struct/guid.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/runtime/stack.h"
#include "libc/sock/wsaid.internal.h"
#include "libc/stdio/sysparam.h"
#if SupportsWindows()

#define kNtMsgTrunc  0x0100
#define kNtMsgCtrunc 0x0200

struct RecvFromArgs {
  const struct iovec *iov;
  size_t iovlen;
  void *opt_out_srcaddr;
  uint32_t *opt_inout_srcaddrsize;
  struct NtMsgHdr *msg;
  struct NtIovec iovnt[16];
};

static struct {
  atomic_uint once;
  int (*__msabi fn)(int64_t, struct NtMsgHdr *, uint32_t *,
                    struct NtOverlapped *, NtWsaOverlappedCompletionRoutine);
} g_wsarecvmsg;

textwindows static void wsarecvmsg_init(void) {
  static struct NtGuid guid = WSAID_WSARECVMSG;
  g_wsarecvmsg.fn = __get_wsaid(&guid);
}

textwindows static int sys_recvfrom_nt_msg(int64_t handle,
                                           struct RecvFromArgs *args,
                                           uint32_t flags, uint32_t *got,
                                           struct NtOverlapped *overlap) {
  struct NtMsgHdr *m = args->msg;
  m->name = args->opt_out_srcaddr;
  m->namelen = args->opt_inout_srcaddrsize ? *args->opt_inout_srcaddrsize : 0;
  m->lpBuffers = args->iovnt;
  m->dwBufferCount = __iovec2nt(args->iovnt, args->iov, args->iovlen);
  m->dwFlags = flags;
  cosmo_once(&g_wsarecvmsg.once, wsarecvmsg_init);
  return g_wsarecvmsg.fn(handle, m, got, overlap, 0);
}

textwindows static int sys_recvfrom_nt_start(int64_t handle,
                                             struct NtOverlapped *overlap,
                                             uint32_t *flags, void *arg) {
  struct RecvFromArgs *args = arg;
  if (args->msg)
    return sys_recvfrom_nt_msg(handle, args, *flags, 0, overlap);
  return WSARecvFrom(
      handle, args->iovnt, __iovec2nt(args->iovnt, args->iov, args->iovlen), 0,
      flags, args->opt_out_srcaddr, args->opt_inout_srcaddrsize, overlap, 0);
}

textwindows ssize_t __winsock_recvfrom_nt(int fd, const struct iovec *iov,
                                          size_t iovlen, uint32_t flags,
                                          void *opt_out_srcaddr,
                                          uint32_t *opt_inout_srcaddrsize,
                                          struct NtMsgHdr *msg) {

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
  if (__scm_stream_nt(f)) {
    rc = __scm_recv_nt(f, iov, iovlen, flags, nonblock, waitmask);
    if (opt_inout_srcaddrsize)
      *opt_inout_srcaddrsize = 0;
  } else if (msg && (f->flags & O_NONBLOCK)) {
    uint32_t got;
    struct RecvFromArgs args = {iov, iovlen, opt_out_srcaddr,
                                opt_inout_srcaddrsize, msg};
    if (__winsock_fionbio(f) ||
        sys_recvfrom_nt_msg(f->handle, &args, __msg2host(flags & ~MSG_DONTWAIT),
                            &got, 0)) {
      rc = __winsockerr();
    } else {
      rc = got;
    }
  } else if (f->flags & O_NONBLOCK) {
    rc = __winsock_recv_nonblock(f, iov, iovlen,
                                 __msg2host(flags & ~MSG_DONTWAIT),
                                 opt_out_srcaddr, opt_inout_srcaddrsize);
  } else if (nonblock && !__winsock_recv_ready(f->handle, flags)) {
    rc = eagain();
  } else {
    rc = __winsock_block(f->handle, __msg2host(flags & ~MSG_DONTWAIT),
                         nonblock, f->rcvtimeo, waitmask,
                         sys_recvfrom_nt_start,
                         &(struct RecvFromArgs){iov, iovlen, opt_out_srcaddr,
                                                opt_inout_srcaddrsize, msg});
  }
  bool truncated = false;
  rc = __winsock_dgram_rc(f, rc, iov, iovlen, &truncated);
  if (truncated && msg)
    msg->dwFlags |= kNtMsgTrunc;
  if (rc != -1 && msg && opt_inout_srcaddrsize)
    *opt_inout_srcaddrsize = msg->namelen;
  if (rc != -1) {
    __unfixsunpath(opt_out_srcaddr, opt_inout_srcaddrsize, addrcapacity);
    if (opt_out_srcaddr && opt_inout_srcaddrsize && *opt_inout_srcaddrsize >= 2)
      ((struct sockaddr *)opt_out_srcaddr)->sa_family =
          __af2linux(((struct sockaddr *)opt_out_srcaddr)->sa_family);
  }
  __sig_unblock(waitmask);
  return rc;
}

textwindows static ssize_t sys_recvfrom_nt_rearm(int fd, const struct iovec *iov,
                                                 size_t iovlen, uint32_t flags,
                                                 void *opt_out_srcaddr,
                                                 uint32_t *opt_inout_srcaddrsize,
                                                 struct NtMsgHdr *msg) {
  ssize_t rc;
  if (__udg_nt(__get_pib()->fds.p + fd)) {
    rc = __udg_recv_nt(fd, iov, iovlen, flags, opt_out_srcaddr,
                       opt_inout_srcaddrsize, 0);
  } else {
    rc = __winsock_recvfrom_nt(fd, iov, iovlen, flags, opt_out_srcaddr,
                               opt_inout_srcaddrsize, msg);
    // a receive into memory that's only reserved so far fails with
    // WSAEFAULT rather than faulting it in; commit and try once more
    if (rc == -1 && errno == EFAULT) {
      bool any = false;
      for (size_t i = 0; i < iovlen; ++i)
        if (iov[i].iov_len)
          any |= __nt_commit_range(iov[i].iov_base, iov[i].iov_len);
      if (any)
        rc = __winsock_recvfrom_nt(fd, iov, iovlen, flags, opt_out_srcaddr,
                                   opt_inout_srcaddrsize, msg);
    }
  }
  if ((rc > 0 || (rc == -1 && errno == EAGAIN)) && _weaken(__epoll_rearm_in))
    _weaken(__epoll_rearm_in)(fd);
  return rc;
}

textwindows ssize_t sys_recvfrom_nt(int fd, const struct iovec *iov,
                                    size_t iovlen, uint32_t flags,
                                    void *opt_out_srcaddr,
                                    uint32_t *opt_inout_srcaddrsize) {
  return sys_recvfrom_nt_rearm(fd, iov, iovlen, flags, opt_out_srcaddr,
                               opt_inout_srcaddrsize, 0);
}

// recvmsg() with room for ancillary data on a datagram or raw socket
textwindows ssize_t sys_recvmsg_nt(int fd, struct msghdr *msg,
                                   uint32_t flags) {
  size_t cap = MAX(msg->msg_controllen, 256);
#pragma GCC push_options
#pragma GCC diagnostic ignored "-Walloca-larger-than="
  void *control = alloca(cap);
#pragma GCC pop_options
  CheckLargeStackAllocation(control, cap);
  struct NtMsgHdr m = {.Control = {cap, control}};
  ssize_t rc = sys_recvfrom_nt_rearm(fd, msg->msg_iov, msg->msg_iovlen, flags,
                                     msg->msg_name,
                                     msg->msg_name ? &msg->msg_namelen : 0, &m);
  if (rc == -1)
    return -1;
  bool truncated = !!(m.dwFlags & kNtMsgCtrunc);
  msg->msg_controllen =
      __cmsg2linux_nt(control, m.Control.len, msg->msg_control,
                      msg->msg_controllen, &truncated);
  msg->msg_flags = 0;
  if (truncated)
    msg->msg_flags |= MSG_CTRUNC;
  if (m.dwFlags & kNtMsgTrunc)
    msg->msg_flags |= MSG_TRUNC;
  return rc;
}

#endif /* __x86_64__ */
