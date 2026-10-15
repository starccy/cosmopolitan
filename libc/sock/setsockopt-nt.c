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
#include "libc/calls/struct/timeval.h"
#include "libc/cosmotime.h"
#include "libc/dce.h"
#include "libc/sysv/consts/af.h"
#include "libc/intrin/fds.h"
#include "libc/nt/errors.h"
#include "libc/nt/struct/linger.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/nt/winsock.h"
#include "libc/sock/ifname.h"
#include "libc/sock/internal.h"
#include "libc/sock/sock.h"
#include "libc/sock/struct/ifreq.h"
#include "libc/str/str.h"
#include "libc/sock/struct/linger.h"
#include "libc/sock/syscall_fd.internal.h"
#include "libc/stdio/sysparam.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/ip.h"
#include "libc/sysv/consts/ipproto.h"
#include "libc/sysv/consts/ipv6.h"
#include "libc/sysv/consts/so.h"
#include "libc/sysv/consts/sock.h"
#include "libc/sysv/consts/sol.h"
#include "libc/sysv/consts/udp.h"
#include "libc/sysv/errfuns.h"

#define UDP_RECV_MAX_COALESCED_SIZE_NT 3
#if SupportsWindows()

__msabi extern typeof(__sys_setsockopt_nt) *const __imp_setsockopt;
__msabi extern typeof(__sys_getsockopt_nt) *const __imp_getsockopt;

// options linux takes that winsock refuses with WSAEINVAL, while the
// socket already is the way they ask for
textwindows static bool setsockopt_nt_moot(struct Fd *fd, int level,
                                           int optname, const void *optval,
                                           uint32_t optlen) {
  uint32_t v = 0, len = sizeof(v);
  // an ipv4 option on an ipv6 socket that can't carry ipv4
  if (level == SOL_IP && fd->family == AF_INET6)
    return !__imp_getsockopt(fd->handle, IPPROTO_IPV6,
                             __sockopt2host(SOL_IPV6, IPV6_V6ONLY), &v,
                             &len) &&
           v;
  // IPV6_DONTFRAG after IPV6_MTU_DISCOVER, which decides the bit
  if (level == SOL_IPV6 && optname == IPV6_DONTFRAG && optval &&
      optlen >= sizeof(int) &&
      !__imp_getsockopt(fd->handle, IPPROTO_IPV6,
                        __sockopt2host(SOL_IPV6, IPV6_MTU_DISCOVER), &v,
                        &len) &&
      v)
    return !!*(const int *)optval == (v != __pmtudisc2nt(IP_PMTUDISC_DONT));
  return false;
}

textwindows int sys_setsockopt_nt(struct Fd *fd, int level, int optname,
                                  const void *optval, uint32_t optlen) {

  // every SOL_PACKET option is either already true of an SIO_RCVALL
  // capture (promiscuous mode) or a tuning knob with no nt counterpart
  // (fanout, ring buffers); failing them would abort a capture that's
  // about to work
  if (fd->family == AF_PACKET && level == SOL_PACKET)
    return 0;

  // socket read/write timeouts
  // timeout of zero means wait forever (default)
  if (level == SOL_SOCKET &&
      (optname == SO_RCVTIMEO || optname == SO_SNDTIMEO)) {
    if (!optval)
      return einval();
    if (optlen < sizeof(struct timeval))
      return einval();
    const struct timeval *tv = optval;
    int64_t ms = timeval_tomillis(*tv);
    if (ms > -1u)
      ms = -1u;
    if (optname == SO_RCVTIMEO)
      fd->rcvtimeo = ms;
    if (optname == SO_SNDTIMEO)
      fd->sndtimeo = ms;
    return 0;  // we want to handle this on our own
  }

  // how to make close() a blocking i/o call lool
  union {
    uint32_t millis;
    struct linger_nt linger;
  } u;
  if (level == SOL_SOCKET &&             //
      optname == SO_LINGER && optval &&  //
      optlen == sizeof(struct linger)) {
    const struct linger *linger = optval;
    u.linger.l_onoff = linger->l_onoff;
    u.linger.l_linger = MIN(0xFFFF, MAX(0, linger->l_linger));
    optval = &u.linger;
    optlen = sizeof(u.linger);
  }

  // winsock binds a socket to an interface by index, with IP_UNICAST_IF
  // in network byte order for ipv4 and IPV6_UNICAST_IF for ipv6, which
  // a dual-stack socket needs both of
  if (level == SOL_SOCKET && optname == SO_BINDTODEVICE) {
    char name[IFNAMSIZ] = {0};
    uint32_t idx = 0, idx4;
    if (optval)
      memcpy(name, optval, MIN(optlen, sizeof(name) - 1));
    if (*name && !(idx = if_nametoindex(name)))
      return enodev();
    idx4 = htonl(idx);
    if (fd->family == AF_INET6) {
      if (__imp_setsockopt(fd->handle, IPPROTO_IPV6, 31, &idx, sizeof(idx)) ==
          -1)
        return __winsockerr();
      __imp_setsockopt(fd->handle, IPPROTO_IP, 31, &idx4, sizeof(idx4));
      return 0;
    }
    if (__imp_setsockopt(fd->handle, IPPROTO_IP, 31, &idx4, sizeof(idx4)) == -1)
      return __winsockerr();
    return 0;
  }

  // winsock has no SO_REUSEPORT and its SO_REUSEADDR already lets a
  // port be bound again
  if (level == SOL_SOCKET && optname == SO_REUSEPORT) {
    if (optlen < sizeof(int))
      return einval();
    fd->reuseport = !!*(const int *)optval;
    return 0;
  }

  // winsock has no IPV6_TCLASS; the value is kept for getsockopt()
  if (level == SOL_IPV6 && optname == IPV6_TCLASS) {
    if (fd->family != AF_INET6)
      return enoprotoopt();
    if (optlen < sizeof(int))
      return einval();
    fd->tclass = *(const int *)optval;
    return 0;
  }

  // linux's UDP_GRO is a boolean; winsock coalesces up to a byte count
  // given with UDP_RECV_MAX_COALESCED_SIZE, which only WSARecvMsg()
  // honors. the coalesced size comes back as UDP_COALESCED_INFO and
  // cmsg-nt.c turns it into linux's UDP_GRO control message
  uint32_t coalesced;
  if (level == SOL_UDP && optname == UDP_GRO) {
    if (fd->type != SOCK_DGRAM)
      return enoprotoopt();
    if (!optval || optlen < sizeof(int))
      return einval();
    coalesced = *(const int *)optval ? 65535 : 0;
    if (__imp_setsockopt(fd->handle, IPPROTO_UDP, UDP_RECV_MAX_COALESCED_SIZE_NT,
                         &coalesced, sizeof(coalesced)) == -1)
      return __winsockerr();
    return 0;
  }

  int pmtud;
  if (__is_pmtudisc(level, optname) && optval && optlen >= sizeof(int)) {
    pmtud = __pmtudisc2nt(*(const int *)optval);
    optval = &pmtud;
    optlen = sizeof(pmtud);
  }

  int hopt = __sockopt2host(level, optname);
  if (!hopt)
    return enoprotoopt();
  if (__imp_setsockopt(fd->handle, __sol2host(level), hopt, optval, optlen) !=
      -1)
    return 0;
  int err = WSAGetLastError();
  if (err == WSAEINVAL &&
      setsockopt_nt_moot(fd, level, optname, optval, optlen))
    return 0;
  WSASetLastError(err);
  if (WSAGetLastError() == WSAEINVAL && fd->connecting == 1 && optval &&
      optlen == sizeof(int) &&
      __sockopt_park(fd->handle, level, optname, *(const int *)optval))
    return 0;
  return __winsockerr();
}

#endif /* __x86_64__ */
