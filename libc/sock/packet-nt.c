#include "libc/calls/internal.h"
#include "libc/calls/struct/iovec.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/fds.h"
#include "libc/mem/mem.h"
#include "libc/nt/enum/sio.h"
#include "libc/nt/errors.h"
#include "libc/nt/iphlpapi.h"
#include "libc/nt/struct/iovec.h"
#include "libc/nt/struct/ipadapteraddresses.h"
#include "libc/nt/struct/overlapped.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/nt/winsock.h"
#include "libc/sock/internal.h"
#include "libc/sock/sock.h"
#include "libc/sock/struct/sockaddr.h"
#include "libc/sock/struct/sockaddr6.h"
#include "libc/sock/struct/sockaddr_ll.h"
#include "libc/sock/syscall_fd.internal.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/af.h"
#include "libc/sysv/consts/ipproto.h"
#include "libc/sysv/consts/msg.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/packet.h"
#include "libc/sysv/consts/sock.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#if SupportsWindows()

/**
 * @fileoverview AF_PACKET on Windows.
 *
 * NT has nothing like a packet socket. A raw IP socket switched into
 * SIO_RCVALL mode sees every IP packet an interface carries, so that is
 * what stands in for one: socket() hands out a raw AF_INET socket marked
 * as AF_PACKET, bind() looks the interface up and turns the capture on,
 * and recv() puts the Ethernet header a caller expects back in front of
 * each packet (or leaves it off for SOCK_DGRAM, the cooked form). One raw
 * socket carries one address family, so an interface with an IPv6
 * address gets a second, hidden socket, which poll() watches alongside
 * the visible one. Frames can't be sent, and there are no MAC addresses
 * to report: the capture happens above the link layer.
 */

#define NT_AF_INET6 23
#define ETH_HLEN    14
#define DRAIN_MAX   64

__msabi extern typeof(__sys_bind_nt) *const __imp_bind;
__msabi extern typeof(__sys_closesocket_nt) *const __imp_closesocket;

struct PacketAddrs {
  bool have4, have6;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;  // nt's layout, family 23
};

struct PacketRecvArgs {
  void *buf;
  size_t len;
  struct NtIovec iov;
};

textwindows int sys_socket_packet_nt(int type, int protocol) {
  int truetype = type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK);
  if (truetype != SOCK_RAW && truetype != SOCK_DGRAM)
    return esocktnosupport();
  // EACCES here means "not an administrator"
  int fd = sys_socket_nt(AF_INET, SOCK_RAW | (type & (SOCK_CLOEXEC | SOCK_NONBLOCK)),
                         IPPROTO_IP);
  if (fd == -1)
    return -1;
  struct Fd *f = __get_pib()->fds.p + fd;
  f->family = AF_PACKET;
  f->type = truetype;
  f->protocol = protocol;
  f->pkthandle6 = 0;
  f->pktifindex = 0;
  f->pktturn = 0;
  return fd;
}

// both addresses of the adapter whose IfIndex is ifindex, which is the
// number if_nametoindex() reports. a link-local ipv6 address works only
// with its scope, so a global one is preferred and the scope filled in
// either way
textwindows static bool GetAdapterAddrs(unsigned ifindex,
                                        struct PacketAddrs *out) {
  bzero(out, sizeof(*out));
  uint32_t flags = kNtGaaFlagSkipAnycast | kNtGaaFlagSkipMulticast |
                   kNtGaaFlagSkipDnsServer;
  uint32_t size = 0;
  GetAdaptersAddresses(0, flags, 0, 0, &size);
  if (!size)
    return false;
  struct NtIpAdapterAddresses *aa = malloc(size);
  if (!aa)
    return false;
  bool found = false;
  if (!GetAdaptersAddresses(0, flags, 0, aa, &size)) {
    for (struct NtIpAdapterAddresses *p = aa; p; p = p->Next) {
      if (p->IfIndex != ifindex)
        continue;
      found = true;
      bool v6_global = false;
      for (struct NtIpAdapterUnicastAddress *u = p->FirstUnicastAddress; u;
           u = u->Next) {
        struct sockaddr *sa = u->Address.lpSockaddr;
        if (!sa)
          continue;
        if (sa->sa_family == AF_INET && !out->have4) {
          memcpy(&out->a4, sa, sizeof(out->a4));
          out->a4.sin_port = 0;
          out->have4 = true;
        } else if (sa->sa_family == NT_AF_INET6 && !v6_global) {
          struct sockaddr_in6 s6;
          memcpy(&s6, sa, sizeof(s6));
          s6.sin6_port = 0;
          bool link_local = s6.sin6_addr.s6_addr[0] == 0xfe &&
                            (s6.sin6_addr.s6_addr[1] & 0xc0) == 0x80;
          if (out->have6 && link_local)
            continue;
          if (!s6.sin6_scope_id)
            s6.sin6_scope_id = p->Ipv6IfIndex ? p->Ipv6IfIndex : ifindex;
          out->a6 = s6;
          out->have6 = true;
          v6_global = !link_local;
        }
      }
      break;
    }
  }
  free(aa);
  return found;
}

// bind + SIO_RCVALL. the addresses are already in nt's layout
textwindows static int SniffOn(int64_t h, const void *sa, uint32_t len) {
  if (__imp_bind(h, sa, len) == -1)
    return __winsockerr();
  uint32_t on = 1, got = 0, unused;
  if (WSAIoctl(h, kNtSioRcvall, &on, sizeof(on), &unused, 0, &got, 0, 0))
    return __winsockerr();
  return 0;
}

textwindows int sys_bind_packet_nt(struct Fd *f, const void *addr,
                                   uint32_t addrsize) {
  if (!addr || addrsize < 8)
    return einval();
  const struct sockaddr_ll *sll = addr;
  // "every interface" has no nt form
  if (sll->sll_ifindex <= 0)
    return einval();
  struct PacketAddrs ia;
  if (!GetAdapterAddrs(sll->sll_ifindex, &ia))
    return enodev();
  int err4 = 0;
  bool ok4 = false;
  if (ia.have4) {
    if (!SniffOn(f->handle, &ia.a4, sizeof(ia.a4)))
      ok4 = true;
    else
      err4 = errno;
  } else {
    err4 = EADDRNOTAVAIL;
  }
  // the ipv6 half is best effort: an adapter without an ipv6 address, or
  // a host that refuses SIO_RCVALL on one, simply reports no ipv6 traffic
  int64_t h6 = 0;
  if (ia.have6) {
    h6 = WSASocket(NT_AF_INET6, SOCK_RAW, IPPROTO_IPV6, 0, 0,
                   kNtWsaFlagOverlapped);
    if (h6 == -1) {
      h6 = 0;
    } else if (SniffOn(h6, &ia.a6, sizeof(ia.a6))) {
      __imp_closesocket(h6);
      h6 = 0;
    }
  }
  if (!ok4 && !h6) {
    errno = err4 ? err4 : EADDRNOTAVAIL;
    return -1;
  }
  if (f->pkthandle6)
    __imp_closesocket(f->pkthandle6);
  f->pkthandle6 = h6;
  f->pktifindex = sll->sll_ifindex;
  f->isbound = true;
  return 0;
}

textwindows static int PacketRecvStart(int64_t handle,
                                       struct NtOverlapped *overlap,
                                       uint32_t *flags, void *arg) {
  struct PacketRecvArgs *a = arg;
  a->iov.len = a->len;
  a->iov.buf = a->buf;
  return WSARecv(handle, &a->iov, 1, 0, flags, overlap, 0);
}

// one ip packet from handle, framed at the front of buf. returns the
// framed length, or -1 with EAGAIN when the socket is dry. *consumed
// counts datagrams taken off the socket, framed or not; *bad is set when
// one wasn't an ip header at all
textwindows static ssize_t RecvFramed(int64_t handle, unsigned char *buf,
                                      size_t n, int hdr, bool nonblock,
                                      uint32_t timeout, sigset_t waitmask,
                                      int *consumed, bool *bad,
                                      unsigned *ethertype) {
  for (int i = 0; i < DRAIN_MAX; i++) {
    ssize_t r = __winsock_block(handle, 0, nonblock, timeout, waitmask,
                                PacketRecvStart,
                                &(struct PacketRecvArgs){buf + hdr, n - hdr});
    if (r == -1 && errno == kNtErrorHandleEof)
      r = 0;
    if (r < 0)
      return -1;
    (*consumed)++;
    if (!r)
      continue;
    unsigned ver = buf[hdr] >> 4;
    if (ver == 4 && r >= 20) {
      *ethertype = ETH_P_IP;
    } else if (ver == 6 && r >= 40) {
      *ethertype = ETH_P_IPV6;
    } else {
      *bad = true;
      continue;
    }
    if (hdr) {
      // no MACs: the capture is above the link layer
      bzero(buf, 12);
      buf[12] = *ethertype >> 8;
      buf[13] = *ethertype;
    }
    return r + hdr;
  }
  return eagain();
}

// waits for either capture to have something, in slices so signals and
// cancelation are noticed. timeout is in millis, 0 meaning forever
textwindows static int WaitEither(int64_t h4, int64_t h6, uint32_t timeout,
                                  sigset_t waitmask) {
  struct sys_pollfd_nt p[2] = {{h4, 0x0100, 0}, {h6, 0x0100, 0}};
  uint32_t waited = 0;
  for (;;) {
    if (__sigcheck(waitmask, false))
      return -1;
    uint32_t slice = 50;
    if (timeout && timeout - waited < slice)
      slice = timeout - waited;
    int r = WSAPoll(p, 2, slice);
    if (r == -1)
      return __winsockerr();
    if (r)
      return 0;
    waited += slice;
    if (timeout && waited >= timeout)
      return eagain();
  }
}

// the address a packet socket reports is the interface it's bound to,
// which is the whole of it: there are no link-layer addresses here
textwindows static void FillSockaddrLl(struct Fd *f, unsigned ethertype,
                                       void *addr, uint32_t *addrsize) {
  if (!addr || !addrsize)
    return;
  struct sockaddr_ll sll;
  bzero(&sll, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = ethertype >> 8 | (ethertype & 255) << 8;
  sll.sll_ifindex = f->pktifindex;
  sll.sll_hatype = 1;  // ARPHRD_ETHER
  memcpy(addr, &sll, *addrsize < sizeof(sll) ? *addrsize : sizeof(sll));
  *addrsize = sizeof(sll);
}

textwindows ssize_t sys_recv_packet_nt(struct Fd *f, const struct iovec *iov,
                                       size_t iovlen, uint32_t flags,
                                       void *addr, uint32_t *addrsize) {
  if (flags & ~(MSG_DONTWAIT | MSG_TRUNC))
    return einval();
  int hdr = f->type == SOCK_DGRAM ? 0 : ETH_HLEN;

  // the caller's buffer, or a scratch one scattered afterwards
  unsigned char *buf;
  size_t n = 0;
  void *scratch = 0;
  if (iovlen == 1) {
    buf = iov[0].iov_base;
    n = iov[0].iov_len;
  } else {
    for (size_t i = 0; i < iovlen; i++)
      n += iov[i].iov_len;
    if (!(scratch = malloc(n)))
      return enomem();
    buf = scratch;
  }
  if (n <= hdr) {
    free(scratch);
    return einval();
  }

  bool nonblock = (f->flags & O_NONBLOCK) || (flags & MSG_DONTWAIT);
  sigset_t waitmask = __sig_block();
  ssize_t rc;
  unsigned ethertype = 0;
  for (;;) {
    int64_t h6 = f->pkthandle6;
    int64_t hands[2] = {f->handle, h6};
    // neither family starves the other
    int first = h6 ? f->pktturn : 0;
    if (h6)
      f->pktturn = !f->pktturn;
    int consumed = 0;
    bool bad4 = false, bad6 = false;
    rc = -1;
    errno = EAGAIN;
    for (int i = 0; i < 2 && rc < 0; i++) {
      int which = first ^ i;
      if (!hands[which])
        continue;
      // with one socket a blocking caller can just block on it
      rc = RecvFramed(hands[which], buf, n, hdr, nonblock || h6, f->rcvtimeo,
                      waitmask, &consumed, which ? &bad6 : &bad4, &ethertype);
      if (rc < 0 && errno != EAGAIN)
        break;
    }
    if (rc >= 0 || errno != EAGAIN)
      break;
    // nt is documented to hand an ipv6 raw socket the payload without
    // the header on some configurations, and the first packet is the
    // only way to find out. the capture goes on over ipv4 alone
    if (bad6 && h6) {
      __imp_closesocket(h6);
      f->pkthandle6 = 0;
    }
    if (nonblock) {
      // datagrams came off a socket but none could be framed. a caller
      // that polled the fd readable treats EAGAIN as the channel breaking,
      // so it gets an empty frame instead, which parses to no packet
      if (consumed)
        rc = 0;
      break;
    }
    if (!h6)
      continue;
    if (WaitEither(f->handle, h6, f->rcvtimeo, waitmask) == -1) {
      rc = -1;
      break;
    }
  }
  __sig_unblock(waitmask);

  if (rc > 0) {
    FillSockaddrLl(f, ethertype, addr, addrsize);
    if (scratch) {
      size_t o = 0;
      for (size_t i = 0; i < iovlen && o < rc; i++) {
        size_t k = iov[i].iov_len < rc - o ? iov[i].iov_len : rc - o;
        memcpy(iov[i].iov_base, buf + o, k);
        o += k;
      }
    }
  }
  free(scratch);
  return rc;
}

#endif /* SupportsWindows() */
