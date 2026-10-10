#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/fds.h"
#include "libc/nt/enum/sio.h"
#include "libc/nt/winsock.h"
#include "libc/sock/internal.h"
#include "libc/sock/struct/cmsghdr.h"
#include "libc/sock/struct/in6_pktinfo.h"
#include "libc/sock/struct/in_pktinfo.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/ip.h"
#include "libc/sysv/consts/ipproto.h"
#include "libc/sysv/consts/ipv6.h"
#include "libc/sysv/consts/sock.h"
#include "libc/sysv/consts/sol.h"
#include "libc/sysv/consts/udp.h"
#include "libc/sysv/errfuns.h"
#if SupportsWindows()

/*
 * WSACMSGHDR has the same 16 byte header and 8 byte alignment as
 * Linux's cmsghdr, and both use protocol numbers for the level. The
 * types and some payloads differ.
 */

#define NT_IP_TOS             3
#define NT_IP_TTL             4
#define NT_IP_PKTINFO         19
#define NT_IP_ECN             50
#define NT_IPV6_PKTINFO       19
#define NT_IPV6_HOPLIMIT      21
#define NT_IPV6_TCLASS        39
#define NT_IPV6_ECN           50
#define NT_UDP_SEND_MSG_SIZE  2
#define NT_UDP_COALESCED_INFO 3

struct NtInPktinfo {
  uint32_t ipi_addr;
  uint32_t ipi_ifindex;
};

static bool put(unsigned char *d, size_t cap, size_t *di, int level, int type,
                const void *data, size_t len) {
  size_t space = CMSG_SPACE(len);
  if (space > cap - *di)
    return false;
  struct cmsghdr h = {
      .cmsg_len = CMSG_LEN(len), .cmsg_level = level, .cmsg_type = type};
  memcpy(d + *di, &h, sizeof(h));
  memcpy(d + *di + sizeof(h), data, len);
  bzero(d + *di + CMSG_LEN(len), space - CMSG_LEN(len));
  *di += space;
  return true;
}

/**
 * Converts the control messages of a Linux sendmsg() for WSASendMsg().
 *
 * IP_TOS and IPV6_TCLASS become IP_ECN and IPV6_ECN, which is all
 * winsock lets a sender set, so the DSCP bits are dropped.
 *
 * @return byte length written to `dst`, or -1 w/ EINVAL if a message
 *     has no winsock counterpart
 */
textwindows ssize_t __cmsg2nt(const void *src, size_t srclen, void *dst,
                              size_t dstcap) {
  const unsigned char *s = src;
  size_t si = 0, di = 0;
  while (si + sizeof(struct cmsghdr) <= srclen) {
    struct cmsghdr h;
    memcpy(&h, s + si, sizeof(h));
    if (h.cmsg_len < sizeof(h) || h.cmsg_len > srclen - si)
      break;
    const unsigned char *p = s + si + sizeof(h);
    size_t n = h.cmsg_len - sizeof(h);
    bool ok;
    int v;
    if (h.cmsg_level == SOL_IP && h.cmsg_type == IP_TOS && n >= 1) {
      v = p[0] & 3;
      ok = put(dst, dstcap, &di, IPPROTO_IP, NT_IP_ECN, &v, sizeof(v));
    } else if (h.cmsg_level == SOL_IPV6 && h.cmsg_type == IPV6_TCLASS &&
               n >= sizeof(int)) {
      memcpy(&v, p, sizeof(v));
      v &= 3;
      ok = put(dst, dstcap, &di, IPPROTO_IPV6, NT_IPV6_ECN, &v, sizeof(v));
    } else if (h.cmsg_level == SOL_IP && h.cmsg_type == IP_PKTINFO &&
               n >= sizeof(struct in_pktinfo)) {
      struct in_pktinfo pi;
      memcpy(&pi, p, sizeof(pi));
      struct NtInPktinfo ni = {
          pi.ipi_spec_dst.s_addr ? pi.ipi_spec_dst.s_addr : pi.ipi_addr.s_addr,
          pi.ipi_ifindex};
      ok = put(dst, dstcap, &di, IPPROTO_IP, NT_IP_PKTINFO, &ni, sizeof(ni));
    } else if (h.cmsg_level == SOL_IPV6 && h.cmsg_type == IPV6_PKTINFO &&
               n >= sizeof(struct in6_pktinfo)) {
      ok = put(dst, dstcap, &di, IPPROTO_IPV6, NT_IPV6_PKTINFO, p,
               sizeof(struct in6_pktinfo));
    } else if (h.cmsg_level == SOL_UDP && h.cmsg_type == UDP_SEGMENT &&
               n >= sizeof(uint16_t)) {
      uint16_t seg;
      memcpy(&seg, p, sizeof(seg));
      uint32_t size = seg;
      ok = put(dst, dstcap, &di, IPPROTO_UDP, NT_UDP_SEND_MSG_SIZE, &size,
               sizeof(size));
    } else {
      return einval();
    }
    if (!ok)
      return einval();
    si += CMSG_ALIGN(h.cmsg_len);
  }
  return di;
}

/**
 * Converts the control messages WSARecvMsg() gave back into Linux's.
 *
 * Messages Linux has no counterpart for are left out, as are ones that
 * don't fit in `dstcap`, which sets `*truncated`.
 *
 * @return byte length written to `dst`
 */
textwindows size_t __cmsg2linux_nt(const void *src, size_t srclen, void *dst,
                                   size_t dstcap, bool *truncated) {
  const unsigned char *s = src;
  size_t si = 0, di = 0;
  while (si + sizeof(struct cmsghdr) <= srclen) {
    struct cmsghdr h;
    memcpy(&h, s + si, sizeof(h));
    if (h.cmsg_len < sizeof(h) || h.cmsg_len > srclen - si)
      break;
    const unsigned char *p = s + si + sizeof(h);
    size_t n = h.cmsg_len - sizeof(h);
    bool ok = true;
    int v;
    unsigned char tos;
    if (h.cmsg_level == IPPROTO_IP && h.cmsg_type == NT_IP_PKTINFO &&
        n >= sizeof(struct NtInPktinfo)) {
      struct NtInPktinfo ni;
      memcpy(&ni, p, sizeof(ni));
      struct in_pktinfo pi = {ni.ipi_ifindex, {ni.ipi_addr}, {ni.ipi_addr}};
      ok = put(dst, dstcap, &di, SOL_IP, IP_PKTINFO, &pi, sizeof(pi));
    } else if (h.cmsg_level == IPPROTO_IP &&
               (h.cmsg_type == NT_IP_TOS || h.cmsg_type == NT_IP_ECN) &&
               n >= 1) {
      tos = p[0];
      ok = put(dst, dstcap, &di, SOL_IP, IP_TOS, &tos, sizeof(tos));
    } else if (h.cmsg_level == IPPROTO_IP && h.cmsg_type == NT_IP_TTL &&
               n >= sizeof(int)) {
      ok = put(dst, dstcap, &di, SOL_IP, IP_TTL, p, sizeof(int));
    } else if (h.cmsg_level == IPPROTO_IPV6 && h.cmsg_type == NT_IPV6_PKTINFO &&
               n >= sizeof(struct in6_pktinfo)) {
      ok = put(dst, dstcap, &di, SOL_IPV6, IPV6_PKTINFO, p,
               sizeof(struct in6_pktinfo));
    } else if (h.cmsg_level == IPPROTO_IPV6 &&
               (h.cmsg_type == NT_IPV6_TCLASS || h.cmsg_type == NT_IPV6_ECN) &&
               n >= sizeof(int)) {
      ok = put(dst, dstcap, &di, SOL_IPV6, IPV6_TCLASS, p, sizeof(int));
    } else if (h.cmsg_level == IPPROTO_IPV6 &&
               h.cmsg_type == NT_IPV6_HOPLIMIT && n >= sizeof(int)) {
      ok = put(dst, dstcap, &di, SOL_IPV6, IPV6_HOPLIMIT, p, sizeof(int));
    } else if (h.cmsg_level == IPPROTO_UDP &&
               h.cmsg_type == NT_UDP_COALESCED_INFO && n >= sizeof(uint32_t)) {
      memcpy(&v, p, sizeof(v));
      ok = put(dst, dstcap, &di, SOL_UDP, UDP_GRO, &v, sizeof(v));
    }
    if (!ok)
      *truncated = true;
    si += CMSG_ALIGN(h.cmsg_len);
  }
  return di;
}

/**
 * Turns winsock's answer for a datagram socket into Linux's.
 *
 * A datagram bigger than the buffer is a short read that sets
 * `*truncated`, not WSAEMSGSIZE, an ICMP port unreachable is
 * ECONNREFUSED, not WSAECONNRESET, and sending without an address on
 * a socket that isn't connected is EDESTADDRREQ. Sends pass no `iov`.
 */
textwindows ssize_t __winsock_dgram_rc(struct Fd *f, ssize_t rc,
                                       const struct iovec *iov, size_t iovlen,
                                       bool *truncated) {
  if (rc != -1 || f->type == SOCK_STREAM)
    return rc;
  if (errno == EMSGSIZE && iov) {
    size_t n = 0;
    for (size_t i = 0; i < iovlen; ++i)
      n += iov[i].iov_len;
    if (truncated)
      *truncated = true;
    return n;
  }
  if (errno == ECONNRESET)
    errno = ECONNREFUSED;
  else if (errno == ENOTCONN && !iov)
    errno = EDESTADDRREQ;
  return rc;
}

// linux only reports ICMP errors to a connected datagram socket
textwindows void __winsock_udp_connreset(int64_t handle, bool on) {
  uint32_t got;
  bool32 v = on;
  WSAIoctl(handle, kNtSioUdpConnreset, &v, sizeof(v), &got, 0, &got, 0, 0);
}

#endif /* __x86_64__ */
