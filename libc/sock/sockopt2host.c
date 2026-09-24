#include "libc/dce.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/ip.h"
#include "libc/sysv/consts/ipv6.h"
#include "libc/sysv/consts/so.h"
#include "libc/sysv/consts/sol.h"
#include "libc/sysv/consts/tcp.h"

struct SockOpt {
  int linux;
  const int *host;
};

#define OPT(NAME) {NAME, &__host_##NAME},

#define SO_OPTS(X)     \
  X(SO_TYPE)           \
  X(SO_ERROR)          \
  X(SO_ACCEPTCONN)     \
  X(SO_REUSEADDR)      \
  X(SO_KEEPALIVE)      \
  X(SO_DONTROUTE)      \
  X(SO_BROADCAST)      \
  X(SO_USELOOPBACK)    \
  X(SO_LINGER)         \
  X(SO_OOBINLINE)      \
  X(SO_SNDBUF)         \
  X(SO_RCVBUF)         \
  X(SO_RCVTIMEO)       \
  X(SO_SNDTIMEO)       \
  X(SO_RCVLOWAT)       \
  X(SO_SNDLOWAT)       \
  X(SO_REUSEPORT)

#define TCP_OPTS(X)             \
  X(TCP_MAXSEG)                 \
  X(TCP_CORK)                   \
  X(TCP_KEEPIDLE)               \
  X(TCP_KEEPINTVL)              \
  X(TCP_KEEPCNT)                \
  X(TCP_SYNCNT)                 \
  X(TCP_LINGER2)                \
  X(TCP_DEFER_ACCEPT)           \
  X(TCP_WINDOW_CLAMP)           \
  X(TCP_INFO)                   \
  X(TCP_QUICKACK)               \
  X(TCP_CONGESTION)             \
  X(TCP_MD5SIG)                 \
  X(TCP_COOKIE_TRANSACTIONS)    \
  X(TCP_THIN_LINEAR_TIMEOUTS)   \
  X(TCP_THIN_DUPACK)            \
  X(TCP_USER_TIMEOUT)           \
  X(TCP_REPAIR)                 \
  X(TCP_REPAIR_QUEUE)           \
  X(TCP_QUEUE_SEQ)              \
  X(TCP_REPAIR_OPTIONS)         \
  X(TCP_FASTOPEN)               \
  X(TCP_TIMESTAMP)              \
  X(TCP_NOTSENT_LOWAT)          \
  X(TCP_CC_INFO)                \
  X(TCP_SAVE_SYN)               \
  X(TCP_SAVED_SYN)              \
  X(TCP_FASTOPEN_CONNECT)       \
  X(TCP_ULP)                    \
  X(TCP_MD5SIG_MAXKEYLEN)

#define IP_OPTS(X)        \
  X(IP_TOS)               \
  X(IP_TTL)               \
  X(IP_HDRINCL)           \
  X(IP_OPTIONS)           \
  X(IP_PKTINFO)           \
  X(IP_RECVTTL)           \
  X(IP_RECVTOS)           \
  X(IP_MTU)               \
  X(IP_MULTICAST_IF)      \
  X(IP_MULTICAST_TTL)     \
  X(IP_MULTICAST_LOOP)    \
  X(IP_ADD_MEMBERSHIP)    \
  X(IP_DROP_MEMBERSHIP)

#define IPV6_OPTS(X)        \
  X(IPV6_CHECKSUM)          \
  X(IPV6_UNICAST_HOPS)      \
  X(IPV6_MULTICAST_IF)      \
  X(IPV6_MULTICAST_HOPS)    \
  X(IPV6_MULTICAST_LOOP)    \
  X(IPV6_JOIN_GROUP)        \
  X(IPV6_LEAVE_GROUP)       \
  X(IPV6_V6ONLY)            \
  X(IPV6_PKTINFO)           \
  X(IPV6_HOPLIMIT)          \
  X(IPV6_HOPOPTS)           \
  X(IPV6_RECVRTHDR)         \
  X(IPV6_RTHDR)             \
  X(IPV6_DONTFRAG)          \
  X(IPV6_RECVTCLASS)        \
  X(IPV6_TCLASS)

#define DECL(NAME) extern const int __host_##NAME __asm__(#NAME);
SO_OPTS(DECL)
TCP_OPTS(DECL)
IP_OPTS(DECL)
IPV6_OPTS(DECL)
__HOSTCONST(int, SOL_SOCKET);

static const struct SockOpt kSo[] = {SO_OPTS(OPT)};
static const struct SockOpt kTcp[] = {TCP_OPTS(OPT)};
static const struct SockOpt kIp[] = {IP_OPTS(OPT)};
static const struct SockOpt kIpv6[] = {IPV6_OPTS(OPT)};

static int lookup(const struct SockOpt *t, int n, int optname) {
  for (int i = 0; i < n; ++i)
    if (t[i].linux == optname)
      return *t[i].host;
  return optname;
}

static int unlookup(const struct SockOpt *t, int n, int optname) {
  for (int i = 0; i < n; ++i)
    if (*t[i].host && *t[i].host == optname)
      return t[i].linux;
  return optname;
}

/**
 * Turns a socket option level into the host's number for it.
 *
 * Only SOL_SOCKET differs; the rest are protocol numbers.
 */
int __sol2host(int level) {
  if (IsLinux() || level != SOL_SOCKET)
    return level;
  return __host_SOL_SOCKET;
}

/**
 * Turns a socket option name into the host's number for it.
 *
 * Names cosmo doesn't know pass through as they are. `level` is the
 * Linux level, not the value __sol2host() returns.
 *
 * @return host option name, or 0 if the host has no such option
 */
int __sockopt2host(int level, int optname) {
  if (IsLinux())
    return optname;
  switch (level) {
    case SOL_SOCKET:
      return lookup(kSo, sizeof(kSo) / sizeof(*kSo), optname);
    case SOL_TCP:
      return lookup(kTcp, sizeof(kTcp) / sizeof(*kTcp), optname);
    case SOL_IP:
      return lookup(kIp, sizeof(kIp) / sizeof(*kIp), optname);
    case SOL_IPV6:
      return lookup(kIpv6, sizeof(kIpv6) / sizeof(*kIpv6), optname);
    default:
      return optname;
  }
}

/**
 * Turns the host's socket option name back into Linux's number for it.
 */
int __sockopt2linux(int level, int optname) {
  if (IsLinux())
    return optname;
  switch (level) {
    case SOL_SOCKET:
      return unlookup(kSo, sizeof(kSo) / sizeof(*kSo), optname);
    case SOL_TCP:
      return unlookup(kTcp, sizeof(kTcp) / sizeof(*kTcp), optname);
    case SOL_IP:
      return unlookup(kIp, sizeof(kIp) / sizeof(*kIp), optname);
    case SOL_IPV6:
      return unlookup(kIpv6, sizeof(kIpv6) / sizeof(*kIpv6), optname);
    default:
      return optname;
  }
}
