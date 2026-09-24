#include "libc/dce.h"
#include "libc/sysv/consts/af.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/sock.h"

#define AF_NAMES(X)   \
  X(AF_INET6)         \
  X(AF_IPX)           \
  X(AF_APPLETALK)     \
  X(AF_LINK)          \
  X(AF_SNA)           \
  X(AF_AX25)          \
  X(AF_NETROM)        \
  X(AF_BRIDGE)        \
  X(AF_ATMPVC)        \
  X(AF_X25)           \
  X(AF_ROSE)          \
  X(AF_NETBEUI)       \
  X(AF_SECURITY)      \
  X(AF_KEY)           \
  X(AF_NETLINK)       \
  X(AF_PACKET)        \
  X(AF_ASH)           \
  X(AF_ECONET)        \
  X(AF_ATMSVC)        \
  X(AF_RDS)           \
  X(AF_IRDA)          \
  X(AF_PPPOX)         \
  X(AF_WANPIPE)       \
  X(AF_LLC)           \
  X(AF_IB)            \
  X(AF_MPLS)          \
  X(AF_CAN)           \
  X(AF_TIPC)          \
  X(AF_BLUETOOTH)     \
  X(AF_IUCV)          \
  X(AF_RXRPC)         \
  X(AF_ISDN)          \
  X(AF_PHONET)        \
  X(AF_IEEE802154)    \
  X(AF_CAIF)          \
  X(AF_ALG)           \
  X(AF_NFC)           \
  X(AF_VSOCK)         \
  X(AF_KCM)

#define DECL(NAME) extern const int __host_##NAME __asm__(#NAME);
AF_NAMES(DECL)
__HOSTCONST(int, SOCK_CLOEXEC);
__HOSTCONST(int, SOCK_NONBLOCK);

#define ENTRY(NAME) {NAME, &__host_##NAME},
static const struct {
  int linux;
  const int *host;
} kAf[] = {AF_NAMES(ENTRY)};

/**
 * Turns an address family into the host's number for it.
 *
 * AF_UNSPEC, AF_UNIX and AF_INET are the same everywhere. AF_ROUTE is
 * AF_NETLINK on Linux and goes the way AF_NETLINK goes. Families cosmo
 * doesn't know pass through as they are.
 *
 * @return host family, or -1 if the host has no such family
 */
int __af2host(int family) {
  if (IsLinux())
    return family;
  for (int i = 0; i < sizeof(kAf) / sizeof(*kAf); ++i)
    if (family == kAf[i].linux)
      return *kAf[i].host;
  return family;
}

/**
 * Turns the host's address family back into Linux's number for it.
 *
 * A host family cosmo has no name for passes through as it is.
 */
int __af2linux(int family) {
  if (IsLinux())
    return family;
  for (int i = 0; i < sizeof(kAf) / sizeof(*kAf); ++i)
    if (*kAf[i].host != -1 && family == *kAf[i].host)
      return kAf[i].linux;
  return family;
}

/**
 * Turns a socket type into the host's bits for it.
 *
 * Only the SOCK_CLOEXEC and SOCK_NONBLOCK modifiers differ.
 */
int __socktype2host(int type) {
  if (IsLinux())
    return type;
  int host = type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK);
  if (type & SOCK_CLOEXEC)
    host |= __host_SOCK_CLOEXEC;
  if (type & SOCK_NONBLOCK)
    host |= __host_SOCK_NONBLOCK;
  return host;
}
