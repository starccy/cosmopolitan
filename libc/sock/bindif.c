#include "libc/calls/internal.h"
#include "libc/calls/state.internal.h"
#include "libc/dce.h"
#include "libc/intrin/fds.h"
#include "libc/macros.h"
#include "libc/sock/internal.h"
#include "libc/sock/struct/sockaddr.internal.h"
#include "libc/sock/ifname.h"
#include "libc/sock/sock.h"
#include "libc/sock/struct/ifreq.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/af.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/ip.h"
#include "libc/sysv/consts/ipproto.h"
#include "libc/sysv/consts/ipv6.h"
#include "libc/sysv/consts/so.h"
#include "libc/sysv/consts/sol.h"
#include "libc/sysv/errfuns.h"

// SO_BINDTOIFINDEX, IP_UNICAST_IF and IPV6_UNICAST_IF off linux. xnu
// binds a socket to an interface by index with IP_BOUND_IF and
// IPV6_BOUND_IF, windows with IP_UNICAST_IF and IPV6_UNICAST_IF. the
// two UNICAST_IF options take the index in network byte order on
// linux, windows takes only the ipv4 one that way, xnu neither.
// SO_BINDTODEVICE reads back as the name of the index bound this way

#define IP_BOUND_IF_XNU   25
#define IPV6_BOUND_IF_XNU 125

bool __bindif(int level, int optname) {
  if (IsLinux())
    return false;
  return (level == SOL_SOCKET && optname == SO_BINDTOIFINDEX) ||
         (level == SOL_IP && optname == IP_UNICAST_IF) ||
         (level == SOL_IPV6 && optname == IPV6_UNICAST_IF);
}

bool __bindif_name(int level, int optname) {
  return !IsLinux() && level == SOL_SOCKET && optname == SO_BINDTODEVICE;
}

// which of the pair of host options a request means: the socket's
// family for SO_BINDTOIFINDEX and SO_BINDTODEVICE, else the option's
static int IsV6(int fd, int optname, bool *v6) {
  if (optname == IP_UNICAST_IF) {
    *v6 = false;
    return 0;
  }
  if (IsWindows()) {
    if (!__isfdopen(fd))
      return ebadf();
    if (!__isfdkind(fd, kFdSocket))
      return enotsock();
    *v6 = __get_pib()->fds.p[fd].family == AF_INET6;
    if (optname == IPV6_UNICAST_IF && !*v6)
      return enoprotoopt();
    return 0;
  }
  union sockaddr_storage_bsd ss;
  uint32_t len = sizeof(ss);
  if (__sys_getsockname(fd, &ss, &len) == -1)
    return -1;
  *v6 = ss.sa.sa_family == __af2host(AF_INET6);
  if (optname == IPV6_UNICAST_IF && !*v6)
    return enoprotoopt();
  return 0;
}

static int SetXnu(int fd, bool v6, unsigned idx) {
  if (v6)
    return sys_setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF_XNU, &idx,
                          sizeof(idx));
  return sys_setsockopt(fd, IPPROTO_IP, IP_BOUND_IF_XNU, &idx, sizeof(idx));
}

static int GetXnu(int fd, bool v6, unsigned *idx) {
  uint32_t len = sizeof(*idx);
  *idx = 0;
  if (v6)
    return sys_getsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF_XNU, idx, &len);
  return sys_getsockopt(fd, IPPROTO_IP, IP_BOUND_IF_XNU, idx, &len);
}

int __bindif_set(int fd, int level, int optname, const void *optval,
                 uint32_t optlen) {
  bool v6;
  if (!optval)
    return efault();
  if (optlen < sizeof(unsigned))
    return einval();
  if (IsV6(fd, optname, &v6) == -1)
    return -1;
  unsigned idx = *(const unsigned *)optval;
  if (optname != SO_BINDTOIFINDEX)
    idx = ntohl(idx);
  if (IsWindows())
    return __bindif_nt_set(__get_pib()->fds.p + fd, v6, idx);
  if (IsXnu())
    return SetXnu(fd, v6, idx);
  return enoprotoopt();
}

static int Get(int fd, int optname, unsigned *idx) {
  bool v6;
  if (IsV6(fd, optname, &v6) == -1)
    return -1;
  if (IsWindows())
    return __bindif_nt_get(__get_pib()->fds.p + fd, v6, idx);
  if (IsXnu())
    return GetXnu(fd, v6, idx);
  return enoprotoopt();
}

int __bindif_get(int fd, int level, int optname, void *optval,
                 uint32_t *optlen) {
  unsigned idx = 0;
  if (!optval || !optlen)
    return efault();
  if (Get(fd, optname, &idx) == -1)
    return -1;
  if (optname != SO_BINDTOIFINDEX)
    idx = htonl(idx);
  uint32_t n = MIN(*optlen, sizeof(idx));
  memcpy(optval, &idx, n);
  *optlen = n;
  return 0;
}

// linux answers an unbound socket with length zero and leaves the
// buffer alone
int __bindif_name_get(int fd, void *optval, uint32_t *optlen) {
  unsigned idx = 0;
  char name[IFNAMSIZ];
  if (!optval || !optlen)
    return efault();
  if (Get(fd, SO_BINDTODEVICE, &idx) == -1)
    return -1;
  if (!idx) {
    *optlen = 0;
    return 0;
  }
  if (!if_indextoname(idx, name))
    return -1;
  uint32_t n = MIN(*optlen, strlen(name) + 1);
  memcpy(optval, name, n);
  *optlen = n;
  return 0;
}
