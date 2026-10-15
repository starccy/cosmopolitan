#include "libc/dce.h"
#include "libc/intrin/fds.h"
#include "libc/nt/errors.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/nt/winsock.h"
#include "libc/sock/internal.h"
#include "libc/sysv/consts/ipproto.h"
#if SupportsWindows()

#define IP_UNICAST_IF_NT   31
#define IPV6_UNICAST_IF_NT 31

__msabi extern typeof(__sys_setsockopt_nt) *const __imp_setsockopt;
__msabi extern typeof(__sys_getsockopt_nt) *const __imp_getsockopt;

// an ipv6 socket may be dual stack, so it gets the ipv4 binding too.
// winsock takes the ipv4 index in network byte order but reads it
// back in host order
textwindows int __bindif_nt_set(struct Fd *fd, bool v6, unsigned idx) {
  unsigned idx4 = htonl(idx);
  if (v6) {
    if (__imp_setsockopt(fd->handle, IPPROTO_IPV6, IPV6_UNICAST_IF_NT, &idx,
                         sizeof(idx)) == -1)
      return __winsockerr();
    __imp_setsockopt(fd->handle, IPPROTO_IP, IP_UNICAST_IF_NT, &idx4,
                     sizeof(idx4));
    return 0;
  }
  if (__imp_setsockopt(fd->handle, IPPROTO_IP, IP_UNICAST_IF_NT, &idx4,
                       sizeof(idx4)) == -1)
    return __winsockerr();
  return 0;
}

textwindows int __bindif_nt_get(struct Fd *fd, bool v6, unsigned *idx) {
  uint32_t len = sizeof(*idx);
  *idx = 0;
  if (v6) {
    if (__imp_getsockopt(fd->handle, IPPROTO_IPV6, IPV6_UNICAST_IF_NT, idx,
                         &len) == -1)
      return __winsockerr();
    return 0;
  }
  if (__imp_getsockopt(fd->handle, IPPROTO_IP, IP_UNICAST_IF_NT, idx, &len) ==
      -1)
    return __winsockerr();
  return 0;
}

#endif /* SupportsWindows() */
