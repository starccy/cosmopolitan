#include "libc/calls/internal.h"
#include "libc/calls/state.internal.h"
#include "libc/dce.h"
#include "libc/intrin/fds.h"
#include "libc/macros.h"
#include "libc/sock/internal.h"
#include "libc/sock/struct/sockaddr.internal.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/af.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/so.h"
#include "libc/sysv/consts/sock.h"
#include "libc/sysv/consts/sol.h"
#include "libc/sysv/consts/tcp.h"
#include "libc/sysv/errfuns.h"

// TCP_QUICKACK and TCP_DEFER_ACCEPT off linux, where no host has them,
// and TCP_CORK on windows, which has no TCP_NOPUSH either: setsockopt()
// takes them on a tcp socket and getsockopt() answers with what was set,
// kept in the descriptor table. quickack starts on, as on linux

bool __tcphint(int level, int optname) {
  return !IsLinux() && level == SOL_TCP &&
         (optname == TCP_QUICKACK || optname == TCP_DEFER_ACCEPT ||
          (IsWindows() && optname == TCP_CORK));
}

int __tcphint_check(int fd) {
  if (IsWindows()) {
    if (!__isfdopen(fd))
      return ebadf();
    if (!__isfdkind(fd, kFdSocket))
      return enotsock();
    struct Fd *f = __get_pib()->fds.p + fd;
    if (f->family == AF_UNIX)
      return eopnotsupp();
    if (f->type != SOCK_STREAM ||
        (f->family != AF_INET && f->family != AF_INET6))
      return enoprotoopt();
    return 0;
  }
  int type;
  uint32_t len = sizeof(type);
  if (sys_getsockopt(fd, __sol2host(SOL_SOCKET),
                     __sockopt2host(SOL_SOCKET, SO_TYPE), &type, &len) == -1)
    return -1;
  union sockaddr_storage_bsd ss;
  len = sizeof(ss);
  if (__sys_getsockname(fd, &ss, &len) == -1)
    return -1;
  if (ss.sa.sa_family == __af2host(AF_UNIX))
    return eopnotsupp();
  if (type != SOCK_STREAM || (ss.sa.sa_family != __af2host(AF_INET) &&
                              ss.sa.sa_family != __af2host(AF_INET6)))
    return enoprotoopt();
  return 0;
}

int __tcphint_set(int fd, int optname, const void *optval, uint32_t optlen) {
  if (optlen < sizeof(int))
    return einval();
  if (__tcphint_check(fd) == -1)
    return -1;
  int v = *(const int *)optval;
  __fds_lock();
  if (__ensurefds_unlocked(fd) == -1) {
    __fds_unlock();
    return -1;
  }
  struct Fd *f = __get_pib()->fds.p + fd;
  if (optname == TCP_QUICKACK) {
    f->noquickack = !v;
  } else if (optname == TCP_CORK) {
    f->cork = !!v;
  } else {
    f->deferaccept = MAX(v, 0);
  }
  __fds_unlock();
  return 0;
}

int __tcphint_get(int fd, int optname, void *optval, uint32_t *optlen) {
  if (!optval || !optlen)
    return efault();
  if (__tcphint_check(fd) == -1)
    return -1;
  int v = optname == TCP_QUICKACK;
  if (fd < __get_pib()->fds.n) {
    struct Fd *f = __get_pib()->fds.p + fd;
    v = optname == TCP_QUICKACK     ? !f->noquickack
        : optname == TCP_CORK ? f->cork
                              : f->deferaccept;
  }
  uint32_t n = MIN(*optlen, sizeof(v));
  memcpy(optval, &v, n);
  *optlen = n;
  return 0;
}

// a new socket off linux and windows, whose number may have been some
// other socket's with hints or SO_PASSCRED set
void __tcphint_reset(int fd) {
  if (!IsLinux() && !IsWindows() && fd >= 0 && fd < __get_pib()->fds.n) {
    __get_pib()->fds.p[fd].noquickack = 0;
    __get_pib()->fds.p[fd].deferaccept = 0;
    __get_pib()->fds.p[fd].usertimeout = 0;
    __get_pib()->fds.p[fd].passcred = 0;
    __get_pib()->fds.p[fd].sockbuf = 0;
  }
}

// linux doubles SO_SNDBUF and SO_RCVBUF when they're set and reports
// the doubled figure; the other hosts keep the figure as given. the
// descriptor remembers which of the two was set so getsockopt()
// answers like linux for those.
void __sockbuf_set(int fd, int optname) {
  __fds_lock();
  if (__ensurefds_unlocked(fd) != -1)
    __get_pib()->fds.p[fd].sockbuf |= optname == SO_SNDBUF ? 1 : 2;
  __fds_unlock();
}

bool __sockbuf_set_p(int fd, int optname) {
  return fd >= 0 && fd < __get_pib()->fds.n &&
         (__get_pib()->fds.p[fd].sockbuf & (optname == SO_SNDBUF ? 1 : 2));
}
