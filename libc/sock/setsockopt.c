/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2020 Justine Alexandra Roberts Tunney                              │
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
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/describeflags.h"
#include "libc/intrin/fds.h"
#include "libc/intrin/strace.h"
#include "libc/nt/winsock.h"
#include "libc/sock/internal.h"
#include "libc/sock/sock.h"
#include "libc/sock/ifname.h"
#include "libc/sock/struct/ifreq.h"
#include "libc/stdio/sysparam.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/ipproto.h"
#include "libc/sysv/consts/so.h"
#include "libc/sock/struct/sockaddr.internal.h"
#include "libc/sock/syscall_fd.internal.h"
#include "libc/sysv/consts/af.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/ip.h"
#include "libc/sysv/consts/sol.h"
#include "libc/sysv/consts/so.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"

// xnu refuses ipv4 options on an ipv6 socket, dual-stack or not, where
// linux applies them to the ipv4 traffic; say the socket lacks them
static void setsockopt_xnu_ipv4_on_ipv6(int fd, int level) {
  union sockaddr_storage_bsd ss;
  uint32_t len = sizeof(ss);
  if (IsXnu() && level == SOL_IP && errno == EINVAL &&
      __sys_getsockname(fd, &ss, &len) != -1 &&
      ss.sa.sa_family == __af2host(AF_INET6))
    errno = ENOPROTOOPT;
}

// xnu binds a socket to an interface by index, with IP_BOUND_IF for
// ipv4 and IPV6_BOUND_IF for ipv6, where linux names it
static int setsockopt_xnu_bindtodevice(int fd, const void *optval,
                                       uint32_t optlen) {
  char name[IFNAMSIZ] = {0};
  unsigned idx = 0;
  union sockaddr_storage_bsd ss;
  uint32_t len = sizeof(ss);
  memcpy(name, optval, MIN(optlen, sizeof(name) - 1));
  if (*name && !(idx = if_nametoindex(name)))
    return enodev();
  if (__sys_getsockname(fd, &ss, &len) == -1)
    return -1;
  if (ss.sa.sa_family == __af2host(AF_INET6))
    return sys_setsockopt(fd, IPPROTO_IPV6, 125, &idx, sizeof(idx));
  return sys_setsockopt(fd, IPPROTO_IP, 25, &idx, sizeof(idx));
}

static bool setsockopt_polyfill(int *optname) {
  if (errno == ENOPROTOOPT && *optname == SO_REUSEPORT /* RHEL5 */) {
    *optname = SO_REUSEADDR; /* close enough */
    return true;             /* fudges errno */
  }
  return false;
}

/**
 * Modifies socket settings.
 *
 * Basic usage:
 *
 *     int yes = 1;
 *     setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
 *
 * @param level can be SOL_SOCKET, SOL_IP, SOL_TCP, etc.
 * @param optname can be SO_{REUSE{PORT,ADDR},KEEPALIVE,etc.} etc.
 * @return 0 on success, or -1 w/ errno
 * @error ENOPROTOOPT for unknown (level,optname)
 * @error EINVAL if `optlen` is invalid somehow
 * @error ENOTSOCK if `fd` is valid but not a socket
 * @error EBADF if `fd` isn't valid
 * @error EFAULT if optval memory isn't valid
 * @see libc/sysv/consts.sh for tuning catalogue
 * @see getsockopt()
 */
int setsockopt(int fd, int level, int optname, const void *optval,
               uint32_t optlen) {
  int e, rc;

  if (level == -1 || !optname) {
    rc = enoprotoopt();  // see libc/sysv/consts.sh
  } else if ((!optval && optlen)) {
    rc = efault();
  } else if (__isfdkind(fd, kFdZip)) {
    rc = enotsock();
  } else if (__tcphint(level, optname)) {
    rc = __tcphint_set(fd, optname, optval, optlen);
  } else if (__credopt(level, optname)) {
    rc = __credopt_set(fd, optname, optval, optlen);
  } else if (IsXnu() && level == SOL_SOCKET && optname == SO_BINDTODEVICE) {
    rc = setsockopt_xnu_bindtodevice(fd, optval, optlen);
  } else if (IsXnu() && __is_pmtudisc(level, optname)) {
    // xnu only has the don't fragment bit, IP_DONTFRAG and IPV6_DONTFRAG
    if (optlen < sizeof(int)) {
      rc = einval();
    } else {
      int df = *(const int *)optval >= IP_PMTUDISC_DO;
      rc = sys_setsockopt(fd, level, level == SOL_IP ? 28 : 62, &df,
                          sizeof(df));
      if (rc == -1)
        setsockopt_xnu_ipv4_on_ipv6(fd, level);
    }
  } else if (!IsWindows()) {
    rc = -1;
    e = errno;
    do {
      int hopt = __sockopt2host(level, optname);
      if (!hopt) {
        errno = ENOPROTOOPT;
      } else if (sys_setsockopt(fd, __sol2host(level), hopt, optval, optlen) !=
                 -1) {
        errno = e;
        rc = 0;
        break;
      }
    } while (setsockopt_polyfill(&optname));
    if (rc == -1)
      setsockopt_xnu_ipv4_on_ipv6(fd, level);
  } else if (!__isfdopen(fd)) {
    rc = ebadf();
  } else if (__isfdkind(fd, kFdSocket)) {
    rc = sys_setsockopt_nt(&__get_pib()->fds.p[fd], level, optname, optval,
                           optlen);
  } else if (__scm_msgpipe_nt(&__get_pib()->fds.p[fd])) {
    rc = __scm_msgpipe_setsockopt_nt(level, optname, optval, optlen);
  } else {
    rc = enotsock();
  }

  if (!rc && !IsLinux() && level == SOL_SOCKET &&
      (optname == SO_SNDBUF || optname == SO_RCVBUF))
    __sockbuf_set(fd, optname);

#if SYSDEBUG
  if (!(rc == -1 && errno == EFAULT)) {
    STRACE("setsockopt(%d, %s, %s, %#.*hhs, %'u) → %d% lm", fd,
           DescribeSockLevel(level), DescribeSockOptname(level, optname),
           optlen, optval, optlen, rc);
  } else {
    STRACE("setsockopt(%d, %s, %s, %p, %'u) → %d% lm", fd,
           DescribeSockLevel(level), DescribeSockOptname(level, optname),
           optval, optlen, rc);
  }
#endif

  return rc;
}
