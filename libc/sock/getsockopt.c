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
#include "libc/intrin/describeflags.h"
#include "libc/intrin/fds.h"
#include "libc/intrin/strace.h"
#include "libc/sock/internal.h"
#include "libc/sock/tcpinfo.internal.h"
#include "libc/sock/sock.h"
#include "libc/sysv/consts/af.h"
#include "libc/sock/struct/sockaddr.h"
#include "libc/sock/syscall_fd.internal.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/ip.h"
#include "libc/sysv/consts/ipproto.h"
#include "libc/sysv/consts/so.h"
#include "libc/sysv/consts/sock.h"
#include "libc/sysv/consts/sol.h"
#include "libc/sysv/consts/tcp.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/errno.h"
#include "libc/sysv/pib.h"

// the options linux answers with 0 or 1
static bool sockopt_is_boolean(int level, int optname) {
  if (level == SOL_SOCKET)
    switch (optname) {
      case SO_REUSEADDR:
      case SO_DONTROUTE:
      case SO_BROADCAST:
      case SO_KEEPALIVE:
      case SO_OOBINLINE:
      case SO_REUSEPORT:
      case SO_ACCEPTCONN:
        return true;
    }
  if (level == IPPROTO_TCP)
    switch (optname) {
      case TCP_NODELAY:
      case TCP_CORK:
        return true;
    }
  return false;
}

// xnu has no option for the family or the protocol and can't read
// SO_ACCEPTCONN back: the family comes from getsockname(), the
// protocol from the family and the type, and listen() leaves a mark
static int getsockopt_xnu_derived(int fd, int optname, void *out,
                                  uint32_t *len) {
  if (!out || !len || *len < sizeof(int))
    return einval();
  int v = 0;
  if (optname == SO_ACCEPTCONN) {
    v = fd < __get_pib()->fds.n && __get_pib()->fds.p[fd].listening;
  } else {
    struct sockaddr_storage ss;
    uint32_t n = sizeof(ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &n) == -1)
      return -1;
    v = ss.ss_family;
    if (optname == SO_PROTOCOL) {
      int type = 0;
      uint32_t tn = sizeof(type);
      if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &tn) == -1)
        return -1;
      if (v == AF_INET || v == AF_INET6)
        v = type == SOCK_STREAM ? IPPROTO_TCP : type == SOCK_DGRAM ? IPPROTO_UDP : 0;
      else
        v = 0;
    }
  }
  *(int *)out = v;
  *len = sizeof(int);
  return 0;
}

/**
 * Retrieves socket setting.
 *
 * @param level can be SOL_SOCKET, IPPROTO_TCP, etc.
 * @param optname can be SO_{REUSE{PORT,ADDR},KEEPALIVE,etc.} etc.
 * @return 0 on success, or -1 w/ errno
 * @error ENOPROTOOPT for unknown (level,optname)
 * @error EINVAL if `out_optlen` is invalid somehow
 * @error ENOTSOCK if `fd` is valid but not a socket
 * @error EBADF if `fd` isn't valid
 * @error EFAULT if optval memory isn't valid
 * @see libc/sysv/consts.sh for tuning catalogue
 * @see setsockopt()
 */
int getsockopt(int fd, int level, int optname, void *out_opt_optval,
               uint32_t *out_optlen) {
  int rc, hopt6;

  if (level == -1 || !optname) {
    rc = enoprotoopt();  // see libc/sysv/consts.sh
  } else if (__isfdkind(fd, kFdZip)) {
    rc = enotsock();
  } else if (__tcphint(level, optname)) {
    rc = __tcphint_get(fd, optname, out_opt_optval, out_optlen);
  } else if (__usertimeout(level, optname)) {
    rc = __usertimeout_get(fd, out_opt_optval, out_optlen);
  } else if (__credopt(level, optname)) {
    rc = __credopt_get(fd, optname, out_opt_optval, out_optlen);
  } else if (__bindif(level, optname)) {
    rc = __bindif_get(fd, level, optname, out_opt_optval, out_optlen);
  } else if (__bindif_name(level, optname)) {
    rc = __bindif_name_get(fd, out_opt_optval, out_optlen);
  } else if (__tcpinfo(level, optname)) {
    rc = __tcpinfo_get(fd, out_opt_optval, out_optlen);
  } else if (IsXnu() && __is_pmtudisc(level, optname)) {
    int df;
    uint32_t len = sizeof(df);
    if (!out_opt_optval || !out_optlen || *out_optlen < sizeof(int)) {
      rc = einval();
    } else if ((rc = sys_getsockopt(fd, level, level == SOL_IP ? 28 : 62, &df,
                                    &len)) != -1) {
      int mode = fd < __get_pib()->fds.n ? __get_pib()->fds.p[fd].pmtudisc : 0;
      *(int *)out_opt_optval =
          mode ? mode - 1 : df ? IP_PMTUDISC_DO : IP_PMTUDISC_DONT;
      *out_optlen = sizeof(int);
    }
  } else if (IsXnu() && level == SOL_SOCKET &&
             (optname == SO_DOMAIN || optname == SO_PROTOCOL ||
              optname == SO_ACCEPTCONN)) {
    rc = getsockopt_xnu_derived(fd, optname, out_opt_optval, out_optlen);
  } else if (__sockopt_xnu_v4mcast_on_v6(fd, level, optname, &hopt6)) {
    int v = 0;
    uint32_t len = sizeof(v);
    if (!out_opt_optval || !out_optlen || !*out_optlen) {
      rc = einval();
    } else if (!(rc = sys_getsockopt(fd, IPPROTO_IPV6, hopt6, &v, &len))) {
      if (*out_optlen < sizeof(int)) {
        *(uint8_t *)out_opt_optval = v;
        *out_optlen = 1;
      } else {
        *(int *)out_opt_optval = v;
        *out_optlen = sizeof(int);
      }
    }
  } else if (!IsWindows()) {
    int hopt = __sockopt2host(level, optname);
    if (hopt) {
      rc = sys_getsockopt(fd, __sol2host(level), hopt, out_opt_optval,
                          out_optlen);
    } else {
      rc = enoprotoopt();
    }
    if (!rc && IsXnu() && level == SOL_SOCKET && optname == SO_TYPE &&
        out_opt_optval && *out_optlen >= sizeof(int) &&
        ((*(int *)out_opt_optval == SOCK_DGRAM && __xnu_seqpacket(fd)) ||
         (*(int *)out_opt_optval == SOCK_STREAM && __xnu_unix_seq(fd))))
      *(int *)out_opt_optval = SOCK_SEQPACKET;
    if (!rc && !IsLinux() && level == SOL_SOCKET && optname == SO_ERROR &&
        out_opt_optval && out_optlen && *out_optlen >= sizeof(int) &&
        *(int *)out_opt_optval)
      *(int *)out_opt_optval = __errno_host2linux(*(int *)out_opt_optval);
    // the bsds answer a boolean option with their own flag bit (xnu
    // reads TCP_NODELAY back as 4 and SO_KEEPALIVE as 8)
    if (!rc && IsBsd() && out_opt_optval && out_optlen &&
        *out_optlen == sizeof(int) && sockopt_is_boolean(level, optname))
      *(int *)out_opt_optval = !!*(int *)out_opt_optval;
  } else if (!__isfdopen(fd)) {
    rc = ebadf();
  } else if (__isfdkind(fd, kFdSocket)) {
    rc = sys_getsockopt_nt(&__get_pib()->fds.p[fd], level, optname,
                           out_opt_optval, out_optlen);
  } else if (__scm_msgpipe_nt(&__get_pib()->fds.p[fd])) {
    rc = __scm_msgpipe_getsockopt_nt(&__get_pib()->fds.p[fd], level, optname,
                                     out_opt_optval, out_optlen);
  } else {
    rc = enotsock();
  }

  if (!rc && !IsLinux() && level == SOL_SOCKET &&
      (optname == SO_SNDBUF || optname == SO_RCVBUF) && out_opt_optval &&
      out_optlen && *out_optlen == sizeof(int) && __sockbuf_set_p(fd, optname))
    *(int *)out_opt_optval *= 2;

#if SYSDEBUG
  if (out_opt_optval && out_optlen && rc != -1) {
    STRACE("getsockopt(%d, %s, %s, [%#.*hhs], [%d]) → %d% lm", fd,
           DescribeSockLevel(level), DescribeSockOptname(level, optname),
           *out_optlen, out_opt_optval, *out_optlen, rc);
  } else {
    STRACE("getsockopt(%d, %s, %s, %p, %p) → %d% lm", fd,
           DescribeSockLevel(level), DescribeSockOptname(level, optname),
           out_opt_optval, out_optlen, rc);
  }
#endif

  return rc;
}
