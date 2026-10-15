#include "libc/calls/internal.h"
#include "libc/calls/state.internal.h"
#include "libc/dce.h"
#include "libc/intrin/fds.h"
#include "libc/macros.h"
#include "libc/sock/internal.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/sol.h"
#include "libc/sysv/consts/tcp.h"
#include "libc/sysv/errfuns.h"

// TCP_USER_TIMEOUT off linux: how many milliseconds sent data may go
// unacknowledged before the connection is dropped, zero for the host's
// default. windows has it in milliseconds as TCP_MAXRTMS, or in seconds
// as TCP_MAXRT on versions before 1709; xnu has TCP_RXT_CONNDROPTIME in
// seconds, and TCP_CONNECTIONTIMEOUT for the handshake, which linux's
// option covers too. the figure as given is kept for getsockopt()

#define TCP_RXT_CONNDROPTIME_XNU 0x80
#define TCP_CONNECTIONTIMEOUT_XNU 0x20

bool __usertimeout(int level, int optname) {
  return !IsLinux() && level == SOL_TCP && optname == TCP_USER_TIMEOUT;
}

static int SetXnu(int fd, unsigned ms) {
  int secs = (ms + 999) / 1000;
  if (sys_setsockopt(fd, __sol2host(SOL_TCP), TCP_RXT_CONNDROPTIME_XNU, &secs,
                     sizeof(secs)) == -1)
    return -1;
  return sys_setsockopt(fd, __sol2host(SOL_TCP), TCP_CONNECTIONTIMEOUT_XNU,
                        &secs, sizeof(secs));
}

int __usertimeout_set(int fd, const void *optval, uint32_t optlen) {
  if (!optval)
    return efault();
  if (optlen < sizeof(unsigned))
    return einval();
  if (__tcphint_check(fd) == -1)
    return -1;
  unsigned ms = *(const unsigned *)optval;
  if (IsWindows()) {
    if (__usertimeout_nt(__get_pib()->fds.p + fd, ms) == -1)
      return -1;
  } else if (IsXnu()) {
    if (SetXnu(fd, ms) == -1)
      return -1;
  } else {
    return enoprotoopt();
  }
  __fds_lock();
  if (__ensurefds_unlocked(fd) == -1) {
    __fds_unlock();
    return -1;
  }
  __get_pib()->fds.p[fd].usertimeout = ms;
  __fds_unlock();
  return 0;
}

int __usertimeout_get(int fd, void *optval, uint32_t *optlen) {
  if (!optval || !optlen)
    return efault();
  if (__tcphint_check(fd) == -1)
    return -1;
  if (!IsWindows() && !IsXnu())
    return enoprotoopt();
  unsigned ms = 0;
  if (fd < __get_pib()->fds.n)
    ms = __get_pib()->fds.p[fd].usertimeout;
  uint32_t n = MIN(*optlen, sizeof(ms));
  memcpy(optval, &ms, n);
  *optlen = n;
  return 0;
}
