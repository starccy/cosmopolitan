#include "libc/dce.h"
#include "libc/intrin/fds.h"
#include "libc/nt/errors.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/nt/winsock.h"
#include "libc/sock/internal.h"
#include "libc/sysv/consts/ipproto.h"
#if SupportsWindows()

#define TCP_MAXRT_NT   5
#define TCP_MAXRTMS_NT 14

__msabi extern typeof(__sys_setsockopt_nt) *const __imp_setsockopt;

textwindows int __usertimeout_nt(struct Fd *fd, unsigned ms) {
  if (__imp_setsockopt(fd->handle, IPPROTO_TCP, TCP_MAXRTMS_NT, &ms,
                       sizeof(ms)) != -1)
    return 0;
  int err = WSAGetLastError();
  if (err != WSAENOPROTOOPT && err != WSAEINVAL)
    return __winsockerr();
  unsigned secs = (ms + 999) / 1000;
  if (__imp_setsockopt(fd->handle, IPPROTO_TCP, TCP_MAXRT_NT, &secs,
                       sizeof(secs)) == -1)
    return __winsockerr();
  return 0;
}

#endif /* SupportsWindows() */
