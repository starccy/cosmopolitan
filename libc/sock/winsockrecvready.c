#include "libc/dce.h"
#include "libc/nt/struct/pollfd.h"
#include "libc/nt/winsock.h"
#include "libc/sock/internal.h"
#if SupportsWindows()

/**
 * Returns true if a receive on the socket would complete without waiting.
 *
 * Every receive runs as an overlapped operation and, on a non-blocking
 * socket, gets cancelled the moment it reports pending. A send arriving
 * between the two can complete the receive, consuming the data, while
 * the cancel still reports aborted: the caller sees EAGAIN, the data is
 * gone, and the socket never polls readable again. So a non-blocking
 * receive asks winsock first. Data, a hangup or an error all count as
 * ready, and so does a failed poll, since that only runs the usual path
 * while a false EAGAIN loses a wakeup.
 */
textwindows bool __winsock_recv_ready(int64_t handle, uint32_t flags) {
  struct sys_pollfd_nt p = {handle, (flags & 1 /* MSG_OOB */) ? 0x0200 : 0x0100,
                            0};
  int r = WSAPoll(&p, 1, 0);
  return r != 0;
}

#endif /* __x86_64__ */
