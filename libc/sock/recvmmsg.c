#include "libc/calls/cp.internal.h"
#include "libc/calls/struct/timespec.h"
#include "libc/calls/struct/timespec.internal.h"
#include "libc/mem/alg.h"
#include "libc/mem/mem.h"
#include "libc/cosmotime.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/strace.h"
#include "libc/sock/internal.h"
#include "libc/sock/struct/msghdr.h"
#include "libc/sock/struct/pollfd.h"
#include "libc/sysv/consts/clock.h"
#include "libc/sysv/consts/iov.h"
#include "libc/sysv/consts/msg.h"
#include "libc/sysv/consts/poll.h"

/**
 * Receives multiple messages from a socket.
 *
 * Linux has the kernel do it. Elsewhere the first entry is received the
 * way recvmsg() would with `flags`, and the rest while data is queued.
 * `MSG_WAITFORONE` makes those later receives non-blocking. When
 * `timeout` is given, the deadline is checked before every entry after
 * the first, so the call returns once it has passed and at least one
 * message is in hand.
 *
 * @return number of messages received, or -1 w/ errno
 */
int recvmmsg(int fd, struct mmsghdr *msgvec, unsigned int vlen, int flags,
             struct timespec *timeout) {
  int rc;
  unsigned int i;
  struct timespec deadline;
  if (IsLinux()) {
    BEGIN_CANCELATION_POINT;
    rc = sys_recvmmsg(fd, msgvec, vlen, flags, timeout);
    END_CANCELATION_POINT;
    STRACE("recvmmsg(%d, %p, %u, %#x, %s) → %d% m", fd, msgvec, vlen, flags,
           DescribeTimespec(0, timeout), rc);
    return rc;
  }
  int e = errno;
  if (timeout)
    deadline = timespec_add(timespec_real(), *timeout);
  if (vlen > IOV_MAX)
    vlen = IOV_MAX;
  for (i = 0; i < vlen; ++i) {
    int f = flags & ~MSG_WAITFORONE;
    if (i) {
      if (flags & MSG_WAITFORONE)
        f |= MSG_DONTWAIT;
      if (timeout) {
        struct timespec left = timespec_subz(deadline, timespec_real());
        struct pollfd pfd = {fd, POLLIN, 0};
        int ms = timespec_tomillis(left);
        if (!(f & MSG_DONTWAIT) && poll(&pfd, 1, ms) <= 0)
          break;
        if (timespec_iszero(left))
          break;
      }
    }
    ssize_t n = recvmsg(fd, &msgvec[i].msg_hdr, f);
    if (n == -1)
      break;
    msgvec[i].msg_len = n;
  }
  rc = i || !vlen ? (int)i : -1;
  if (i)
    errno = e;
  STRACE("recvmmsg(%d, %p, %u, %#x, %s) → %d% m", fd, msgvec, vlen, flags,
         DescribeTimespec(0, timeout), rc);
  return rc;
}
