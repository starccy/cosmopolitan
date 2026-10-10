#include "libc/calls/cp.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/strace.h"
#include "libc/sock/internal.h"
#include "libc/sock/struct/msghdr.h"
#include "libc/sysv/consts/iov.h"

/**
 * Sends multiple messages on a socket.
 *
 * Each entry goes out through sendmsg(); the byte count lands in its
 * msg_len. Sending stops at the first failure: if that was the first
 * entry the call fails, otherwise the entries already sent are counted
 * and the error is dropped, which is what Linux does.
 *
 * @return number of messages sent, or -1 w/ errno
 */
int sendmmsg(int fd, struct mmsghdr *msgvec, unsigned int vlen, int flags) {
  int rc;
  unsigned int i;
  if (IsLinux()) {
    BEGIN_CANCELATION_POINT;
    rc = sys_sendmmsg(fd, msgvec, vlen, flags);
    END_CANCELATION_POINT;
    STRACE("sendmmsg(%d, %p, %u, %#x) → %d% m", fd, msgvec, vlen, flags, rc);
    return rc;
  }
  int e = errno;
  if (vlen > IOV_MAX)
    vlen = IOV_MAX;
  for (i = 0; i < vlen; ++i) {
    ssize_t n = sendmsg(fd, &msgvec[i].msg_hdr, flags);
    if (n == -1)
      break;
    msgvec[i].msg_len = n;
  }
  rc = i || !vlen ? (int)i : -1;
  if (i)
    errno = e;
  STRACE("sendmmsg(%d, %p, %u, %#x) → %d% m", fd, msgvec, vlen, flags, rc);
  return rc;
}
