#include "libc/intrin/strace.h"
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
  unsigned int i;
  if (vlen > IOV_MAX)
    vlen = IOV_MAX;
  for (i = 0; i < vlen; ++i) {
    ssize_t n = sendmsg(fd, &msgvec[i].msg_hdr, flags);
    if (n == -1)
      break;
    msgvec[i].msg_len = n;
  }
  int rc = i || !vlen ? (int)i : -1;
  STRACE("sendmmsg(%d, %p, %u, %#x) → %d% m", fd, msgvec, vlen, flags, rc);
  return rc;
}
