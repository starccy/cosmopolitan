#include "libc/calls/struct/iovec.h"
#include "libc/dce.h"
#include "libc/macros.h"
#include "libc/nt/struct/pollfd.h"
#include "libc/nt/winsock.h"
#include "libc/sock/internal.h"
#if SupportsWindows()

textwindows bool __winsock_send_ready(int64_t handle) {
  struct sys_pollfd_nt p = {handle, 0x0010 /* POLLWRNORM */, 0};
  return WSAPoll(&p, 1, 0) != 0;
}

// __winsock_block() can't be told not to block on a send (see the note
// in it), so a nonblocking send first asks whether the socket is
// writable, then sends at most this much, which a writable but nearly
// full buffer can be expected to take without a long wait
#define NONBLOCK_SEND_MAX 65536

textwindows size_t __winsock_clamp_send(struct iovec out[hasatleast 16],
                                        const struct iovec *iov,
                                        size_t iovlen) {
  size_t n, left = NONBLOCK_SEND_MAX;
  for (n = 0; n < iovlen && n < 16 && left; ++n) {
    out[n].iov_base = iov[n].iov_base;
    out[n].iov_len = MIN(iov[n].iov_len, left);
    left -= out[n].iov_len;
  }
  return n;
}

#endif /* __x86_64__ */
