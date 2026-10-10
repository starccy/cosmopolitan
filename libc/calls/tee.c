#include "libc/calls/calls.h"
#include "libc/calls/internal.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/intrin/strace.h"
#include "libc/calls/struct/stat.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/macros.h"
#include "libc/nt/errors.h"
#include "libc/nt/ipc.h"
#include "libc/nt/runtime.h"
#include "libc/mem/alloca.h"
#include "libc/runtime/stack.h"
#include "libc/sock/struct/pollfd.h"
#include "libc/sysv/consts/poll.h"
#include "libc/sysv/consts/s.h"
#include "libc/sysv/consts/splice.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"

#define SPLICE_BUF 16384

// NT pipes can be read without taking the data, so the copy comes from
// PeekNamedPipe() and the input pipe keeps it
textwindows static ssize_t sys_tee_nt(int infd, int outfd, size_t n,
                                      unsigned flags) {
  struct stat st;
  if (fstat(infd, &st) == -1)
    return -1;
  if (!S_ISFIFO(st.st_mode))
    return einval();
  if (fstat(outfd, &st) == -1)
    return -1;
  if (!S_ISFIFO(st.st_mode))
    return einval();
  if (!n)
    return 0;
#pragma GCC push_options
#pragma GCC diagnostic ignored "-Walloca-larger-than="
  char *buf = alloca(SPLICE_BUF);
#pragma GCC pop_options
  CheckLargeStackAllocation(buf, SPLICE_BUF);
  uint32_t got, avail;
  int64_t handle = __get_pib()->fds.p[infd].handle;
  for (;;) {
    if (!PeekNamedPipe(handle, buf, MIN(n, SPLICE_BUF), &got, &avail, 0)) {
      if (GetLastError() == kNtErrorBrokenPipe)
        return 0;
      return __winerr();
    }
    if (got)
      break;
    if (flags & SPLICE_F_NONBLOCK)
      return eagain();
    struct pollfd p = {infd, POLLIN};
    if (poll(&p, 1, -1) == -1)
      return -1;
  }
  ssize_t put = 0;
  while (put < got) {
    ssize_t w = write(outfd, buf + put, got - put);
    if (w == -1)
      break;
    put += w;
  }
  return put ? put : -1;
}

/**
 * Duplicates pipe content.
 *
 * @param flags can have SPLICE_F_{MOVE,NONBLOCK,MORE,GIFT}
 * @return number of bytes duplicated, 0 on input end, or -1 w/ errno
 * @raise ENOSYS on hosts other than Linux and Windows
 * @see splice()
 */
ssize_t tee(int infd, int outfd, size_t uptobytes, unsigned flags) {
  ssize_t rc;
  if (__isfdkind(infd, kFdZip) || __isfdkind(outfd, kFdZip)) {
    rc = einval();
  } else if (IsWindows()) {
    rc = sys_tee_nt(infd, outfd, uptobytes, flags);
  } else {
    rc = sys_tee(infd, outfd, uptobytes, flags);
  }
  STRACE("tee(%d, %d, %'zu, %#x) → %'ld% m", infd, outfd, uptobytes, flags,
         rc);
  return rc;
}
