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
#include "libc/calls/calls.h"
#include "libc/calls/internal.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/cosmo.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/fmt/itoa.h"
#include "libc/intrin/describeflags.h"
#include "libc/intrin/strace.h"
#include "libc/mem/alloca.h"
#include "libc/str/str.h"
#include "libc/calls/struct/stat.h"
#include "libc/macros.h"
#include "libc/runtime/stack.h"
#include "libc/sock/struct/pollfd.h"
#include "libc/sysv/consts/poll.h"
#include "libc/sysv/consts/s.h"
#include "libc/sysv/consts/splice.h"
#include "libc/sysv/errfuns.h"

#define SPLICE_BUF 16384

static struct Splice {
  _Atomic(uint32_t) once;
  bool ok;
} g_splice;

static bool HasSplice(void) {
  int e;
  bool ok;
  e = errno;
  if (IsLinux()) {
    // Our testing indicates splice() doesn't work as documneted on
    // RHEL5 and RHEL7 so let's require a modern kernel to be safe.
    // We choose close_range() for this since it's listed by pledge
    ok = sys_close_range(-1, -2, 0) == -1 && errno == EINVAL;
  } else {
    ok = false;
  }
  errno = e;
  return ok;
}

static void splice_init(void) {
  g_splice.ok = HasSplice();
}

// one read and as many writes as it takes to pass it on, for hosts
// without splice(). as on linux one side has to be a pipe, and a pipe
// side takes no offset
static ssize_t splice_copy(int infd, int64_t *inoff, int outfd,
                           int64_t *outoff, size_t n, uint32_t flags) {
  struct stat st;
  bool inpipe, outpipe;
  if (fstat(infd, &st) == -1)
    return -1;
  inpipe = S_ISFIFO(st.st_mode);
  if (fstat(outfd, &st) == -1)
    return -1;
  outpipe = S_ISFIFO(st.st_mode);
  if (!inpipe && !outpipe)
    return einval();
  if ((inpipe && inoff) || (outpipe && outoff))
    return espipe();
  if ((inoff && *inoff < 0) || (outoff && *outoff < 0))
    return einval();
  if (!n)
    return 0;
  if (flags & SPLICE_F_NONBLOCK) {
    int k = 0;
    struct pollfd p[2];
    if (inpipe)
      p[k++] = (struct pollfd){infd, POLLIN};
    if (outpipe)
      p[k++] = (struct pollfd){outfd, POLLOUT};
    if (poll(p, k, 0) == -1)
      return -1;
    for (int i = 0; i < k; ++i)
      if (!(p[i].revents & (p[i].events | POLLHUP | POLLERR | POLLNVAL)))
        return eagain();
  }
#pragma GCC push_options
#pragma GCC diagnostic ignored "-Walloca-larger-than="
  char *buf = alloca(SPLICE_BUF);
#pragma GCC pop_options
  CheckLargeStackAllocation(buf, SPLICE_BUF);
  size_t want = MIN(n, SPLICE_BUF);
  ssize_t got = inoff ? pread(infd, buf, want, *inoff) : read(infd, buf, want);
  if (got <= 0)
    return got;
  ssize_t put = 0;
  while (put < got) {
    ssize_t w;
    if (outoff) {
      w = pwrite(outfd, buf + put, got - put, *outoff + put);
    } else {
      w = write(outfd, buf + put, got - put);
    }
    if (w == -1)
      break;
    put += w;
  }
  if (inoff)
    *inoff += put;
  if (outoff)
    *outoff += put;
  if (put < got && !inoff && !inpipe) {
    int e = errno;
    lseek(infd, put - got, SEEK_CUR);
    errno = e;
  }
  return put ? put : -1;
}

/**
 * Transfers data to/from pipe.
 *
 * @param flags can have SPLICE_F_{MOVE,NONBLOCK,MORE,GIFT}
 * @param opt_in_out_inoffset may be specified if `infd` isn't a pipe and is
 *     used as both an input and output parameter for pread() behavior
 * @param opt_in_out_outoffset may be specified if `outfd` isn't a pipe and is
 *     used as both an input and output parameter for pwrite() behavior
 * @return number of bytes transferred, 0 on input end, or -1 w/ errno
 * @raise EBADF if `infd` or `outfd` aren't open files or append-only
 * @raise ESPIPE if an offset arg was specified for a pipe fd
 * @raise EINVAL if offset was given for non-seekable device
 * @raise EINVAL if file system doesn't support splice()
 * @raise EFAULT if one of the pointers memory is bad
 * @raise EINVAL if `flags` is invalid
 * @note hosts other than Linux 5.9+ get a copy through a 16kb buffer,
 *     one read per call, which SPLICE_F_NONBLOCK checks with poll()
 * @see copy_file_range() for file ↔ file
 * @see sendfile() for seekable → socket
 */
ssize_t splice(int infd, int64_t *opt_in_out_inoffset, int outfd,
               int64_t *opt_in_out_outoffset, size_t uptobytes,
               uint32_t flags) {
  ssize_t rc;
  cosmo_once(&g_splice.once, splice_init);
  if (g_splice.ok && !__isfdkind(infd, kFdZip) && !__isfdkind(outfd, kFdZip)) {
    rc = sys_splice(infd, opt_in_out_inoffset, outfd, opt_in_out_outoffset,
                    uptobytes, flags);
  } else {
    rc = splice_copy(infd, opt_in_out_inoffset, outfd, opt_in_out_outoffset,
                     uptobytes, flags);
  }
  STRACE("splice(%d, %s, %d, %s, %'zu, %#x) → %'ld% m", infd,
         DescribeInOutInt64(rc, opt_in_out_inoffset), outfd,
         DescribeInOutInt64(rc, opt_in_out_outoffset), uptobytes, flags);
  return rc;
}
