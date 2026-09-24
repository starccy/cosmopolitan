/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2022 Justine Alexandra Roberts Tunney                              │
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
#include "libc/atomic.h"
#include "libc/calls/blockcancel.internal.h"
#include "libc/calls/calls.h"
#include "libc/calls/cp.internal.h"
#include "libc/calls/internal.h"
#include "libc/calls/struct/sigset.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/cosmo.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/describeflags.h"
#include "libc/intrin/strace.h"
#include "libc/macros.h"
#include "libc/runtime/runtime.h"
#include "libc/sysv/consts/sig.h"
#include "libc/sysv/errfuns.h"

#define COPY_STACK_BUF 2048
#define COPY_MAP_BUF   (1024 * 1024)

static struct CopyFileRange {
  atomic_uint once;
  bool ok;
} g_copy_file_range;

static bool HasCopyFileRange(void) {
  int e;
  bool ok;
  e = errno;
  BLOCK_CANCELATION;
  if (IsLinux()) {
    // We modernize our detection by a few years for simplicity.
    // This system call is chosen since it's listed by pledge().
    // https://www.cygwin.com/bugzilla/show_bug.cgi?id=26338
    ok = sys_close_range(-1, -2, 0) == -1 && errno == EINVAL;
  } else if (IsFreebsd()) {
    ok = sys_copy_file_range(-1, 0, -1, 0, 0, 0) == -1 && errno == EBADF;
  } else {
    ok = false;
  }
  ALLOW_CANCELATION;
  errno = e;
  return ok;
}

static void copy_file_range_init(void) {
  g_copy_file_range.ok = HasCopyFileRange();
}

/**
 * Moves bytes from one descriptor to another with read() and write().
 *
 * A null offset pointer means the descriptor's own position is used and
 * advanced; a non-null one means pread()/pwrite() at that offset, which
 * is then advanced by what moved. Whatever got copied before an error
 * is returned as a short count, so the caller sees -1 only when nothing
 * moved at all. When a write fails partway through a chunk that was
 * read from the descriptor's own position, the read position is moved
 * back over the unwritten bytes if the source is seekable.
 */
ssize_t __copy_fd_range(int infd, int64_t *inoff, int outfd, int64_t *outoff,
                        size_t n) {
  char stack[COPY_STACK_BUF];
  char *buf = stack;
  size_t bufsize = sizeof(stack);
  size_t total = 0;
  bool failed = false;
  if (n > sizeof(stack)) {
    bufsize = MIN(n, COPY_MAP_BUF);
    if (!(buf = _mapanon(bufsize)))
      return -1;
  }
  while (total < n && !failed) {
    ssize_t got;
    size_t want = MIN(n - total, bufsize);
    if (inoff) {
      got = pread(infd, buf, want, *inoff);
    } else {
      got = read(infd, buf, want);
    }
    if (got == -1) {
      failed = true;
      break;
    }
    if (!got)
      break;
    size_t put = 0;
    while (put < got) {
      ssize_t w;
      if (outoff) {
        w = pwrite(outfd, buf + put, got - put, *outoff);
      } else {
        w = write(outfd, buf + put, got - put);
      }
      if (w == -1) {
        failed = true;
        break;
      }
      put += w;
      if (outoff)
        *outoff += w;
    }
    if (inoff) {
      *inoff += put;
    } else if (put < got) {
      int e = errno;
      lseek(infd, -(int64_t)(got - put), SEEK_CUR);
      errno = e;
    }
    total += put;
  }
  if (buf != stack) {
    int e = errno;
    munmap(buf, bufsize);
    errno = e;
  }
  if (failed && !total)
    return -1;
  return total;
}

/**
 * Transfers data between files.
 *
 * If this system call is available (Linux c. 2018 or FreeBSD c. 2021)
 * and the file system supports it (e.g. ext4) and the source and dest
 * files are on the same file system, then this system call shall make
 * copies go about 2x faster.
 *
 * This implementation requires Linux 5.9+ even though the system call
 * was introduced in Linux 4.5. That's to ensure ENOSYS works reliably
 * due to a faulty backport, that happened in RHEL7. FreeBSD detection
 * on the other hand will work fine.
 *
 * Where the kernel has no such call (Windows, MacOS, NetBSD, OpenBSD,
 * older Linux) or answers EXDEV or EOPNOTSUPP before anything moved,
 * the copy is done with pread()/pwrite() or read()/write() instead,
 * with the same offset semantics. That also covers a source under
 * /zip/, which the kernel call can't see.
 *
 * @param infd is source file, which should be on same file system
 * @param opt_in_out_inoffset may be specified for pread() behavior
 * @param outfd should be a writable file, but not `O_APPEND`
 * @param opt_in_out_outoffset may be specified for pwrite() behavior
 * @param uptobytes is maximum number of bytes to transfer
 * @param flags is reserved for future use and must be zero
 * @return number of bytes transferred, or -1 w/ errno
 * @raise EBADF if `infd` or `outfd` aren't open files or append-only
 * @raise EPERM if `fdout` refers to an immutable file on Linux
 * @raise ECANCELED if thread was cancelled in masked mode
 * @raise EINVAL if ranges overlap or `flags` is non-zero
 * @raise EINVAL on eCryptFs filesystems that have a bug
 * @raise EFBIG if `setrlimit(RLIMIT_FSIZE)` is exceeded
 * @raise EFAULT if one of the pointers memory is bad
 * @raise ERANGE if overflow happens computing ranges
 * @raise ENOSPC if file system has run out of space
 * @raise ETXTBSY if source or dest is a swap file
 * @raise EINTR if a signal was delivered instead
 * @raise EISDIR if source or dest is a directory
 * @raise EIO if a low-level i/o error happens
 * @see sendfile() for seekable → socket
 * @see splice() for fd ↔ pipe
 * @cancelationpoint
 */
ssize_t copy_file_range(int infd, int64_t *opt_in_out_inoffset, int outfd,
                        int64_t *opt_in_out_outoffset, size_t uptobytes,
                        uint32_t flags) {
  ssize_t rc;
  cosmo_once(&g_copy_file_range.once, copy_file_range_init);
  BEGIN_CANCELATION_POINT;
  if (flags) {
    rc = einval();
  } else if (__isfdkind(outfd, kFdZip)) {
    rc = ebadf();
  } else if (!g_copy_file_range.ok || __isfdkind(infd, kFdZip)) {
    rc = __copy_fd_range(infd, opt_in_out_inoffset, outfd,
                         opt_in_out_outoffset, uptobytes);
  } else {
    rc = sys_copy_file_range(infd, opt_in_out_inoffset, outfd,
                             opt_in_out_outoffset, uptobytes, flags);
    if (rc == -1 &&
        (errno == ENOSYS || errno == EXDEV || errno == EOPNOTSUPP)) {
      rc = __copy_fd_range(infd, opt_in_out_inoffset, outfd,
                           opt_in_out_outoffset, uptobytes);
    }
  }
  END_CANCELATION_POINT;
  STRACE("copy_file_range(%d, %s, %d, %s, %'zu, %#x) → %'ld% m", infd,
         DescribeInOutInt64(rc, opt_in_out_inoffset), outfd,
         DescribeInOutInt64(rc, opt_in_out_outoffset), uptobytes, flags, rc);
  return rc;
}
