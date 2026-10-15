/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2025 Justine Alexandra Roberts Tunney                              │
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
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/intrin/describeflags.h"
#include "libc/intrin/strace.h"
#include "libc/sysv/consts/f.h"
#include "libc/sysv/errfuns.h"
#include "libc/calls/internal.h"
#include "libc/nt/enum/filetype.h"
#include "libc/nt/files.h"
#include "libc/calls/calls.h"
#include "libc/calls/struct/stat.h"
#include "libc/sysv/consts/s.h"
#include "libc/sysv/pib.h"

int __fcntl_misc(int fd, int cmd, ...) {
  int rc;
  va_list va;
  uintptr_t arg;
  va_start(va, cmd);
  arg = va_arg(va, uintptr_t);
  va_end(va);
  if (IsWindows() && (cmd == F_GETPIPE_SZ || cmd == F_SETPIPE_SZ)) {
    if (!__isfdopen(fd)) {
      rc = ebadf();
    } else if (!__isfdkind(fd, kFdFile) ||
               GetFileType(__get_pib()->fds.p[fd].handle) != kNtFileTypePipe) {
      rc = ebadf();
    } else if (cmd == F_GETPIPE_SZ) {
      rc = 65536;  // what pipe-nt.c makes them with
    } else {
      rc = eperm();  // a pipe's buffer is sized when it's made
    }
  } else if (IsXnu() && (cmd == F_GETPIPE_SZ || cmd == F_SETPIPE_SZ)) {
    // a pipe grows to 64kb for a big write and no further
    struct stat st;
    if (fstat(fd, &st) == -1) {
      rc = -1;
    } else if (!S_ISFIFO(st.st_mode)) {
      rc = ebadf();
    } else if (cmd == F_GETPIPE_SZ || arg <= 65536) {
      rc = 65536;
    } else {
      rc = eperm();
    }
  } else if (IsWindows() || IsMetal()) {
    rc = einval();
  } else {
    rc = __sys_fcntl(fd, cmd, arg);
  }
  STRACE("fcntl(%d, %s, %ld) → %d% m", fd, DescribeFcntlCmd(cmd), arg, rc);
  return rc;
}
