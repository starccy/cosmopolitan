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
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/dce.h"
#include "libc/nt/files.h"
#include "libc/str/str.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"

int sys_chdir_nt16(char16_t[hasatleast PATH_MAX], uint32_t);

textwindows int sys_fchdir_nt(int dirfd) {
  char16_t dir[PATH_MAX];
  if (!__isfdkind(dirfd, kFdFile))
    return ebadf();
  uint32_t len = GetFinalPathNameByHandle(
      __get_pib()->fds.p[dirfd].handle, dir, ARRAYLEN(dir),
      kNtFileNameNormalized | kNtVolumeNameDos);

  // GetFinalPathNameByHandle() always answers in the \\?\ namespace,
  // which disables win32 path normalization, so SetCurrentDirectory()
  // would store the prefix verbatim and every child spawned afterwards
  // would inherit a \\?\C:\x cwd most programs can't parse. chdir()
  // doesn't have this problem since __mkntpath() only keeps the prefix
  // on paths too long for the classic limit, so do the same here
  if (len && len < ARRAYLEN(dir) && dir[0] == '\\' && dir[1] == '\\' &&
      dir[2] == '?' && dir[3] == '\\') {
    if (dir[4] == 'U' && dir[5] == 'N' && dir[6] == 'C' && dir[7] == '\\') {
      // \\?\UNC\srv\share\x -> \\srv\share\x
      if (len - 6 < 260) {
        memmove(dir + 2, dir + 8, (len - 8 + 1) * sizeof(char16_t));
        len -= 6;
      }
    } else {
      // \\?\C:\x -> C:\x
      if (len - 4 < 260) {
        memmove(dir, dir + 4, (len - 4 + 1) * sizeof(char16_t));
        len -= 4;
      }
    }
  }
  return sys_chdir_nt16(dir, len);
}
