/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2023 Justine Alexandra Roberts Tunney                              │
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
#include "libc/dce.h"
#include "libc/fmt/itoa.h"
#include "libc/mem/mem.h"
#include "libc/paths.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/errfuns.h"
#include "libc/unistd.h"

// what a program that loads host libraries would be running against,
// which is the host's glibc and not ours. the version is read out of
// the host's libc.so.6, whose symbol versions name it
static const char *const kGlibcPaths[] = {
#ifdef __x86_64__
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/lib64/libc.so.6",
    "/usr/lib/libc.so.6",
    "/usr/lib64/libc.so.6",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
#else
    "/lib/aarch64-linux-gnu/libc.so.6",
    "/lib64/libc.so.6",
    "/usr/lib/libc.so.6",
    "/usr/lib/aarch64-linux-gnu/libc.so.6",
#endif
};

static int host_glibc_minor(void) {
  static int cached = -2;
  if (cached != -2)
    return cached;
  cached = -1;
  for (size_t i = 0; i < sizeof(kGlibcPaths) / sizeof(*kGlibcPaths); ++i) {
    int fd;
    if ((fd = open(kGlibcPaths[i], O_RDONLY | O_CLOEXEC)) == -1)
      continue;
    // the strings can straddle a read, so each one keeps the tail
    enum { CHUNK = 65536, KEEP = 16 };
    char *buf;
    if (!(buf = malloc(CHUNK + KEEP))) {
      close(fd);
      break;
    }
    size_t have = 0;
    ssize_t got;
    while ((got = read(fd, buf + have, CHUNK)) > 0) {
      have += got;
      for (size_t j = 0; j + 8 < have; ++j) {
        if (memcmp(buf + j, "GLIBC_2.", 8))
          continue;
        int v = 0;
        size_t k = j + 8;
        while (k < have && buf[k] >= '0' && buf[k] <= '9')
          v = v * 10 + buf[k++] - '0';
        if (k < have && !buf[k] && v > cached)
          cached = v;
      }
      if (have > KEEP) {
        memmove(buf, buf + have - KEEP, KEEP);
        have = KEEP;
      }
    }
    free(buf);
    close(fd);
    if (cached >= 0)
      break;
  }
  return cached;
}

size_t confstr(int name, char *buf, size_t len) {
  char tmp[32];
  if (name == _CS_PATH)
    return strlcpy(buf, _PATH_DEFPATH, len) + 1;
  if (name == _CS_GNU_LIBC_VERSION || name == _CS_GNU_LIBPTHREAD_VERSION) {
    int minor;
    if (!IsLinux() || (minor = host_glibc_minor()) < 0) {
      einval();
      return 0;
    }
    char *p = tmp;
    p = stpcpy(p, name == _CS_PATH ? "" : "glibc 2.");
    p = FormatInt32(p, minor);
    return strlcpy(buf, tmp, len) + 1;
  }
  einval();
  return 0;
}
