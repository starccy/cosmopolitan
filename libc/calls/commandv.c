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
#include "libc/calls/struct/stat.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/strace.h"
#include "libc/paths.h"
#include "libc/runtime/runtime.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/ok.h"
#include "libc/sysv/consts/s.h"
#include "libc/sysv/errfuns.h"

static bool commandv_is_executable(const char *path, bool *seen_eacces) {
  if (!access(path, X_OK)) {
    struct stat st;
    if (!stat(path, &st) && S_ISREG(st.st_mode))
      return true;
  } else if (errno == EACCES) {
    *seen_eacces = true;
  }
  return false;
}

/**
 * Resolves full pathname of executable.
 *
 * On Windows a name with no extension that isn't found as it is gets
 * tried with `.exe` and then `.com` appended, in each directory, which
 * is how every resolver native to that platform treats a bare name.
 *
 * @return execve()'able path, or NULL w/ errno
 * @errno ENOENT, EACCES, ENOMEM
 * @see free(), execvpe()
 * @asyncsignalsafe
 * @vforksafe
 */
char *commandv(const char *name, char *pathbuf, size_t pathbufsz) {

  // bounce empty names
  size_t namelen;
  if (!(namelen = strlen(name))) {
    enoent();
    return 0;
  }

  // get system path
  const char *syspath;
  if (memchr(name, '/', namelen)) {
    syspath = "";
  } else if (!(syspath = getenv("PATH"))) {
    syspath = _PATH_DEFPATH;
  }

  // a name that already has an extension is taken as it is
  const char *dot = strrchr(name, '.');
  const char *slash = strrchr(name, '/');
  bool suffixable = IsWindows() && (!dot || (slash && dot < slash));

  // iterate through directories
  int old_errno = errno;
  bool seen_eacces = false;
  const char *b, *a = syspath;
  errno = ENOENT;
  do {
    b = strchrnul(a, ':');
    size_t dirlen = b - a;
    if (dirlen + 1 + namelen < pathbufsz) {
      size_t len;
      if (dirlen) {
        memcpy(pathbuf, a, dirlen);
        pathbuf[dirlen] = '/';
        memcpy(pathbuf + dirlen + 1, name, namelen + 1);
        len = dirlen + 1 + namelen;
      } else {
        memcpy(pathbuf, name, namelen + 1);
        len = namelen;
      }
      if (commandv_is_executable(pathbuf, &seen_eacces)) {
        errno = old_errno;
        return pathbuf;
      }
      if (suffixable && len + 4 + 1 <= pathbufsz) {
        static const char kSuffixes[2][5] = {".exe", ".com"};
        for (int i = 0; i < 2; ++i) {
          memcpy(pathbuf + len, kSuffixes[i], 5);
          if (commandv_is_executable(pathbuf, &seen_eacces)) {
            errno = old_errno;
            return pathbuf;
          }
        }
      }
    } else {
      enametoolong();
    }
    a = b + 1;
  } while (*b);

  // return error if not found
  if (seen_eacces) {
    errno = EACCES;
  }
  return 0;
}
