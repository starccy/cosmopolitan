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
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/ctype.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/limits.h"
#include "libc/mem/mem.h"
#include "libc/nt/files.h"
#include "libc/proc/ntspawn.h"
#include "libc/stdio/sysparam.h"
#include "libc/str/str.h"
#include "libc/str/thompike.h"
#include "libc/str/utf16.h"
#include "libc/sysv/consts/at.h"
#include "libc/sysv/errfuns.h"

#define APPEND(c)     \
  do {                \
    if (k < size)     \
      cmdline[k] = c; \
    ++k;              \
  } while (0)

textwindows static bool NeedsQuotes(const char *s) {
  if (!*s)
    return true;
  do {
    switch (*s) {
      case '"':
      case ' ':
      case '\t':
      case '\v':
      case '\n':
        return true;
      default:
        break;
    }
  } while (*s++);
  return false;
}

textwindows static bool LooksLikeCosmoDrivePath(const char *s) {
  return s[0] == '/' &&    //
         isalpha(s[1]) &&  //
         s[2] == '/';
}

// "/xx/..." is a cosmos drive path if it exists there, otherwise a native
// switch like "/nologo". "/x" and "/x/..." are drive spellings, handled
// above, so the switch "/c" never becomes "C:\c"
textwindows static bool IsExistingRootPath(const char *s) {
  char16_t path16[PATH_MAX];
  if (s[0] != '/' || !s[1] || s[1] == '/')
    return false;
  if (isalpha(s[1]) && (s[2] == '/' || !s[2]))
    return false;
  return __mkntpath(s, path16) != -1 && GetFileAttributes(path16) != -1u;
}

// Converts System V argv to Windows-style command line.
//
// Escaping is performed and it's designed to round-trip with
// GetDosArgv() or GetDosArgv(). This function does NOT escape
// command interpreter syntax, e.g. $VAR (sh), %VAR% (cmd).
//
// @param cmdline is output buffer
// @param argv is an a NULL-terminated array of UTF-8 strings
// @param size is number of characters in cmdline buffer
// @return length on success, which is >=size on truncation
// @see "Everyone quotes command line arguments the wrong way" MSDN
// @see libc/runtime/getdosargv.c
// @asyncsignalsafe
// @param rewrite_paths says whether arguments spelled like "/x/..."
//     become "x:\...": a native program wants that, an ape child reads
//     unix paths itself and would rather see the argument as typed. a
//     letter that names no drive is never rewritten, since "/t/f" is then
//     a real directory on the cosmos drive (see __mkntpath)
textwindows size_t mkntcmdline2(char16_t *cmdline, char *const argv[],
                                size_t size, bool rewrite_paths) {
  char *arg;
  int slashes, n;
  bool needsquote;
  size_t i, j, k, s;
  char argbuf[PATH_MAX];
  for (k = i = 0; argv[i]; ++i) {
    if (i)
      APPEND(u' ');
    if (rewrite_paths &&
        ((LooksLikeCosmoDrivePath(argv[i]) && __ntdriveexists(argv[i][1])) ||
         (!i && argv[i][0] == '/' && argv[i][1] && argv[i][1] != '/') ||
         IsExistingRootPath(argv[i])) &&
        __unixtodospath(argv[i], argbuf, PATH_MAX) != -1) {
      arg = argbuf;
    } else {
      arg = argv[i];
    }
    if ((needsquote = NeedsQuotes(arg)))
      APPEND(u'"');
    for (slashes = j = 0;;) {
      wint_t x = arg[j++] & 255;
      if (x >= 0300) {
        n = ThomPikeLen(x);
        x = ThomPikeByte(x);
        while (--n) {
          wint_t y;
          if ((y = arg[j++] & 255)) {
            x = ThomPikeMerge(x, y);
          } else {
            x = 0;
            break;
          }
        }
      }
      if (!x)
        break;
      if (x == '\\') {
        ++slashes;
      } else if (x == '"') {
        APPEND(u'"');
        APPEND(u'"');
        APPEND(u'"');
      } else {
        for (s = 0; s < slashes; ++s)
          APPEND(u'\\');
        slashes = 0;
        uint32_t w = EncodeUtf16(x);
        do
          APPEND(w);
        while ((w >>= 16));
      }
    }
    for (s = 0; s < (slashes << needsquote); ++s)
      APPEND(u'\\');
    if (needsquote)
      APPEND(u'"');
  }
  if (size)
    cmdline[MIN(k, size - 1)] = 0;
  return k;
}

textwindows size_t mkntcmdline(char16_t *cmdline, char *const argv[],
                               size_t size) {
  return mkntcmdline2(cmdline, argv, size, true);
}
