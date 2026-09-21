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
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/ctype.h"
#include "libc/proc/ntspawn.h"

textwindows void mungentpath(char *path) {
  char *p;

  // turn colon into semicolon
  // unless it already looks like a dos path
  for (p = path; *p; ++p) {
    if (p[0] == ':' && p[1] != '\\') {
      p[0] = ';';
    }
  }

  // turn /c/... into c:\...
  p = path;
  if (p[0] == '/' && isalpha(p[1]) && p[2] == '/') {
    p[0] = p[1];
    p[1] = ':';
  }
  for (; *p; ++p) {
    if (p[0] == ';' && p[1] == '/' && isalpha(p[2]) && p[3] == '/') {
      p[1] = p[2];
      p[2] = ':';
    }
  }

  // turn slash into backslash
  for (p = path; *p; ++p) {
    if (*p == '/') {
      *p = '\\';
    }
  }
}

// Spells a unix path, or a colon separated list of them in the DOS way.
// Returns the length, or -1 when out is too small.
textwindows int __unixtodospath(const char *path, char *out, size_t size) {
  size_t k = 0;
  const char *p = path;
  char drive = __getcosmosdrive();
#define PUT(c)     \
  do {             \
    if (k < size)  \
      out[k] = c;  \
    ++k;           \
  } while (0)
  for (;;) {
    if (p[0] == '/' && p[1] != '/') {
      if (isalpha(p[1]) && p[2] == '/') {
        PUT(p[1]);
        PUT(':');
        p += 2;
      } else {
        PUT(drive);
        PUT(':');
      }
    }
    while (*p && !(p[0] == ':' && p[1] != '\\')) {
      PUT(*p == '/' ? '\\' : *p);
      ++p;
    }
    if (!*p)
      break;
    PUT(';');
    ++p;
  }
#undef PUT
  if (k >= size)
    return -1;
  out[k] = 0;
  return k;
}
