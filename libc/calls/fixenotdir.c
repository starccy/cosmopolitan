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
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/ctype.h"
#include "libc/errno.h"
#include "libc/nt/enum/fileflagandattributes.h"
#include "libc/nt/errors.h"
#include "libc/nt/files.h"
#include "libc/nt/process.h"
#include "libc/nt/runtime.h"
#include "libc/str/str.h"

// prefixes where earlier walks found the first missing component. a
// walk under one asks about it first, which settles a whole missing
// subtree (a module resolver trying src/pkg/... with no src/) in one
// query instead of one per missing level. the answer still comes from
// that query, so a stale hint costs a query and never a wrong errno
#define HINTS 8
static uint64_t __enotdir_hints[HINTS];  // 48-bit fnv-1a << 16 | length
static unsigned __enotdir_hints_next;

textwindows static uint64_t __hintkey(uint64_t hash, size_t len) {
  return (hash & 0xffffffffffff) << 16 | len;
}

textwindows static bool __ishint(uint64_t key) {
  for (int i = 0; i < HINTS; ++i)
    if (__atomic_load_n(&__enotdir_hints[i], __ATOMIC_RELAXED) == key)
      return true;
  return false;
}

// length of the deepest hinted prefix of p above its last component
textwindows static size_t __findhint(const char16_t *p, size_t n) {
  size_t parent = n;
  while (parent && p[parent - 1] != '\\')
    --parent;
  if (parent < 2)
    return 0;
  --parent;
  size_t best = 0;
  uint64_t hash = 0xcbf29ce484222325;
  for (size_t i = 0; i <= parent; ++i) {
    if (i && (i == parent || p[i] == '\\') && __ishint(__hintkey(hash, i)))
      best = i;
    hash = (hash ^ p[i]) * 0x100000001b3;
  }
  return best;
}

textwindows static void __addhint(const char16_t *p, size_t len) {
  uint64_t hash = 0xcbf29ce484222325;
  for (size_t i = 0; i < len; ++i)
    hash = (hash ^ p[i]) * 0x100000001b3;
  uint64_t key = __hintkey(hash, len);
  if (!__ishint(key))
    __atomic_store_n(&__enotdir_hints[__atomic_fetch_add(
                         &__enotdir_hints_next, 1, __ATOMIC_RELAXED) %
                                      HINTS],
                     key, __ATOMIC_RELAXED);
}

textwindows bool __hasregularparent(char16_t *p) {
  size_t n = strlen16(p);
  size_t h;
  if ((h = __findhint(p, n))) {
    char16_t c = p[h];
    p[h] = 0;
    uint32_t dwFileAttrs = GetFileAttributes(p);
    uint32_t dwErrorCode = dwFileAttrs == -1u ? GetLastError() : 0;
    if (dwFileAttrs != -1u && !(dwFileAttrs & kNtFileAttributeDirectory))
      return true;
    if (dwErrorCode == kNtErrorFileNotFound)
      return false;
    if (dwErrorCode == kNtErrorPathNotFound) {
      n = h;  // the break is above the hint, walk on from there
    } else {
      p[h] = c;  // below it, or unknown: the whole walk
    }
  }
  bool first = true;
  char16_t *e = p + n;
  while (e > p) {
    if (e[-1] == '\\')
      break;
    if (e - p >= 2 && e[-1] == '?' && e[-2] == '\\')
      break;
    if (e - p >= 3 && e[-1] == '?' && e[-2] == '?' && e[-3] == '\\')
      break;
    if (e - p >= 3 && e[-1] == ':' && isalpha(e[-2]) && e[-3] == '\\')
      break;
    if (first) {
      first = false;
    } else {
      uint32_t dwFileAttrs;
      if ((dwFileAttrs = GetFileAttributes(p)) != -1u)
        return !(dwFileAttrs & kNtFileAttributeDirectory);
      if (GetLastError() == kNtErrorFileNotFound) {
        __addhint(p, e - p);
        return false;  // missing, in a directory that's there
      }
    }
    while (e > p) {
      int c = e[-1];
      *--e = 0;
      if (c == '\\')
        break;
    }
  }
  return false;
}

// When files don't exist, normally UNIX systems raise ENOENT, except if
// one of the parent directory components in the path exists, but is not
// actually a dirctory, in which case ENOTDIR is raised instead. Example
// would be stat("/etc/passwd/lol") raising ENOTDIR since /etc/passwd is
// obviously a regular file.
textwindows int64_t __fix_enotdir(int64_t rc, char16_t *path) {
  if (rc == -1) {
    // restored at the end, the walk leaves its own last error behind
    uint32_t dwErrorCode = GetLastError();
    switch (errno) {
      case ENOTDIR:
        if (!__hasregularparent(path))
          errno = ENOENT;
        break;
      case ENOENT:
        // nt reports a regular file in the middle of the path as
        // ERROR_PATH_NOT_FOUND, on ntfs and smb alike, so the parent of
        // an ERROR_FILE_NOT_FOUND is a directory and there's no walk
        if (dwErrorCode != kNtErrorFileNotFound && __hasregularparent(path))
          errno = ENOTDIR;
        break;
      default:
        break;
    }
    SetLastError(dwErrorCode);
  }
  return rc;
}
