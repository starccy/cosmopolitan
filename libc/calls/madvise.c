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
#include "libc/calls/syscall-nt.internal.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/runtime/runtime.h"
#include "libc/runtime/syslib.internal.h"
#include "libc/sysv/consts/madv.h"
#include "libc/sysv/errfuns.h"
#include "libc/intrin/maps.h"
#include "libc/macros.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/map.h"
#include "libc/sysv/consts/prot.h"

#define XNU_MAP_PRIVATE 0x2
#define XNU_MAP_FIXED   0x10
#define XNU_MAP_ANON    0x1000

int sys_mprotect(void *, size_t, int);

// fresh anonymous pages over a range, through the syslib on apple silicon
static int madvise_xnu_remap(char *addr, size_t len, int prot) {
  int flags = XNU_MAP_FIXED | XNU_MAP_PRIVATE | XNU_MAP_ANON;
  long p;
  if (IsXnuSilicon()) {
    p = _sysret(__syslib->__mmap(addr, len, prot, flags, -1, 0));
  } else {
    p = (long)__sys_mmap(addr, len, prot, flags, -1, 0, 0);
  }
  return p == -1 ? -1 : 0;
}

// linux frees the pages madvise(MADV_DONTNEED) names and a private
// anonymous mapping reads back as zeros, where xnu keeps them: fresh
// pages go over the range. MADV_REMOVE frees a shared anonymous
// mapping's pages for everyone who maps them, which zeroing in place
// does. anything else goes to the kernel as it is
static int madvise_xnu(char *addr, size_t len, int advice) {
  int rc = 0;
  __maps_lock();
  struct Map *map;
  if (!(map = __maps_floor(addr)))
    map = __maps_first();
  for (; map && map->addr <= addr + len; map = __maps_next(map)) {
    char *beg = MAX(addr, map->addr);
    char *end = MIN(addr + len, map->addr + ROUNDUP(map->size, __pagesize));
    if (beg >= end || !(map->flags & MAP_ANONYMOUS))
      continue;
    bool shared = map->flags & MAP_SHARED;
    if (advice == MADV_DONTNEED && !shared) {
      if (madvise_xnu_remap(beg, end - beg, map->prot) == -1) {
        rc = -1;
        break;
      }
    } else if (advice == MADV_REMOVE && shared) {
      if (!(map->prot & PROT_WRITE))
        sys_mprotect(beg, end - beg, map->prot | PROT_WRITE);
      bzero(beg, end - beg);
      if (!(map->prot & PROT_WRITE))
        sys_mprotect(beg, end - beg, map->prot);
    }
  }
  __maps_unlock();
  if (!rc)
    rc = sys_madvise(addr, len, advice == MADV_REMOVE ? MADV_DONTNEED : advice);
  return rc;
}

/**
 * Advises kernel about memory intentions.
 *
 * @return 0 on success, or -1 w/ errno
 * @raise EINVAL if `advice` isn't valid
 * @raise EINVAL if `len` is negative
 * @raise EINVAL if `addr` isn't multiple of `sysconf(_SC_PAGESIZE)`
 * @raise ENOMEM if interval overlaps unmapped pages (on some OSes)
 */
int madvise(void *addr, size_t len, int advice) {

  int sysadvice = advice;
  switch (advice) {
    case MADV_NORMAL:
    case MADV_RANDOM:
    case MADV_WILLNEED:
    case MADV_SEQUENTIAL:
    case MADV_DONTNEED:
      break;
    case MADV_REMOVE:
      if (!IsLinux() && !IsXnu())
        return einval();
      break;
    case MADV_FREE:
      if (IsXnu() || IsFreebsd()) {
        sysadvice = 5;
      } else if (IsNetbsd() || IsOpenbsd()) {
        sysadvice = 6;
      } else if (IsWindows()) {
        sysadvice = MADV_DONTNEED;
      }
      break;
    default:
      // the kernel knows its own advice values, which are what we use
      if (IsLinux())
        break;
      return einval();
  }

  if (!len)
    return 0;

  if ((int64_t)len < 0)
    return einval();

  if ((uintptr_t)addr & (__pagesize - 1))
    return einval();

  int rc = 0;
  if (IsXnu() && (advice == MADV_DONTNEED || advice == MADV_REMOVE)) {
    rc = madvise_xnu(addr, len, advice);
  } else if (!IsWindows()) {
    rc = sys_madvise(addr, len, sysadvice);
  } else {
    errno_t err = __madvise_nt(addr, len, sysadvice, advice == MADV_DONTNEED);
    if (err) {
      errno = err;
      rc = -1;
    }
  }

  return rc;
}
