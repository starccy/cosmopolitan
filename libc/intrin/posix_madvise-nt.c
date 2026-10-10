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
#include "libc/calls/syscall-nt.internal.h"
#include "libc/errno.h"
#include "libc/intrin/maps.h"
#include "libc/nt/enum/offerpriority.h"
#include "libc/nt/enum/memflags.h"
#include "libc/nt/memory.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/memoryrangeentry.h"
#include "libc/runtime/runtime.h"
#include "libc/stdio/sysparam.h"
#include "libc/sysv/consts/map.h"
#include "libc/sysv/consts/posix.h"
#include "libc/sysv/errno.h"

// `decommit` is madvise(MADV_DONTNEED), which gives private anonymous
// pages back to nt; posix_madvise() only discards their contents, since
// cosmo's own callers (the thread stack cache) hand the memory to code
// that can't fault it back in, like a new thread's first push
textwindows errno_t __madvise_nt(char *addr, size_t size, int advice,
                                 bool decommit) {
  errno_t err = 0;
  size = (size + __pagesize - 1) & -__pagesize;
  __maps_lock();
  struct Map *map;
  if (!(map = __maps_floor(addr)))
    map = __maps_first();
  for (; map && map->addr <= addr + size; map = __maps_next(map)) {
    char *map_addr = map->addr;
    size_t map_size = map->size;
    char *beg = MAX(addr, map_addr);
    char *end = MIN(addr + size,
                    map_addr + ((map_size + __pagesize - 1) & -__pagesize));
    if (beg >= end)
      continue;
    switch (advice) {
      case POSIX_MADV_NORMAL:
        break;
      case POSIX_MADV_RANDOM:
      case POSIX_MADV_WILLNEED:
      case POSIX_MADV_SEQUENTIAL:
        if (!PrefetchVirtualMemory(GetCurrentProcess(), 1,
                                   &(struct NtMemoryRangeEntry){beg, end - beg},
                                   0))
          if (!err)
            err = __winerrno(GetLastError());
        break;
      case POSIX_MADV_DONTNEED:
        // private anonymous pages are decommitted, which gives their
        // commit charge back the way linux drops the pages; the next
        // touch faults and __nt_commit_on_fault() (mmap.c) commits them
        // again, zero filled. the allocation is then one fork() copies
        // by NT's own page state (MAP_NOCOMMIT). file views and memory
        // that isn't ours (stacks) keep their pages
        if (!(map->flags & (MAP_HOLE | MAP_NOFORK)) &&
            __maps_head(map)->hand == MAPS_VIRTUAL) {
          if (decommit && (map->flags & MAP_ANONYMOUS) &&
              (map->flags & MAP_TYPE) != MAP_SHARED) {
            if (VirtualFree(beg, end - beg, kNtMemDecommit)) {
              map->flags |= MAP_NOCOMMIT;
            } else if (!err) {
              err = __winerrno(GetLastError());
            }
          } else {
            DiscardVirtualMemory(beg, end - beg);
          }
        }
        break;
      default:
        err = EINVAL;
        break;
    }
  }
  __maps_unlock();
  return err;
}

textwindows errno_t sys_posix_madvise_nt(char *addr, size_t size, int advice) {
  return __madvise_nt(addr, size, advice, false);
}
