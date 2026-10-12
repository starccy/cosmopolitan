/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2024 Justine Alexandra Roberts Tunney                              │
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
#include "ape/sections.internal.h"
#include "libc/assert.h"
#include "libc/calls/calls.h"
#include "libc/calls/internal.h"
#include "libc/calls/state.internal.h"
#include "libc/calls/struct/rlimit.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/cosmo.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/atomic.h"
#include "libc/intrin/bsr.h"
#include "libc/intrin/describebacktrace.h"
#include "libc/intrin/describeflags.h"
#include "libc/intrin/directmap.h"
#include "libc/intrin/kprintf.h"
#include "libc/intrin/maps.h"
#include "libc/intrin/strace.h"
#include "libc/intrin/tree.h"
#include "libc/intrin/weaken.h"
#include "libc/inttypes.h"
#include "libc/limits.h"
#include "libc/macros.h"
#include "libc/nt/enum/filemapflags.h"
#include "libc/nt/enum/memflags.h"
#include "libc/nt/enum/pageflags.h"
#include "libc/nt/errors.h"
#include "libc/nt/memory.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/memorybasicinformation.h"
#include "libc/runtime/runtime.h"
#include "libc/runtime/syslib.internal.h"
#include "libc/runtime/zipos.internal.h"
#include "libc/stdckdint.h"
#include "libc/stdio/sysparam.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/map.h"
#include "libc/sysv/consts/mremap.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/prot.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#include "libc/thread/lock.h"
#include "libc/thread/posixthread.internal.h"
#include "libc/thread/thread.h"
#include "libc/thread/tls.h"
#include "third_party/nsync/common.internal.h"

#define MAX_SIZE 0x0ff800000000ul

#define SPARSE_GROWTH  8
#define SPARSE_MINIMUM 2097152
#define SPARSE_RANDPAD 2097152

#define MAP_EXCL_freebsd 0x4000

#define MAP_FIXED_NOREPLACE_linux 0x100000

#define PGUP(x) (((x) + __pagesize - 1) & -__pagesize)
#define GRUP(x) (((x) + __gransize - 1) & -__gransize)

struct DirectMap {
  void *addr;
  int64_t hand;
};

static bool __maps_overlaps(const char *addr, size_t size) {
  struct Map *map;
  if (!(map = __maps_floor(addr)))
    map = __maps_first();
  for (; map && map->addr <= addr + size; map = __maps_next(map))
    if (MAX(addr, map->addr) <
        MIN(addr + PGUP(size), map->addr + PGUP(map->size)))
      return true;
  return false;
}

// returns true if all fragments of all allocations which overlap
// [addr,addr+size) are completely contained by [addr,addr+size).
textwindows static bool __maps_envelops(const char *addr, size_t size) {
  struct Map *map;
  size = PGUP(size);
  if (!(map = __maps_floor(addr)))
    map = __maps_first();
  while (map && map->addr <= addr + size) {
    if (MAX(addr, map->addr) < MIN(addr + size, map->addr + map->size)) {
      if (!__maps_isalloc(map))
        return false;  // didn't include first fragment of alloc
      if (addr > map->addr)
        return false;    // excluded leading pages of first fragment
      struct Map *next;  // set map to last fragment in allocation
      for (; (next = __maps_next(map)) && !__maps_isalloc(next); map = next)
        MAPS_ASSERT(map->addr + map->size == next->addr);  // contiguous
      if (addr + size < map->addr + PGUP(map->size))
        return false;  // excluded trailing pages of allocation
      map = next;
    } else {
      map = __maps_next(map);
    }
  }
  return true;
}

// windows can't release part of a VirtualAlloc() allocation. munmap()
// of a subrange decommits its pages and keeps the fragment in the tree
// as a hole, address space nothing may be handed until every fragment
// of the allocation is a hole, at which point it's released for real.
// mmap(MAP_FIXED) of anonymous private memory into such an allocation
// recommits in place, which is how allocators commit and decommit.

// splits map at `at`, which must lie strictly inside it. returns the
// new righthand fragment, or null if a tracking object couldn't be had
textwindows static struct Map *__maps_split(struct Map *map, char *at) {
  struct Map *right;
  if (!(right = __maps_alloc()))
    return 0;
  size_t left = at - map->addr;
  right->addr = at;
  right->size = map->size - left;
  right->off = (map->flags & MAP_ANONYMOUS) ? 0 : map->off + left;
  right->prot = map->prot;
  right->flags = map->flags;
  right->iscow = map->iscow;
  right->readonlyfile = map->readonlyfile;
  right->hand = MAPS_SUBREGION;
  map->size = left;
  tree_insert(&__maps.maps, &right->tree, __maps_compare);
  __maps.count += 1;
  return right;
}

// returns true if every mapping overlapping [addr,addr+size) is part of
// a VirtualAlloc() allocation that may have holes punched into it. with
// `gaps` false the range must also be covered without unmapped space
textwindows static bool __maps_nt_punchable(const char *addr, size_t size,
                                            bool gaps) {
  struct Map *map;
  const char *cur = addr;
  if (!(map = __maps_floor(addr)))
    map = __maps_first();
  for (; map && map->addr < addr + size; map = __maps_next(map)) {
    if (map->addr + PGUP(map->size) <= addr)
      continue;
    if (map->addr > cur && !gaps)
      return false;
    if (map->hand == MAPS_RESERVATION || (map->flags & MAP_NOFORK))
      return false;
    if (__maps_head(map)->hand != MAPS_VIRTUAL)
      return false;
    cur = map->addr + PGUP(map->size);
  }
  return gaps || cur >= addr + size;
}

// turns [addr,addr+size) into holes. the range must be punchable
textwindows static int __maps_nt_punch(char *addr, size_t size) {
  int rc = 0;
  struct Map *map, *next;
  if (!(map = __maps_floor(addr)))
    map = __maps_first();
  for (; map && map->addr < addr + size; map = next) {
    next = __maps_next(map);
    char *beg = MAX(addr, map->addr);
    char *end = MIN(addr + size, map->addr + PGUP(map->size));
    if (beg >= end)
      continue;
    if (map->flags & MAP_HOLE)
      continue;
    if (beg > map->addr)
      if (!(map = __maps_split(map, beg)))
        return enomem();
    if (end < map->addr + map->size)
      if (!(next = __maps_split(map, end)))
        return enomem();
    if (!VirtualFree(map->addr, map->size, kNtMemDecommit))
      rc = __winerr();
    __maps_unmark(map->addr, PGUP(map->size));
    map->prot = PROT_NONE;
    map->flags |= MAP_HOLE | MAP_NOCOMMIT;
    map->iscow = false;
  }
  return rc;
}

// releases every allocation touching [addr,addr+size) that's all holes
textwindows static int __maps_nt_release_holes(char *addr, size_t size) {
  int rc = 0;
  struct Map *map, *head, *next;
  if (!(map = __maps_floor(addr)))
    map = __maps_first();
  if (map)
    map = __maps_head(map);
  while (map && map->addr < addr + size) {
    head = map;
    bool holes = true;
    for (next = map; next && (next == head || !__maps_isalloc(next));
         next = __maps_next(next))
      if (!(next->flags & MAP_HOLE))
        holes = false;
    if (holes && head->hand == MAPS_VIRTUAL) {
      if (!VirtualFree(head->addr, 0, kNtMemRelease))
        rc = __winerr();
      for (map = head; map != next;) {
        struct Map *gone = map;
        map = __maps_next(map);
        tree_remove(&__maps.maps, &gone->tree);
        __maps.pages -= (gone->size + __pagesize - 1) / __pagesize;
        __maps.count -= 1;
        __maps_free(gone);
      }
    }
    map = next;
  }
  return rc;
}

// called by the vectored exception handler on an access violation. a
// page that's reserved but not committed inside a private anonymous
// mapping whose protection allows the access is committed, a granule
// at a time, and the faulting instruction runs again. that's how
// MAP_NORESERVE memory and pages madvise(MADV_DONTNEED) decommitted
// come back: zero filled, charged only once touched, as on linux
textwindows bool __nt_commit_on_fault(void *addr, int kind) {
  struct NtMemoryBasicInformation mbi;
  if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi))
    return false;
  if (mbi.State != kNtMemReserve && mbi.State != kNtMemCommit)
    return false;
  // a fault by the thread that holds the lock (the memory manager
  // touching memory it hasn't committed) is a real one; anyone else
  // waits for the holder to finish
  if (!__maps_lock_unless_mine())
    return false;
  bool ok = false;
  int prot = 0;
  char *beg = 0, *end = 0;
  struct Map *map = __maps_floor(addr);
  if (map && (char *)addr >= map->addr &&
      (char *)addr < map->addr + PGUP(map->size) &&
      (map->flags & MAP_ANONYMOUS) && (map->flags & MAP_TYPE) != MAP_SHARED &&
      !(map->flags & (MAP_HOLE | MAP_NOFORK)) &&
      __maps_head(map)->hand == MAPS_VIRTUAL) {
    prot = map->prot;
    // only an access the mapping allows is ours to satisfy
    if (kind == 1)
      ok = prot & PROT_WRITE;
    else if (kind == 8)
      ok = prot & PROT_EXEC;
    else
      ok = prot & (PROT_READ | PROT_WRITE);
  }
  if (ok) {
    // look again under the lock: another thread may have committed
    // this granule since the fault, and then the access just retries
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
      ok = false;
    } else if (mbi.State == kNtMemCommit) {
      ok = mbi.Protect == (uint32_t)__prot2nt(prot, false);
      __maps_unlock();
      return ok;
    } else if (mbi.State != kNtMemReserve) {
      ok = false;
    }
  }
  if (ok) {
    beg = (char *)((uintptr_t)addr & -__gransize);
    end = beg + __gransize;
    if (beg < map->addr)
      beg = map->addr;
    if (end > map->addr + PGUP(map->size))
      end = map->addr + PGUP(map->size);
    char *rend = (char *)mbi.BaseAddress + mbi.RegionSize;
    if (end > rend)
      end = rend;
    if (beg < (char *)mbi.BaseAddress)
      beg = mbi.BaseAddress;
    ok = beg < end &&
         VirtualAlloc(beg, end - beg, kNtMemCommit, __prot2nt(prot, false));
  }
  __maps_unlock();
  return ok;
}

// commits whatever of [addr,addr+size) is reserved but not committed in
// memory __nt_commit_on_fault() would commit on a touch. the kernel
// doesn't take our fault handler's help for buffers it's handed, it
// fails the call (ERROR_NOACCESS, WSAEFAULT) instead, so i/o calls this
// and retries. returns true if anything was committed
textwindows bool __nt_commit_range(void *addr, size_t size) {
  if (!size || !__maps_lock_unless_mine())
    return false;
  bool any = false;
  char *p = (char *)((uintptr_t)addr & -__pagesize);
  char *e = (char *)addr + size;
  while (p < e) {
    struct NtMemoryBasicInformation mbi;
    if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi))
      break;
    char *re = (char *)mbi.BaseAddress + mbi.RegionSize;
    if (re > e)
      re = e;
    if (mbi.State == kNtMemReserve) {
      struct Map *map = __maps_floor(p);
      if (!map || p >= map->addr + PGUP(map->size) ||
          !(map->prot & (PROT_READ | PROT_WRITE)) ||
          !(map->flags & MAP_ANONYMOUS) ||
          (map->flags & MAP_TYPE) == MAP_SHARED ||
          (map->flags & (MAP_HOLE | MAP_NOFORK)) ||
          __maps_head(map)->hand != MAPS_VIRTUAL)
        break;
      if (re > map->addr + PGUP(map->size))
        re = map->addr + PGUP(map->size);
      if (!VirtualAlloc(p, re - p, kNtMemCommit, __prot2nt(map->prot, false)))
        break;
      any = true;
    }
    p = re;
  }
  __maps_unlock();
  return any;
}

// fixed anonymous private mapping inside VirtualAlloc() memory, done in
// place: decommit, then commit again for fresh zeroed pages. the range
// must be punchable without gaps. called with the lock held
textwindows static void *__mmap_nt_inplace(char *addr, size_t size, int prot,
                                           int flags) {
  if (__maps_nt_punch(addr, size))
    return MAP_FAILED;
  struct Map *map;
  if (!(map = __maps_floor(addr)))
    map = __maps_first();
  for (; map && map->addr < addr + size; map = __maps_next(map)) {
    if (map->addr + PGUP(map->size) <= addr)
      continue;
    if (prot != PROT_NONE) {
      if (!VirtualAlloc(map->addr, map->size, kNtMemCommit,
                        __prot2nt(prot, false)))
        return (void *)enomem();
      map->flags = flags;
      if (prot & (PROT_READ | PROT_WRITE))
        __maps_mark(map->addr, PGUP(map->size));
    } else {
      map->flags = flags | MAP_NOCOMMIT;
    }
    map->prot = prot;
  }
  return addr;
}

#if MMAP_DEBUG
void __maps_check(void) {
  MAPS_ASSERT(!__tls_enabled || __maps_held());
  size_t maps = 0;
  size_t pages = 0;
  static unsigned mono;
  unsigned id = ++mono;
  for (struct Map *map = __maps_first(); map; map = __maps_next(map)) {
    MAPS_ASSERT(map->addr != MAP_FAILED);
    MAPS_ASSERT(map->visited != id);
    MAPS_ASSERT(map->size);  // todo: how did this fail
    map->visited = id;
    pages += (map->size + __pagesize - 1) / __pagesize;
    maps += 1;
    struct Map *next;
    if ((next = __maps_next(map))) {
      MAPS_ASSERT(map->addr < next->addr);
      MAPS_ASSERT(
          MAX(map->addr, next->addr) >=
          MIN(map->addr + PGUP(map->size), next->addr + PGUP(next->size)));
    }
  }
  MAPS_ASSERT(maps == __maps.count);
  MAPS_ASSERT(pages == __maps.pages);
}
#endif

#if MMAP_DEBUG
static void __maps_ok(void) {
  __maps_lock();
  __maps_check();
  __maps_unlock();
}
__attribute__((__constructor__)) static void __maps_ctor(void) {
  atexit(__maps_ok);
  __maps_ok();
}
__attribute__((__destructor__)) static void __maps_dtor(void) {
  __maps_ok();
}
#endif

static int __muntrack(char *addr, size_t size, struct Map **deleted,
                      struct Map **untracked, struct Map temp[2]) {
  int rc = 0;
  size_t ti = 0;
  struct Map *map;
  struct Map *next;
  size = PGUP(size);
  if (!(map = __maps_floor(addr)))
    map = __maps_first();
  for (; map && map->addr <= addr + size; map = next) {
    next = __maps_next(map);
    char *map_addr = map->addr;
    size_t map_size = map->size;
    if (MAX(addr, map_addr) >= MIN(addr + size, map_addr + PGUP(map_size)))
      continue;
    if (addr <= map_addr && addr + size >= map_addr + PGUP(map_size)) {
      if (map->hand == MAPS_RESERVATION)
        continue;
      // remove mapping completely
      tree_remove(&__maps.maps, &map->tree);
      map->freed = *deleted;
      *deleted = map;
      __maps.pages -= (map_size + __pagesize - 1) / __pagesize;
      __maps.count -= 1;
      __maps_check();
    } else if (addr <= map_addr) {
      // shave off lefthand side of mapping
      MAPS_ASSERT(addr + size < map_addr + PGUP(map_size));
      size_t left = addr + size - map_addr;
      size_t right = map_size - left;
      MAPS_ASSERT(right > 0);
      MAPS_ASSERT(left > 0);
      map->addr += left;
      map->size = right;
      MAPS_ASSERT(map->size);
      if (!(map->flags & MAP_ANONYMOUS))
        map->off += left;
      __maps.pages -= (left + __pagesize - 1) / __pagesize;
      if (untracked) {
        MAPS_ASSERT(ti < 2);
        temp[ti].addr = map_addr;
        temp[ti].size = left;
        MAPS_ASSERT(temp[ti].size);
        temp[ti].freed = *untracked;
        *untracked = temp;
        ++ti;
      }
      __maps_check();
    } else if (addr + size >= map_addr + PGUP(map_size)) {
      // shave off righthand side of mapping
      size_t left = addr - map_addr;
      size_t right = map_addr + map_size - addr;
      map->size = left;
      MAPS_ASSERT(map->size);
      __maps.pages -= (right + __pagesize - 1) / __pagesize;
      if (untracked) {
        MAPS_ASSERT(ti < 2);
        temp[ti].addr = addr;
        temp[ti].size = right;
        MAPS_ASSERT(temp[ti].size);
        temp[ti].freed = *untracked;
        *untracked = temp;
        ++ti;
      }
      __maps_check();
    } else {
      // punch hole in mapping
      size_t left = addr - map_addr;
      size_t middle = size;
      size_t right = map_size - middle - left;
      struct Map *leftmap;
      if ((leftmap = __maps_alloc())) {
        leftmap->addr = map_addr;
        leftmap->size = left;
        MAPS_ASSERT(leftmap->size);
        leftmap->off = map->off;
        leftmap->prot = map->prot;
        leftmap->flags = map->flags;
        map->addr += left + middle;
        map->size = right;
        MAPS_ASSERT(map->size);
        if (!(map->flags & MAP_ANONYMOUS))
          map->off += left + middle;
        tree_insert(&__maps.maps, &leftmap->tree, __maps_compare);
        __maps.pages -= (middle + __pagesize - 1) / __pagesize;
        __maps.count += 1;
        if (untracked) {
          MAPS_ASSERT(ti < 2);
          temp[ti].addr = addr;
          temp[ti].size = size;
          MAPS_ASSERT(temp[ti].size);
          temp[ti].freed = *untracked;
          *untracked = temp;
          ++ti;
        }
        __maps_check();
      } else {
        rc = -1;
      }
    }
  }
  return rc;
}

static void __maps_free_all(struct Map *list) {
  struct Map *next;
  for (struct Map *map = list; map; map = next) {
    next = map->freed;
    __maps_free(map);
  }
}

static void __maps_insert_all(struct Map *list) {
  struct Map *next;
  for (struct Map *map = list; map; map = next) {
    next = map->freed;
    __maps_insert(map);
  }
}

static int __maps_destroy_all(struct Map *list) {
  int rc = 0;
  for (struct Map *map = list; map; map = map->freed) {
    if (!IsWindows()) {
      if (sys_munmap(map->addr, map->size))
        rc = -1;
    } else {
      switch (map->hand) {
        case MAPS_SUBREGION:
        case MAPS_RESERVATION:
          break;
        case MAPS_VIRTUAL:
          if (!VirtualFree(map->addr, 0, kNtMemRelease))
            rc = __winerr();
          break;
        default:
          MAPS_ASSERT(map->hand > 0);
          if (!UnmapViewOfFile(map->addr))
            rc = __winerr();
          if (!CloseHandle(map->hand))
            rc = __winerr();
          break;
      }
    }
  }
  return rc;
}

static int __maps_funge_flags(int flags) {
  flags &= ~MAP_FIXED;
  flags &= ~MAP_FIXED_NOREPLACE;
  if ((flags & MAP_TYPE) == MAP_SHARED_VALIDATE) {
    flags &= ~MAP_TYPE;
    flags |= MAP_SHARED;
  }
  return flags;
}

static bool __maps_fungible(const struct Map *map) {
  // anonymous memory is fungible on unix, so we may coalesce such
  // mappings in the rbtree to have fewer objects. on windows even
  // anonymous memory has unique win32 handles we need to preserve
  return !IsWindows() && (map->flags & MAP_ANONYMOUS);
}

static bool __maps_adjacent(const struct Map *x, const struct Map *y) {
  char *a = x->addr + PGUP(x->size);
  char *b = y->addr;
  MAPS_ASSERT(a <= b);
  return a == b;
}

static bool __maps_mergeable(const struct Map *x, const struct Map *y) {
  if (!__maps_adjacent(x, y))
    return false;
  if (!__maps_fungible(x))
    return false;
  if (!__maps_fungible(y))
    return false;
  if (x->prot != y->prot)
    return false;
  if (__maps_funge_flags(x->flags) != __maps_funge_flags(y->flags))
    return false;
  return true;
}

void __maps_insert(struct Map *map) {
  struct Map *left, *right;
  MAPS_ASSERT(map->size);
  MAPS_ASSERT(!__tls_enabled || __maps_held());
  MAPS_ASSERT(!__maps_overlaps(map->addr, map->size));
  __maps.pages += (map->size + __pagesize - 1) / __pagesize;

  // find adjacent mappings
  if ((left = __maps_floor(map->addr))) {
    right = __maps_next(left);
  } else {
    right = __maps_first();
  }

  // avoid insert by making mapping on left bigger
  if (left)
    if (__maps_mergeable(left, map)) {
      left->size = PGUP(left->size);
      MAPS_ASSERT(left->size);
      left->size += map->size;
      MAPS_ASSERT(left->size);
      __maps_free(map);
      map = 0;
    }

  // avoid insert by making mapping on right bigger
  if (map && right)
    if (__maps_mergeable(map, right)) {
      map->size = PGUP(map->size);
      MAPS_ASSERT(map->size);
      right->addr -= map->size;
      right->size += map->size;
      MAPS_ASSERT(right->size);
      __maps_free(map);
      map = 0;
    }

  // check if we filled a hole
  if (!map && left && right)
    if (__maps_mergeable(left, right)) {
      left->size = PGUP(left->size);
      MAPS_ASSERT(left->size);
      left->size += right->size;
      MAPS_ASSERT(left->size);
      tree_remove(&__maps.maps, &right->tree);
      __maps_free(right);
      __maps.count -= 1;
    }

  // otherwise just insert
  if (map)
    __maps_add(map);

  // sanity check
  __maps_check();
}

// removes interval from rbtree (no sys_munmap)
int __maps_untrack(char *addr, size_t size) {
  struct Map *deleted = 0;
  int rc = __muntrack(addr, size, &deleted, 0, 0);
  __maps_free_all(deleted);
  __maps_unmark(addr, size);
  return rc;
}

// the MapViewOfFile() access that gives a view the page protection
// `prot` asks for. a private mapping writes copy-on-write
textwindows int __prot2ntview(int prot, int iscow, int shared) {
  int access = kNtFileMapRead;
  if (prot & PROT_WRITE)
    access = iscow ? kNtFileMapCopy : kNtFileMapWrite;
  (void)shared;
  return access;
}

// the page protection a view mapped with `access` starts out with
textwindows int __ntview2prot(int access) {
  int exec = access & kNtFileMapExecute;
  if (access & kNtFileMapCopy)
    return exec ? kNtPageExecuteWritecopy : kNtPageWritecopy;
  if (access & kNtFileMapWrite)
    return exec ? kNtPageExecuteReadwrite : kNtPageReadwrite;
  return exec ? kNtPageExecuteRead : kNtPageReadonly;
}

textwindows dontinline static struct DirectMap sys_mmap_nt(
    void *addr, size_t size, int prot, int flags, int fd, int64_t off) {
  struct DirectMap dm;

  // it's 5x faster
  if (!MAP_ANONYMOUS ||
      ((flags & MAP_ANONYMOUS) && (flags & MAP_TYPE) != MAP_SHARED)) {
    // allocators reserve huge PROT_NONE spans and grow into them with
    // mprotect(), which commits the pages it's given (see mprotect.c).
    // MAP_NORESERVE memory is reserved too and committed a granule at a
    // time by __nt_commit_on_fault() as it's touched, which is what the
    // flag asks for: linux charges such pages only once they're used
    uint32_t alloc = kNtMemReserve;
    if ((prot != PROT_NONE && !(flags & MAP_NORESERVE)) || (flags & MAP_FIXED))
      alloc |= kNtMemCommit;
    if (!(dm.addr = VirtualAlloc(addr, size, alloc, __prot2nt(prot, false))))
      dm.addr = MAP_FAILED;
    dm.hand = MAPS_VIRTUAL;
    return dm;
  }

  int64_t file_handle;
  if (flags & MAP_ANONYMOUS) {
    file_handle = -1;
  } else {
    file_handle = __get_pib()->fds.p[fd].handle;
  }

  // mark map handle as inheritable if fork might need it
  const struct NtSecurityAttributes *mapsec;
  if ((flags & MAP_TYPE) == MAP_SHARED) {
    mapsec = &kNtIsInheritable;
  } else {
    mapsec = 0;
  }

  // the section is created with the most a view could ever want, since
  // a view can't be given more than its section allows. the view itself
  // is mapped with what `prot` asks for and no more, which lands it on
  // the right page protection without a VirtualProtect() call, a call
  // that costs about as much as the mapping did. the exception is a
  // private writable view, which is mapped with execute and then has it
  // taken away: mprotect() can't remap a view that may hold private
  // pages, so execute has to be there from the start (see mprotect.c
  // for the views it can remap). open-nt.c always requests an
  // kNtGenericExecute accessmask, so the section usually gets execute
  int iscow = 0;
  int page_flags;
  int file_flags;
  if (file_handle != -1) {
    if ((flags & MAP_TYPE) != MAP_SHARED) {
      // windows has cow pages but they can't propagate across fork()
      // that means we only get copy-on-write for the root process :(
      page_flags = kNtPageExecuteWritecopy;
      iscow = 1;
    } else {
      if ((__get_pib()->fds.p[fd].flags & O_ACCMODE) == O_RDONLY) {
        page_flags = kNtPageExecuteRead;
      } else {
        page_flags = kNtPageExecuteReadwrite;
      }
    }
  } else {
    page_flags = kNtPageExecuteReadwrite;
  }
  file_flags = __prot2ntview(prot, iscow, (flags & MAP_TYPE) == MAP_SHARED);
  if (prot & PROT_EXEC)
    file_flags |= kNtFileMapExecute;
  if (iscow && (prot & PROT_WRITE))
    file_flags |= kNtFileMapExecute;
  if (page_flags == kNtPageExecuteRead && (file_flags & kNtFileMapWrite))
    return (dm.hand = -1, dm.addr = (void *)eacces(), dm);

  int e = errno;
TryAgain:
  if ((dm.hand = CreateFileMapping(file_handle, mapsec, page_flags,
                                   (size + off) >> 32, (size + off), 0))) {
    if ((dm.addr = MapViewOfFileEx(dm.hand, file_flags, off >> 32, off, size,
                                   addr))) {
      uint32_t oldprot;
      if (__ntview2prot(file_flags) == __prot2nt(prot, iscow) ||
          VirtualProtect(dm.addr, size, __prot2nt(prot, iscow), &oldprot))
        return dm;
      UnmapViewOfFile(dm.addr);
    }
    CloseHandle(dm.hand);
  } else if (!(prot & PROT_EXEC) &&                        //
             (page_flags == kNtPageExecuteWritecopy ||     //
              page_flags == kNtPageExecuteReadwrite ||     //
              page_flags == kNtPageExecuteRead) &&         //
             GetLastError() == kNtErrorAccessDenied) {
    // your file needs to have been O_CREAT'd with exec `mode` bits in
    // order to be mapped with executable permission. we always try to
    // get execute permission if the kernel will give it to us because
    // win32 would otherwise forbid mprotect() from elevating later on
    file_flags &= ~kNtFileMapExecute;
    switch (page_flags) {
      case kNtPageExecuteWritecopy:
        page_flags = kNtPageWritecopy;
        break;
      case kNtPageExecuteReadwrite:
        page_flags = kNtPageReadwrite;
        break;
      case kNtPageExecuteRead:
        page_flags = kNtPageReadonly;
        break;
      default:
        __builtin_unreachable();
    }
    errno = e;
    goto TryAgain;
  }

  dm.hand = -1;
  dm.addr = (void *)(intptr_t)-1;
  return dm;
}

static struct DirectMap sys_mmap(void *addr, size_t size, int prot, int flags,
                                 int fd, int64_t off) {
  struct DirectMap d;
  if (IsXnuSilicon()) {
    long p = _sysret(__syslib->__mmap(addr, size, prot, flags, fd, off));
    d.hand = -1;
    d.addr = (void *)p;
  } else if (IsWindows()) {
    d = sys_mmap_nt(addr, size, prot, flags, fd, off);
  } else if (IsMetal()) {
    d.addr = sys_mmap_metal(addr, size, prot, flags, fd, off);
    d.hand = -1;
  } else {
    d.addr = __sys_mmap(addr, size, prot, flags, fd, off, off);
    d.hand = -1;
  }
  return d;
}

static int __munmap(char *addr, size_t size) {

  // validate arguments
  if (((uintptr_t)addr & (__pagesize - 1)) ||  //
      !size || (uintptr_t)addr + size < size)
    return einval();

  // lock the memory manager
  __maps_lock();
  __maps_check();

  // on windows only whole allocations can be released. anything less
  // is decommitted and stays reserved as holes until the rest goes
  if (IsWindows())
    if (!__maps_envelops(addr, size)) {
      int rc;
      if (__maps_nt_punchable(addr, size, true)) {
        __maps_unmark(addr, size);
        rc = __maps_nt_punch(addr, size);
        rc |= __maps_nt_release_holes(addr, size);
      } else {
        rc = enotsup();
      }
      __maps_unlock();
      return rc;
    }

  // make this interval dangerous
  __maps_unmark(addr, size);

  // untrack mappings
  int rc;
  struct Map temp[2];
  struct Map *deleted = 0;
  struct Map *untracked = 0;
  rc = __muntrack(addr, size, &deleted, &untracked, temp);
  __maps_unlock();

  // ask operating system to remove mappings
  rc |= __maps_destroy_all(untracked);
  rc |= __maps_destroy_all(deleted);
  __maps_free_all(deleted);

  return rc;
}

// on platforms without sys_mremap() our mremap() polyfill makes the
// assumption that mmap() will auto-assign sparse addresses, so that
// mappings can grow in place. this is essential for realloc() speed
static size_t __maps_sparse(size_t size) {
  MAPS_ASSERT(!__tls_enabled || __maps_held());
  size *= SPARSE_GROWTH;
  if (size < SPARSE_MINIMUM)
    size = SPARSE_MINIMUM;
  if (SPARSE_RANDPAD)
    size += __maps_rand() % SPARSE_RANDPAD;
  size &= -__gransize;
  return size;
}

static void *__maps_pickaddr(size_t size, bool query) {
  MAPS_ASSERT(!__tls_enabled || __maps_held());
  char *addr = 0;
  struct Map *map, *prev;
  size = GRUP(size);
  if (!(map = __maps_last()))
    notpossible;
  // linux on arm64 puts the stack and the kernel's own picks in the
  // 48th bit, which is where pointers kept in 47 bits get cut off
  char *ceiling = IsLinux() && IsAarch64() ? (char *)(1ull << 47) : 0;
  // choose address beneath higher mapping
  for (; map; map = prev) {
    char *min = (char *)(intptr_t)__gransize;
    char *top = map->addr;
    if (ceiling && top > ceiling)
      top = ceiling;
    if ((prev = __maps_prev(map)))
      min = prev->addr + GRUP(prev->size);
    while (top > min && top - min >= size) {
      addr = top - size;
      if (query && IsWindows()) {
        for (char *p = addr; p < top;) {
          struct NtMemoryBasicInformation mbi;
          if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            // past what the host lets us map, keep looking lower down
            top = (char *)((uintptr_t)p & -__gransize);
            addr = 0;
            break;
          }
          if (mbi.State != kNtMemFree) {
            // skip the whole allocation, an image comes in many regions
            char *base = mbi.AllocationBase ? (char *)mbi.AllocationBase
                                            : (char *)mbi.BaseAddress;
            top = (char *)((uintptr_t)base & -__gransize);
            addr = 0;
            break;
          }
          char *end = (char *)mbi.BaseAddress + mbi.RegionSize;
          if (end <= p)
            return 0;
          p = end;
        }
      }
      if (addr)
        break;
    }
    if (addr)
      break;
  }
  // append if existing maps are too dense
  if (!addr) {
    map = __maps_last();
    addr = map->addr + GRUP(map->size);
    intptr_t end = (intptr_t)addr;
    if (ckd_add(&end, end, size))
      return 0;
    if (ceiling && (char *)end > ceiling)
      return 0;
  }
  return addr;
}

static void *__mmap_impl(char *addr, size_t size, int prot, int flags, int fd,
                         int64_t off) {

  // /dev/zero on windows maps as anonymous memory, the way linux does it
  if (IsWindows() && !(flags & MAP_ANONYMOUS) && __isfdkind(fd, kFdDevRandom) &&
      __get_pib()->fds.p[fd].devzero)
    flags |= MAP_ANONYMOUS;

  // validate file map args
  if (flags & MAP_ANONYMOUS) {
    // some operating systems will complain unless we do this
    fd = -1;
    off = 0;
  } else {
    // validate arguments for file mapping
    if (off & (__gransize - 1))
      return (void *)einval();
    if (IsWindows()) {
      if (!__isfdkind(fd, kFdFile))
        return (void *)eacces();
      if (__get_pib()->fds.p[fd].flags & _O_PATH)
        return (void *)ebadf();
      if ((__get_pib()->fds.p[fd].flags & O_ACCMODE) == O_WRONLY)
        return (void *)eacces();
    }
  }

  // windows: fixed anonymous private memory that lands inside existing
  // VirtualAlloc() allocations is recommitted in place, see above
  if (IsWindows() && (flags & MAP_FIXED) && (flags & MAP_ANONYMOUS) &&
      (flags & MAP_TYPE) != MAP_SHARED) {
    __maps_lock();
    if (!__maps_envelops(addr, size) &&
        __maps_nt_punchable(addr, size, false)) {
      void *res = __mmap_nt_inplace(addr, size, prot, flags);
      __maps_unlock();
      return res;
    }
    __maps_unlock();
    if ((uintptr_t)addr & (__gransize - 1))
      return (void *)eperm();
  }

  // allocate Map object
  struct Map *map;
  if (!(map = __maps_alloc()))
    return MAP_FAILED;

  // polyfill nuances of fixed mappings
  int sysflags = __mmap2host(flags & ~MAP_FIXED_NOREPLACE);
  bool hintmode = false;
  bool noreplace = false;
  bool fixedmode = false;
  if (flags & MAP_FIXED_NOREPLACE) {
    if (flags & MAP_FIXED) {
      __maps_free(map);
      return (void *)einval();
    }
    if (IsLinux()) {
      sysflags |= MAP_FIXED_NOREPLACE_linux;
    } else if (IsFreebsd()) {
      sysflags |= MAP_FIXED | MAP_EXCL_freebsd;
    }
    noreplace = true;
  } else if (flags & MAP_FIXED) {
    fixedmode = true;
  } else if (addr && IsFreebsd()) {
    // POSIX says addr is a hint when MAP_FIXED isn't used, but behavior
    // is implementation defined. In practice, every kernel will give us
    // addr if it's available. The only exception is FreeBSD, which goes
    // its own way. Cosmo believes mmap() should give you want you want.
    sysflags |= MAP_FIXED | MAP_EXCL_freebsd;
    hintmode = true;
  }

  // loop for memory
  int olderr = errno;
  int retries = 0;
  bool hostquery = false;
  struct DirectMap res;
  for (;;) {

    // transactionally find the mark on windows
    if (IsWindows()) {
      __maps_lock();
      if (!fixedmode) {
        // give user desired address if possible
        if (addr && __maps_overlaps(addr, size)) {
          if (noreplace) {
            __maps_unlock();
            __maps_free(map);
            return (void *)eexist();
          }
          addr = 0;
        }
        // choose suitable address then claim it in our rbtree
        if (!addr)
          addr = __maps_pickaddr(__maps_sparse(size), hostquery);
        if (!addr && !(addr = __maps_pickaddr(size, hostquery))) {
          __maps_unlock();
          __maps_free(map);
          return (void *)enomem();
        }
      } else {
        // remove existing mappings and their tracking objects
        if (!__maps_envelops(addr, size)) {
          __maps_unlock();
          __maps_free(map);
          return (void *)enotsup();
        }
        struct Map *deleted = 0;
        if (__muntrack(addr, size, &deleted, 0, 0)) {
          __maps_insert_all(deleted);
          __maps_unlock();
          __maps_free(map);
          return MAP_FAILED;
        }
        int rc = __maps_destroy_all(deleted);
        __maps_free_all(deleted);
        if (rc) {
          __maps_unlock();
          __maps_free(map);
          return (void *)eperm();
        }
      }
      // claims intended interval while still holding the lock
      map->addr = addr;
      map->size = size;
      MAPS_ASSERT(map->size);
      map->prot = 0;
      map->flags = 0;
      map->hand = MAPS_RESERVATION;
      __maps_insert(map);
      __maps_unlock();
    } else if (MMAP_IS_SPARSE && !fixedmode && !addr) {
      __maps_lock();
      addr = __maps_pickaddr(__maps_sparse(size), false);
      __maps_unlock();
    }

    // ask operating system for our memory
    // notice how we're not holding the lock
  TryAgain:
    res = sys_mmap(addr, size, prot, sysflags, fd, off);
    if (res.addr != MAP_FAILED)
      break;

    // handle failure
    if (IsWindows()) {
      // untrack reservation
      __maps_lock();
      tree_remove(&__maps.maps, &map->tree);
      __maps.pages -= (map->size + __pagesize - 1) / __pagesize;
      __maps.count -= 1;
      __maps_unlock();
      if (errno == EFAULT) {  // kNtErrorInvalidAddress
        // we've encountered mystery memory
        if (fixedmode) {
          // TODO(jart): Use VirtualQuery() to destroy mystery memory.
          errno = ENOMEM;
        } else if (noreplace) {
          // we can't try again with a different address in this case
          errno = EEXIST;
        } else if (++retries < 64) {
          hostquery = true;
          errno = olderr;
          addr = 0;
          continue;
        } else {
          errno = ENOMEM;
        }
      }
    }
    if (IsFreebsd() && (errno == EINVAL || errno == ENOMEM)) {
      // FreeBSD documents many reasons EINVAL can happen, e.g. size
      // being zero. We've already checked every single one of those
      // except for MAP_EXCL, which is the only possible reason now.
      // However, in practice, FreeBSD 14.1 seems to raise ENOMEM if
      // this fails instead. Wow MAP_EXCL is such total a trainwreck
      if (noreplace) {
        errno = EEXIST;
      } else if (hintmode) {
        errno = olderr;
        hintmode = false;
        sysflags &= ~(MAP_FIXED | MAP_EXCL_freebsd);
        goto TryAgain;
      }
    }
    __maps_free(map);
    return MAP_FAILED;
  }

  // polyfill map fixed noreplace
  if (noreplace && res.addr != addr) {
    MAPS_ASSERT(!IsWindows());
    sys_munmap(res.addr, size);
    __maps_free(map);
    return (void *)eexist();
  }

  // setup map object
  map->addr = res.addr;
  map->size = size;
  MAPS_ASSERT(map->size);
  map->off = off;
  map->prot = prot;
  map->flags = flags;
  map->hand = res.hand;
  if (IsWindows()) {
    if ((flags & MAP_ANONYMOUS) && (flags & MAP_TYPE) != MAP_SHARED &&
        (prot == PROT_NONE || (flags & MAP_NORESERVE)) && !fixedmode)
      map->flags |= MAP_NOCOMMIT;
    map->iscow = (flags & MAP_TYPE) != MAP_SHARED && fd != -1;
    map->readonlyfile = (flags & MAP_TYPE) == MAP_SHARED && fd != -1 &&
                        (__get_pib()->fds.p[fd].flags & O_ACCMODE) == O_RDONLY;
  }

  // track map object
  if (!IsWindows()) {
    struct Map *deleted = 0;
    __maps_lock();
    if (fixedmode)
      if (__muntrack(res.addr, size, &deleted, 0, 0))
        STRACE("memtrack compromised by hole punch oom");
    __maps_insert(map);
    __maps_unlock();
    __maps_free_all(deleted);
  } else {
    atomic_thread_fence(memory_order_release);
  }

  return res.addr;
}

static void *__mmap(char *addr, size_t size, int prot, int flags, int fd,
                    int64_t off) {
  char *res;

  // validate arguments. on windows a fixed mapping may be page aligned
  // when it lands inside an allocation, since it's then done in place
  if ((uintptr_t)addr & (__gransize - 1))
    if (!IsWindows() || !(flags & MAP_FIXED) ||
        ((uintptr_t)addr & (__pagesize - 1)))
      addr = NULL;
  if (!addr && (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)))
    return (void *)eperm();
  if ((intptr_t)addr < 0)
    return (void *)enomem();
  if (!size || (uintptr_t)addr + size < size)
    return (void *)einval();
  if (size > MAX_SIZE)
    return (void *)enomem();
  if (__maps.count * __pagesize + size >
      ~__get_pib()->rlimit[RLIMIT_AS].rlim_cur)
    return (void *)enomem();

  // create memory mappping
  if (__isfdkind(fd, kFdProc)) {
    res = (void *)enodev();
  } else if (!__isfdkind(fd, kFdZip)) {
    res = __mmap_impl(addr, size, prot, flags, fd, off);
  } else {
    res = _weaken(__zipos_mmap)(
        addr, size, prot, flags,
        (struct ZiposHandle *)(uintptr_t)__get_pib()->fds.p[fd].handle, off);
  }

  return res;
}

static long __mremap_polyfill_check(char *addr, size_t old_size) {

  // we support anon maps
  struct Map *base, *map, *next;
  if (!(base = map = __maps_floor(addr)))
    return efault();
  if (!(map->addr <= addr && addr < map->addr + map->size))
    return efault();
  if (!(map->flags & MAP_ANONYMOUS) || (map->flags & MAP_TYPE) == MAP_SHARED)
    return einval();
  if (!__maps_isalloc(base))
    return efault();

  // make sure old range fully covers existing mappings
  int prot;
  int flags;
  char *end = addr + old_size;
  for (;; map = next) {
    prot = map->prot;
    flags = map->flags & MAP_TYPE;
    if (map->addr + map->size == end)
      break;
    if (map->addr + map->size > end)
      return enomem();
    if (!(next = __maps_next(map)))
      return efault();
    if (map->addr + map->size != next->addr)
      return efault();
  }

  return (unsigned long)flags << 32 | prot;
}

static void *__mremap_polyfill_impl(char *addr, size_t old_size,
                                    size_t new_size) {

  __maps_lock();
  long rc = __mremap_polyfill_check(addr, old_size);
  __maps_unlock();
  if (rc == -1)
    return MAP_FAILED;
  int flags = rc >> 32;
  int prot = rc;

  // request system memory and create entry
  if (__mmap_impl(addr + old_size, new_size - old_size, prot,
                  flags | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1,
                  0) == MAP_FAILED)
    return (void *)enomem();

  return addr;
}

static void *__mremap_polyfill(char *addr, size_t old_size, size_t new_size,
                               int flags) {

  // round up new size
  new_size = PGUP(new_size);

  // we only support enough features to make dlrealloc happy
  if (flags & ~MREMAP_MAYMOVE)
    return (void *)einval();
  if (old_size & (__gransize - 1))
    return (void *)einval();
  if (new_size & (__gransize - 1))
    return (void *)einval();
  if (new_size < old_size) {
    if (__munmap(addr + new_size, old_size - new_size))
      return MAP_FAILED;
    return addr;
  }

  return __mremap_polyfill_impl(addr, old_size, new_size);
}

static void *__mremap_impl(char *old_addr, size_t old_size, size_t new_size,
                           int flags, char *new_addr) {

  // allocate object for tracking new mapping
  struct Map *map;
  if (!(map = __maps_alloc()))
    return (void *)enomem();

  // check old interval is fully contained within one mapping
  __maps_lock();
  struct Map *old_map;
  if (!(old_map = __maps_floor(old_addr)) ||
      old_addr + PGUP(old_size) > old_map->addr + PGUP(old_map->size) ||
      old_addr < old_map->addr) {
    __maps_unlock();
    __maps_free(map);
    return (void *)efault();
  }

  // save old properties
  int old_off = old_map->off;
  int old_prot = old_map->prot;
  int old_flags = old_map->flags;
  __maps_unlock();

  // netbsd mremap fixed returns enoent rather than unmapping old pages
  if (IsNetbsd() && (flags & MREMAP_FIXED))
    if (__munmap(new_addr, new_size)) {
      __maps_free(map);
      return MAP_FAILED;
    }

  // the time has come
  char *res;
  if (IsNetbsd()) {
    int sysfl = (flags & MREMAP_FIXED) ? MAP_FIXED : 0;
    res = sys_mremap(old_addr, old_size, (uintptr_t)new_addr, new_size, sysfl);
  } else {
    res = sys_mremap(old_addr, old_size, new_size, flags, (uintptr_t)new_addr);
  }

  if (res == MAP_FAILED) {
    __maps_free(map);
    return MAP_FAILED;
  }

  if (!(flags & MREMAP_MAYMOVE))
    MAPS_ASSERT(res == old_addr);

  __maps_lock();

  // untrack old mapping
  struct Map *deleted = 0;
  __muntrack(old_addr, old_size, &deleted, 0, 0);
  __maps_free_all(deleted);

  // track map object
  map->addr = res;
  map->size = new_size;
  MAPS_ASSERT(map->size);
  map->off = old_off;
  map->prot = old_prot;
  map->flags = old_flags;
  map->hand = -1;
  __maps_insert(map);

  __maps_unlock();

  return res;
}

static void *__mremap(char *old_addr, size_t old_size, size_t new_size,
                      int flags, char *new_addr) {

  // sizes must not be zero
  if (!old_size)
    return (void *)einval();
  if (!new_size)
    return (void *)einval();

  // check for big size
  if (old_size > MAX_SIZE)
    return (void *)enomem();
  if (new_size > MAX_SIZE)
    return (void *)enomem();

  // round up old size
  old_size = PGUP(old_size);

  // it is not needed
  if (new_size <= old_size)
    if (!(flags & MREMAP_FIXED))
      if (flags & MREMAP_MAYMOVE)
        flags &= ~MREMAP_MAYMOVE;

  // we support these flags
  if (flags & ~(MREMAP_MAYMOVE | MREMAP_FIXED))
    return (void *)einval();
  if ((flags & MREMAP_FIXED) && !(flags & MREMAP_MAYMOVE))
    return (void *)einval();

  // addresses must be granularity aligned
  if ((uintptr_t)old_addr & (__gransize - 1))
    return (void *)einval();
  if (flags & MREMAP_FIXED)
    if ((uintptr_t)new_addr & (__gransize - 1))
      return (void *)einval();

  // check for overflow
  if ((uintptr_t)old_addr + old_size < old_size)
    return (void *)enomem();
  if (flags & MREMAP_FIXED)
    if ((uintptr_t)new_addr + new_size < new_size)
      return (void *)enomem();

  // old and new intervals must not overlap
  if (flags & MREMAP_FIXED)
    if (MAX(old_addr, new_addr) <
        MIN(old_addr + old_size, new_addr + PGUP(new_size)))
      return (void *)einval();

  // handle no-op case
  if (PGUP(new_size) == old_size)
    return old_addr;

  // memory increase must not exceed RLIMIT_AS
  if (PGUP(new_size) > old_size)
    if (__maps.count * __pagesize - old_size + PGUP(new_size) >
        ~__get_pib()->rlimit[RLIMIT_AS].rlim_cur)
      return (void *)enomem();

  // use polyfill if needed
  if (IsNetbsd() && !(flags & MREMAP_MAYMOVE) && PGUP(new_size) > old_size)
    return __mremap_polyfill(old_addr, old_size, new_size, flags);
  if (!IsLinux() && !IsNetbsd())
    return __mremap_polyfill(old_addr, old_size, new_size, flags);

  // perform operation
  return __mremap_impl(old_addr, old_size, new_size, flags, new_addr);
}

static void __mmap_expand_memory_space(void) {
  // kludge to ensure address picking algorithm has plenty of room
  uintptr_t addr = 0x7e0000000000;
  for (;;) {
    if (__mmap((void *)addr, 1, PROT_NONE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1,
               0) != MAP_FAILED)
      break;
    addr >>= 1;
  }
}

/**
 * Creates memory mapping.
 *
 * The mmap() function is used by Cosmopolitan's malloc() implementation
 * to obtain new memory from the operating system. This function is also
 * useful for establishing a mapping between a file on disk and a memory
 * address, which avoids most need to call read() and write(). It is how
 * executables are loaded into memory, for instance, in which case pages
 * are loaded lazily from disk by the operating system.
 *
 * The `addr` parameter may be zero. This lets the implementation choose
 * an available address in memory. OSes normally pick something randomly
 * assigned, for security. Most OSes try to make sure subsequent mapping
 * requests will be adjacent to one another. More paranoid OSes may have
 * different mappings be sparse, with unmapped content between them. You
 * may not use the `MAP_FIXED` parameter to create a memory map at NULL.
 *
 * The `addr` parameter may be non-zero, in which case Cosmopolitan will
 * give you a mapping at that specific address if it's available. When a
 * mapping already exists at the requested address then another one will
 * be chosen automatically. On most OSes the newly selected address will
 * be as close-by as possible, but that's not guaranteed. If `MAP_FIXED`
 * is also supplied in `flags` then this hint is taken as mandatory, and
 * existing mappings at the requested interval will be auto-unmapped. If
 * the OS allows cheaply relocating pages via mremap() then the assigned
 * addresses will be dense. Otherwise assigned addresses will be sparse.
 *
 * The `size` parameter is implicitly rounded up to the system page size
 * reported by getpagesize() and sysconf(_SC_PAGESIZE). Your extra bytes
 * will be zero-initialized.
 *
 * The returned address will always be aligned, on the system allocation
 * granularity. This value may be obtained from getgransize() or calling
 * sysconf(_SC_GRANSIZE). Granularity is always greater than or equal to
 * the page size. On some platforms, i.e. Windows, it may be larger than
 * the page size.
 *
 * The `prot` value specifies the memory protection of the mapping. This
 * may be `PROT_NONE` to disallow all access otherwise it's a bitwise or
 * of the following constants:
 *
 * - `PROT_READ` allows read access
 * - `PROT_WRITE` allows write access
 * - `PROT_EXEC` allows execute access
 *
 * Some OSes (i.e. OpenBSD) will raise an error if both `PROT_WRITE` and
 * `PROT_EXEC` are requested. You may still modify executable memory but
 * you must use mprotect() to transition between the two states. On some
 * OSes like MacOS ARM64, you need to pass the `MAP_JIT` flag to get RWX
 * memory, which is considered zero on other OSes.
 *
 * The lower bits of the `flags` parameter specify the `MAP_TYPE`, which
 * may be:
 *
 * - `MAP_PRIVATE` for non-shared and copy-on-write mappings
 * - `MAP_SHARED` for memory that may be shared between processes
 *
 * Your `fd` argument specifies the file descriptor of the open file you
 * want to map. This parameter is ignored when `MAP_ANONYMOUS` is passed
 * via `flags`.
 *
 * Your `off` argument specifies the offset into a, file at which mapped
 * memory shall begin. It must be aligned to the allocation granularity,
 * which may be obtained from getgransize() or sysconf(_SC_GRANSIZE).
 *
 * The `MAP_FIXED_NOREPLACE` flag may be passed in `flags` which has the
 * same behavior as `MAP_FIXED` except it raises `EEXIST` when a mapping
 * already exists on the requested interval.
 *
 * The `MAP_CONCEAL` flag may be passed to prevent a memory mapping from
 * appearing in core dumps. This is currently supported on BSD OSes, and
 * is ignored on everything else.
 *
 * POSIX does not require mmap() to be asynchronous signal safe. But you
 * should be able to call this from a signal handler safely, if you know
 * that your signal will never interrupt the cosmopolitan memory manager
 * and the only way you can ensure that, is by blocking signals whenever
 * you call mmap(), munmap(), mprotect(), etc.
 *
 * @raise ENOMEM if `RUSAGE_AS` or similar limits are exceeded
 * @raise EEXIST if `flags` has `MAP_FIXED_NOREPLACE` and `addr` is used
 * @raise ENOTSUP if interval overlapped without enveloping win32 alloc
 * @raise EPERM if `addr` is null and `flags` has `MAP_FIXED`
 * @raise EINVAL if `addr` isn't granularity aligned with `MAP_FIXED`
 * @raise EINVAL if `size` is zero
 * @raise EINVAL if `flags` or `prot` hold invalid values
 * @raise EACCESS if `fd` isn't a regular file
 * @raise EACCESS if `fd` was opened in write-only mode
 * @raise EACCESS if `off` isn't getgransize() aligned
 */
void *mmap(void *addr, size_t size, int prot, int flags, int fd, int64_t off) {
  if (IsXnu() || IsFreebsd() || IsOpenbsd()) {
    __rarechange static atomic_uint once;
    cosmo_once(&once, __mmap_expand_memory_space);
  }
  void *res;
  BLOCK_SIGNALS;
  res = __mmap(addr, size, prot, flags, fd, off);
  ALLOW_SIGNALS;
  if (res != MAP_FAILED) {
    if (prot & (PROT_READ | PROT_WRITE)) {
      __maps_mark(res, size);
    } else {
      __maps_unmark(res, size);
    }
  }
  STRACE("mmap(%p, %'zu, %s, %s, %d, %'ld) → %p% m (%'zu bytes total)", addr,
         size, DescribeProtFlags(prot), DescribeMapFlags(flags), fd, off, res,
         __maps.pages * __pagesize);
  return res;
}

/**
 * Changes memory mapping.
 *
 * The `flags` parameter may have:
 *
 * - `MREMAP_MAYMOVE` to allow relocation
 *
 * - `MREMAP_FIXED` in which case, an additional parameter `new_addr` is
 *   taken. This flag is only supported on Linux and NetBSD. If you fail
 *   to also specify the `MREMAP_MAYMOVE` flag too, then EINVAL happens.
 *
 * This system call is intended to support the realloc() implementation.
 * As such, mremap() can be used to shrink mappings, grow mappings, then
 * finally if needed, relocate mappings. Cosmopolitan supports shrinking
 * and growing on every platform, however only Linux and NetBSD are able
 * to relocate memory without copying it. On other platforms, Cosmo will
 * try to auto-assign sparse addresses so that mappings may grow without
 * needing to be relocated. However this isn't guaranteed to work, based
 * on memory layout. So this function might return ENOMEM or EINVAL when
 * the system or process hasn't actually run out of memory. Callers need
 * to be prepared to ignore this, and fall back to another strategy like
 * explicit copying when this function fails. This function won't do any
 * work unless the operation can be fast.
 *
 * @return base address on success, or MAP_FAILED w/ errno
 * @raise EFAULT if pages in old address range didn't exist
 * @raise ENOMEM if the extra memory wasn't available
 * @raise ENOMEM if relocation was needed but not supported by system
 * @raise EINVAL if address isn't granularity aligned
 * @raise EINVAL if either size is zero
 * @raise EINVAL if flags has invalid or unsupported bits
 * @raise ENOTSUP if interval overlapped without enveloping win32 alloc
 */
void *cosmo_mremap(void *old_addr, size_t old_size, size_t new_size, int flags,
                   ...) {
  void *res;
  va_list ap;
  void *new_addr = 0;
  if (flags & MREMAP_FIXED) {
    va_start(ap, flags);
    new_addr = va_arg(ap, void *);
    va_end(ap);
  }
  BLOCK_SIGNALS;
  res = __mremap(old_addr, old_size, new_size, flags, new_addr);
  ALLOW_SIGNALS;
  if (res != MAP_FAILED) {
    if (old_addr != res)
      __maps_unmark(old_addr, old_size);
    __maps_mark(res, new_size);
  }
  STRACE("mremap(%p, %'zu, %'zu, %s, %p) → %p% m (%'zu bytes total)", old_addr,
         old_size, new_size, DescribeMremapFlags(flags), new_addr, res,
         __maps.pages * __pagesize);
  return res;
}

/**
 * Removes memory mapping.
 *
 * The `size` parameter is implicitly rounded up to the page size.
 *
 * @return 0 on success, or -1 w/ errno.
 * @raise ENOMEM if OOM happened when punching hole in existing mapping
 * @raise ENOTSUP if interval overlapped without enveloping win32 alloc
 * @raise EINVAL if `addr` isn't granularity aligned
 */
int munmap(void *addr, size_t size) {
  int rc;
  BLOCK_SIGNALS;
  rc = __munmap(addr, size);
  ALLOW_SIGNALS;
  STRACE("munmap(%p, %'zu) → %d% m (%'zu bytes total)", addr, size, rc,
         __maps.pages * __pagesize);
  return rc;
}

__weak_reference(mmap, mmap64);

// linux's name for it, which is the one code looks for
__weak_reference(cosmo_mremap, mremap);
