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
#include "libc/dce.h"
#include "libc/intrin/atomic.h"
#include "libc/intrin/hostlibc.h"
#include "libc/intrin/kprintf.h"
#include "libc/intrin/maps.h"
#include "libc/nt/enum/memflags.h"
#include "libc/nt/memory.h"
#include "libc/nt/struct/memorybasicinformation.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/runtime/runtime.h"
#include "libc/runtime/syslib.internal.h"

/**
 * Returns true if memory address doesn't officially exist.
 *
 * This function is lockless. It uses a five layer atomic radix trie for
 * validating memory addresses. Ideally we would find a way to crawl the
 * rbtree without locking. Not locking is important, since we don't want
 * to affect the scalability of functions like read() and write(), which
 * consult this function in order to raise EFAULT.
 *
 * This function supports address spaces up to 56 bits. The highest byte
 * in `addr` is ignored. Your page size much be at least 4096 bytes, and
 * rounded to a two power.
 *
 * @see https://en.wikipedia.org/wiki/Intel_5-level_paging
 */
__msabi extern typeof(VirtualQuery) *const __imp_VirtualQuery;

// memory that host libraries loaded by cosmo_dlopen() allocated, and
// the libraries themselves, aren't in our table, so ask the system
__privileged static bool32 host_mapped(uintptr_t page) {
  if (IsWindows()) {
    struct NtMemoryBasicInformation mbi;
    return __imp_VirtualQuery((void *)page, &mbi, sizeof(mbi)) &&
           mbi.State == kNtMemCommit;
  }
  if (IsXnuSilicon()) {
    static int (*mincore_)(void *, size_t, char *);
    char vec[1];
    if (!mincore_)
      mincore_ = __syslib->__dlsym((void *)-2, "mincore");
    return !mincore_ || !mincore_((void *)page, 1, vec);
  }
  if (IsLinux()) {
    long rc;
    unsigned char vec[1];
#ifdef __x86_64__
    asm volatile("syscall"
                 : "=a"(rc)
                 : "0"(27), "D"(page), "S"(1), "d"(vec)
                 : "rcx", "r11", "memory");
#elif defined(__aarch64__)
    register long x0 asm("x0") = page;
    register long x1 asm("x1") = 1;
    register long x2 asm("x2") = (long)vec;
    register long x8 asm("x8") = 232;
    asm volatile("svc\t0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    rc = x0;
#endif
    return !rc;
  }
  return true;
}

// pages the system confirmed. a page unmapped since is still let
// through, and the kernel's own EFAULT covers that
static _Atomic(uintptr_t) __host_pages[64];

__privileged static bool32 unknown(uintptr_t page) {
  if (!__hostlibc.loaded)
    return true;
  _Atomic(uintptr_t) *slot = __host_pages + (page / __pagesize) % 64;
  if (atomic_load_explicit(slot, memory_order_relaxed) == page + 1)
    return false;
  if (!host_mapped(page))
    return true;
  atomic_store_explicit(slot, page + 1, memory_order_relaxed);
  return false;
}

__privileged bool32 kisdangerous(const void *addr) {
  uintptr_t w = (uintptr_t)addr & -__pagesize;
  struct MapPageDirectory *pd;
  struct MapPageTable *pt;
  if (!(pd = atomic_load_explicit(&__maps.alive, memory_order_relaxed)))
    return unknown(w);
  size_t i = (w >> 48) & 511;
  if (!(pd = atomic_load_explicit(&pd->p[i].pd, memory_order_relaxed)))
    return unknown(w);
  i = (w >> 39) & 511;
  if (!(pd = atomic_load_explicit(&pd->p[i].pd, memory_order_relaxed)))
    return unknown(w);
  i = (w >> 30) & 511;
  if (!(pd = atomic_load_explicit(&pd->p[i].pd, memory_order_relaxed)))
    return unknown(w);
  i = (w >> 21) & 511;
  if (!(pt = atomic_load_explicit(&pd->p[i].pt, memory_order_relaxed)))
    return unknown(w);
  i = (w >> 12) & 511;
  if (atomic_load_explicit(&pt->p[i / 64], memory_order_acquire) &
      (1ull << (i & 63)))
    return false;
  return unknown(w);
}
