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
#include "ape/sections.internal.h"
#include "libc/calls/struct/rseq.h"
#include "libc/dce.h"
#include "libc/intrin/atomic.h"
#include "libc/macros.h"
#include "libc/mem/mem.h"
#include "libc/runtime/internal.h"
#include "libc/runtime/runtime.h"
#include "libc/stdio/sysparam.h"
#include "libc/str/locale.h"
#include "libc/str/str.h"
#include "libc/thread/tls.h"
#include "third_party/dlmalloc/dlmalloc.h"

static_assert(sizeof(struct CosmoTib) == 1024);

#define I(x) ((uintptr_t)x)

static char *_mktls_finish(struct CosmoTib **out_tib, char *mem,
                           struct CosmoTib *tib, struct CosmoTib *old) {
  bzero(tib, sizeof(*tib));
  tib->tib_self = tib;
  tib->tib_self2 = tib;
  if (old) {
    tib->tib_ftrace = old->tib_ftrace;
    tib->tib_strace = old->tib_strace;
    tib->tib_sigmask = old->tib_sigmask;
  } else {
    tib->tib_ftrace = __ftrace;
    tib->tib_strace = __strace;
  }
  ((struct rseq *)tib->tib_rseq)->cpu_id = RSEQ_CPU_ID_UNINITIALIZED;
  atomic_init(&tib->tib_ctid, -1);
  if (out_tib)
    *out_tib = tib;
  return mem;
}

static size_t _mktls_below_size(void) {
  return ROUNDUP(I(_tls_size) + sizeof(struct CosmoTib),
                 _Alignof(struct CosmoTib));
}

static char *_mktls_below(char *mem, struct CosmoTib **out_tib,
                          struct CosmoTib *old) {
  size_t siz;
  char *tls;
  struct CosmoTib *tib;

  // Here's the TLS memory layout on x86_64
  //
  //                           __get_tls()
  //                               │
  //                              %fs OpenBSD/NetBSD
  //            _Thread_local      │
  //     ┌───┬──────────┬──────────┼───┐
  //     │pad│  .tdata  │  .tbss   │tib│
  //     └───┴──────────┴──────────┼───┘
  //                               │
  //    Linux/FreeBSD/Windows/Mac %gs
  //

  siz = _mktls_below_size();
  tib = (struct CosmoTib *)(mem + siz - sizeof(*tib));
  tls = mem + siz - sizeof(*tib) - I(_tls_size);

  // copy in initialized data section
  if (I(_tdata_size))
    memcpy(tls, _tdata_start, I(_tdata_size));

  // clear .tbss
  if (I(_tbss_size))
    bzero(tls + I(_tbss_offset), I(_tbss_size));

  // set up thread information block
  return _mktls_finish(out_tib, mem, tib, old);
}

static size_t _mktls_above_size(void) {
  return ROUNDUP(sizeof(struct CosmoTib), I(_tls_align)) +  //
         ROUNDUP(sizeof(uintptr_t) * 2, I(_tdata_align)) +  //
         ROUNDUP(I(_tdata_size), I(_tbss_align)) +          //
         I(_tbss_size);
}

static char *_mktls_above(char *mem, struct CosmoTib **out_tib,
                          struct CosmoTib *old) {

  // Here's the TLS memory layout on aarch64
  //
  //            x28
  //         %tpidr_el0
  //             │
  //             │    _Thread_local
  //         ┌───┼───┬──────────┬──────────┐
  //         │tib│dtv│  .tdata  │  .tbss   │
  //         ├───┴───┴──────────┴──────────┘
  //         │
  //     __get_tls()
  //

  struct CosmoTib *tib =
      (struct CosmoTib *)(mem +
                          ROUNDUP(sizeof(struct CosmoTib), I(_tls_align)) -
                          sizeof(struct CosmoTib));

  uintptr_t *dtv = (uintptr_t *)(tib + 1);
  size_t dtv_size = sizeof(uintptr_t) * 2;

  char *tdata = (char *)dtv + ROUNDUP(dtv_size, I(_tdata_align));
  if (I(_tdata_size))
    memmove(tdata, _tdata_start, I(_tdata_size));

  char *tbss = tdata + ROUNDUP(I(_tdata_size), I(_tbss_align));
  if (I(_tbss_size))
    bzero(tbss, I(_tbss_size));

  dtv[0] = 1;
  dtv[1] = (uintptr_t)tib;  // the thread register points at dtv, see tlsasm.S

  return _mktls_finish(out_tib, mem, tib, old);
}

/**
 * Returns how much memory _mktls_at() lays out, and its alignment.
 */
size_t _mktls_size(size_t *out_align) {
#ifdef __x86_64__
  if (out_align)
    *out_align = _Alignof(struct CosmoTib);
  return _mktls_below_size();
#else
  if (out_align)
    *out_align = I(_tls_align);
  return _mktls_above_size();
#endif
}

/**
 * Lays out thread-local storage for a new thread in `mem`.
 *
 * This neither allocates nor reads the calling thread's tls, so it can
 * set up a thread that has no tib yet. The tracing flags come from the
 * globals and the signal mask starts out empty.
 */
char *_mktls_at(char *mem, struct CosmoTib **out_tib) {
#ifdef __x86_64__
  return _mktls_below(mem, out_tib, 0);
#else
  return _mktls_above(mem, out_tib, 0);
#endif
}

/**
 * Allocates thread-local storage memory for new thread.
 * @return buffer that must be released with free()
 */
char *_mktls(struct CosmoTib **out_tib) {
  char *mem;
  size_t align, size = _mktls_size(&align);
  if (!(mem = memalign(align, size)))
    return 0;
#ifdef __x86_64__
  return _mktls_below(mem, out_tib, __get_tls());
#else
  return _mktls_above(mem, out_tib, __get_tls());
#endif
}
