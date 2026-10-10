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
#include "libc/dce.h"
#include "libc/intrin/cxaatexit.h"
#include "libc/intrin/strace.h"
#include "libc/intrin/weaken.h"
#include "libc/macros.h"
#include "libc/mem/mem.h"
#include "libc/nexgen32e/gc.internal.h"
#include "libc/nt/runtime.h"
#include "libc/thread/posixthread.internal.h"
#include "libc/thread/tls.h"

struct Dtor {
  void *fun;
  void *arg;
  struct Dtor *next;
};

static void _pthread_unwind(struct CosmoTib *tib) {
  struct PosixThread *pt;
  struct _pthread_cleanup_buffer *cb;
  pt = (struct PosixThread *)tib->tib_pthread;
  while ((cb = pt->pt_cleanup)) {
    pt->pt_cleanup = cb->__prev;
    cb->__routine(cb->__arg);
  }
}

static void _pthread_unkey(struct CosmoTib *tib) {
  for (int j = 0; j < PTHREAD_DESTRUCTOR_ITERATIONS; ++j) {
    bool gotsome = false;
    for (pthread_key_t i = 0; i < PTHREAD_KEYS_MAX; ++i) {
      void **slot;
      if (i < PTHREAD_KEYS_FAST) {
        slot = &tib->tib_keys_static[i];
      } else {
        if (!tib->tib_keys_dynamic)
          break;
        slot = &tib->tib_keys_dynamic[i - PTHREAD_KEYS_FAST];
      }
      // a key without a destructor keeps its value, so a destructor of
      // another key that runs later can still read it (rust's thread
      // handle lives in such a key and is released by the destructor of
      // another one)
      pthread_key_dtor dtor =
          atomic_load_explicit(&_pthread_key_dtor[i], memory_order_acquire);
      if (!dtor || dtor == (pthread_key_dtor)-1)
        continue;
      void *val = *slot;
      if (val) {
        *slot = 0;
        gotsome = true;
        STRACE("pthread_key_dtor(%t, %p)", dtor, val);
        dtor(val);
      }
    }
    if (!gotsome) {
      if (_weaken(free))
        _weaken(free)(tib->tib_keys_dynamic);
      tib->tib_keys_dynamic = 0;
      break;
    }
  }
}

static void _pthread_ungarbage(struct CosmoTib *tib) {
  struct Garbages *g;
  while ((g = tib->tib_garbages)) {
    tib->tib_garbages = 0;
    while (g->i--)
      ((void (*)(intptr_t))g->p[g->i].fn)(g->p[g->i].arg);
    if (_weaken(free)) {
      _weaken(free)(g->p);
      _weaken(free)(g);
    }
  }
}

void __cxa_thread_finalize(void) {
  struct Dtor *dtor;
  struct CosmoTib *tib;
  tib = __get_tls();

  // "Any cancellation cleanup handlers that have been pushed and not
  //  yet popped shall be popped in the reverse order that they were
  //  pushed and then executed." ──Quoth POSIX.1-2017
  _pthread_unwind(tib);

  // thread_local destructors registered through __cxa_thread_atexit
  // run before the key destructors, as glibc has it, so one can still
  // use what a key holds (rust's thread handle, say)
  while ((dtor = tib->tib_atexit)) {
    STRACE("__cxa_finalize(%t, %p)", dtor->fun, dtor->arg);
    tib->tib_atexit = dtor->next;
    ((void (*)(void *))dtor->fun)(dtor->arg);
    _weaken(free)(dtor);
  }

  // "After all cancellation cleanup handlers have been executed, if the
  //  thread has any thread-specific data, appropriate destructor
  //  functions shall be called in an unspecified order."
  //                              ──Quoth POSIX.1-2017
  _pthread_unkey(tib);
  _pthread_ungarbage(tib);

  if (_weaken(__emutls_thread_finalize))
    _weaken(__emutls_thread_finalize)();
  // get rid of cached win32 event handles
  if (IsWindows()) {
    for (int i = 0; i < ARRAYLEN(tib->tib_events); ++i) {
      if (tib->tib_events[i]) {
        CloseHandle(tib->tib_events[i]);
        tib->tib_events[i] = 0;
      }
    }
  }
}
