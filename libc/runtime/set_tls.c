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
#include "libc/assert.h"
#include "libc/calls/calls.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/nexgen32e/msr.internal.h"
#include "libc/nt/thread.h"
#include "libc/sysv/consts/arch.h"
#include "libc/intrin/weaken.h"
#include "libc/runtime/runtime.h"
#include "libc/runtime/syslib.internal.h"
#include "libc/thread/tls.h"

#define AMD64_SET_FSBASE 129
#define AMD64_SET_GSBASE 131

int sys_set_tls(uintptr_t, void *);

#ifdef __aarch64__

static int (*__tls_setspecific)(unsigned long, const void *);

// our tib's tsd slot is a libSystem pthread key, whose destructor is
// how threads the host created get cleaned up after, see adopt.c
dontinstrument static void __tls_init_xnu(void) {
  unsigned long key;
  int (*key_create)(unsigned long *, void (*)(void *)) =
      __syslib->__dlsym((void *)-2, "pthread_key_create");
  __tls_setspecific = __syslib->__dlsym((void *)-2, "pthread_setspecific");
  void (*dtor)(void *) = _weaken(__tls_adopt_xnu_exit);
  if (!key_create || !__tls_setspecific || key_create(&key, dtor))
    notpossible;
  __tls_slot_offset = key * sizeof(void *);
}

// writes the calling thread's tib to its tsd slot. this goes through
// libSystem rather than tpidrro_el0, since libSystem only runs the key
// destructors up to the highest key a thread has set that way
dontinstrument void __tls_set_xnu(struct CosmoTib *tib) {
  if (!__tls_slot_offset)
    __tls_init_xnu();
  __tls_setspecific(__tls_slot_offset / sizeof(void *), tib);
}

#endif /* __aarch64__ */

// we can't allow --ftrace here because cosmo_dlopen() calls this
// function to fix the tls register, and ftrace needs it unbroken
dontinstrument textstartup void __set_tls(struct CosmoTib *tib) {
  tib = __adj_tls(tib);
#ifdef __x86_64__
  // ask the operating system to change the x86 segment register
  if (IsWindows()) {
    __set_tls_win32(tib);
  } else if (IsLinux()) {
    sys_set_tls(ARCH_SET_FS, tib);
  } else if (IsFreebsd()) {
    sys_set_tls(AMD64_SET_FSBASE, tib);
  } else if (IsNetbsd()) {
    // netbsd has sysarch(X86_SET_FSBASE) but we can't use that because
    // signal handlers will cause it to be reset due to not setting the
    // _mc_tlsbase field in struct mcontext_netbsd.
    sys_set_tls((uintptr_t)tib, 0);
  } else if (IsOpenbsd()) {
    sys_set_tls((uintptr_t)tib, 0);
  } else if (IsXnu()) {
    // thread_fast_set_cthread_self has a weird ABI
    sys_set_tls((intptr_t)tib - 0x30, 0);
  } else {
    uint64_t val = (uint64_t)tib;
    asm volatile("wrmsr"
                 : /* no outputs */
                 : "c"(MSR_IA32_GS_BASE), "a"((uint32_t)val),
                   "d"((uint32_t)(val >> 32)));
  }
#elif defined(__aarch64__)
  // the word after the tib holds its address, see libc/sysv/tlsasm.S
  ((struct CosmoTib **)tib)[1] = tib - 1;
  if (IsXnu()) {
    __tls_set_xnu(tib - 1);
  } else {
    asm volatile("msr\ttpidr_el0,%0" : /* no outputs */ : "r"(tib) : "memory");
  }
#else
#error "unsupported architecture"
#endif
}
