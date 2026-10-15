#include "libc/intrin/atomic.h"
#include "libc/intrin/likely.h"
#include "libc/mem/mem.h"
#include "libc/str/str.h"
#include "libc/thread/thread.h"
#include "libc/thread/tls.h"

// llvm's emulated tls. a compiler told to emulate thread_local turns
// each access into a call to __emutls_get_address() with the variable's
// control block (__emutls_v.<name>), which carries the object's size,
// alignment, a slot number handed out on first use, and the initial
// image. each thread keeps its objects in an array hung off its tib,
// which __cxa_thread_finalize() frees once the destructors ran.
//
// the fast path is libc/mem/emutlsget.S, which tail calls
// __emutls_get_address_slow() for anything it doesn't find

struct EmutlsControl {
  size_t size;
  size_t align;
  _Atomic(uintptr_t) index;  // 1-based slot, 0 until first use
  const void *value;         // initial image, or null for zeroes
};

struct EmutlsArray {
  size_t n;
  void *p[];
};

static_assert(offsetof(struct EmutlsControl, index) == 16);
static_assert(offsetof(struct EmutlsArray, p) == 8);
static_assert(offsetof(struct CosmoTib, tib_emutls) == 0x1d0);

static _Atomic(uintptr_t) emutls_count;

void *__emutls_get_address_slow(struct EmutlsControl *);

static uintptr_t emutls_index(struct EmutlsControl *c) {
  uintptr_t want = 0;
  uintptr_t i = atomic_fetch_add(&emutls_count, 1) + 1;
  if (!atomic_compare_exchange_strong_explicit(&c->index, &want, i,
                                               memory_order_acq_rel,
                                               memory_order_acquire))
    i = want;
  return i;
}

static struct EmutlsArray *emutls_grow(struct CosmoTib *tib,
                                       struct EmutlsArray *a, uintptr_t i) {
  size_t n = a ? a->n : 0;
  size_t m = n ? n * 2 : 16;
  if (m < i)
    m = i;
  a = realloc(a, sizeof(*a) + m * sizeof(void *));
  if (!a)
    __builtin_trap();
  bzero(a->p + n, (m - n) * sizeof(void *));
  a->n = m;
  tib->tib_emutls = a;
  return a;
}

static void *emutls_create(struct EmutlsControl *c) {
  size_t align = c->align < sizeof(void *) ? sizeof(void *) : c->align;
  void *p = memalign(align, c->size);
  if (!p)
    __builtin_trap();
  if (c->value) {
    memcpy(p, c->value, c->size);
  } else {
    bzero(p, c->size);
  }
  return p;
}

// a variable's first use in the process or in this thread, or a thread
// the host made that has no tib yet (__get_tls() adopts it)
dontinline void *__emutls_get_address_slow(struct EmutlsControl *c) {
  uintptr_t i = atomic_load_explicit(&c->index, memory_order_acquire);
  if (!i)
    i = emutls_index(c);
  struct CosmoTib *tib = __get_tls();
  struct EmutlsArray *a = tib->tib_emutls;
  if (!a || i > a->n)
    a = emutls_grow(tib, a, i);
  void *p = a->p[i - 1];
  if (!p)
    p = a->p[i - 1] = emutls_create(c);
  return p;
}

// frees the calling thread's objects. runs after the thread's
// destructors, which may still read them
void __emutls_thread_finalize(void) {
  if (!atomic_load_explicit(&emutls_count, memory_order_acquire))
    return;
  struct CosmoTib *tib = __get_tls();
  struct EmutlsArray *a = tib->tib_emutls;
  if (!a)
    return;
  tib->tib_emutls = 0;
  for (size_t i = 0; i < a->n; ++i)
    free(a->p[i]);
  free(a);
}
