#include "libc/intrin/atomic.h"
#include "libc/intrin/likely.h"
#include "libc/mem/mem.h"
#include "libc/str/str.h"
#include "libc/thread/thread.h"
#include "libc/thread/tls.h"

// llvm's emulated tls. a compiler told to emulate thread_local turns
// each access into a call here with the variable's control block
// (__emutls_v.<name>), which carries the object's size, alignment, a
// slot number handed out on first use, and the initial image. each
// thread keeps its objects in an array hung off a pthread key, which
// __cxa_thread_finalize() frees once the thread's destructors ran

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

static pthread_key_t emutls_key;
static _Atomic(int) emutls_state;  // 0 no key yet, 1 making it, 2 made
static _Atomic(uintptr_t) emutls_count;

static void emutls_init(void) {
  int s = 0;
  if (atomic_compare_exchange_strong_explicit(&emutls_state, &s, 1,
                                              memory_order_acq_rel,
                                              memory_order_acquire)) {
    if (pthread_key_create(&emutls_key, 0))
      __builtin_trap();
    atomic_store_explicit(&emutls_state, 2, memory_order_release);
  } else {
    while (atomic_load_explicit(&emutls_state, memory_order_acquire) != 2) {
    }
  }
}

static uintptr_t emutls_index(struct EmutlsControl *c) {
  emutls_init();
  uintptr_t want = 0;
  uintptr_t i = atomic_fetch_add(&emutls_count, 1) + 1;
  if (!atomic_compare_exchange_strong_explicit(&c->index, &want, i,
                                               memory_order_acq_rel,
                                               memory_order_acquire))
    i = want;
  return i;
}

static struct EmutlsArray *emutls_array(void) {
  pthread_key_t k = emutls_key;
  if (LIKELY(k < PTHREAD_KEYS_FAST))
    return __get_tls()->tib_keys_static[k];
  return pthread_getspecific(k);
}

static struct EmutlsArray *emutls_grow(struct EmutlsArray *a, uintptr_t i) {
  size_t n = a ? a->n : 0;
  size_t m = n ? n * 2 : 16;
  if (m < i)
    m = i;
  a = realloc(a, sizeof(*a) + m * sizeof(void *));
  if (!a)
    __builtin_trap();
  bzero(a->p + n, (m - n) * sizeof(void *));
  a->n = m;
  if (pthread_setspecific(emutls_key, a))
    __builtin_trap();
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

dontinline static void *emutls_slow(struct EmutlsControl *c) {
  uintptr_t i = atomic_load_explicit(&c->index, memory_order_acquire);
  if (!i)
    i = emutls_index(c);
  struct EmutlsArray *a = emutls_array();
  if (!a || i > a->n)
    a = emutls_grow(a, i);
  void *p = a->p[i - 1];
  if (!p)
    p = a->p[i - 1] = emutls_create(c);
  return p;
}

void *__emutls_get_address(struct EmutlsControl *c) {
  uintptr_t i = atomic_load_explicit(&c->index, memory_order_acquire);
  if (LIKELY(i)) {
    pthread_key_t k = emutls_key;
    if (LIKELY(k < PTHREAD_KEYS_FAST)) {
      struct EmutlsArray *a = __get_tls()->tib_keys_static[k];
      if (LIKELY(a && i <= a->n)) {
        void *p = a->p[i - 1];
        if (LIKELY(p))
          return p;
      }
    }
  }
  return emutls_slow(c);
}

// frees the calling thread's objects. runs after the thread's
// destructors, which may still read them
void __emutls_thread_finalize(void) {
  if (!atomic_load_explicit(&emutls_count, memory_order_acquire))
    return;
  struct EmutlsArray *a = emutls_array();
  if (!a)
    return;
  pthread_setspecific(emutls_key, 0);
  for (size_t i = 0; i < a->n; ++i)
    free(a->p[i]);
  free(a);
}
