#include "libc/calls/calls.h"
#include "libc/runtime/runtime.h"
#include "libc/sysv/consts/map.h"
#include "libc/sysv/consts/prot.h"
#include "libc/thread/thread.h"
#include "third_party/libffi/fficonfig.h"
#include "third_party/libffi/ffi.h"
#include "third_party/libffi/ffi_common.h"

// Memory for closures, in place of upstream's closures.c.
//
// Closures live in pages that are readable, writable and executable at
// once. That's MAP_JIT on macOS arm64, where writing to them is only
// allowed between __jit_begin() and __jit_end(), and a no-op elsewhere.
// Pages come from mmap(), so fork() copies them on every host. Upstream
// looks for a libffi shared object to map static trampolines from, or
// maps a temporary file twice, neither of which suits a binary that's
// one static executable.
//
// Every allocation has a header saying how big it is. Those that fit a
// block are carved out of 64 KiB chunks and kept on a free list, bigger
// ones get pages of their own.

#define CHUNK 65536
#define BLOCK 128
#define HEAD  16

struct Free {
  struct Free *next;
};

static struct {
  pthread_mutex_t lock;
  struct Free *free;
  char *next, *end;
} closures = {PTHREAD_MUTEX_INITIALIZER};

static void *closure_map(size_t n) {
  void *p = mmap(0, n, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
  return p == MAP_FAILED ? 0 : p;
}

void *ffi_closure_alloc(size_t size, void **code) {
  char *p = 0;
  size_t n = size + HEAD;
  if (!code)
    return 0;
  if (n > BLOCK) {
    n = (n + 4095) & -4096;
    if (!(p = closure_map(n)))
      return 0;
    __jit_begin();
  } else {
    pthread_mutex_lock(&closures.lock);
    __jit_begin();
    if (closures.free) {
      p = (char *)closures.free;
      closures.free = closures.free->next;
    } else {
      if (closures.next == closures.end) {
        __jit_end();
        closures.next = closure_map(CHUNK);
        __jit_begin();
        closures.end = closures.next ? closures.next + CHUNK : 0;
      }
      if (closures.next) {
        p = closures.next;
        closures.next += BLOCK;
      }
    }
    pthread_mutex_unlock(&closures.lock);
    n = BLOCK;
    if (!p) {
      __jit_end();
      return 0;
    }
  }
  *(size_t *)p = n;
  __jit_end();
  *code = p + HEAD;
  return p + HEAD;
}

void ffi_closure_free(void *ptr) {
  char *p;
  if (!ptr)
    return;
  p = (char *)ptr - HEAD;
  if (*(size_t *)p > BLOCK) {
    munmap(p, *(size_t *)p);
    return;
  }
  pthread_mutex_lock(&closures.lock);
  __jit_begin();
  ((struct Free *)p)->next = closures.free;
  closures.free = (struct Free *)p;
  __jit_end();
  pthread_mutex_unlock(&closures.lock);
}

void *ffi_data_to_code_pointer(void *data) {
  return data;
}

int ffi_tramp_is_present(void *closure) {
  return 0;
}
