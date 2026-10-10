#include "ape/sections.internal.h"
#include "libc/dce.h"
#include "libc/dlopen/ntunwind.internal.h"
#include "libc/intrin/atomic.h"
#include "libc/intrin/kprintf.h"
#include "libc/intrin/strace.h"
#include "libc/mem/mem.h"
#include "libc/runtime/runtime.h"
#include "libc/intrin/weaken.h"
#include "libc/macros.h"
#include "libc/nt/dll.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/runtime/runtime.h"
#include "libc/serialize.h"
#include "libc/str/str.h"
#include "libc/nt/struct/context.h"
#include "libc/thread/tls.h"

// Windows unwinds a stack by asking each module for the table of its
// functions' frame layouts, and a frame without one is taken to be a
// leaf. A host library's longjmp() or C++ throw that lands on the far
// side of frames of ours (a callback of ours in between) walks them,
// so this answers for our code from the .eh_frame the linker left, via
// libunwind, and for the thunks made at runtime from what their makers
// say about them.

#ifdef __x86_64__

#define UWOP_ALLOC_LARGE     1
#define UWOP_ALLOC_SMALL     2
#define UWOP_SET_FPREG       3
#define UWOP_SAVE_NONVOL     4
#define UWOP_SAVE_NONVOL_FAR 5
#define UWOP_SAVE_XMM128     8
#define UWOP_SAVE_XMM128_FAR 9

// how far below rbp the frame base goes when rbp is the frame pointer,
// in units of 16, so saves below it can still be described
#define FPOFF 15

// the DWARF numbers of what microsoft's convention keeps, and theirs
static const int8_t kNtReg[33] = {
    [3] = 3, [4] = 6, [5] = 7, [6] = 5, [12] = 12, [13] = 13, [14] = 14,
    [15] = 15,
};

static uint8_t *put_code(uint8_t *p, int op, int info) {
  *p++ = 0;
  *p++ = op | (info << 4);
  return p;
}

// an integer register saved `off` bytes above the frame base
static uint8_t *put_save(uint8_t *p, int reg, int64_t off) {
  if (off < 0 || off & 7 || off > 0xffffffff)
    return 0;
  if (off / 8 <= 0xffff) {
    p = put_code(p, UWOP_SAVE_NONVOL, reg);
    WRITE16LE(p, off / 8), p += 2;
  } else {
    p = put_code(p, UWOP_SAVE_NONVOL_FAR, reg);
    WRITE32LE(p, off), p += 4;
  }
  return p;
}

/**
 * Writes microsoft's unwind info for the frame layout `f` describes.
 *
 * The result unwinds any point of the function the same way, as a body
 * address does, which is all a return address on the stack needs.
 *
 * @return bytes written, or 0 if the layout can't be described
 */
size_t __nt_unwind_make(uint8_t *out, size_t cap, const struct UnwFrame *f) {
  uint8_t *p = out + 4;
  int64_t base;  // where the frame base sits, relative to the CFA
  if (cap < NTUNWIND_MAX)
    return 0;
  if (f->cfa_reg == 7) {
    base = -f->cfa_off;
  } else if (f->cfa_reg == 6) {
    base = -f->cfa_off - 16 * FPOFF;
  } else {
    return 0;
  }
  // the frame register is restored last: the unwinder reads it again
  // when it gets to UWOP_SET_FPREG
  for (int r = 3; r <= 15; ++r) {
    if (!(f->mask & (1ull << r)) || !kNtReg[r] || r == f->cfa_reg)
      continue;
    if (!(p = put_save(p, kNtReg[r], f->saved[r] - base)))
      return 0;
  }
  for (int r = 17 + 6; r <= 32; ++r) {
    if (!(f->mask & (1ull << r)))
      continue;
    int64_t off = f->saved[r] - base;
    if (off < 0 || off & 15 || off > 0xffffffff)
      return 0;
    if (off / 16 <= 0xffff) {
      p = put_code(p, UWOP_SAVE_XMM128, r - 17);
      WRITE16LE(p, off / 16), p += 2;
    } else {
      p = put_code(p, UWOP_SAVE_XMM128_FAR, r - 17);
      WRITE32LE(p, off), p += 4;
    }
  }
  if (f->cfa_reg == 6) {
    p = put_code(p, UWOP_SET_FPREG, 0);
    if (f->mask & (1 << 6) &&
        !(p = put_save(p, kNtReg[6], f->saved[6] - base)))
      return 0;
  }
  // from the frame base up to the return address
  int64_t alloc = -8 - base;
  if (alloc < 0 || alloc & 7)
    return 0;
  if (alloc == 0) {
  } else if (alloc <= 128) {
    p = put_code(p, UWOP_ALLOC_SMALL, alloc / 8 - 1);
  } else if (alloc / 8 <= 0xffff) {
    p = put_code(p, UWOP_ALLOC_LARGE, 0);
    WRITE16LE(p, alloc / 8), p += 2;
  } else if (alloc <= 0xffffffff) {
    p = put_code(p, UWOP_ALLOC_LARGE, 1);
    WRITE32LE(p, alloc), p += 4;
  } else {
    return 0;
  }
  size_t codes = (p - (out + 4)) / 2;
  if (codes > 255)
    return 0;
  out[0] = 1;  // version 1, no handler
  out[1] = 0;  // SizeOfProlog
  out[2] = codes;
  out[3] = f->cfa_reg == 6 ? 5 | (FPOFF << 4) : 0;
  if (codes & 1)
    p += 2;
  return p - out;
}

// ntdll's dynamic function tables
typedef __msabi void *(*NtGetRuntimeFunction)(uint64_t, void *);
typedef __msabi int32_t (*NtInstallFunctionTableCallback)(
    uint64_t, uint64_t, uint32_t, NtGetRuntimeFunction, void *,
    const char16_t *);
static NtInstallFunctionTableCallback RtlInstallFunctionTableCallback;

// answers for this program's own code are made when asked, into a ring
// the unwinder reads right away; they must sit within 4 GiB above the
// image, since a table entry holds offsets from its base
struct NtUnwindEntry {
  uint32_t rf[3];
  uint8_t info[NTUNWIND_MAX];
};

static struct {
  _Atomic(unsigned) next;
  struct NtUnwindEntry e[64];
} image_ring;

static bool __ntunwind_trace;

static void *ntunwind_image(uint64_t pc, void *ctx) {
  struct UnwFrame f;
  int r;
  if (!_weaken(__unw_frame_info) || pc <= (uint64_t)__executable_start)
    return 0;
  // the address before a return address is still the call
  if ((r = _weaken(__unw_frame_info)(pc - 1, &f)) <= 0) {
    if (__ntunwind_trace)
      kprintf("ntunwind %p: no frame info (%d)\n", pc, r);
    return 0;
  }
  unsigned i = atomic_fetch_add_explicit(&image_ring.next, 1,
                                         memory_order_relaxed) %
               ARRAYLEN(image_ring.e);
  struct NtUnwindEntry *e = image_ring.e + i;
  if (!__nt_unwind_make(e->info, sizeof(e->info), &f))
    return 0;
  e->rf[0] = f.begin - (uintptr_t)__executable_start;
  e->rf[1] = f.end - (uintptr_t)__executable_start;
  e->rf[2] = (uintptr_t)e->info - (uintptr_t)__executable_start;
  if (__ntunwind_trace) {
    kprintf("ntunwind %p in [%p,%p) cfa r%d%+d mask %#lx codes", pc, f.begin,
            f.end, f.cfa_reg, f.cfa_off, f.mask);
    for (int i = 0; i < e->info[2]; ++i)
      kprintf(" %02x%02x", e->info[4 + 2 * i], e->info[5 + 2 * i]);
    kprintf(" fr %#x\n", e->info[3]);
  }
  return e->rf;
}

static __msabi void *ntunwind_image_nt(uint64_t pc, void *ctx) {
  return ntunwind_image(pc, ctx);
}

// a block of runtime-made thunks keeps its own table at its tail: the
// count, then the entries, with each one's unwind info stored down from
// the block's end
#define BLOCK   65536
#define TAIL    2048
#define TAILCAP 64

struct BlockTail {
  uint32_t count;
  uint32_t info_top;  // offset from the block's start
  uint32_t rf[TAILCAP][3];
};

static struct BlockTail *block_tail(char *block) {
  return (struct BlockTail *)(block + BLOCK - TAIL);
}

size_t __nt_unwind_block_reserve(void) {
  return IsWindows() ? TAIL : 0;
}

static void *ntunwind_block(uint64_t pc, void *ctx) {
  char *block = ctx;
  struct BlockTail *t = block_tail(block);
  uint32_t rva = pc - (uintptr_t)block;
  uint32_t n = atomic_load_explicit((_Atomic(uint32_t) *)&t->count,
                                    memory_order_acquire);
  for (uint32_t i = 0; i < n; ++i)
    if (rva >= t->rf[i][0] && rva < t->rf[i][1]) {
      if (__ntunwind_trace)
        kprintf("ntunwind %p in block %p entry %u\n", pc, block, i);
      return t->rf[i];
    }
  if (__ntunwind_trace)
    kprintf("ntunwind %p in block %p: not described\n", pc, block);
  return 0;
}

static __msabi void *ntunwind_block_nt(uint64_t pc, void *ctx) {
  return ntunwind_block(pc, ctx);
}

static bool ntunwind_setup(void) {
  static _Atomic(int) state;
  int s = atomic_load_explicit(&state, memory_order_acquire);
  if (s)
    return s > 0;
  if (!IsWindows()) {
    atomic_store_explicit(&state, -1, memory_order_release);
    return false;
  }
  int64_t ntdll = GetModuleHandle("ntdll.dll");
  void *f = ntdll ? GetProcAddress(ntdll, "RtlInstallFunctionTableCallback")
                  : 0;
  if (!f) {
    STRACE("RtlInstallFunctionTableCallback not found");
    atomic_store_explicit(&state, -1, memory_order_release);
    return false;
  }
  RtlInstallFunctionTableCallback = f;
  atomic_store_explicit(&state, 1, memory_order_release);
  return true;
}

/**
 * Tells Windows how to unwind through this program's code.
 */
void __nt_unwind_init(void) {
  static _Atomic(bool) done;
  if (!IsWindows() || atomic_exchange_explicit(&done, true, memory_order_acq_rel))
    return;
  if (!ntunwind_setup())
    return;
  __ntunwind_trace = !!getenv("NTUNWIND_TRACE");
  uint64_t base = (uintptr_t)__executable_start;
  uint32_t len = (uintptr_t)_end - base;
  if (!RtlInstallFunctionTableCallback(base | 3, base, len, ntunwind_image_nt,
                                       0, 0))
    STRACE("RtlInstallFunctionTableCallback failed for the image");
}

/**
 * Registers a block of runtime-made code with the Windows unwinder.
 *
 * The last __nt_unwind_block_reserve() bytes of the block are its
 * table, filled by __nt_unwind_describe().
 */
void __nt_unwind_block(char *block) {
  if (!IsWindows() || !ntunwind_setup())
    return;
  struct BlockTail *t = block_tail(block);
  t->count = 0;
  t->info_top = BLOCK;
  if (!RtlInstallFunctionTableCallback((uint64_t)(uintptr_t)block | 3,
                                       (uintptr_t)block, BLOCK,
                                       ntunwind_block_nt, block, 0))
    STRACE("RtlInstallFunctionTableCallback failed for %p", block);
}

/**
 * Describes runtime-made code in [begin, end) to the Windows unwinder.
 *
 * The code must be inside a block registered with __nt_unwind_block(),
 * and the caller holds the block's lock. `f` gives the layout the
 * code's frame has once it's set up, in DWARF terms.
 */
bool __nt_unwind_describe(const void *begin, const void *end,
                          const struct UnwFrame *f) {
  if (!IsWindows() || !ntunwind_setup())
    return false;
  char *block = (char *)((uintptr_t)begin & -(uintptr_t)BLOCK);
  struct BlockTail *t = block_tail(block);
  uint8_t info[NTUNWIND_MAX];
  size_t n = __nt_unwind_make(info, sizeof(info), f);
  if (!n || t->count == TAILCAP)
    return false;
  uint32_t top = (t->info_top - n) & -4;
  if (top < BLOCK - TAIL + sizeof(*t))
    return false;
  memcpy(block + top, info, n);
  t->info_top = top;
  uint32_t i = t->count;
  t->rf[i][0] = (uintptr_t)begin - (uintptr_t)block;
  t->rf[i][1] = (uintptr_t)end - (uintptr_t)block;
  t->rf[i][2] = top;
  atomic_store_explicit((_Atomic(uint32_t) *)&t->count, i + 1,
                        memory_order_release);
  return true;
}

/**
 * Prints the stack as the Windows unwinder sees it, for debugging.
 */
void __nt_unwind_walk(void) {
  typedef void __msabi (*capture_f)(void *);
  typedef void *__msabi (*lookup_f)(uint64_t, uint64_t *, void *);
  typedef void *__msabi (*unwind_f)(uint32_t, uint64_t, uint64_t, void *,
                                    void *, void **, uint64_t *, void *);
  if (!IsWindows())
    return;
  int64_t k32 = GetModuleHandle("kernel32.dll");
  capture_f capture = (capture_f)GetProcAddress(k32, "RtlCaptureContext");
  unwind_f unwind = (unwind_f)GetProcAddress(k32, "RtlVirtualUnwind");
  lookup_f lookup = (lookup_f)GetProcAddress(k32, "RtlLookupFunctionEntry");
  if (!capture || !unwind || !lookup)
    return;
  _Alignas(16) struct NtContext c = {0};
  capture(&c);
  uintptr_t st[3];
  __get_stack_win32(st);
  kprintf("ntunwind walk: stack [%p,%p)\n", st[0], st[1]);
  for (int i = 0; i < 40 && c.Rip; ++i) {
    uint64_t base = 0, frame = 0;
    void *entry, *data;
    entry = lookup(c.Rip, &base, 0);
    kprintf("  #%d rip %p rsp %p rbp %p entry %p base %p", i, c.Rip, c.Rsp,
            c.Rbp, entry, base);
    if (entry) {
      unwind(0, base, c.Rip, entry, &c, &data, &frame, 0);
      kprintf(" -> frame %p\n", frame);
    } else {
      c.Rip = *(uint64_t *)c.Rsp;
      c.Rsp += 8;
      kprintf(" leaf\n");
    }
    if (c.Rsp < st[0] || c.Rsp >= st[1]) {
      kprintf("  rsp left the stack\n");
      break;
    }
  }
}

#else

size_t __nt_unwind_make(uint8_t *out, size_t cap, const struct UnwFrame *f) {
  return 0;
}

void __nt_unwind_walk(void) {
}

size_t __nt_unwind_block_reserve(void) {
  return 0;
}

void __nt_unwind_init(void) {
}

void __nt_unwind_block(char *block) {
}

bool __nt_unwind_describe(const void *begin, const void *end,
                          const struct UnwFrame *f) {
  return false;
}

#endif /* __x86_64__ */
