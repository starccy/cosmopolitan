#ifndef COSMOPOLITAN_LIBC_DLOPEN_TEMPLATES_INTERNAL_H_
#define COSMOPOLITAN_LIBC_DLOPEN_TEMPLATES_INTERNAL_H_
#include "libc/serialize.h"
#include "libc/str/str.h"
COSMOPOLITAN_C_START_

// code made at runtime is copied from these, see templates.S. each one
// ends in eight byte slots for the values a copy needs
extern const char __tmpl_jump[], __tmpl_jump_end[];
extern const char __tmpl_sysv_thunk[], __tmpl_sysv_thunk_end[];
extern const int32_t __tmpl_vtramps[][2];
extern const int32_t __tmpl_vtramp_count;
#ifdef __x86_64__
extern const char __tmpl_ms2sysv[], __tmpl_ms2sysv_end[];
extern const char __tmpl_nt_thunk[], __tmpl_nt_thunk_end[];
extern const char __tmpl_dual_thunk[], __tmpl_dual_thunk_end[];
extern const char __tmpl_hostcall_stub[], __tmpl_hostcall_stub_end[];
extern const char __tmpl_hostlink_thunk[], __tmpl_hostlink_thunk_end[];
#endif

#define TMPL_SIZE(t) ((size_t)(t##_end - t))

// copies template `t` to `p` and fills its slots with the values after
// it, in order
#define TMPL_PUT(p, t, ...)                                     \
  __tmpl_put(p, t, t##_end, (const uint64_t[]){__VA_ARGS__}, \
             sizeof((const uint64_t[]){__VA_ARGS__}) / 8)

// whether `p` holds a copy of template `t`, which has `n` slots
#define TMPL_IS(p, t, n) (!memcmp(p, t, TMPL_SIZE(t) - 8 * (n)))

// slot `i` of the `n` in a copy of template `t` at `p`
#define TMPL_SLOT(p, t, n, i) \
  READ64LE((const char *)(p) + TMPL_SIZE(t) - 8 * ((n) - (i)))

static inline void __tmpl_put(void *p, const char *start, const char *end,
                              const uint64_t *v, size_t n) {
  size_t size = end - start;
  memcpy(p, start, size);
  for (size_t i = 0; i < n; ++i)
    WRITE64LE((char *)p + size - 8 * (n - i), v[i]);
}

// the frame of __tmpl_ms2sysv around its call, for the windows
// unwinder: rbp, rsi and rdi pushed, then 128 bytes of copied arguments
// and xmm6-15 above them
#define MS2SYSV_FRAME                                                    \
  {                                                                      \
    .cfa_reg = 7, .cfa_off = 128 + 160 + 32,                             \
    .mask = 1 << 6 | 1 << 4 | 1 << 5 | 0x3ffull << 23,                   \
    .saved = {[6] = -16, [4] = -24, [5] = -32,                           \
              [23] = 128 + 16 * 0 - (128 + 160 + 32),                    \
              [24] = 128 + 16 * 1 - (128 + 160 + 32),                    \
              [25] = 128 + 16 * 2 - (128 + 160 + 32),                    \
              [26] = 128 + 16 * 3 - (128 + 160 + 32),                    \
              [27] = 128 + 16 * 4 - (128 + 160 + 32),                    \
              [28] = 128 + 16 * 5 - (128 + 160 + 32),                    \
              [29] = 128 + 16 * 6 - (128 + 160 + 32),                    \
              [30] = 128 + 16 * 7 - (128 + 160 + 32),                    \
              [31] = 128 + 16 * 8 - (128 + 160 + 32),                    \
              [32] = 128 + 16 * 9 - (128 + 160 + 32)},                   \
  }

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_DLOPEN_TEMPLATES_INTERNAL_H_ */
