#ifndef COSMOPOLITAN_LIBC_DLOPEN_NTUNWIND_INTERNAL_H_
#define COSMOPOLITAN_LIBC_DLOPEN_NTUNWIND_INTERNAL_H_
COSMOPOLITAN_C_START_

// a frame's layout in DWARF terms: the CFA is a register plus an
// offset, and each register with a bit in `mask` is saved at its
// `saved` offset from the CFA. x86-64 numbering: 3 rbx, 4 rsi, 5 rdi,
// 6 rbp, 7 rsp, 12-15 r12-r15, 17-32 xmm0-15
struct UnwFrame {
  uintptr_t begin;
  uintptr_t end;
  int cfa_reg;
  int32_t cfa_off;
  uint64_t mask;
  int64_t saved[33];
};

// the most bytes __nt_unwind_make() writes: rbx, rbp, rsi, rdi and
// r12-r15, xmm6-15, all in their far forms, the frame pointer and a
// big allocation, padded to an even count of codes
#define NTUNWIND_MAX (4 + 2 * (8 * 3 + 10 * 3 + 1 + 3 + 1))

int __unw_frame_info(uintptr_t, struct UnwFrame *);

size_t __nt_unwind_make(uint8_t *, size_t, const struct UnwFrame *);
void __nt_unwind_init(void);
void __nt_unwind_block(char *);
bool __nt_unwind_describe(const void *, const void *, const struct UnwFrame *);
size_t __nt_unwind_block_reserve(void);
void __nt_unwind_walk(void);

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_DLOPEN_NTUNWIND_INTERNAL_H_ */
