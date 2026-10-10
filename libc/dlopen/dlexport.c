#include "libc/calls/calls.h"
#include "libc/dce.h"
#include "libc/dlopen/dlfcn.h"
#include "libc/dlopen/ntunwind.internal.h"
#include "libc/dlopen/templates.internal.h"
#include "libc/elf/def.h"
#include "libc/elf/struct/dyn.h"
#include "libc/elf/struct/ehdr.h"
#include "libc/elf/struct/phdr.h"
#include "libc/elf/struct/sym.h"
#include "libc/errno.h"
#include "libc/fmt/itoa.h"
#include "libc/intrin/strace.h"
#include "libc/limits.h"
#include "ape/sections.internal.h"
#include "libc/intrin/atomic.h"
#include "libc/assert.h"
#include "libc/macros.h"
#include "libc/mem/alg.h"
#include "libc/mem/mem.h"
#include "libc/nt/enum/memflags.h"
#include "libc/nt/memory.h"
#include "libc/nt/struct/memorybasicinformation.h"
#include "libc/runtime/runtime.h"
#include "libc/serialize.h"
#include "libc/stdio/stdio.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/mfd.h"
#include "libc/sysv/consts/o.h"
#include "libc/temp.h"
#include "libc/thread/thread.h"

void __dlerror_set(const char *);
void __dlglobal_forget(void *);

// whether a generator already said what went wrong
static _Thread_local bool dlexport_said;

static void dlexport_error(const char *msg) {
  dlexport_said = true;
  __dlerror_set(msg);
}

// cosmo_dlexport() makes a host shared library that exports functions of
// this program under names, for host libraries that look symbols up by
// name. The library holds one small trampoline per function, which jumps to
// an absolute address written into it when it's built, so it needs no relocations. 
// It's built in memory for the host we're on, an ELF on Linux and the BSDs,
// a PE on Windows and a Mach-O with an ad-hoc signature on macOS, and loaded with the host's loader.

struct Buf {
  char *p;
  size_t n, c;
};

static bool buf_grow(struct Buf *b, size_t n) {
  if (b->n + n <= b->c)
    return true;
  size_t c = MAX(b->c * 2, b->n + n + 4096);
  char *p;
  if (!(p = realloc(b->p, c)))
    return false;
  bzero(p + b->c, c - b->c);
  b->p = p;
  b->c = c;
  return true;
}

// reserves n zeroed bytes aligned to a and returns their offset
static long buf_add(struct Buf *b, size_t n, size_t a) {
  size_t off = ROUNDUP(b->n, a);
  if (!buf_grow(b, off - b->n + n))
    return -1;
  b->n = off + n;
  return off;
}

static long buf_str(struct Buf *b, const char *s) {
  size_t n = strlen(s) + 1;
  long off = buf_add(b, n, 1);
  if (off != -1)
    memcpy(b->p + off, s, n);
  return off;
}

static void put_tramp(char *p, void *addr) {
  TMPL_PUT(p, __tmpl_jump, (uintptr_t)addr);
}

#define TRAMP 16
#define VTRAMP 512
#define CTRAMP 512

#ifdef __x86_64__
static const struct UnwFrame kCtrampFrame = MS2SYSV_FRAME;
// the frame of a vtramp around its call, for the windows unwinder: rbp,
// rsi and rdi pushed, then xmm6-15 saved below the va_list
static const struct UnwFrame kVtrampFrame = {
    .cfa_reg = 6,
    .cfa_off = 16,
    .mask = 1 << 6 | 1 << 4 | 1 << 5 | 0x3ffull << 23,
    .saved = {[6] = -16, [4] = -24, [5] = -32, [23] = -224 + 16 * 0 - 16,
              [24] = -224 + 16 * 1 - 16, [25] = -224 + 16 * 2 - 16,
              [26] = -224 + 16 * 3 - 16, [27] = -224 + 16 * 4 - 16,
              [28] = -224 + 16 * 5 - 16, [29] = -224 + 16 * 6 - 16,
              [30] = -224 + 16 * 7 - 16, [31] = -224 + 16 * 8 - 16,
              [32] = -224 + 16 * 9 - 16},
};
#endif

// a function of ours for a host caller that uses another convention
static bool put_ctramp(char *code, void *func) {
#ifdef __x86_64__
  TMPL_PUT(code, __tmpl_ms2sysv, (uintptr_t)func);
  return true;
#else
  return false;
#endif
}

// a variadic function of this program, for a host caller whose variadic
// arguments don't land where ours do. the trampoline takes the host's
// arguments, points a va_list of our own at them and calls `va`, the
// same function in its va_list form. `nfixed` parameters come first and
// are passed along, up to 16 of them on x86-64 and 8 on arm64
static bool put_vtramp(char *code, void *va, size_t nfixed) {
  if (nfixed >= (size_t)__tmpl_vtramp_count)
    return false;
  const char *t = (const char *)__tmpl_vtramps + __tmpl_vtramps[nfixed][0];
  __tmpl_put(code, t, t + __tmpl_vtramps[nfixed][1],
             (const uint64_t[]){(uintptr_t)va}, 1);
  return true;
}

////////////////////////////////////////////////////////////////////////////////
// ELF

static uint32_t elf_hash(const char *s) {
  uint32_t h = 0, g;
  while (*s) {
    h = (h << 4) + (unsigned char)*s++;
    if ((g = h & 0xf0000000))
      h ^= g >> 24;
    h &= ~g;
  }
  return h;
}

// a COSMO_DLEXPORT_DATA symbol becomes an absolute address, which is
// what a copy relocation would have left; a function gets a trampoline
static char *make_elf(const char *soname, const struct CosmoDlexport2 *syms,
                      size_t n, size_t *out_size) {
  long pagesz = 65536;
  size_t nfunc = 0;
  for (size_t i = 0; i < n; ++i)
    nfunc += syms[i].kind != COSMO_DLEXPORT_DATA;
  struct Buf b = {0};
  long ehdr = buf_add(&b, sizeof(Elf64_Ehdr), 8);
  long phdr = buf_add(&b, sizeof(Elf64_Phdr) * 4, 8);
  long text = buf_add(&b, nfunc * TRAMP, 16);
  long dynsym = buf_add(&b, (n + 1) * sizeof(Elf64_Sym), 8);
  long hash = buf_add(&b, (2 + 1 + (n + 1)) * 4, 8);
  long dynstr = buf_add(&b, 1, 1);
  long so = buf_str(&b, soname);
  long *names = calloc(n, sizeof(long));
  if (ehdr == -1 || !names)
    goto Fail;
  for (size_t i = 0; i < n; ++i)
    if ((names[i] = buf_str(&b, syms[i].name)) == -1)
      goto Fail;
  long strsz = b.n - dynstr;
  long rx_end = b.n;
  long dynamic = buf_add(&b, 7 * sizeof(Elf64_Dyn), pagesz);
  if (dynamic == -1)
    goto Fail;

  // trampolines and symbols
  Elf64_Sym *sym = (Elf64_Sym *)(b.p + dynsym);
  size_t fi = 0;
  for (size_t i = 0; i < n; ++i) {
    sym[i + 1].st_name = names[i] - dynstr;
    if (syms[i].kind == COSMO_DLEXPORT_DATA) {
      sym[i + 1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
      sym[i + 1].st_shndx = SHN_ABS;
      sym[i + 1].st_value = (uintptr_t)syms[i].addr;
      sym[i + 1].st_size = syms[i].size;
    } else {
      put_tramp(b.p + text + fi * TRAMP,
                syms[i].kind == COSMO_DLEXPORT_NATIVE ? syms[i].va
                                                      : syms[i].addr);
      sym[i + 1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
      sym[i + 1].st_shndx = 1;
      sym[i + 1].st_value = text + fi * TRAMP;
      sym[i + 1].st_size = TRAMP;
      ++fi;
    }
  }

  // sysv hash table with one bucket
  uint32_t *h = (uint32_t *)(b.p + hash);
  h[0] = 1;
  h[1] = n + 1;
  h[2] = n ? 1 : 0;  // bucket
  for (size_t i = 1; i <= n; ++i)
    h[3 + i] = i < n ? i + 1 : 0;  // chain
  (void)elf_hash;

  Elf64_Dyn *d = (Elf64_Dyn *)(b.p + dynamic);
  d[0] = (Elf64_Dyn){DT_HASH, {hash}};
  d[1] = (Elf64_Dyn){DT_STRTAB, {dynstr}};
  d[2] = (Elf64_Dyn){DT_SYMTAB, {dynsym}};
  d[3] = (Elf64_Dyn){DT_STRSZ, {strsz}};
  d[4] = (Elf64_Dyn){DT_SYMENT, {sizeof(Elf64_Sym)}};
  d[5] = (Elf64_Dyn){DT_SONAME, {so - dynstr}};
  d[6] = (Elf64_Dyn){DT_NULL, {0}};

  Elf64_Ehdr *e = (Elf64_Ehdr *)(b.p + ehdr);
  memcpy(e->e_ident, "\177ELF\2\1\1", 7);
  e->e_type = ET_DYN;
#ifdef __x86_64__
  e->e_machine = EM_NEXGEN32E;
#else
  e->e_machine = EM_AARCH64;
#endif
  e->e_version = 1;
  e->e_phoff = phdr;
  e->e_ehsize = sizeof(Elf64_Ehdr);
  e->e_phentsize = sizeof(Elf64_Phdr);
  e->e_phnum = 4;

  Elf64_Phdr *p = (Elf64_Phdr *)(b.p + phdr);
  p[0] = (Elf64_Phdr){.p_type = PT_LOAD,
                      .p_flags = PF_R | PF_X,
                      .p_filesz = rx_end,
                      .p_memsz = rx_end,
                      .p_align = pagesz};
  p[1] = (Elf64_Phdr){.p_type = PT_LOAD,
                      .p_flags = PF_R | PF_W,
                      .p_offset = dynamic,
                      .p_vaddr = dynamic,
                      .p_paddr = dynamic,
                      .p_filesz = 7 * sizeof(Elf64_Dyn),
                      .p_memsz = 7 * sizeof(Elf64_Dyn),
                      .p_align = pagesz};
  p[2] = (Elf64_Phdr){.p_type = PT_DYNAMIC,
                      .p_flags = PF_R | PF_W,
                      .p_offset = dynamic,
                      .p_vaddr = dynamic,
                      .p_paddr = dynamic,
                      .p_filesz = 7 * sizeof(Elf64_Dyn),
                      .p_memsz = 7 * sizeof(Elf64_Dyn),
                      .p_align = 8};
  p[3] = (Elf64_Phdr){.p_type = PT_GNU_STACK, .p_flags = PF_R | PF_W};

  free(names);
  *out_size = b.n;
  return b.p;
Fail:
  free(names);
  free(b.p);
  return 0;
}

////////////////////////////////////////////////////////////////////////////////
// PE

static int cmp_names(const void *a, const void *b) {
  const struct CosmoDlexport2 *x = *(const struct CosmoDlexport2 **)a;
  const struct CosmoDlexport2 *y = *(const struct CosmoDlexport2 **)b;
  return strcmp(x->name, y->name);
}

// an export directory holds offsets from the image base, so a library
// loaded at a fixed base below this program can name addresses inside
// it, both variables and functions, with no code of its own. the image
// gets no relocations and no dynamic base, or the loader would move it
// and every offset with it
#define DLEXPORT_PE_IMAGE 0x2000

// the highest free spot for a `size` image whose offsets must reach
// every address in [lo,hi], or zero when there's no room
static uint64_t pe_pick_base(uintptr_t lo, uintptr_t hi, size_t size) {
  uint64_t floor = hi > 0xffffffffull ? (hi - 0xffffffffull + 0xffff) & -0x10000
                                      : 0x10000;
  for (uint64_t b = (lo - size) & -0x10000; b >= floor; b -= 0x10000) {
    struct NtMemoryBasicInformation mi;
    if (!VirtualQuery((void *)b, &mi, sizeof(mi)))
      continue;
    if (mi.State != kNtMemFree)
      continue;
    if ((uintptr_t)mi.BaseAddress + mi.RegionSize < b + size)
      continue;
    return b;
  }
  return 0;
}

static char *make_pe(const char *dllname, const struct CosmoDlexport2 *syms,
                     size_t n, size_t *out_size) {
  enum { FILEALIGN = 0x200, SECTALIGN = 0x1000 };
  const struct CosmoDlexport2 **sorted;
  char *p = 0;
  long *names = 0;
  struct Buf t = {0}, x = {0};
  if (!n) {
    dlexport_error("cosmo_dlexport: nothing to export");
    return 0;
  }
  if (!(sorted = calloc(n + 1, sizeof(*sorted))))
    return 0;
  for (size_t i = 0; i < n; ++i)
    sorted[i] = syms + i;
  qsort(sorted, n, sizeof(*sorted), cmp_names);

  // only the addresses an export points at directly constrain the base
  size_t text_size = 0;
  uintptr_t lo = 0, hi = 0;
  uint32_t edata_rva, image_size;
  uint64_t base;
  for (size_t i = 0; i < n; ++i) {
    if (sorted[i]->kind == COSMO_DLEXPORT_VARARG) {
      text_size += VTRAMP;
      continue;
    }
    if (sorted[i]->kind == COSMO_DLEXPORT_COSMO) {
      text_size += CTRAMP;
      continue;
    }
    uintptr_t a = (uintptr_t)sorted[i]->addr;
    if (!lo || a < lo)
      lo = a;
    if (a > hi)
      hi = a;
  }
  size_t nvar = text_size;
  uint32_t text_rva = SECTALIGN;
  edata_rva = text_rva + (uint32_t)ROUNDUP(text_size, SECTALIGN);
  if (!lo) {
    lo = (uintptr_t)__executable_start;
    hi = lo;
  }

  if (text_size && buf_add(&t, text_size, 16) == -1)
    goto Fail;

  // the export directory, laid out relative to its own start
  long dir = buf_add(&x, 40, 4);
  long funcs = buf_add(&x, n * 4, 4);
  long namep = buf_add(&x, n * 4, 4);
  long ords = buf_add(&x, n * 2, 2);
  long dll = buf_str(&x, dllname);
  names = calloc(n + 1, sizeof(long));
  if (dir == -1 || dll == -1 || !names)
    goto Fail;
  for (size_t i = 0; i < n; ++i)
    if ((names[i] = buf_str(&x, sorted[i]->name)) == -1)
      goto Fail;

  // the converters' frames, for the windows unwinder
  uint32_t edata_size = x.n;
  long pdata = -1, nfun = 0;
#ifdef __x86_64__
  if (text_size) {
    uint8_t info[NTUNWIND_MAX];
    long cx = -1, vx = -1, off = 0;
    size_t nc = __nt_unwind_make(info, sizeof(info), &kCtrampFrame);
    if (nc && (cx = buf_add(&x, nc, 4)) != -1)
      memcpy(x.p + cx, info, nc);
    size_t nv = __nt_unwind_make(info, sizeof(info), &kVtrampFrame);
    if (nv && (vx = buf_add(&x, nv, 4)) != -1)
      memcpy(x.p + vx, info, nv);
    for (size_t i = 0; i < n; ++i)
      nfun += sorted[i]->kind == COSMO_DLEXPORT_VARARG ||
              sorted[i]->kind == COSMO_DLEXPORT_COSMO;
    if ((pdata = buf_add(&x, nfun * 12, 4)) != -1) {
      char *e = x.p + pdata;
      for (size_t i = 0; i < n; ++i) {
        long xd, len;
        if (sorted[i]->kind == COSMO_DLEXPORT_VARARG) {
          xd = vx, len = VTRAMP;
        } else if (sorted[i]->kind == COSMO_DLEXPORT_COSMO) {
          xd = cx, len = CTRAMP;
        } else {
          continue;
        }
        WRITE32LE(e + 0, text_rva + off);
        WRITE32LE(e + 4, text_rva + off + len);
        WRITE32LE(e + 8, xd == -1 ? 0 : edata_rva + xd);
        e += 12;
        off += len;
      }
    }
  }
#endif

  // the base can only be picked once the whole image is measured, or
  // the loader finds the tail of it on top of something else
  image_size = edata_rva + (uint32_t)ROUNDUP(x.n, SECTALIGN);
  if (!(base = pe_pick_base(lo, hi, image_size))) {
    dlexport_error("cosmo_dlexport: no free address space within 4 GiB below "
                   "what's being exported");
    goto Fail;
  }

  for (size_t i = 0, off = 0; i < n; ++i) {
    uint32_t rva;
    if (sorted[i]->kind == COSMO_DLEXPORT_VARARG) {
      if (!put_vtramp(t.p + off, sorted[i]->va, sorted[i]->size)) {
        dlexport_error("cosmo_dlexport: too many fixed parameters");
        goto Fail;
      }
      rva = text_rva + (uint32_t)off;
      off += VTRAMP;
    } else if (sorted[i]->kind == COSMO_DLEXPORT_COSMO) {
      if (!put_ctramp(t.p + off, sorted[i]->addr)) {
        dlexport_error("cosmo_dlexport: no converter on this architecture");
        goto Fail;
      }
      rva = text_rva + (uint32_t)off;
      off += CTRAMP;
    } else {
      rva = (uint32_t)((uintptr_t)sorted[i]->addr - base);
    }
    WRITE32LE(x.p + funcs + i * 4, rva);
    WRITE32LE(x.p + namep + i * 4, edata_rva + names[i]);
    WRITE16LE(x.p + ords + i * 2, i);
  }
  WRITE32LE(x.p + dir + 12, edata_rva + dll);    // Name
  WRITE32LE(x.p + dir + 16, 1);                  // Base
  WRITE32LE(x.p + dir + 20, n);                  // NumberOfFunctions
  WRITE32LE(x.p + dir + 24, n);                  // NumberOfNames
  WRITE32LE(x.p + dir + 28, edata_rva + funcs);  // AddressOfFunctions
  WRITE32LE(x.p + dir + 32, edata_rva + namep);  // AddressOfNames
  WRITE32LE(x.p + dir + 36, edata_rva + ords);   // AddressOfNameOrdinals

  // the file
  uint32_t text_off = FILEALIGN;
  uint32_t edata_off = text_off + (uint32_t)ROUNDUP(t.n, FILEALIGN);
  size_t size = edata_off + ROUNDUP(x.n, FILEALIGN);
  if (!(p = calloc(1, size)))
    goto Fail;
  if (t.n)
    memcpy(p + text_off, t.p, t.n);
  memcpy(p + edata_off, x.p, x.n);

  p[0] = 'M';
  p[1] = 'Z';
  WRITE32LE(p + 0x3c, 0x40);
  char *pe = p + 0x40;
  memcpy(pe, "PE\0\0", 4);
  char *coff = pe + 4;
  WRITE16LE(coff + 0, 0x8664);      // Machine
  WRITE16LE(coff + 2, nvar ? 2 : 1);
  WRITE16LE(coff + 16, 240);        // SizeOfOptionalHeader
  // RELOCS_STRIPPED keeps the loader from moving us off `base`
  WRITE16LE(coff + 18, 0x2023);
  char *opt = coff + 20;
  WRITE16LE(opt + 0, 0x20b);        // PE32+
  WRITE32LE(opt + 4, t.n);          // SizeOfCode
  WRITE32LE(opt + 8, x.n);          // SizeOfInitializedData
  WRITE32LE(opt + 20, text_rva);    // BaseOfCode
  WRITE64LE(opt + 24, base);        // ImageBase
  WRITE32LE(opt + 32, SECTALIGN);
  WRITE32LE(opt + 36, FILEALIGN);
  WRITE16LE(opt + 40, 6);           // MajorOperatingSystemVersion
  WRITE16LE(opt + 48, 6);           // MajorSubsystemVersion
  WRITE32LE(opt + 56, image_size);
  WRITE32LE(opt + 60, FILEALIGN);   // SizeOfHeaders
  WRITE16LE(opt + 68, 2);           // Subsystem: GUI
  WRITE16LE(opt + 70, 0x0100);      // NX_COMPAT, no DYNAMIC_BASE
  WRITE64LE(opt + 72, 0x100000);    // SizeOfStackReserve
  WRITE64LE(opt + 80, 0x1000);      // SizeOfStackCommit
  WRITE64LE(opt + 88, 0x100000);    // SizeOfHeapReserve
  WRITE64LE(opt + 96, 0x1000);      // SizeOfHeapCommit
  WRITE32LE(opt + 108, 16);         // NumberOfRvaAndSizes
  WRITE32LE(opt + 112, edata_rva);  // export table
  WRITE32LE(opt + 116, edata_size);
  if (pdata != -1 && nfun) {
    WRITE32LE(opt + 136, edata_rva + pdata);  // exception table
    WRITE32LE(opt + 140, nfun * 12);
  }
  char *sect = opt + 240;
  if (nvar) {
    strcpy(sect, ".text");
    WRITE32LE(sect + 8, t.n);
    WRITE32LE(sect + 12, text_rva);
    WRITE32LE(sect + 16, ROUNDUP(t.n, FILEALIGN));
    WRITE32LE(sect + 20, text_off);
    WRITE32LE(sect + 36, 0x60000020);  // CODE|MEM_EXECUTE|MEM_READ
    sect += 40;
  }
  strcpy(sect, ".edata");
  WRITE32LE(sect + 8, x.n);
  WRITE32LE(sect + 12, edata_rva);
  WRITE32LE(sect + 16, ROUNDUP(x.n, FILEALIGN));
  WRITE32LE(sect + 20, edata_off);
  WRITE32LE(sect + 36, 0x40000040);  // INITIALIZED_DATA|MEM_READ

  *out_size = size;
  p = (free(names), free(t.p), free(x.p), free(sorted), p);
  return p;
Fail:
  free(names);
  free(t.p);
  free(x.p);
  free(sorted);
  free(p);
  return 0;
}

////////////////////////////////////////////////////////////////////////////////
// Mach-O

struct Sha256 {
  uint32_t h[8];
  uint64_t n;
  unsigned char b[64];
};

static const uint32_t kSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROR(x, n) ((x) >> (n) | (x) << (32 - (n)))

static void sha256_block(struct Sha256 *s, const unsigned char *p) {
  uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
  for (int i = 0; i < 16; ++i)
    w[i] = READ32BE(p + i * 4);
  for (int i = 16; i < 64; ++i)
    w[i] = (ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10)) +
           w[i - 7] +
           (ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3)) +
           w[i - 16];
  a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
  e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
  for (int i = 0; i < 64; ++i) {
    t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) +
         kSha256K[i] + w[i];
    t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    h = g, g = f, f = e, e = d + t1, d = c, c = b, b = a, a = t1 + t2;
  }
  s->h[0] += a, s->h[1] += b, s->h[2] += c, s->h[3] += d;
  s->h[4] += e, s->h[5] += f, s->h[6] += g, s->h[7] += h;
}

static void sha256(const void *data, size_t n, unsigned char out[32]) {
  struct Sha256 s = {{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}};
  const unsigned char *p = data;
  size_t i;
  for (i = 0; i + 64 <= n; i += 64)
    sha256_block(&s, p + i);
  unsigned char last[128] = {0};
  size_t r = n - i;
  memcpy(last, p + i, r);
  last[r] = 0x80;
  size_t len = r + 9 <= 64 ? 64 : 128;
  WRITE64BE(last + len - 8, (uint64_t)n * 8);
  sha256_block(&s, last);
  if (len == 128)
    sha256_block(&s, last + 64);
  for (int j = 0; j < 8; ++j)
    WRITE32BE(out + j * 4, s.h[j]);
}

static void put_uleb(struct Buf *b, uint64_t x) {
  do {
    long off = buf_add(b, 1, 1);
    if (off == -1)
      return;
    b->p[off] = (x & 127) | (x > 127 ? 128 : 0);
    x >>= 7;
  } while (x);
}

static size_t uleb_size(uint64_t x) {
  size_t n = 0;
  do
    ++n;
  while (x >>= 7);
  return n;
}

// a node of the export trie, over names[lo,hi) sharing prefix [0,depth)
struct TrieNode {
  int lo, hi, depth;
  long terminal;  // index of the name that ends here, or -1
  int nkids;
  struct TrieNode *kids;
  int *edge;  // length of each child's edge label
  size_t off;
};

static char **g_trie_names;
static uint64_t *g_trie_addrs;
static char *g_trie_abs;  // whether each address is absolute, not an offset

static void trie_build(struct TrieNode *t, int lo, int hi, int depth) {
  t->lo = lo, t->hi = hi, t->depth = depth, t->terminal = -1;
  t->nkids = 0, t->kids = 0, t->edge = 0;
  if (lo < hi && !g_trie_names[lo][depth]) {
    t->terminal = lo++;
  }
  t->kids = calloc(hi - lo + 1, sizeof(*t->kids));
  t->edge = calloc(hi - lo + 1, sizeof(*t->edge));
  for (int i = lo; i < hi;) {
    // names [i,j) share their next character; extend the edge while
    // they share more, stopping where one of them ends
    int j = i + 1;
    while (j < hi && g_trie_names[j][depth] == g_trie_names[i][depth])
      ++j;
    int len = 1;
    for (;;) {
      char c = g_trie_names[i][depth + len];
      if (!c)
        break;
      bool same = true;
      for (int k = i + 1; k < j; ++k)
        if (g_trie_names[k][depth + len] != c)
          same = false;
      if (!same)
        break;
      ++len;
    }
    t->edge[t->nkids] = len;
    trie_build(&t->kids[t->nkids], i, j, depth + len);
    ++t->nkids;
    i = j;
  }
}

static size_t trie_node_size(struct TrieNode *t) {
  size_t term = 0;
  if (t->terminal != -1)
    term = uleb_size(g_trie_abs[t->terminal] ? 2 : 0) +
           uleb_size(g_trie_addrs[t->terminal]);
  size_t n = uleb_size(term) + term + 1;
  for (int i = 0; i < t->nkids; ++i)
    n += t->edge[i] + 1 + uleb_size(t->kids[i].off);
  return n;
}

// assigns offsets until they stop changing, since node sizes depend on
// the uleb128 widths of their children's offsets
static bool trie_layout(struct TrieNode *t, size_t *off) {
  bool changed = t->off != *off;
  t->off = *off;
  *off += trie_node_size(t);
  for (int i = 0; i < t->nkids; ++i)
    changed |= trie_layout(&t->kids[i], off);
  return changed;
}

static void trie_emit(struct TrieNode *t, struct Buf *b) {
  if (t->terminal != -1) {
    uint64_t addr = g_trie_addrs[t->terminal];
    uint64_t flags = g_trie_abs[t->terminal] ? 2 : 0;  // KIND_ABSOLUTE
    put_uleb(b, uleb_size(flags) + uleb_size(addr));
    put_uleb(b, flags);
    put_uleb(b, addr);
  } else {
    put_uleb(b, 0);
  }
  long off = buf_add(b, 1, 1);
  if (off != -1)
    b->p[off] = t->nkids;
  for (int i = 0; i < t->nkids; ++i) {
    long s = buf_add(b, t->edge[i] + 1, 1);
    if (s != -1)
      memcpy(b->p + s, g_trie_names[t->kids[i].lo] + t->depth, t->edge[i]);
    put_uleb(b, t->kids[i].off);
  }
  for (int i = 0; i < t->nkids; ++i)
    trie_emit(&t->kids[i], b);
}

static void trie_free(struct TrieNode *t) {
  for (int i = 0; i < t->nkids; ++i)
    trie_free(&t->kids[i]);
  free(t->kids);
  free(t->edge);
}

static int cmp_strs(const void *a, const void *b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}

static char *make_macho(const char *install_name,
                        const struct CosmoDlexport2 *syms, size_t n,
                        size_t *out_size) {
  enum { PAGE = 16384 };
  size_t code = 0;
  for (size_t i = 0; i < n; ++i)
    if (syms[i].kind == COSMO_DLEXPORT_VARARG)
      code += VTRAMP;
    else if (syms[i].kind != COSMO_DLEXPORT_DATA)
      code += TRAMP;
  struct Buf b = {0}, trie = {0};
  char **names = calloc(n + 1, sizeof(char *));
  uint64_t *addrs = calloc(n + 1, sizeof(uint64_t));
  char *absolute = calloc(n + 1, 1);
  struct TrieNode root = {0};
  if (!names || !addrs || !absolute)
    goto Fail;

  // text: header and load commands, then trampolines
  size_t cmds_size = 72 + 80 +                          // __TEXT seg+sect
                     72 +                               // __LINKEDIT
                     ROUNDUP(24 + strlen(install_name) + 1, 8) +  // ID_DYLIB
                     16 + 24 + 80 +                     // trie symtab dysym
                     24 + 16 +                          // build_version sig
                     56;                                // libSystem
  size_t text = ROUNDUP(32 + cmds_size, 16);
  size_t text_end = text + code;
  size_t linkedit = ROUNDUP(text_end, PAGE);

  // names sorted with the leading underscore mach-o wants
  for (size_t i = 0; i < n; ++i) {
    if (!(names[i] = malloc(strlen(syms[i].name) + 2)))
      goto Fail;
    names[i][0] = '_';
    strcpy(names[i] + 1, syms[i].name);
  }
  struct CosmoDlexport2 *order = calloc(n + 1, sizeof(*order));
  if (!order)
    goto Fail;
  for (size_t i = 0; i < n; ++i)
    order[i] = syms[i];
  // sort names and keep the addresses alongside
  for (size_t i = 0; i < n; ++i)
    for (size_t j = i + 1; j < n; ++j)
      if (strcmp(names[j], names[i]) < 0) {
        char *t = names[i];
        names[i] = names[j];
        names[j] = t;
        struct CosmoDlexport2 u = order[i];
        order[i] = order[j];
        order[j] = u;
      }
  for (size_t i = 0, off = 0; i < n; ++i) {
    absolute[i] = order[i].kind == COSMO_DLEXPORT_DATA;
    if (absolute[i]) {
      addrs[i] = (uint64_t)(uintptr_t)order[i].addr;
      continue;
    }
    addrs[i] = text + off;
    off += order[i].kind == COSMO_DLEXPORT_VARARG ? VTRAMP : TRAMP;
  }

  g_trie_names = names;
  g_trie_addrs = addrs;
  g_trie_abs = absolute;
  trie_build(&root, 0, n, 0);
  size_t off;
  do
    off = 0;
  while (trie_layout(&root, &off));
  trie_emit(&root, &trie);
  size_t trie_size = ROUNDUP(trie.n, 8);

  // linkedit: export trie, then one symbol per export, then strings
  size_t symoff = linkedit + trie_size;
  size_t stroff = symoff + n * 16;
  struct Buf strs = {0};
  buf_add(&strs, 1, 1);  // leading space
  long *strx = calloc(n + 1, sizeof(long));
  if (!strx)
    goto Fail2;
  for (size_t i = 0; i < n; ++i)
    strx[i] = buf_str(&strs, names[i]);
  size_t strsize = ROUNDUP(strs.n, 16);
  size_t sigoff = ROUNDUP(stroff + strsize, 16);

  // the code signature covers everything before it
  static const char kIdent[] = "cosmo.dlexport";
  size_t nslots = (sigoff + 4095) / 4096;
  size_t cd_hash_off = 88 + sizeof(kIdent);
  size_t cd_size = cd_hash_off + nslots * 32;
  size_t sig_size = ROUNDUP(12 + 8 + cd_size, 16);
  size_t total = sigoff + sig_size;

  if (buf_add(&b, total, 1) == -1)
    goto Fail3;
  char *p = b.p;

  // mach header
  WRITE32LE(p + 0, 0xfeedfacf);
  WRITE32LE(p + 4, 0x0100000c);  // CPU_TYPE_ARM64
  WRITE32LE(p + 8, 0);
  WRITE32LE(p + 12, 6);          // MH_DYLIB
  WRITE32LE(p + 16, 9);          // ncmds, see cmds_size
  WRITE32LE(p + 20, cmds_size);
  WRITE32LE(p + 24, 0x00100085);  // NOUNDEFS|DYLDLINK|TWOLEVEL|NO_REEXPORTED
  char *c = p + 32;

  // LC_SEGMENT_64 __TEXT with one __text section
  WRITE32LE(c + 0, 0x19);
  WRITE32LE(c + 4, 72 + 80);
  strcpy(c + 8, "__TEXT");
  WRITE64LE(c + 24, 0);          // vmaddr
  WRITE64LE(c + 32, linkedit);   // vmsize
  WRITE64LE(c + 40, 0);          // fileoff
  WRITE64LE(c + 48, linkedit);   // filesize
  WRITE32LE(c + 56, 5);          // maxprot r-x
  WRITE32LE(c + 60, 5);          // initprot r-x
  WRITE32LE(c + 64, 1);          // nsects
  char *sc = c + 72;
  strcpy(sc, "__text");
  strcpy(sc + 16, "__TEXT");
  WRITE64LE(sc + 32, text);
  WRITE64LE(sc + 40, code);
  WRITE32LE(sc + 48, text);
  WRITE32LE(sc + 52, 4);          // align 2^4
  WRITE32LE(sc + 64, 0x80000400); // PURE_INSTRUCTIONS|SOME_INSTRUCTIONS
  c += 72 + 80;

  // LC_SEGMENT_64 __LINKEDIT
  WRITE32LE(c + 0, 0x19);
  WRITE32LE(c + 4, 72);
  strcpy(c + 8, "__LINKEDIT");
  WRITE64LE(c + 24, linkedit);
  WRITE64LE(c + 32, ROUNDUP(total - linkedit, PAGE));
  WRITE64LE(c + 40, linkedit);
  WRITE64LE(c + 48, total - linkedit);
  WRITE32LE(c + 56, 1);
  WRITE32LE(c + 60, 1);
  c += 72;

  // LC_ID_DYLIB
  size_t idsize = ROUNDUP(24 + strlen(install_name) + 1, 8);
  WRITE32LE(c + 0, 0xd);
  WRITE32LE(c + 4, idsize);
  WRITE32LE(c + 8, 24);          // name offset
  WRITE32LE(c + 12, 2);          // timestamp
  WRITE32LE(c + 16, 0x10000);    // current version 1.0.0
  WRITE32LE(c + 20, 0x10000);    // compatibility version 1.0.0
  strcpy(c + 24, install_name);
  c += idsize;

  // LC_DYLD_EXPORTS_TRIE
  WRITE32LE(c + 0, 0x80000033);
  WRITE32LE(c + 4, 16);
  WRITE32LE(c + 8, linkedit);
  WRITE32LE(c + 12, trie.n);
  c += 16;

  // LC_SYMTAB
  WRITE32LE(c + 0, 0x2);
  WRITE32LE(c + 4, 24);
  WRITE32LE(c + 8, symoff);
  WRITE32LE(c + 12, n);
  WRITE32LE(c + 16, stroff);
  WRITE32LE(c + 20, strsize);
  c += 24;

  // LC_DYSYMTAB, every symbol an external definition
  WRITE32LE(c + 0, 0xb);
  WRITE32LE(c + 4, 80);
  WRITE32LE(c + 16, 0);          // iextdefsym
  WRITE32LE(c + 20, n);          // nextdefsym
  WRITE32LE(c + 24, n);          // iundefsym
  c += 80;


  // LC_BUILD_VERSION: macOS 11.0
  WRITE32LE(c + 0, 0x32);
  WRITE32LE(c + 4, 24);
  WRITE32LE(c + 8, 1);           // PLATFORM_MACOS
  WRITE32LE(c + 12, 0xb0000);
  WRITE32LE(c + 16, 0xb0000);
  c += 24;

  // LC_LOAD_DYLIB, since dyld wants every image to link libSystem
  WRITE32LE(c + 0, 0xc);
  WRITE32LE(c + 4, 56);
  WRITE32LE(c + 8, 24);
  WRITE32LE(c + 12, 2);
  WRITE32LE(c + 16, 0x05000000);
  WRITE32LE(c + 20, 0x10000);
  strcpy(c + 24, "/usr/lib/libSystem.B.dylib");
  c += 56;

  // LC_CODE_SIGNATURE
  WRITE32LE(c + 0, 0x1d);
  WRITE32LE(c + 4, 16);
  WRITE32LE(c + 8, sigoff);
  WRITE32LE(c + 12, sig_size);
  c += 16;

  for (size_t i = 0; i < n; ++i) {
    if (absolute[i])
      continue;
    if (order[i].kind == COSMO_DLEXPORT_VARARG) {
      if (!put_vtramp(p + addrs[i], order[i].va, order[i].size)) {
        dlexport_error("cosmo_dlexport: too many fixed parameters");
        goto Fail3;
      }
    } else {
      put_tramp(p + addrs[i], order[i].addr);
    }
  }
  memcpy(p + linkedit, trie.p, trie.n);
  for (size_t i = 0; i < n; ++i) {
    char *nl = p + symoff + i * 16;
    WRITE32LE(nl + 0, strx[i]);
    nl[4] = absolute[i] ? 0x03 : 0x0f;  // N_ABS|N_EXT or N_SECT|N_EXT
    nl[5] = absolute[i] ? 0 : 1;        // n_sect
    WRITE64LE(nl + 8, addrs[i]);
  }
  memcpy(p + stroff, strs.p, strs.n);

  // ad-hoc signature: a superblob holding one code directory
  char *sb = p + sigoff;
  WRITE32BE(sb + 0, 0xfade0cc0);  // CSMAGIC_EMBEDDED_SIGNATURE
  WRITE32BE(sb + 4, 12 + 8 + cd_size);
  WRITE32BE(sb + 8, 1);
  WRITE32BE(sb + 12, 0);          // CSSLOT_CODEDIRECTORY
  WRITE32BE(sb + 16, 20);
  char *cd = sb + 20;
  WRITE32BE(cd + 0, 0xfade0c02);  // CSMAGIC_CODEDIRECTORY
  WRITE32BE(cd + 4, cd_size);
  WRITE32BE(cd + 8, 0x20400);     // version with exec segment fields
  WRITE32BE(cd + 12, 0x2);        // CS_ADHOC
  WRITE32BE(cd + 16, cd_hash_off);
  WRITE32BE(cd + 20, 88);         // identOffset
  WRITE32BE(cd + 24, 0);          // nSpecialSlots
  WRITE32BE(cd + 28, nslots);
  WRITE32BE(cd + 32, sigoff);     // codeLimit
  cd[36] = 32;                    // hashSize
  cd[37] = 2;                     // CS_HASHTYPE_SHA256
  cd[38] = 0;                     // platform
  cd[39] = 12;                    // log2 page size
  WRITE64BE(cd + 64, 0);          // execSegBase
  WRITE64BE(cd + 72, linkedit);   // execSegLimit
  WRITE64BE(cd + 80, 0);          // execSegFlags
  memcpy(cd + 88, kIdent, sizeof(kIdent));
  for (size_t i = 0; i < nslots; ++i) {
    size_t lo = i * 4096;
    size_t len = MIN(4096, sigoff - lo);
    sha256(p + lo, len, (unsigned char *)cd + cd_hash_off + i * 32);
  }

  *out_size = total;
  free(strx);
  free(strs.p);
  free(order);
  trie_free(&root);
  free(trie.p);
  for (size_t i = 0; i < n; ++i)
    free(names[i]);
  free(names);
  free(addrs);
  free(absolute);
  return b.p;
Fail3:
  free(strx);
Fail2:
  free(strs.p);
  free(order);
  trie_free(&root);
  free(trie.p);
Fail:
  if (names)
    for (size_t i = 0; i < n; ++i)
      free(names[i]);
  free(names);
  free(addrs);
  free(absolute);
  free(b.p);
  return 0;
}

////////////////////////////////////////////////////////////////////////////////

// cosmo_dlopen() tries foo.so as foo.dylib on macOS and foo.dll on
// Windows, so that's the name the file needs there
static const char *host_name(const char *name, char *buf, size_t size) {
  size_t n = strlen(name);
  if (IsLinux() || n < 3 || strcmp(name + n - 3, ".so") || n + 4 > size)
    return name;
  memcpy(buf, name, n - 3);
  strcpy(buf + n - 3, IsWindows() ? ".dll" : ".dylib");
  return buf;
}

// a private directory per process, made once, so the files can carry
// the exact names plugins import them by
static char *dlexport_dir(void) {
  static char *dir;
  static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock(&lock);
  if (!dir) {
    const char *tmp = __get_tmpdir();
    char *d = malloc(strlen(tmp) + 32);
    if (d) {
      stpcpy(stpcpy(d, tmp), "cosmo-dlexport-XXXXXX");
      if (mkdtemp(d)) {
        dir = d;
      } else {
        free(d);
      }
    }
  }
  pthread_mutex_unlock(&lock);
  return dir;
}

// writes the library where the host loader can open it
static char *dlexport_file(const char *name, const char *data, size_t size) {
  char *path;
  const char *dir;
  if (!(dir = dlexport_dir()))
    return 0;
  if (!(path = malloc(strlen(dir) + strlen(name) + 2)))
    return 0;
  stpcpy(stpcpy(stpcpy(path, dir), "/"), name);
  int fd;
  if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0700)) == -1) {
    free(path);
    return 0;
  }
  bool ok = write(fd, data, size) == size;
  if (close(fd))
    ok = false;
  if (!ok) {
    unlink(path);
    free(path);
    return 0;
  }
  return path;
}

// the libraries built so far, so that dlopen() of one's name finds it:
// what to open again for each, so the host's reference count goes up and
// a dlclose() later doesn't pull it from under the other users
static struct {
  pthread_mutex_t lock;
  size_t n, cap;
  struct {
    char *name;
    char *path;
  } *p;
} dlexport_libs = {PTHREAD_MUTEX_INITIALIZER};

static void dlexport_remember_lib(const char *name, const char *path) {
  pthread_mutex_lock(&dlexport_libs.lock);
  if (dlexport_libs.n == dlexport_libs.cap) {
    size_t cap = dlexport_libs.cap ? dlexport_libs.cap * 2 : 8;
    void *p = realloc(dlexport_libs.p, cap * sizeof(*dlexport_libs.p));
    if (p) {
      dlexport_libs.p = p;
      dlexport_libs.cap = cap;
    }
  }
  char *copy, *pcopy;
  if (dlexport_libs.n < dlexport_libs.cap && (copy = strdup(name))) {
    if (!(pcopy = strdup(path))) {
      free(copy);
    } else {
      dlexport_libs.p[dlexport_libs.n].name = copy;
      dlexport_libs.p[dlexport_libs.n].path = pcopy;
      ++dlexport_libs.n;
    }
  }
  pthread_mutex_unlock(&dlexport_libs.lock);
}

/**
 * Returns what to open to get the library cosmo_dlexport() built under
 * `name` once more, or null. cosmo_dlopen() of a bare name asks here
 * first, so a program can stand in for a library by the name other code
 * loads it as; the handle it gets is the host's, counted like any other.
 */
const char *__dlexport_library(const char *name) {
  const char *res = 0;
  pthread_mutex_lock(&dlexport_libs.lock);
  for (size_t i = 0; i < dlexport_libs.n; ++i)
    if (!strcmp(dlexport_libs.p[i].name, name)) {
      res = dlexport_libs.p[i].path;
      break;
    }
  pthread_mutex_unlock(&dlexport_libs.lock);
  return res;
}

/**
 * Exports functions of this program to host libraries, by name.
 *
 * This builds and loads a host shared library called `name` whose only
 * contents are the functions in `syms`, each forwarding to its `addr`.
 * Load it before a library that looks those names up: a Lua C module
 * wants the lua_* functions from its host, a plugin wants its host's
 * API. On Linux and macOS the functions become visible to libraries
 * loaded afterwards (`RTLD_GLOBAL`), and `name` also satisfies their
 * dependencies on a library by that name. On Windows, where a DLL
 * imports from a named DLL, `name` should be exactly the DLL name the
 * library imports from, e.g. `"lua54.dll"`.
 *
 * Each `addr` is called with the host's calling convention, which on
 * Windows is Microsoft's x64 one, not SysV. Only functions can be
 * exported.
 *
 * @return handle for cosmo_dlsym() and cosmo_dlclose(), or NULL w/
 *     cosmo_dlerror()
 */
// every function made known so far, for dlsym(RTLD_DEFAULT), and the
// host-convention versions of the native ones
static struct {
  pthread_mutex_t lock;
  size_t n, cap;
  struct CosmoDlexport *p;
  size_t nnative, capnative;
  void **native;
} dlexport_known = {PTHREAD_MUTEX_INITIALIZER};

static void dlexport_remember_native(void *addr) {
  if (dlexport_known.nnative == dlexport_known.capnative) {
    size_t cap = dlexport_known.capnative ? dlexport_known.capnative * 2 : 16;
    void **p = realloc(dlexport_known.native, cap * sizeof(*p));
    if (!p)
      return;
    dlexport_known.native = p;
    dlexport_known.capnative = cap;
  }
  dlexport_known.native[dlexport_known.nnative++] = addr;
}

static void dlexport_remember(const struct CosmoDlexport2 *syms, size_t n) {
  pthread_mutex_lock(&dlexport_known.lock);
  for (size_t i = 0; i < n; ++i) {
    size_t j;
    for (j = 0; j < dlexport_known.n; ++j)
      if (!strcmp(dlexport_known.p[j].name, syms[i].name))
        break;
    if (j < dlexport_known.n)
      continue;
    if (dlexport_known.n == dlexport_known.cap) {
      size_t cap = dlexport_known.cap ? dlexport_known.cap * 2 : 16;
      struct CosmoDlexport *p =
          realloc(dlexport_known.p, cap * sizeof(*p));
      if (!p)
        break;
      dlexport_known.p = p;
      dlexport_known.cap = cap;
    }
    char *name;
    if (!(name = strdup(syms[i].name)))
      break;
    // callers here are ours, and a native export's `addr` is the host's
    void *addr = syms[i].addr;
    if (syms[i].kind == COSMO_DLEXPORT_NATIVE && syms[i].va) {
      dlexport_remember_native(syms[i].addr);
      addr = syms[i].va;
    }
    dlexport_known.p[dlexport_known.n++] = (struct CosmoDlexport){name, addr};
  }
  pthread_mutex_unlock(&dlexport_known.lock);
}

/**
 * Returns whether `func` is the host's version of a native export,
 * which takes the host's calling convention.
 */
bool __dlexport_native(const void *func) {
  bool res = false;
  pthread_mutex_lock(&dlexport_known.lock);
  for (size_t i = 0; i < dlexport_known.nnative && !res; ++i)
    res = dlexport_known.native[i] == func;
  pthread_mutex_unlock(&dlexport_known.lock);
  return res;
}

// the table cosmocc -rdynamic puts in the program, empty otherwise
extern const struct CosmoDlexport2 __ape_exports[] __attribute__((__weak__));
extern const unsigned long __ape_exports_count __attribute__((__weak__));
extern const char *const __ape_export_names[] __attribute__((__weak__));

/**
 * Returns the function cosmo_dlexport() made known as `name`, or null.
 * What -rdynamic collected counts too, before anything is loaded.
 */
void *__dlexport_find(const char *name) {
  void *res = 0;
  pthread_mutex_lock(&dlexport_known.lock);
  for (size_t i = 0; i < dlexport_known.n; ++i) {
    if (!strcmp(dlexport_known.p[i].name, name)) {
      res = dlexport_known.p[i].addr;
      break;
    }
  }
  pthread_mutex_unlock(&dlexport_known.lock);
  if (!res && __ape_exports) {
    for (size_t i = 0; i < __ape_exports_count; ++i) {
      const struct CosmoDlexport2 *e = __ape_exports + i;
      if (!strcmp(e->name, name)) {
        res = e->kind == COSMO_DLEXPORT_NATIVE && e->va ? e->va : e->addr;
        break;
      }
    }
  }
  return res;
}

static void *dlexport_impl(const char *name, const struct CosmoDlexport2 *syms,
                           size_t n) {
  char dylib[PATH_MAX];
  char *lib, *path = 0;
  size_t size, i, j, m;
  void *res = 0;
  struct CosmoDlexport2 *uniq;
  dlexport_said = false;
  if (!name || !*name || strchr(name, '/')) {
    __dlerror_set("cosmo_dlexport: the name must be a bare file name");
    return 0;
  }
  if (IsXnu() && !IsXnuSilicon()) {
    __dlerror_set("cosmo_dlexport() isn't supported on x86-64 MacOS");
    return 0;
  }
  // the first of two exports with the same name wins, as with a linker
  if (!(uniq = malloc((n + 1) * sizeof(*uniq)))) {
    __dlerror_set("cosmo_dlexport: out of memory");
    return 0;
  }
  for (i = m = 0; i < n; ++i) {
    if (!syms[i].name || !syms[i].addr)
      continue;
    for (j = 0; j < m && strcmp(uniq[j].name, syms[i].name); ++j) {
    }
    if (j == m)
      uniq[m++] = syms[i];
  }
  syms = uniq;
  n = m;
  if (IsWindows()) {
    lib = make_pe(host_name(name, dylib, sizeof(dylib)), syms, n, &size);
  } else if (IsXnu()) {
#ifdef __aarch64__
    lib = make_macho(name, syms, n, &size);
#else
    lib = 0;
#endif
  } else {
    lib = make_elf(name, syms, n, &size);
  }
  if (!lib) {
    free(uniq);
    if (!dlexport_said)
      __dlerror_set("cosmo_dlexport: couldn't build the library");
    return 0;
  }
  if (IsLinux()) {
    // no need for a file. the descriptor stays open, since the host
    // loader knows the library by its /proc/self/fd path and a later
    // export that got the same number would be taken for this one
    int fd;
    if ((fd = memfd_create(name, MFD_CLOEXEC)) != -1) {
      if (write(fd, lib, size) == size) {
        char proc[32] = "/proc/self/fd/";
        FormatInt32(proc + 14, fd);
        res = cosmo_dlopen(proc, RTLD_NOW | RTLD_GLOBAL);
        if (res)
          dlexport_remember_lib(name, proc);
      } else {
        __dlerror_set("cosmo_dlexport: writing the memfd failed");
      }
      if (!res)
        close(fd);
    } else {
      __dlerror_set("cosmo_dlexport: memfd_create() failed");
    }
  } else if ((path = dlexport_file(host_name(name, dylib, sizeof(dylib)), lib,
                                   size))) {
    res = cosmo_dlopen(path, IsWindows() ? RTLD_NOW : RTLD_NOW | RTLD_GLOBAL);
    // the file goes away on macOS, where dyld knows the image by its
    // install name, which is `name`
    if (res)
      dlexport_remember_lib(name, IsWindows() ? path : name);
    if (!IsWindows())
      unlink(path);
    free(path);
  } else {
    __dlerror_set("cosmo_dlexport: couldn't write the library to the "
                  "temporary directory");
  }
  if (res) {
    // its functions are this program's, dlsym() finds them as such
    __dlglobal_forget(res);
    dlexport_remember(syms, n);
  }
  free(lib);
  free(uniq);
  STRACE("cosmo_dlexport(%#s, %zu) → %p", name, n, res);
  return res;
}

void *cosmo_dlexport(const char *name, const struct CosmoDlexport *syms,
                     size_t n) {
  void *res;
  struct CosmoDlexport2 *two;
  if (!(two = calloc(n + 1, sizeof(*two)))) {
    __dlerror_set("cosmo_dlexport: out of memory");
    return 0;
  }
  for (size_t i = 0; i < n; ++i) {
    two[i].name = syms[i].name;
    two[i].addr = syms[i].addr;
    two[i].kind = COSMO_DLEXPORT_FUNC;
  }
  res = dlexport_impl(name, two, n);
  free(two);
  return res;
}

/**
 * Exports functions and variables of this program to host libraries.
 *
 * This is cosmo_dlexport() with a kind per symbol. A
 * `COSMO_DLEXPORT_DATA` symbol is the variable at `addr`, `size` bytes
 * of it, which a library loaded afterwards binds to as if it had a copy
 * relocation, so both sides share the one variable. It must be a static
 * of this program, not heap memory, since on Windows the export table
 * can only name addresses within 4 GiB of where the library loads.
 *
 * @return handle for cosmo_dlsym() and cosmo_dlclose(), or NULL w/
 *     cosmo_dlerror()
 */
void *cosmo_dlexport2(const char *name, const struct CosmoDlexport2 *syms,
                      size_t n) {
  return dlexport_impl(name, syms, n);
}

// whether this host wants the library called `name`. a name is picked
// for the host whose libraries end that way, and when none does, every
// name is used and the extension gets adapted
static bool dlexport_name_fits(const char *name, bool any) {
  size_t n = strlen(name);
  bool dll = n > 4 && !strcasecmp(name + n - 4, ".dll");
  if (any)
    return true;
  return IsWindows() ? dll : !dll;
}

/**
 * Exports what `cosmocc -rdynamic` collected, once, before the first
 * host library is loaded. Does nothing in a program that didn't ask.
 */
void __dlexport_auto(void) {
  static atomic_bool done;
  size_t n;
  if (!__ape_exports)
    return;
  if (!(n = __ape_exports_count))
    return;
  if (atomic_exchange_explicit(&done, true, memory_order_acq_rel))
    return;
  size_t count = 0;
  bool any = true;
  for (size_t i = 0; __ape_export_names && __ape_export_names[i]; ++i) {
    ++count;
    if (dlexport_name_fits(__ape_export_names[i], false))
      any = false;
  }
  if (!count) {
    dlexport_impl(IsWindows() ? "ape-exports.dll" : "libape-exports.so",
                  __ape_exports, n);
    return;
  }
  for (size_t i = 0; i < count; ++i)
    if (dlexport_name_fits(__ape_export_names[i], any))
      dlexport_impl(__ape_export_names[i], __ape_exports, n);
}

