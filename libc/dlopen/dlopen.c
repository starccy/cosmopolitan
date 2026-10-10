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
#include "ape/sections.internal.h"
#include "libc/assert.h"
#include "libc/atomic.h"
#include "libc/calls/blockcancel.internal.h"
#include "libc/calls/calls.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/calls/struct/stat.h"
#include "libc/calls/struct/timespec.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/cosmo.h"
#include "libc/cosmotime.h"
#include "libc/dce.h"
#include "libc/dlopen/dlfcn.h"
#include "libc/dlopen/ntunwind.internal.h"
#include "libc/dlopen/templates.internal.h"
#include "libc/dlopen/hostfile.internal.h"
#include "libc/elf/def.h"
#include "libc/elf/elf.h"
#include "libc/elf/link.h"
#include "libc/elf/scalar.h"
#include "libc/elf/struct/auxv.h"
#include "libc/elf/struct/ehdr.h"
#include "libc/elf/struct/phdr.h"
#include "libc/errno.h"
#include "libc/fmt/itoa.h"
#include "libc/intrin/atomic.h"
#include "libc/intrin/fds.h"
#include "libc/intrin/hostlibc.h"
#include "libc/intrin/kprintf.h"
#include "libc/intrin/strace.h"
#include "libc/limits.h"
#include "libc/macros.h"
#include "libc/nt/dll.h"
#include "libc/nt/pedef.internal.h"
#include "libc/nt/struct/imagedatadirectory.internal.h"
#include "libc/nt/struct/imageimportdescriptor.internal.h"
#include "libc/nt/struct/imagentheaders.internal.h"
#include "libc/nt/struct/imagedosheader.internal.h"
#include "libc/nt/enum/filemapflags.h"
#include "libc/nt/enum/formatmessageflags.h"
#include "libc/nt/enum/getmodulehandleex.h"
#include "libc/nt/enum/loadlibrarysearch.h"
#include "libc/nt/errors.h"
#include "libc/nt/files.h"
#include "libc/nt/process.h"
#include "libc/nt/enum/pageflags.h"
#include "libc/nt/memory.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/context.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/mem/mem.h"
#include "libc/proc/posix_spawn.h"
#include "libc/proc/proc.h"
#include "libc/runtime/internal.h"
#include "libc/runtime/runtime.h"
#include "libc/runtime/syslib.internal.h"
#include "libc/serialize.h"
#include "libc/str/str.h"
#include "libc/str/utf16.h"
#include "libc/sysv/consts/auxv.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/map.h"
#include "libc/sysv/consts/mfd.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/ok.h"
#include "libc/sysv/consts/prot.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/errno.h"
#include "libc/sysv/pib.h"
#include "libc/temp.h"
#include "libc/thread/posixthread.internal.h"
#include "libc/thread/thread.h"
#include "libc/thread/tls.h"

/**
 * @fileoverview Cosmopolitan Dynamic Linker.
 *
 * Every program built using Cosmopolitan is statically-linked. However
 * there are some cases, e.g. GUIs and video drivers, where linking the
 * host platform libraries is desirable. So what we do in such cases is
 * launch a stub executable using the host platform's libc, and longjmp
 * back into this executable. The stub executable passes back to us the
 * platform-specific dlopen() implementation, which we shall then wrap.
 *
 * @kudos jacereda for figuring out how to do this
 */

#define XNU_RTLD_LAZY     1
#define XNU_RTLD_NOW      2
#define XNU_RTLD_LOCAL    4
#define XNU_RTLD_GLOBAL   8
#define XNU_RTLD_NOLOAD   0x10
#define XNU_RTLD_NODELETE 0x80
#define XNU_RTLD_FIRST    0x100

#define HELPER_ABI 2

#include "libc/dlopen/helper/helper.inc"

struct Loaded {
  char *base;
  char *entry;
  Elf64_Ehdr eh;
  Elf64_Phdr ph[25];
};

// what the helper's allocator and exit() call into, see helper.c
struct HelperHooks {
  void *(*malloc)(size_t);
  void (*free)(void *);
  void *(*calloc)(size_t, size_t);
  void *(*realloc)(void *, size_t);
  void *(*memalign)(size_t, size_t);
  size_t (*usable)(void *);
  void (*exit)(int);
  int (*setenv)(const char *, const char *, int);
  int (*unsetenv)(const char *);
  int (*putenv)(char *);
  void *sigaction;
  const char *(*pathmap)(const char *, char *, size_t);
  int remaps;
};

struct {
  atomic_uint once;
  bool is_supported;
  struct CosmoTib *tib;
  void *(*dlopen)(const char *, int);
  void *(*dlsym)(void *, const char *);
  int (*dlclose)(void *);
  char *(*dlerror)(void);
  struct HelperHooks *hooks;
  jmp_buf jb;
} __foreign;

int __host_threads_init(void);
void __host_enter(void);
int __host_sigaction();
const char *__host_pathmap(const char *, char *, size_t);
bool __host_pathmap_remaps(void);

// the GLIBC_TUNABLES value this process started with, if any
static const char *foreign_tunables;
static bool foreign_had_tunables;

long __sysv2nt14();
extern char __sysv2nt_end[];
extern char __hostcall_nt16[], __hostcall_nt14[], __hostcall_nt12[],
    __hostcall_nt10[], __hostcall_nt8[], __hostcall_nt6[], __hostcall_nt4[],
    __hostcall_nt2[], __hostcall_nt0[], __hostcall_nt_end[],
    __hostcall_frame[], __hostcall_frame_end[];
void *__dlexport_find(const char *) __attribute__((__weak__));
const char *__dlexport_library(const char *) __attribute__((__weak__));
bool __dlexport_native(const void *) __attribute__((__weak__));
void __dlexport_auto(void) __attribute__((__weak__));
static void dlglobal_add(void *, const char *);
static void dlglobal_remove(void *);
static bool is_ours(void *);
long foreign_tramp();
void __dlopen_lock(void);
void __dlopen_unlock(void);
void __host_frames_register(void *(*)(const char *, const char *));
static void *host_find(const char *, const char *);

static _Thread_local char dlerror_buf[256];

static const char *get_tmp_dir(void) {
  const char *tmpdir;
  if (!(tmpdir = getenv("TMPDIR")) || !*tmpdir)
    if (!(tmpdir = getenv("HOME")) || !*tmpdir)
      tmpdir = ".";
  return tmpdir;
}

static int is_file_newer_than(const char *path, const char *other) {
  struct stat st1, st2;
  if (stat(path, &st1))
    return -1;
  if (stat(other, &st2)) {
    if (errno == ENOENT) {
      return 2;
    } else {
      return -1;
    }
  }
  return timespec_cmp(st1.st_mtim, st2.st_mtim) > 0;
}

static unsigned elf2prot(unsigned x) {
  unsigned r = 0;
  if (x & PF_R)
    r += PROT_READ;
  if (x & PF_W)
    r += PROT_WRITE;
  if (x & PF_X)
    r += PROT_EXEC;
  return r;
}

static int get_host_elf_machine(void) {
#ifdef __x86_64__
  return EM_NEXGEN32E;
#elif defined(__aarch64__)
  return EM_AARCH64;
#elif defined(__powerpc64__)
  return EM_PPC64;
#elif defined(__riscv)
  return EM_RISCV;
#elif defined(__s390x__)
  return EM_S390;
#else
#error "unsupported architecture"
#endif
}

static char *elf_map(int fd, Elf64_Ehdr *ehdr, Elf64_Phdr *phdr, long pagesz,
                     char *interp_path, size_t interp_size) {
  Elf64_Addr maxva = 0;
  Elf64_Addr minva = -1;
  for (Elf64_Phdr *p = phdr; p < phdr + ehdr->e_phnum; p++) {
    if (p->p_type != PT_LOAD)
      continue;
    if (p->p_vaddr < minva)
      minva = p->p_vaddr & -pagesz;
    if (p->p_vaddr + p->p_memsz > maxva)
      maxva = p->p_vaddr + p->p_memsz;
  }
  uint8_t *base =
      __sys_mmap(0, maxva - minva, PROT_NONE,
                 __mmap2host(MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE), -1, 0,
                 0);
  if (base == MAP_FAILED)
    return MAP_FAILED;
  for (Elf64_Phdr *p = phdr; p < phdr + ehdr->e_phnum; p++) {
    if (p->p_type != PT_LOAD) {
      if (p->p_type == PT_INTERP && interp_size &&
          (p->p_filesz >= interp_size - 1 ||
           pread(fd, interp_path, p->p_filesz, p->p_offset) != p->p_filesz))
        return MAP_FAILED;
      continue;
    }
    Elf64_Addr skew = p->p_vaddr & (pagesz - 1);
    Elf64_Off off = p->p_offset - skew;
    Elf64_Addr a = p->p_vaddr + p->p_filesz;
    Elf64_Addr b = (a + (pagesz - 1)) & -pagesz;
    Elf64_Addr c = p->p_vaddr + p->p_memsz;
    int prot2 = elf2prot(p->p_flags);
    int prot1 = prot2;
    if (b > a) {
      prot1 |= PROT_WRITE;
      prot1 &= ~PROT_EXEC;
    }
    if (__sys_mmap(base + p->p_vaddr - skew, skew + p->p_filesz, prot1,
                   __mmap2host(MAP_FIXED | MAP_PRIVATE), fd, off,
                   off) == MAP_FAILED)
      return MAP_FAILED;
    if (b > a)
      bzero(base + a, b - a);
    if (c > b && __sys_mmap(base + b, c - b, prot2,
                            __mmap2host(MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS),
                            -1, 0, 0) == MAP_FAILED)
      return MAP_FAILED;
    if (prot1 != prot2 &&
        sys_mprotect(base + p->p_vaddr - skew, skew + p->p_filesz, prot2))
      return MAP_FAILED;
  }
  return (void *)base;
}

static bool elf_slurp(struct Loaded *l, int fd, const char *file) {
  if (pread(fd, &l->eh, 64, 0) != 64)
    return false;
  if (!IsElf64Binary(&l->eh, 64) ||                      //
      l->eh.e_phnum > sizeof(l->ph) / sizeof(*l->ph) ||  //
      l->eh.e_machine != get_host_elf_machine()) {
    enoexec();
    return false;
  }
  int bytes = l->eh.e_phnum * sizeof(l->ph[0]);
  if (pread(fd, l->ph, bytes, l->eh.e_phoff) != bytes)
    return false;
  l->entry = (char *)l->eh.e_entry;
  return true;
}

dontinline static bool elf_load_fd(struct Loaded *l, int fd, const char *file,
                                   long pagesz, char *interp_path,
                                   size_t interp_size) {
  if (!elf_slurp(l, fd, file))
    return false;
  if ((l->base = elf_map(fd, &l->eh, l->ph, pagesz, interp_path,
                         interp_size)) == MAP_FAILED)
    return false;
  l->entry += (uintptr_t)l->base;
  return true;
}

dontinline static bool elf_load(struct Loaded *l, const char *file, long pagesz,
                                char *interp_path, size_t interp_size) {
  int fd;
  bool ok;
  if ((fd = open(file, O_RDONLY | O_CLOEXEC)) == -1)
    return false;
  ok = elf_load_fd(l, fd, file, pagesz, interp_path, interp_size);
  close(fd);
  return ok;
}

static long *push_strs(long *sp, char **list, int count) {
  *--sp = 0;
  while (count)
    *--sp = (long)list[--count];
  return sp;
}

// called by the helper's main(), on a thread whose tls register points
// at the thread block ld.so just made, so it mustn't touch our tls
wontreturn dontinstrument static void foreign_helper(void **p) {
  if ((uintptr_t)p[0] == HELPER_ABI) {
    __foreign.dlopen = p[1];
    __foreign.dlsym = p[2];
    __foreign.dlclose = p[3];
    __foreign.dlerror = p[4];
    __hostlibc.kind = (uintptr_t)p[5];
    if (__hostlibc.kind == HOSTLIBC_GLIBC) {
      __hostlibc.pthread_create = p[6];
      __hostlibc.pthread_attr_init = p[7];
      __hostlibc.pthread_attr_setstack = p[8];
      __hostlibc.pthread_attr_setstacksize = p[9];
      __hostlibc.pthread_attr_setdetachstate = p[10];
      __hostlibc.pthread_attr_destroy = p[11];
      __hostlibc.pthread_key_create = p[12];
      __hostlibc.pthread_setspecific = p[13];
      __hostlibc.pthread_getattr_np = p[14];
      __hostlibc.pthread_attr_getstack = p[15];
      __hostlibc.pthread_self = p[16];
      __hostlibc.pthread_atfork = p[17];
      __hostlibc.errno_location = p[18];
      __hostlibc.fork = p[19];
      __hostlibc.exit = p[20];
      __hostlibc.setenv = p[21];
      __hostlibc.unsetenv = p[22];
      __hostlibc.pthread_exit = __foreign.dlsym(0, "pthread_exit");
      __hostlibc.setlocale = p[23];
      __hostlibc.tzset = p[24];
      __hostlibc.fflush = p[25];
      __hostlibc.setvbuf = p[26];
      __hostlibc.stdout_ = p[27];
      __foreign.hooks = p[28];
    }
  }
  _longjmp(__foreign.jb, 1);
}

// where the helper is mapped, see cosmo_dlsym()
static char *helper_lo, *helper_hi;

dontinline static void elf_exec(int fd, const char *file, char **envp) {

  // get microprocessor page size
  long pagesz = __pagesize;

  // load helper executable into address space
  struct Loaded prog;
  char interp_path[256] = {0};
  if (!elf_load_fd(&prog, fd, file, pagesz, interp_path, sizeof(interp_path)))
    return;
  helper_lo = prog.base;
  helper_hi = prog.base;
  for (int i = 0; i < prog.eh.e_phnum && i < 25; ++i)
    if (prog.ph[i].p_type == PT_LOAD &&
        prog.base + prog.ph[i].p_vaddr + prog.ph[i].p_memsz > helper_hi)
      helper_hi = prog.base + prog.ph[i].p_vaddr + prog.ph[i].p_memsz;

  // load platform c library into address space
  struct Loaded interp;
  if (!elf_load(&interp, interp_path, pagesz, 0, 0))
    return;

  // count environment variables
  int envc = 0;
  while (envp[envc])
    envc++;

  // count auxiliary values
  int auxc = 0;
  Elf64_auxv_t *av;
  for (av = (Elf64_auxv_t *)__auxv; av->a_type; ++av)
    auxc++;

  // create environment block for embedded process
  // the platform libc will save its location for getenv(), etc.
  // we need just enough stack memory beneath it for initialization
  char *map;
  size_t stksize = 65536;
  size_t stkalign = 8 * 2;
  size_t argsize = (1 + 2 + 1 + envc + 1 + auxc * 2 + 1 + 3) * 8;
  size_t mapsize = (stksize + argsize + (pagesz - 1)) & -pagesz;
  size_t skew = (mapsize - argsize) & (stkalign - 1);
  if (IsFreebsd())
    skew += 8;  // FreeBSD calls _start() like a C function
  map = __sys_mmap(0, mapsize, PROT_READ | PROT_WRITE,
                   __mmap2host(MAP_PRIVATE | MAP_ANONYMOUS), -1, 0, 0);
  if (map == MAP_FAILED)
    return;
  long *sp = (long *)(map + mapsize - skew);

  // push argument string
  char *address_argument = (char *)(sp -= 3);
  FormatInt64(address_argument, (uintptr_t)foreign_helper);

  // push auxiliary values
  // these tell the platform libc how to load the executable
  *--sp = 0;
  unsigned long key, val;
  for (av = (Elf64_auxv_t *)__auxv; (key = av->a_type); ++av) {
    val = av->a_un.a_val;
    if (key == AT_PHDR)
      val = (long)(prog.base + prog.eh.e_phoff);
    if (key == AT_PHENT)
      val = prog.eh.e_phentsize;
    if (key == AT_PHNUM)
      val = prog.eh.e_phnum;
    if (key == AT_PAGESZ)
      val = pagesz;
    if (key == AT_BASE)
      val = (long)interp.base;
    if (key == AT_FLAGS)
      val = 0;
    if (key == AT_ENTRY)
      val = (long)prog.entry;
    if (key == AT_EXECFN)
      val = (long)program_invocation_name;
    *--sp = val;
    *--sp = key;
  }

  // push environment variable pointers
  sp = push_strs(sp, envp, envc);
  envp = (char **)sp;

  // push argument pointers
  *--sp = 0;
  *--sp = (long)address_argument;
  *--sp = (long)program_invocation_name;
  char **argv = (char **)sp;
  (void)argv;
  int argc = 2;
  *--sp = argc;

  STRACE("running dlopen importer %p...", interp.entry);

  // XXX: ideally we should set most registers to zero
#ifdef __x86_64__
  struct ps_strings {
    char **argv;
    int argc;
    char **envp;
    int envc;
  } pss = {argv, argc, envp, envc};
  asm volatile("mov\t%2,%%rsp\n\t"
               "jmpq\t*%1"
               : /* no outputs */
               : "D"(IsFreebsd() ? sp : 0), "S"(interp.entry), "d"(sp),
                 "b"(IsNetbsd() ? &pss : 0)
               : "memory");
  __builtin_unreachable();
#elif defined(__aarch64__)
  register long x0 asm("x0") = IsFreebsd() ? (long)sp : 0;
  register long x9 asm("x9") = (long)sp;
  register long x16 asm("x16") = (long)interp.entry;
  asm volatile("mov\tsp,x9\n\t"
               "br\tx16"
               : /* no outputs */
               : "r"(x0), "r"(x9), "r"(x16)
               : "memory");
  __builtin_unreachable();
#else
#error "unsupported architecture"
#endif
}

static _Thread_local bool dlerror_have;

static char *dlerror_set(const char *str) {
  strlcpy(dlerror_buf, str ? str : "unknown error", sizeof(dlerror_buf));
  dlerror_have = true;
  return dlerror_buf;
}

void __dlerror_set(const char *str) {
  dlerror_set(str);
}

// the blocks handed out, so a trampoline of ours can be told apart
static struct {
  _Atomic(size_t) n;
  char *p[256];
} foreign_blocks;

dontinline static char *foreign_alloc_block(void) {
  char *p = 0;
  size_t sz = 65536;
  if (!IsWindows()) {
    p = __sys_mmap(0, sz, PROT_READ | PROT_WRITE | PROT_EXEC,
                   __mmap2host(MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT), -1, 0, 0);
    if (p == MAP_FAILED)
      p = 0;
  } else {
    // a mapping of ours, so fork() copies it: a child that inherits a
    // structure full of thunk pointers needs the thunks there too
    p = mmap(0, sz, PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
      p = 0;
  }
  if (p) {
    WRITE32LE(p, 4);  // store used index
    __nt_unwind_block(p);
    if (foreign_blocks.n < ARRAYLEN(foreign_blocks.p)) {
      foreign_blocks.p[foreign_blocks.n] = p;
      atomic_store_explicit(&foreign_blocks.n, foreign_blocks.n + 1,
                            memory_order_release);
    }
  } else {
    dlerror_set("out of memory");
  }
  return p;
}

static bool in_foreign_code(const void *p) {
  size_t n = atomic_load_explicit(&foreign_blocks.n, memory_order_acquire);
  for (size_t i = 0; i < n; ++i)
    if ((char *)p >= foreign_blocks.p[i] &&
        (char *)p < foreign_blocks.p[i] + 65536)
      return true;
  return false;
}

// eight byte aligned, for the slots of what's copied from templates.S
dontinline static void *foreign_alloc(size_t n) {
  void *res;
  static char *block;
  __dlopen_lock();
  if (!block ||
      ROUNDUP(READ32LE(block), 8) + n > 65536 - __nt_unwind_block_reserve())
    if (!(block = foreign_alloc_block())) {
      __dlopen_unlock();
      return 0;
    }
  res = block + ROUNDUP(READ32LE(block), 8);
  WRITE32LE(block, ROUNDUP(READ32LE(block), 8) + n);
  __dlopen_unlock();
  return res;
}

// executable memory for code made at runtime elsewhere in libc/dlopen
void *__dlopen_code(size_t n) {
  return foreign_alloc(n);
}

static void *foreign_thunk_sysv(void *func) {
  uint8_t *code;
#ifdef __aarch64__
  __jit_begin();
#endif
  if ((code = foreign_alloc(TMPL_SIZE(__tmpl_sysv_thunk)))) {
    TMPL_PUT(code, __tmpl_sysv_thunk, (uintptr_t)func,
             (uintptr_t)foreign_tramp);
#ifdef __aarch64__
    __clear_cache(code, code + TMPL_SIZE(__tmpl_sysv_thunk));
#endif
  }
#ifdef __aarch64__
  __jit_end();
#endif
  return code;
}

// a copy of __sysv2nt14 outside this program, which the thunks below
// make their calls into host code from. a host function that tail-calls
// a thunk leaves it the return address of whoever called that function,
// and a return address in this program would read as a SysV caller
static _Atomic(uint8_t *) foreign_sysv2nt;

static size_t foreign_sysv2nt_size(void) {
#ifdef __x86_64__
  return __sysv2nt_end - (char *)__sysv2nt14;
#else
  return 0;
#endif
}

static uint8_t *foreign_sysv2nt_copy(void) {
  uint8_t *p, *had = 0;
  if ((p = atomic_load_explicit(&foreign_sysv2nt, memory_order_acquire)))
    return p;
  if (!(p = foreign_alloc(foreign_sysv2nt_size())))
    return 0;
#ifdef __x86_64__
  memcpy(p, __sysv2nt14, foreign_sysv2nt_size());
  // the thunk that jumps into it pushed %rbp and made it the frame
  struct UnwFrame f = {.cfa_reg = 6, .cfa_off = 16, .mask = 1 << 6};
  f.saved[6] = -16;
  __dlopen_lock();
  __nt_unwind_describe(p, p + foreign_sysv2nt_size(), &f);
  __dlopen_unlock();
#endif
  if (!atomic_compare_exchange_strong_explicit(&foreign_sysv2nt, &had, p,
                                               memory_order_acq_rel,
                                               memory_order_acquire))
    p = had;
  return p;
}

// the thunk converts from our convention to microsoft's, for callers in
// this program. a caller anywhere else is host code, which got the thunk
// handed back to it as a callback and calls in microsoft's convention
// already, so the thunk jumps straight to the function for it
static void *foreign_thunk_nt(void *func) {
#ifdef __x86_64__
  uint8_t *code, *sysv2nt;
  if (!(sysv2nt = foreign_sysv2nt_copy()))
    return 0;
  if (!(code = foreign_alloc(TMPL_SIZE(__tmpl_nt_thunk))))
    return 0;
  TMPL_PUT(code, __tmpl_nt_thunk, (uintptr_t)__executable_start,
           (uintptr_t)_end, (uintptr_t)func, (uintptr_t)sysv2nt);
  return code;
#else
  return 0;
#endif
}

// a copy of hostcall.S outside this program, which calls made in the
// host's convention from this program go through, see
// cosmo_dlhostcall(); and the stub after it, __hostcall_frame
static _Atomic(uint8_t *) foreign_hostcall;

static size_t foreign_hostcall_size(void) {
#ifdef __x86_64__
  return __hostcall_nt_end - __hostcall_nt16;
#else
  return 0;
#endif
}

static uint8_t *foreign_hostcall_copy(void) {
  uint8_t *p, *had = 0;
  if ((p = atomic_load_explicit(&foreign_hostcall, memory_order_acquire)))
    return p;
#ifdef __x86_64__
  if (!(p = foreign_alloc(__hostcall_frame_end - __hostcall_nt16)))
    return 0;
  memcpy(p, __hostcall_nt16, __hostcall_frame_end - __hostcall_nt16);
  struct UnwFrame f = {.cfa_reg = 6, .cfa_off = 16, .mask = 1 << 6};
  f.saved[6] = -16;
  __dlopen_lock();
  __nt_unwind_describe(p, p + foreign_hostcall_size(), &f);
  __dlopen_unlock();
#endif
  if (!atomic_compare_exchange_strong_explicit(&foreign_hostcall, &had, p,
                                               memory_order_acq_rel,
                                               memory_order_acquire))
    p = had;
  return p;
}

// where the copy is entered for `nslots` stack arguments, at most 16
static uint8_t *foreign_hostcall_entry(uint8_t *copy, int nslots) {
#ifdef __x86_64__
  static char *const entries[] = {
      __hostcall_nt0, __hostcall_nt2,  __hostcall_nt4,  __hostcall_nt6,
      __hostcall_nt8, __hostcall_nt10, __hostcall_nt12, __hostcall_nt14,
      __hostcall_nt16};
  return copy + (entries[(nslots + 1) / 2] - __hostcall_nt16);
#else
  return copy;
#endif
}

// for __hostlink_callregs_nt, which lays the arguments out itself: where
// to enter the copy for its `nslots` stack arguments, and the stub to
// call that makes the frame; both null when it has to call directly
struct HostCallEntry {
  void *entry;
  void *stub;
};

struct HostCallEntry __hostcall_entry(size_t nslots) {
  struct HostCallEntry r = {0, 0};
  uint8_t *copy;
  if (nslots <= 16 && (copy = foreign_hostcall_copy())) {
    r.entry = foreign_hostcall_entry(copy, nslots);
#ifdef __x86_64__
    r.stub = copy + (__hostcall_frame - __hostcall_nt16);
#endif
  }
  return r;
}

#ifdef __x86_64__
static struct {
  pthread_mutex_t lock;
  size_t n, cap;
  struct {
    void *func;
    int nslots;
    void *stub;
  } *p;
} hostcalls = {PTHREAD_MUTEX_INITIALIZER};
#endif

/**
 * Returns what to call `func`, a host function, with the host's own
 * convention from this program.
 *
 * On Windows that's a stub outside this program that makes the call,
 * for `nargs` arguments, or as many as 20 when that's negative. A host
 * function that tail-calls a thunk it was handed back (what dlsym()
 * and cosmo_dltramp() make) leaves it the return address of whoever
 * called that function, and a return address in this program reads as
 * a caller in our convention; made from the stub, the call leaves one
 * outside it. A function of this program, one of more than 20
 * arguments, and anything anywhere else comes back as it is. One stub
 * per function and count, never freed.
 */
void *cosmo_dlhostcall(void *func, int nargs) {
#ifdef __x86_64__
  uint8_t *copy, *code, *stub = 0;
  int nslots;
  if (!func || !IsWindows() || is_ours(func))
    return func;
  nslots = nargs < 0 ? 16 : nargs > 4 ? nargs - 4 : 0;
  if (nslots > 16)
    return func;
  pthread_mutex_lock(&hostcalls.lock);
  for (size_t i = 0; i < hostcalls.n; ++i)
    if (hostcalls.p[i].func == func && hostcalls.p[i].nslots == nslots) {
      stub = hostcalls.p[i].stub;
      break;
    }
  if (!stub && hostcalls.n == hostcalls.cap) {
    size_t cap = hostcalls.cap ? hostcalls.cap * 2 : 16;
    void *q = realloc(hostcalls.p, cap * sizeof(*hostcalls.p));
    if (q) {
      hostcalls.p = q;
      hostcalls.cap = cap;
    }
  }
  if (!stub && hostcalls.n < hostcalls.cap && (copy = foreign_hostcall_copy()) &&
      (code = foreign_alloc(TMPL_SIZE(__tmpl_hostcall_stub)))) {
    TMPL_PUT(code, __tmpl_hostcall_stub, (uintptr_t)func,
             (uintptr_t)foreign_hostcall_entry(copy, nslots));
    hostcalls.p[hostcalls.n].func = func;
    hostcalls.p[hostcalls.n].nslots = nslots;
    hostcalls.p[hostcalls.n].stub = code;
    ++hostcalls.n;
    stub = code;
  }
  pthread_mutex_unlock(&hostcalls.lock);
  return stub ? stub : func;
#else
  return func;
#endif
}

dontinline static bool foreign_compile(char exe[hasatleast PATH_MAX]) {

  // construct path
  strlcpy(exe, get_tmp_dir(), PATH_MAX);
  strlcat(exe, "/.cosmo/", PATH_MAX);
  if (mkdir(exe, 0755) && errno != EEXIST)
    return false;
  strlcat(exe, "dlopen-helper", PATH_MAX);

  // skip build if helper exists and this program is older
  bool helper_exe_exists;
  switch (is_file_newer_than(GetProgramExecutableName(), exe)) {
    case -1:
      return false;
    case 0:
      return true;
    case 1:
      helper_exe_exists = true;
      break;
    case 2:
      helper_exe_exists = false;
      break;
    default:
      __builtin_unreachable();
  }

  // skip build if helper has same source code
  int fd;
  char src[PATH_MAX];
  strlcpy(src, exe, PATH_MAX);
  strlcat(src, ".c", PATH_MAX);
  if (helper_exe_exists) {
    char *sauce;
    if ((sauce = malloc(sizeof(kHelperSource)))) {
      bool same = false;
      if ((fd = open(src, O_RDONLY | O_CLOEXEC)) != -1) {
        ssize_t got = pread(fd, sauce, sizeof(kHelperSource), 0);
        close(fd);
        same = got == sizeof(kHelperSource) - 1 &&
               !memcmp(sauce, kHelperSource, sizeof(kHelperSource) - 1);
      }
      free(sauce);
      if (same)
        return true;
    }
  }

  // create source file
  char tmp[PATH_MAX];
  strlcpy(tmp, src, PATH_MAX);
  strlcat(tmp, ".XXXXXX", PATH_MAX);
  if ((fd = mkostemp(tmp, O_CLOEXEC)) == -1)
    return false;
  if (write(fd, kHelperSource, sizeof(kHelperSource) - 1) != sizeof(kHelperSource) - 1) {
    close(fd);
    unlink(tmp);
    return false;
  }
  if (close(fd)) {
    unlink(tmp);
    return false;
  }
  if (rename(tmp, src)) {
    unlink(tmp);
    return false;
  }

  // create executable
  strlcpy(tmp, exe, PATH_MAX);
  strlcat(tmp, ".XXXXXX", PATH_MAX);
  if ((fd = mkostemp(tmp, O_CLOEXEC)) == -1)
    return false;
  int pid, ws;
  char *args[] = {
      "cc",
      "-pie",
      "-fPIC",
      "-rdynamic",
      src,
      "-o",
      tmp,
      IsLinux() ? "-Wl,-z,execstack" : "-DIGNORE",
      "-pthread",
      IsNetbsd() ? 0 : "-ldl",
      0,
  };
  errno_t err = posix_spawnp(&pid, args[0], NULL, NULL, args, environ);
  if (err) {
    unlink(tmp);
    errno = err;
    return false;
  }
  if (waitpid(pid, &ws, 0) == -1) {
    // signals and cancelation are blocked
    // therefore this must be a real error
    unlink(tmp);
    return false;
  }
  if (ws) {
    unlink(tmp);
    return false;
  }
  if (rename(tmp, exe)) {
    unlink(tmp);
    return false;
  }
  return true;
}

// returns a memfd holding the prebuilt helper that suits this host,
// or -1 if there's none and the host's cc has to build one
static int foreign_prebuilt(const char **out_name) {
#if defined(__x86_64__) || defined(__aarch64__)
  const unsigned char *blob = 0;
  size_t size = 0;
  if (!IsLinux())
    return -1;
#ifdef __x86_64__
  if (!access("/lib64/ld-linux-x86-64.so.2", F_OK)) {
    blob = kHelperGlibc, size = sizeof(kHelperGlibc);
  } else if (!access("/lib/ld-musl-x86_64.so.1", F_OK)) {
    blob = kHelperMusl, size = sizeof(kHelperMusl);
  }
#else
  if (!access("/lib/ld-linux-aarch64.so.1", F_OK))
    blob = kHelperGlibc, size = sizeof(kHelperGlibc);
#endif
  if (!blob)
    return -1;
  int fd;
  if ((fd = memfd_create("dlopen-helper", MFD_CLOEXEC)) == -1)
    return -1;
  if (pwrite(fd, blob, size, 0) != size) {
    close(fd);
    return -1;
  }
  *out_name = "dlopen-helper";
  return fd;
#else
  return -1;
#endif
}

// makes this thread and cosmo's pthreads run with the host's thread
// block from now on, see libc/thread/hostthread.c
static bool foreign_dual(struct CosmoTib *cosmo_tib) {
#if defined(__x86_64__) || defined(__aarch64__)
  if (!IsLinux() || __hostlibc.kind != HOSTLIBC_GLIBC || !__foreign.hooks)
    return false;
  __foreign.hooks->malloc = malloc;
  __foreign.hooks->free = free;
  __foreign.hooks->calloc = calloc;
  __foreign.hooks->realloc = realloc;
  __foreign.hooks->memalign = memalign;
  __foreign.hooks->usable = malloc_usable_size;
  __foreign.hooks->exit = exit;
  __foreign.hooks->setenv = setenv;
  __foreign.hooks->unsetenv = unsetenv;
  __foreign.hooks->putenv = putenv;
  __foreign.hooks->sigaction = __host_sigaction;
  __foreign.hooks->pathmap = __host_pathmap;
  __foreign.hooks->remaps = __host_pathmap_remaps();
  if (__host_threads_init())
    return false;
  __hostlibc.pthread_atfork(__fork_prepare_host, __fork_parent_host,
                            __fork_child_host);
  // ld.so has read the tunables, and the environment the host side
  // hands to children should be the one this process started with
  if (IsLinux() && __hostlibc.kind == HOSTLIBC_GLIBC)
    __host_setenv("GLIBC_TUNABLES",
                  foreign_had_tunables ? foreign_tunables : 0);
  return true;
#else
  return false;
#endif
}

// the environment the host libc starts with. glibc's stack cache would
// hand out thread blocks that still hold a dead thread's tib, see the
// helper's pthread_create(), and glibc's rseq registration would leave
// none for our malloc on the threads it creates
static char **foreign_environ(void) {
  int n;
  char **env;
  const char *old = 0;
  static const char kNoCache[] =
      "glibc.pthread.stack_cache_size=0:glibc.pthread.rseq=0";
  for (n = 0; environ[n]; ++n)
    if (!strncmp(environ[n], "GLIBC_TUNABLES=", 15))
      old = environ[n] + 15;
  foreign_had_tunables = !!old;
  foreign_tunables = old ? strdup(old) : 0;
  if (!(env = calloc(n + 2, sizeof(char *))))
    return environ;
  for (n = 0; environ[n]; ++n)
    env[n] = environ[n];
  char *tun = malloc(15 + (old ? strlen(old) + 1 : 0) + sizeof(kNoCache));
  if (!tun)
    return environ;
  stpcpy(tun, "GLIBC_TUNABLES=");
  if (old) {
    strcat(tun, old);
    strcat(tun, ":");
  }
  strcat(tun, kNoCache);
  for (n = 0; env[n]; ++n)
    if (!strncmp(env[n], "GLIBC_TUNABLES=", 15))
      break;
  env[n] = tun;
  return env;
}

static bool foreign_setup(void) {
  int fd;
  const char *name;
  char exe[PATH_MAX];
  if ((fd = foreign_prebuilt(&name)) == -1) {
    // get path of helper executable
    if (!foreign_compile(exe))
      return false;
    if ((fd = open(exe, O_RDONLY | O_CLOEXEC)) == -1)
      return false;
    name = exe;
  }
  // load helper executable into address space
  struct CosmoTib *cosmo_tib = __get_tls();
  if (!setjmp(__foreign.jb)) {
    elf_exec(fd, name, IsLinux() ? foreign_environ() : environ);
    close(fd);
    return false;  // if elf_exec() returns, it failed
  }
  // our tls register now points at the thread block ld.so set up. read
  // it with raw asm, since __get_tls() is pureconst and gcc would reuse
  // the cosmo_tib it read before elf_exec()
  void *tcb;
#ifdef __x86_64__
  __asm__ volatile("movq\t%%fs:0,%0" : "=r"(tcb));
#else
  tcb = __get_tls_raw();
#endif
  __foreign.tib = tcb;
  if (__hostlibc.kind == HOSTLIBC_GLIBC && IsLinux()) {
    // make our tls work right away, foreign_dual() finishes the job. it
    // goes where the tls getters look, see libc/sysv/tlsasm.S
#ifdef __x86_64__
    ((struct CosmoTib **)tcb)[7] = cosmo_tib;
#else
    ((struct CosmoTib **)tcb)[1] = cosmo_tib;
#endif
    __hostlibc.tcb = tcb;
  } else {
    __set_tls(cosmo_tib);
  }
  close(fd);
  if (!foreign_dual(cosmo_tib)) {
    if (__hostlibc.tcb) {
      __hostlibc.tcb = 0;
      __set_tls(cosmo_tib);
    }
  }
  __foreign.dlopen = foreign_thunk_sysv(__foreign.dlopen);
  __foreign.dlsym = foreign_thunk_sysv(__foreign.dlsym);
  __foreign.dlclose = foreign_thunk_sysv(__foreign.dlclose);
  __foreign.dlerror = foreign_thunk_sysv(__foreign.dlerror);
  if (__hostlibc.dual) {
    // glibc takes the main thread's stack to be the mapping holding
    // __libc_stack_end, which is on the helper's stack until told where
    // the process really started
    void **end = __foreign.dlsym(0, "__libc_stack_end");
    if (end && __oldstack) {
      // it's in ld.so's relro, read-only once relocated
      char *page = (char *)((uintptr_t)end & -getpagesize());
      if (!sys_mprotect(page, getpagesize(), PROT_READ | PROT_WRITE)) {
        *end = (void *)__oldstack;
        sys_mprotect(page, getpagesize(), PROT_READ);
      }
    }
  }
  __foreign.is_supported = true;
  return true;
}

static void foreign_once(void) {
  foreign_setup();
}

static bool foreign_init(void) {
  bool res;
  cosmo_once(&__foreign.once, foreign_once);
  if (!(res = __foreign.is_supported))
    dlerror_set("dlopen() isn't supported on this platform");
  return res;
}

// explains a failed LoadLibrary() the way dlerror() would
static void dlerror_nt(const char *path, const char16_t *path16,
                       uint32_t err) {
  char *p;
  char16_t msg[160];
  const char *why = 0;
  switch (err) {
    case kNtErrorModNotFound:
      // also what a dll whose own dependencies are missing gets
      if ((strchr(path, '/') || strchr(path, '\\')) &&
          GetFileAttributes(path16) != -1u)
        why = "a DLL it depends on wasn't found";
      else
        why = "not found";
      break;
    case kNtErrorBadExeFormat:
      why = "not an x86-64 DLL";
      break;
    case kNtErrorDllInitFailed:
      why = "its DllMain() failed";
      break;
    default:
      break;
  }
  strlcpy(dlerror_buf, path, sizeof(dlerror_buf) - 64);
  p = stpcpy(dlerror_buf + strlen(dlerror_buf), ": ");
  if (why) {
    strlcpy(p, why, dlerror_buf + sizeof(dlerror_buf) - p);
  } else if (FormatMessage(kNtFormatMessageFromSystem |
                               kNtFormatMessageIgnoreInserts,
                           0, err, 0, msg, ARRAYLEN(msg), 0)) {
    tprecode16to8(p, dlerror_buf + sizeof(dlerror_buf) - p, msg);
    while (*p && p[strlen(p) - 1] <= ' ')
      p[strlen(p) - 1] = 0;
  } else {
    strlcpy(p, "LoadLibrary() failed", dlerror_buf + sizeof(dlerror_buf) - p);
  }
  p = dlerror_buf + strlen(dlerror_buf);
  if (p + 24 < dlerror_buf + sizeof(dlerror_buf)) {
    p = stpcpy(p, " (error ");
    p = FormatUint32(p, err);
    stpcpy(p, ")");
  }
  dlerror_have = true;
}

static int dlclose_nt(void *handle) {
  int res;
  if (FreeLibrary((uintptr_t)handle)) {
    res = 0;
  } else {
    dlerror_set("FreeLibrary() failed");
    res = -1;
  }
  return res;
}

// how many directories cosmo_dladddir() has added and not removed
static atomic_int dlopen_nt_userdirs;

// LoadLibraryEx() looking in the directories cosmo_dladddir() added.
// the flags that do that leave PATH out, and with it anything the first
// try found there, such as a vcruntime140.dll that python.exe would have
// had next to it, so PATH's directories are added for the duration too
static int64_t dlopen_nt_userdirs_load(const char16_t *path16) {
  static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
  void *cookies[128];
  char16_t *env, *p, *q;
  uint32_t size, err;
  int64_t handle;
  int n = 0;
  pthread_mutex_lock(&lock);
  if ((size = GetEnvironmentVariable(u"PATH", 0, 0)) &&
      (env = malloc(size * sizeof(char16_t)))) {
    if (GetEnvironmentVariable(u"PATH", env, size) < size) {
      for (p = env; *p && n < ARRAYLEN(cookies); p = q) {
        for (q = p; *q && *q != ';'; ++q) {
        }
        if (*q)
          *q++ = 0;
        if (*p && (cookies[n] = AddDllDirectory(p)))
          ++n;
      }
    }
    free(env);
  }
  handle = LoadLibraryEx(
      path16, 0,
      kNtLoadLibrarySearchDefaultDirs | kNtLoadLibrarySearchDllLoadDir);
  err = GetLastError();
  while (n)
    RemoveDllDirectory(cookies[--n]);
  pthread_mutex_unlock(&lock);
  SetLastError(err);
  return handle;
}

dontinline static void *dlopen_nt(const char *path, int mode) {
  int n;
  int64_t handle;
  bool bare;
  char16_t path16[PATH_MAX + 2];
  // RTLD_GLOBAL and RTLD_DEEPBIND are how windows works anyway: every
  // dll resolves its imports on its own, and GetProcAddress() on one
  // handle never looks anywhere else
  if (mode & ~(RTLD_LOCAL | RTLD_LAZY | RTLD_NOW | RTLD_GLOBAL |
               RTLD_NOLOAD | RTLD_DEEPBIND | RTLD_NODELETE)) {
    dlerror_set("invalid mode");
    return 0;
  }
  if ((bare = !strchr(path, '/') && !strchr(path, '\\'))) {
    // a bare name gets the dll search order, not a path under the cwd
    n = tprecode8to16(path16, PATH_MAX, path).ax;
  } else if ((n = __mkntpath(path, path16)) == -1) {
    dlerror_set("path invalid");
    return 0;
  }
  if (mode & RTLD_NOLOAD) {
    // takes a reference, like dlopen() does, for dlclose() to drop
    if (!GetModuleHandleEx(0, path16, &handle)) {
      dlerror_set("not loaded");
      handle = 0;
    }
  } else {
    // a dll loaded by its path finds the dlls it needs next to it
    handle = LoadLibraryEx(path16, 0,
                           bare ? 0 : kNtLoadWithAlteredSearchPath);
    // then the cosmo_dladddir() directories, if a dependency is missing
    if (!handle && !bare && atomic_load(&dlopen_nt_userdirs) &&
        GetLastError() == kNtErrorModNotFound)
      handle = dlopen_nt_userdirs_load(path16);
    if (!handle)
      dlerror_nt(path, path16, GetLastError());
  }
  if (handle && (mode & RTLD_NODELETE)) {
    int64_t pinned;
    GetModuleHandleEx(kNtGetModuleHandleExFlagPin |
                          kNtGetModuleHandleExFlagFromAddress,
                      (const char16_t *)handle, &pinned);
  }
  return (void *)handle;
}

// the symbol in the module or, as dlsym() on the other hosts would find
// it, in the modules it imports from, breadth first: libavformat gets
// libavcodec's functions too
static void *dlsym_nt_deep(uintptr_t module, const char *name) {
  enum { MAX = 64 };
  uintptr_t seen[MAX];
  size_t n = 0, i = 0;
  seen[n++] = module;
  while (i < n) {
    uintptr_t base = seen[i++];
    void *f = GetProcAddress(base, name);
    if (f)
      return f;
    struct NtImageDosHeader *dos = (void *)base;
    if (dos->e_magic != 0x5a4d)
      continue;
    struct NtImageNtHeaders *nt = (void *)(base + dos->e_lfanew);
    struct NtImageDataDirectory *dir =
        &nt->OptionalHeader.DataDirectory[kNtImageDirectoryEntryImport];
    if (!dir->VirtualAddress || !dir->Size)
      continue;
    struct NtImageImportDescriptor *d = (void *)(base + dir->VirtualAddress);
    for (; d->DllNameRva && n < MAX; ++d) {
      int64_t dep = GetModuleHandle((const char *)(base + d->DllNameRva));
      if (!dep)
        continue;
      bool had = false;
      for (size_t k = 0; k < n && !had; ++k)
        had = seen[k] == (uintptr_t)dep;
      if (!had)
        seen[n++] = dep;
    }
  }
  return 0;
}

static void *dlsym_nt(void *handle, const char *name) {
  void *x64_abi_func;
  if ((x64_abi_func = dlsym_nt_deep((uintptr_t)handle, name))) {
    return __host_env_sym(x64_abi_func);
  } else {
    dlerror_set("symbol not found: ");
    strlcat(dlerror_buf, name, sizeof(dlerror_buf));
    return 0;
  }
}

static void *dlopen_silicon(const char *path, int mode) {
  int xnu_mode = 0;
  if (mode & ~(RTLD_LOCAL | RTLD_LAZY | RTLD_NOW | RTLD_GLOBAL |
               RTLD_NOLOAD | RTLD_DEEPBIND | RTLD_NODELETE))
    xnu_mode = -1;  // punt error to system dlerror() impl
  if (!(mode & RTLD_GLOBAL))
    xnu_mode |= XNU_RTLD_LOCAL;  // unlike Linux, XNU defaults to RTLD_GLOBAL
  if (mode & RTLD_NOW)
    xnu_mode |= XNU_RTLD_NOW;
  if (mode & RTLD_LAZY)
    xnu_mode |= XNU_RTLD_LAZY;
  if (mode & RTLD_NOLOAD)
    xnu_mode |= XNU_RTLD_NOLOAD;
  if (mode & RTLD_NODELETE)
    xnu_mode |= XNU_RTLD_NODELETE;
  // RTLD_DEEPBIND is what XNU's two-level namespace does already
  void *res = __syslib->__dlopen(path, xnu_mode);
  // dyld looks for a bare name in the system's directories and the
  // shared cache, not where homebrew keeps its libraries; a program
  // built there has the full path baked in, so this stands in for it
  if (!res && path && !strchr(path, '/')) {
    static const char *const kDirs[] = {"/opt/homebrew/lib/",
                                        "/usr/local/lib/"};
    char buf[PATH_MAX];
    for (int i = 0; i < ARRAYLEN(kDirs) && !res; ++i) {
      if (strlcpy(buf, kDirs[i], sizeof(buf)) >= sizeof(buf) ||
          strlcat(buf, path, sizeof(buf)) >= sizeof(buf))
        continue;
      if (!access(buf, F_OK))
        res = __syslib->__dlopen(buf, xnu_mode);
    }
  }
  return res;
}

// `libfoo.so` becomes `libfoo.dll` on Windows and `libfoo.dylib` on
// MacOS, unless a file by the name given is there: a python extension
// is `foo.cpython-314-darwin.so` on MacOS and nothing else
static const char *dlopen_hostname(const char *path, char *buf,
                                   size_t size) {
  size_t n = strlen(path);
  const char *ext;
  if (IsWindows())
    ext = "dll";
  else if (IsXnuSilicon())
    ext = "dylib";
  else
    return path;
  if (n > 3 && n + 4 < size && !strcmp(path + n - 3, ".so") &&
      !(strchr(path, '/') && !access(path, F_OK))) {
    memcpy(buf, path, n - 2);
    strcpy(buf + n - 2, ext);
    return buf;
  }
  return path;
}

/**
 * Opens dynamic shared object using host platform libc.
 *
 * If a `path` ending with `.so` is passed on Windows or MacOS, then
 * this wrapper will automatically change it to `.dll` or `.dylib` to
 * increase its chance of successfully loading.
 *
 * WARNING: Our API uses a different naming because cosmo_dlopen() lacks
 * many of the features one would reasonably expect from a UNIX dlopen()
 * implementation; and we don't want to lead ./configure scripts astray.
 * A foreign library can't see symbols defined by your executable unless
 * you export them with cosmo_dlexport() before loading it.
 *
 * Once the host's glibc is up on Linux, every thread is a glibc thread
 * and a cosmo thread at once, so foreign code may call back into yours
 * on any thread, including threads it starts itself. The same goes for
 * Windows and Apple Silicon. On Linux the foreign libraries share our
 * heap, signal table and environment; see libc/thread/hostthread.c.
 *
 * @param mode is a bitmask that can contain:
 *     - `RTLD_LOCAL` (default)
 *     - `RTLD_GLOBAL` (no effect on Windows)
 *     - `RTLD_LAZY`
 *     - `RTLD_NOW`
 *     - `RTLD_NOLOAD`
 *     - `RTLD_NODELETE`
 *     - `RTLD_DEEPBIND` (no effect on Windows and MacOS)
 * @return dso handle, or NULL w/ dlerror()
 * @note this non-standard API is feature gated; you need to pass the
 *     `-mcosmo` flag to `cosmocc` so that `<dlfcn.h>` will define it
 */
void *cosmo_dlopen(const char *path, int mode) {
  if (__dlexport_auto)
    __dlexport_auto();
  void *res;
  // a library this program exported under that name is opened again by
  // what the host knows it as
  const char *exported = 0;
  if (path && !strchr(path, '/') && __dlexport_library &&
      (exported = __dlexport_library(path))) {
    STRACE("cosmo_dlopen(%#s) is the exported %#s", path, exported);
    path = exported;
  }
  BLOCK_SIGNALS;
  BLOCK_CANCELATION;
  // the library's initializers may read the environment already
  if (IsWindows() || IsXnuSilicon()) {
    __host_file_init();
    __host_env_init();
  }
  // what the host knows an exported library as is its name exactly (on
  // macOS the install name, which keeps the .so)
  char renamed[PATH_MAX];
  if (path && !exported)
    path = dlopen_hostname(path, renamed, sizeof(renamed));
  // a library inside the zip store is copied out for the host loader
  char mapped[PATH_MAX];
  const char *m;
  if (path && path[0] == '/' &&
      (m = __host_pathmap(path, mapped, sizeof(mapped))))
    path = m;
  if (IsWindows()) {
    __nt_unwind_init();
    res = dlopen_nt(path, mode);
  } else if (IsXnuSilicon()) {
    res = dlopen_silicon(path, mode);
  } else if (IsXnu()) {
    dlerror_set("dlopen() isn't supported on x86-64 MacOS");
    res = 0;
  } else if (IsOpenbsd()) {
    // TODO(jart): implement workaround for msyscall() dilemma
    dlerror_set("dlopen() isn't supported on OpenBSD yet");
    res = 0;
  } else if (foreign_init()) {
    res = __foreign.dlopen(path, mode);
  } else {
    res = 0;
  }
  if (res) {
    __hostlibc.loaded = true;
    // the library may start threads that run our code, and a thread is
    // adopted too late for a lock the owner already skipped taking
    if (__isthreaded < 2)
      __isthreaded = 2;
    // the notifications may come before the C runtime can be found
    if (IsWindows())
      __host_crt_patch_all();
    else
      __host_frames_register(host_find);
    if (mode & RTLD_GLOBAL)
      dlglobal_add(res, path);
  }
  ALLOW_CANCELATION;
  ALLOW_SIGNALS;
  STRACE("cosmo_dlopen(%#s, %d) → %p% m", path, mode, res);
  return res;
}

/**
 * Obtains address of symbol from dynamic shared object.
 *
 * WARNING: You almost always want to say this:
 *
 *     pFunction = cosmo_dltramp(cosmo_dlsym(dso, "function"));
 *
 * That will generate code at runtime for automatically translating to
 * Microsoft's x64 calling convention when appropriate. However the
 * automated solution doesn't always work. For example, the prototype:
 *
 *     void func(int, float);
 *
 * Won't be translated correctly, due to the differences in ABI. We're
 * able to smooth over most of them, but that's just one of several
 * examples where we can't. A good rule of thumb is:
 *
 *   - More than four float/double args is problematic
 *   - Having both integral and floating point parameters is bad
 *
 * For those kinds of functions, you need to translate the ABI by hand.
 * This can be accomplished using the GCC `__ms_abi__` attribute, where
 * you'd have two function pointer types branched upon `IsWindows()`.
 *
 * @param handle was opened by dlopen()
 * @return address of symbol, or NULL w/ dlerror()
 */
void *cosmo_dlsym(void *handle, const char *name) {
  void *func;
  if (IsWindows()) {
    func = dlsym_nt(handle, name);
  } else if (IsXnuSilicon()) {
    func = __syslib->__dlsym(handle, name);
  } else if (IsXnu()) {
    dlerror_set("dlopen() isn't supported on x86-64 MacOS");
    func = 0;
  } else if (foreign_init()) {
    func = __foreign.dlsym(handle, name);
    // looked up in libc by handle, malloc() or setenv() would be glibc's
    // own, which the helper replaces for everything else in the process
    if (func && handle) {
      char *g = __foreign.dlsym(0, name);
      if (g && g != func && g >= helper_lo && g < helper_hi)
        func = g;
    }
  } else {
    func = 0;
  }
  STRACE("cosmo_dlsym(%p, %#s) → %p", handle, name, func);
  return func;
}

/**
 * Returns the host function behind a trampoline dlsym() or
 * cosmo_dltramp() made, and anything else as it is. dladdr() uses it,
 * so a program asking which library a function it looked up came from
 * gets an answer.
 */
void *cosmo_dluntramp(void *p) {
  if (!p || !in_foreign_code(p))
    return p;
  if (TMPL_IS(p, __tmpl_sysv_thunk, 2) &&
      TMPL_SLOT(p, __tmpl_sysv_thunk, 2, 1) == (uintptr_t)foreign_tramp)
    return (void *)TMPL_SLOT(p, __tmpl_sysv_thunk, 2, 0);
#ifdef __x86_64__
  if (TMPL_IS(p, __tmpl_nt_thunk, 4) &&
      TMPL_SLOT(p, __tmpl_nt_thunk, 4, 0) == (uintptr_t)__executable_start &&
      TMPL_SLOT(p, __tmpl_nt_thunk, 4, 1) == (uintptr_t)_end)
    return (void *)TMPL_SLOT(p, __tmpl_nt_thunk, 4, 2);
  // what cosmo_dlhostcall() made
  if (TMPL_IS(p, __tmpl_hostcall_stub, 2))
    return (void *)TMPL_SLOT(p, __tmpl_hostcall_stub, 2, 0);
#endif
  return p;
}

// a symbol of a host library that's loaded, for hostframe.c
static void *host_find(const char *lib, const char *sym) {
  void *h, *p;
  if (IsXnuSilicon())
    return __syslib->__dlsym((void *)-2, sym);
  if (!__foreign.is_supported || !lib)
    return 0;
  if (!(h = __foreign.dlopen(lib, RTLD_LAZY | RTLD_NOLOAD)))
    return 0;
  p = __foreign.dlsym(h, sym);
  __foreign.dlclose(h);
  return p;
}

/**
 * Trampolines foreign function pointer so it can be called safely.
 */
void *cosmo_dltramp(void *foreign_func) {
  if (!IsWindows()) {
    return foreign_thunk_sysv(foreign_func);
  } else {
    return foreign_thunk_nt(foreign_func);
  }
}

// one thunk per function, so a program that keeps calling host code
// through a table doesn't make a new one every time, and so two of the
// same function pointer come back as the same thunk. these are looked
// up on every call an interpreter makes through a plugin's pointers, so
// a lookup takes no lock: a table is only ever added to, and a bigger
// one replaces it whole
struct ThunkMap {
  size_t mask, n;
  struct {
    _Atomic(uintptr_t) key;
    uintptr_t val;
  } e[];
};

static struct {
  pthread_mutex_t lock;
  _Atomic(struct ThunkMap *) call;  // cosmo_dlthunk() answers
  _Atomic(struct ThunkMap *) dual;  // cosmo_dldual() answers
} dlthunks = {PTHREAD_MUTEX_INITIALIZER};

static size_t thunkmap_hash(uintptr_t key, size_t mask) {
  return ((key >> 4) * 0x9e3779b97f4a7c15ull >> 17) & mask;
}

static uintptr_t thunkmap_get(_Atomic(struct ThunkMap *) *map, uintptr_t key) {
  struct ThunkMap *m;
  uintptr_t k;
  if (!(m = atomic_load_explicit(map, memory_order_acquire)))
    return 0;
  for (size_t i = thunkmap_hash(key, m->mask);; i = (i + 1) & m->mask) {
    k = atomic_load_explicit(&m->e[i].key, memory_order_acquire);
    if (k == key)
      return m->e[i].val;
    if (!k)
      return 0;
  }
}

static void thunkmap_put_one(struct ThunkMap *m, uintptr_t key,
                             uintptr_t val) {
  size_t i = thunkmap_hash(key, m->mask);
  while (atomic_load_explicit(&m->e[i].key, memory_order_relaxed))
    i = (i + 1) & m->mask;
  m->e[i].val = val;
  atomic_store_explicit(&m->e[i].key, key, memory_order_release);
}

// called with dlthunks.lock held. keeps each table under half full
static bool thunkmap_put(_Atomic(struct ThunkMap *) *map, uintptr_t key,
                         uintptr_t val) {
  struct ThunkMap *m, *m2;
  m = atomic_load_explicit(map, memory_order_relaxed);
  if (!m || (m->n + 1) * 2 > m->mask + 1) {
    size_t cap = m ? (m->mask + 1) * 2 : 256;
    if (!(m2 = calloc(1, sizeof(*m2) + cap * sizeof(m2->e[0]))))
      return false;
    m2->mask = cap - 1;
    m2->n = m ? m->n : 0;
    if (m)
      for (size_t i = 0; i <= m->mask; ++i)
        if (m->e[i].key)
          thunkmap_put_one(m2, m->e[i].key, m->e[i].val);
    // readers still on the old table find what it had, so it stays
    atomic_store_explicit(map, m2, memory_order_release);
    m = m2;
  }
  thunkmap_put_one(m, key, val);
  ++m->n;
  return true;
}

static bool is_ours(void *func) {
  return (uintptr_t)func >= (uintptr_t)__executable_start &&
         (uintptr_t)func < (uintptr_t)_end;
}

// a function of ours that host code may call as well, which it does
// when a plugin reaches into a structure of ours and calls what it
// finds there. the caller's convention is read off its return address:
// inside this program it is ours, anywhere else it is the host's
#ifdef __x86_64__
// the host side of a dual thunk is __tmpl_ms2sysv's code
static const struct UnwFrame kDualThunkFrame = MS2SYSV_FRAME;
#endif

static void *dual_thunk(void *func) {
#ifdef __x86_64__
  uint8_t *code;
  if (!(code = foreign_alloc(TMPL_SIZE(__tmpl_dual_thunk))))
    return 0;
  TMPL_PUT(code, __tmpl_dual_thunk, (uintptr_t)__executable_start,
           (uintptr_t)_end, (uintptr_t)func);
  __dlopen_lock();
  __nt_unwind_describe(code, code + TMPL_SIZE(__tmpl_dual_thunk),
                       &kDualThunkFrame);
  __dlopen_unlock();
  return code;
#else
  return func;
#endif
}

/**
 * Makes a function pointer callable in both conventions.
 *
 * A plugin that reaches into a structure of this program and calls a
 * function it finds there needs that pointer to work in the host's
 * calling convention, while this program keeps calling it in its own.
 * For a function of ours the pointer this returns does both, decided
 * per call by the caller's return address. For a host function it's
 * the cosmo_dlthunk() one, which decides the same way. It is made once
 * per function, and a pointer this returned comes back unchanged.
 *
 * @return callable pointer, or `func` when nothing needs doing
 */
void *cosmo_dldual(void *func) {
  uintptr_t res;
  if (!func || !IsWindows())
    return func;
  if ((res = thunkmap_get(&dlthunks.dual, (uintptr_t)func)))
    return (void *)res;
  if (!is_ours(func))
    return cosmo_dlthunk(func);
  pthread_mutex_lock(&dlthunks.lock);
  if (!(res = thunkmap_get(&dlthunks.dual, (uintptr_t)func))) {
    if (!(res = (uintptr_t)dual_thunk(func)) ||
        !thunkmap_put(&dlthunks.dual, (uintptr_t)func, res) ||
        !thunkmap_put(&dlthunks.dual, res, res) ||
        !thunkmap_put(&dlthunks.call, res, (uintptr_t)func)) {
      kprintf("cosmo_dldual: out of thunk memory for %p, host calls to it "
              "will be wrong\n", func);
      res = (uintptr_t)func;
    }
  }
  pthread_mutex_unlock(&dlthunks.lock);
  return (void *)res;
}

/**
 * Trampolines a host function pointer, once per pointer.
 *
 * This is cosmo_dltramp() with the answer remembered, for call sites
 * that reach host code over and over, such as an interpreter calling
 * the functions a plugin gave it. A pointer into this program comes
 * back unchanged, a cosmo_dldual() pointer comes back as the function
 * of ours it wraps, and so does everything on hosts whose convention is
 * already ours.
 *
 * @return callable pointer, or null if one couldn't be made
 */
void *cosmo_dlthunk(void *func) {
  uintptr_t res;
  if (!func)
    return 0;
  if (!IsWindows() || is_ours(func))
    return func;
  if ((res = thunkmap_get(&dlthunks.call, (uintptr_t)func)))
    return (void *)res;
  pthread_mutex_lock(&dlthunks.lock);
  if (!(res = thunkmap_get(&dlthunks.call, (uintptr_t)func))) {
    // the thunk jumps straight through for host callers, so it is also
    // the answer cosmo_dldual() gives for this function
    if ((res = (uintptr_t)cosmo_dltramp(func))) {
      thunkmap_put(&dlthunks.call, (uintptr_t)func, res);
      thunkmap_put(&dlthunks.call, res, res);
      thunkmap_put(&dlthunks.dual, (uintptr_t)func, res);
      thunkmap_put(&dlthunks.dual, res, res);
    } else {
      res = (uintptr_t)func;
    }
  }
  pthread_mutex_unlock(&dlthunks.lock);
  return (void *)res;
}

/**
 * Returns whether calling `func` takes the host's convention.
 *
 * That's Microsoft's x64 one on Windows, for a function in a host
 * library, a callback made for one, or what cosmo_dlsym() gives for a
 * function this library hooks. Any other function of this program, a
 * cosmo_dldual() pointer and the trampolines cosmo_dlthunk() and
 * dlsym() hand out take ours, and so does everything anywhere else.
 * For code that picks the convention per call, like libffi's users.
 */
int cosmo_dlhost(const void *func) {
  uintptr_t v;
  if (!IsWindows() || !func)
    return false;
  // what cosmo_dlsym() hands out for the functions we hook is ours, but
  // written in the host's convention
  if (is_ours((void *)func))
    return __host_env_hook(func) || __host_crt_hook(func) ||
           (__dlexport_native && __dlexport_native(func));
  if ((v = thunkmap_get(&dlthunks.call, (uintptr_t)func)) &&
      (v == (uintptr_t)func || is_ours((void *)v)))
    return false;
  return true;
}

/**
 * Closes dynamic shared object.
 *
 * @param handle was opened by dlopen()
 * @return 0 on success, or -1 w/ dlerror()
 */
int cosmo_dlclose(void *handle) {
  int res;
  dlglobal_remove(handle);
  if (IsWindows()) {
    res = dlclose_nt(handle);
  } else if (IsXnuSilicon()) {
    res = __syslib->__dlclose(handle);
  } else if (IsXnu()) {
    dlerror_set("dlopen() isn't supported on x86-64 MacOS");
    res = -1;
  } else if (foreign_init()) {
    res = __foreign.dlclose(handle);
  } else {
    res = -1;
  }
  STRACE("cosmo_dlclose(%p) → %d", handle, res);
  return res;
}

/**
 * Returns string describing last dlopen/dlsym/dlclose error.
 */
char *cosmo_dlerror(void) {
  char *res;
  if (dlerror_have) {
    // an error of our own, which reads once like the host's
    dlerror_have = false;
    res = dlerror_buf;
  } else if (IsXnuSilicon()) {
    res = __syslib->__dlerror();
  } else if (IsWindows() || IsXnu()) {
    res = 0;
  } else if (foreign_init()) {
    if ((res = __foreign.dlerror())) {
      res = dlerror_set(res);
      dlerror_have = false;
    }
  } else if (dlerror_have) {
    dlerror_have = false;
    res = dlerror_buf;
  } else {
    res = 0;
  }
  STRACE("cosmo_dlerror() → %#s", res);
  return res;
}

// whether addr lies in an executable segment of the image at base
static int dlsym_elf_code(const char *base, uintptr_t addr) {
  const Elf64_Ehdr *eh = (const Elf64_Ehdr *)base;
  const Elf64_Phdr *ph = (const Elf64_Phdr *)(base + eh->e_phoff);
  uintptr_t bias = (uintptr_t)base;
  for (int i = 0; i < eh->e_phnum; ++i)
    if (ph[i].p_type == PT_LOAD && !ph[i].p_offset) {
      bias -= ph[i].p_vaddr & -4096ul;
      break;
    }
  for (int i = 0; i < eh->e_phnum; ++i)
    if (ph[i].p_type == PT_LOAD && addr >= bias + ph[i].p_vaddr &&
        addr < bias + ph[i].p_vaddr + ph[i].p_memsz)
      return !!(ph[i].p_flags & PF_X);
  return -1;
}

static int dlsym_macho_code(const char *base, uintptr_t addr) {
  uint32_t ncmds = READ32LE(base + 16);
  const char *lc = base + 32;
  uintptr_t slide = 0;
  for (int pass = 0; pass < 2; ++pass) {
    const char *p = lc;
    for (uint32_t i = 0; i < ncmds; ++i, p += READ32LE(p + 4)) {
      if (READ32LE(p) != 0x19)  // LC_SEGMENT_64
        continue;
      uint64_t vmaddr = READ64LE(p + 24), vmsize = READ64LE(p + 32);
      if (!pass) {
        if (!READ64LE(p + 40) && READ64LE(p + 48)) {  // __TEXT
          slide = (uintptr_t)base - vmaddr;
          break;
        }
      } else if (addr >= slide + vmaddr && addr < slide + vmaddr + vmsize) {
        return !!(READ32LE(p + 60) & 4);  // initprot & VM_PROT_EXECUTE
      }
    }
  }
  return -1;
}

// the host's own dladdr(), ready to call
static int (*dlsym_host_dladdr(void))(const void *, Dl_info *) {
  static int (*host_dladdr)(const void *, Dl_info *);
  if (!host_dladdr) {
    if (IsXnuSilicon()) {
      host_dladdr = __syslib->__dlsym((void *)-2, "dladdr");
    } else if (foreign_init()) {
      void *f = __foreign.dlsym(IsLinux() ? 0 : (void *)-2, "dladdr");
      if (f)
        host_dladdr = foreign_thunk_sysv(f);
    }
  }
  return host_dladdr;
}

// 1 if addr is code, 0 if data, -1 if it can't be told
static int dlsym_is_code(void *addr) {
  if (IsWindows()) {
    struct NtMemoryBasicInformation mbi;
    if (!VirtualQuery(addr, &mbi, sizeof(mbi)))
      return -1;
    return !!(mbi.Protect & (kNtPageExecute | kNtPageExecuteRead |
                             kNtPageExecuteReadwrite | kNtPageExecuteWritecopy));
  }
  int (*host_dladdr)(const void *, Dl_info *);
  if (!(host_dladdr = dlsym_host_dladdr()))
    return -1;
  Dl_info info;
  if (!host_dladdr(addr, &info) || !info.dli_fbase)
    return -1;
  if (IsXnu())
    return dlsym_macho_code(info.dli_fbase, (uintptr_t)addr);
  return dlsym_elf_code(info.dli_fbase, (uintptr_t)addr);
}

// functions dlsym() has handed out, and their trampolines
static struct {
  size_t n, cap;
  uintptr_t *keys, *vals;
} dlsym_tramps;

static void *dlsym_tramp(void *func) {
  uintptr_t k = (uintptr_t)func, t = 0;
  __dlopen_lock();
  if (dlsym_tramps.cap) {
    for (size_t i = (k >> 4) & (dlsym_tramps.cap - 1);;
         i = (i + 1) & (dlsym_tramps.cap - 1)) {
      if (dlsym_tramps.keys[i] == k) {
        t = dlsym_tramps.vals[i];
        break;
      }
      if (!dlsym_tramps.keys[i])
        break;
    }
  }
  __dlopen_unlock();
  if (t)
    return (void *)t;
  if (!(t = (uintptr_t)cosmo_dltramp(func)))
    return 0;
  __dlopen_lock();
  if ((dlsym_tramps.n + 1) * 2 > dlsym_tramps.cap) {
    size_t cap = dlsym_tramps.cap ? dlsym_tramps.cap * 2 : 256;
    uintptr_t *keys = calloc(cap, sizeof(*keys));
    uintptr_t *vals = calloc(cap, sizeof(*vals));
    if (!keys || !vals) {
      free(keys);
      free(vals);
      __dlopen_unlock();
      return (void *)t;
    }
    for (size_t j = 0; j < dlsym_tramps.cap; ++j) {
      uintptr_t key = dlsym_tramps.keys[j];
      if (!key)
        continue;
      size_t i = (key >> 4) & (cap - 1);
      while (keys[i])
        i = (i + 1) & (cap - 1);
      keys[i] = key;
      vals[i] = dlsym_tramps.vals[j];
    }
    free(dlsym_tramps.keys);
    free(dlsym_tramps.vals);
    dlsym_tramps.keys = keys;
    dlsym_tramps.vals = vals;
    dlsym_tramps.cap = cap;
  }
  size_t i = (k >> 4) & (dlsym_tramps.cap - 1);
  while (dlsym_tramps.keys[i] && dlsym_tramps.keys[i] != k)
    i = (i + 1) & (dlsym_tramps.cap - 1);
  if (!dlsym_tramps.keys[i]) {
    dlsym_tramps.keys[i] = k;
    dlsym_tramps.vals[i] = t;
    ++dlsym_tramps.n;
  } else {
    t = dlsym_tramps.vals[i];
  }
  __dlopen_unlock();
  // cosmo_dlhost() tells it apart from host code by this
  if (IsWindows()) {
    pthread_mutex_lock(&dlthunks.lock);
    thunkmap_put(&dlthunks.call, t, t);
    pthread_mutex_unlock(&dlthunks.lock);
  }
  return (void *)t;
}

// what dlsym() hands out for a host function or variable
static void *dlsym_wrap(void *p) {
  if (dlsym_is_code(p))
    p = dlsym_tramp(p);
  return p;
}

// libraries opened with RTLD_GLOBAL, in the order they were opened, for
// dlsym(RTLD_DEFAULT) to look through. `search` is the handle to look
// up by: on MacOS one opened with RTLD_FIRST, since a lookup through
// the library's own handle also searches the libraries it depends on
struct DlGlobal {
  void *handle;
  void *search;
};

static struct {
  size_t n, cap;
  struct DlGlobal *p;
} dlglobal;

static void dlglobal_add(void *handle, const char *path) {
  void *search = handle;
  if (IsXnuSilicon()) {
    // takes a reference of its own, dropped in dlglobal_remove()
    if (!(search = __syslib->__dlopen(
              path, XNU_RTLD_NOLOAD | XNU_RTLD_FIRST | XNU_RTLD_NOW)))
      return;
  }
  __dlopen_lock();
  if (dlglobal.n == dlglobal.cap) {
    size_t cap = dlglobal.cap ? dlglobal.cap * 2 : 8;
    struct DlGlobal *p = realloc(dlglobal.p, cap * sizeof(*p));
    if (!p) {
      __dlopen_unlock();
      if (search != handle)
        __syslib->__dlclose(search);
      return;
    }
    dlglobal.p = p;
    dlglobal.cap = cap;
  }
  dlglobal.p[dlglobal.n++] = (struct DlGlobal){handle, search};
  __dlopen_unlock();
}

// forgets one opening of handle, the latest
static void dlglobal_remove(void *handle) {
  void *search = 0;
  __dlopen_lock();
  for (size_t i = dlglobal.n; i--;) {
    if (dlglobal.p[i].handle == handle) {
      search = dlglobal.p[i].search;
      memmove(dlglobal.p + i, dlglobal.p + i + 1,
              (--dlglobal.n - i) * sizeof(*dlglobal.p));
      break;
    }
  }
  __dlopen_unlock();
  if (search && search != handle)
    __syslib->__dlclose(search);
}

/**
 * Keeps dlsym(RTLD_DEFAULT) out of a library cosmo_dlopen() loaded with
 * RTLD_GLOBAL, as cosmo_dlexport() does with its forwarding libraries.
 */
void __dlglobal_forget(void *handle) {
  dlglobal_remove(handle);
}

// whether sym was found in the library itself, rather than in one it
// depends on. glibc's and musl's handles start with the base address
// and then the path, which is what dladdr() gives as dli_fname
static bool dlglobal_owns(void *handle, void *sym) {
  if (!IsLinux())
    return true;
  Dl_info info;
  int (*host_dladdr)(const void *, Dl_info *);
  const char *name = ((const char **)handle)[1];
  if (!(host_dladdr = dlsym_host_dladdr()))
    return false;
  return host_dladdr(sym, &info) && info.dli_fname && name &&
         !strcmp(info.dli_fname, name);
}

/**
 * Implements dlsym() for `RTLD_DEFAULT`, `RTLD_NEXT` and dlopen(NULL).
 *
 * This program comes first, with the functions cosmo_dlexport() made
 * known, and then each library opened with `RTLD_GLOBAL`, in the order
 * they were opened. A library only answers for its own symbols, not for
 * those of the libraries it depends on, so the host libc is never where
 * a name is found. `RTLD_NEXT` skips this program.
 */
void *__dlsym_global(const char *name, bool next) {
  void *p;
  if (!next && __dlexport_find && (p = __dlexport_find(name)))
    return p;
  for (size_t i = 0;; ++i) {
    struct DlGlobal g;
    __dlopen_lock();
    if (i >= dlglobal.n) {
      __dlopen_unlock();
      break;
    }
    g = dlglobal.p[i];
    __dlopen_unlock();
    if ((p = cosmo_dlsym(g.search, name)) && dlglobal_owns(g.handle, p)) {
      dlerror_have = false;
      return dlsym_wrap(p);
    }
  }
  dlerror_set("symbol not found: ");
  strlcat(dlerror_buf, name, sizeof(dlerror_buf));
  return 0;
}

struct DlPhdrWalk {
  int (*callback)(struct dl_phdr_info *, size_t, void *);
  void *data;
};

static int dl_iterate_phdr_one(struct dl_phdr_info *info, size_t size,
                               void *arg) {
  struct DlPhdrWalk *w = arg;
  // the helper is the host loader's main program, and has no name
  if (!info->dlpi_name || !*info->dlpi_name)
    return 0;
  return w->callback(info, size, w->data);
}

/**
 * Walks the objects the host's loader has mapped, for dl_iterate_phdr(),
 * so that an unwinder finds the frame tables of host libraries.
 */
int __dl_iterate_phdr_host(int (*callback)(struct dl_phdr_info *, size_t,
                                           void *),
                           void *data) {
  static int (*host)(void *, void *);
  if (!IsLinux() || !__hostlibc.dual || !__hostlibc.loaded)
    return 0;
  if (!host) {
    void *f;
    if (!(f = __foreign.dlsym(0, "dl_iterate_phdr")) ||
        !(host = foreign_thunk_sysv(f)))
      return 0;
  }
  struct DlPhdrWalk w = {callback, data};
  return host(dl_iterate_phdr_one, &w);
}

struct DlEhFrame {
  uintptr_t pc, base, hdr;
  size_t hdrlen;
};

static int dl_find_eh_frame(struct dl_phdr_info *info, size_t size,
                            void *arg) {
  struct DlEhFrame *f = arg;
  bool inside = false;
  for (int i = 0; i < info->dlpi_phnum && !inside; ++i) {
    const Elf64_Phdr *ph = info->dlpi_phdr + i;
    uintptr_t lo = info->dlpi_addr + ph->p_vaddr;
    if (ph->p_type == PT_LOAD && f->pc >= lo && f->pc < lo + ph->p_memsz) {
      inside = true;
      f->base = lo;
    }
  }
  if (!inside)
    return 0;
  for (int i = 0; i < info->dlpi_phnum; ++i) {
    const Elf64_Phdr *ph = info->dlpi_phdr + i;
    if (ph->p_type == PT_GNU_EH_FRAME) {
      f->hdr = info->dlpi_addr + ph->p_vaddr;
      f->hdrlen = ph->p_memsz;
    }
  }
  return 1;
}

/**
 * Finds the frame table of the host library holding `pc`, for the
 * unwinder, see third_party/libunwind/AddressSpace.hpp.
 *
 * @return 1 if found, -1 if `pc` is outside this program and no host
 *     library has a table for it, or 0 if it's this program's own code
 */
int __unw_find_host_eh_frame(uintptr_t pc, uintptr_t *base, uintptr_t *hdr,
                             size_t *hdrlen) {
  if (pc >= (uintptr_t)__executable_start && pc < (uintptr_t)_end)
    return 0;
  if (!IsLinux() || !__hostlibc.dual || !__hostlibc.loaded)
    return 0;
  struct DlEhFrame f = {pc};
  if (__dl_iterate_phdr_host(dl_find_eh_frame, &f) <= 0 || !f.hdr)
    return -1;
  *base = f.base;
  *hdr = f.hdr;
  *hdrlen = f.hdrlen;
  return 1;
}

/**
 * Steps the unwinder through a frame of a host library it has no table
 * for, see third_party/libunwind/UnwindCursor.hpp. `r` holds registers
 * in the unwinder's numbering, rax rdx rcx rbx rsi rdi rbp rsp r8-r15
 * rip on x86-64 and x0-x30 sp pc on arm64.
 *
 * On Windows the frame is unwound by the system, from the table every
 * x64 module carries. On MacOS it's the frame pointer chain, which the
 * platform's arm64 abi guarantees, so only fp, lr, sp and pc come out
 * right. Linux needs none of this, since the host libraries' tables are
 * found through dl_iterate_phdr().
 *
 * @param step is false to only ask whether this is a host frame
 * @return 1 if it is, and was stepped through if asked, otherwise 0
 */
int __unw_step_host(uint64_t *r, int step) {
#ifdef __x86_64__
  typedef void *__msabi (*lookup_f)(uint64_t, uint64_t *, void *);
  typedef void *__msabi (*unwind_f)(uint32_t, uint64_t, uint64_t, void *,
                                    void *, void **, uint64_t *, void *);
  static lookup_f lookup;
  static unwind_f unwind;
  int64_t mod;
  uint64_t pc = r[16];
  if (!IsWindows() || !pc)
    return 0;
  if (pc >= (uintptr_t)__executable_start && pc < (uintptr_t)_end)
    return 0;
  uint8_t *sysv2nt = atomic_load_explicit(&foreign_sysv2nt, memory_order_acquire);
  uint8_t *hostcall = atomic_load_explicit(&foreign_hostcall, memory_order_acquire);
  if ((sysv2nt && pc >= (uintptr_t)sysv2nt &&
       pc < (uintptr_t)sysv2nt + foreign_sysv2nt_size()) ||
      (hostcall && pc >= (uintptr_t)hostcall &&
       pc < (uintptr_t)hostcall + foreign_hostcall_size())) {
    // the copy of __sysv2nt14 or of hostcall.S, in the frame the thunk
    // or stub made with push %rbp
    if (step) {
      uint64_t *fp = (uint64_t *)r[6];
      r[16] = fp[1];
      r[7] = (uint64_t)(fp + 2);
      r[6] = fp[0];
    }
    return 1;
  }
  if (!GetModuleHandleEx(kNtGetModuleHandleExFlagFromAddress |
                             kNtGetModuleHandleExFlagUnchangedRefcount,
                         (const char16_t *)pc, &mod))
    return 0;
  if (!step)
    return 1;
  if (!lookup) {
    int64_t k32 = GetModuleHandleW(u"kernel32.dll");
    unwind = (unwind_f)GetProcAddress(k32, "RtlVirtualUnwind");
    lookup = (lookup_f)GetProcAddress(k32, "RtlLookupFunctionEntry");
    if (!unwind || !lookup)
      return 0;
  }
  _Alignas(16) struct NtContext c = {0};
  c.Rax = r[0], c.Rdx = r[1], c.Rcx = r[2], c.Rbx = r[3];
  c.Rsi = r[4], c.Rdi = r[5], c.Rbp = r[6], c.Rsp = r[7];
  c.R8 = r[8], c.R9 = r[9], c.R10 = r[10], c.R11 = r[11];
  c.R12 = r[12], c.R13 = r[13], c.R14 = r[14], c.R15 = r[15];
  c.Rip = pc;
  uint64_t base, frame;
  void *entry, *data;
  if ((entry = lookup(pc, &base, 0))) {
    unwind(0, base, pc, entry, &c, &data, &frame, 0);
  } else {
    // a leaf function, which has no entry and leaves rsp alone
    c.Rip = *(uint64_t *)c.Rsp;
    c.Rsp += 8;
  }
  r[0] = c.Rax, r[1] = c.Rdx, r[2] = c.Rcx, r[3] = c.Rbx;
  r[4] = c.Rsi, r[5] = c.Rdi, r[6] = c.Rbp, r[7] = c.Rsp;
  r[8] = c.R8, r[9] = c.R9, r[10] = c.R10, r[11] = c.R11;
  r[12] = c.R12, r[13] = c.R13, r[14] = c.R14, r[15] = c.R15;
  r[16] = c.Rip;
  return 1;
#elif defined(__aarch64__)
  static int (*host_dladdr)(const void *, Dl_info *);
  Dl_info info;
  uint64_t pc = r[32] & 0x00007fffffffffff;  // pointer auth bits off
  if (!IsXnuSilicon() || !pc)
    return 0;
  if (pc >= (uintptr_t)__executable_start && pc < (uintptr_t)_end)
    return 0;
  if (!host_dladdr &&
      !(host_dladdr = __syslib->__dlsym((void *)-2, "dladdr")))
    return 0;
  if (!host_dladdr((void *)pc, &info))
    return 0;
  if (!step)
    return 1;
  // a frame record is the caller's fp then the return address, and the
  // caller's sp is just above it. records only go up the stack
  uint64_t fp = r[29], sp = r[31];
  if (!fp || (fp & 7) || fp < sp || fp - sp > 0x1000000)
    return 0;
  uint64_t next = ((uint64_t *)fp)[0];
  if (next && next <= fp)
    return 0;
  r[32] = ((uint64_t *)fp)[1] & 0x00007fffffffffff;
  r[30] = r[32];
  r[29] = next;
  r[31] = fp + 16;
  return 1;
#else
  return 0;
#endif
}

/**
 * Answers dladdr() for an address in a host library, once one has been
 * loaded on Linux.
 */
int __dladdr_host(const void *addr, Dl_info *info) {
  int (*host_dladdr)(const void *, Dl_info *);
  if (!IsLinux() || !__hostlibc.loaded || !__foreign.is_supported)
    return 0;
  if (!(host_dladdr = dlsym_host_dladdr()))
    return 0;
  // the helper itself is the host's main program, whose name is empty
  return host_dladdr(addr, info) && info->dli_fname && *info->dli_fname;
}

/**
 * Implements dlsym() for handles dlopen() returned.
 *
 * A function comes back wrapped by cosmo_dltramp(), once per function,
 * so it can be called like any C function pointer. A variable comes
 * back as its own address.
 */
void *__dlsym_plain(void *handle, const char *name) {
  void *p;
  if (!(p = cosmo_dlsym(handle, name)))
    return 0;
  return dlsym_wrap(p);
}

/**
 * Returns where the host libc keeps `errno` for the calling thread.
 *
 * A host library reports errors through its own libc's errno, which
 * isn't ours. On Windows this is the Universal CRT's, which is the one
 * MSVC-built DLLs use, or msvcrt's if only that is loaded.
 *
 * @return pointer, or NULL if the host libc isn't loaded or reachable
 */
int *cosmo_dlerrno(void) {
  int *res = 0;
  if (IsWindows()) {
#ifdef __x86_64__
    static int *(__msabi *get)(void);
    if (!get) {
      uintptr_t h;
      if (!(h = GetModuleHandle("ucrtbase.dll")))
        h = GetModuleHandle("msvcrt.dll");
      if (h)
        get = (int *(__msabi *)(void))GetProcAddress(h, "_errno");
    }
    if (get)
      res = get();
#endif
  } else if (IsXnuSilicon()) {
    int *(*get)(void) = __syslib->__dlsym((void *)-2, "__error");
    if (get)
      res = get();
  } else if (__hostlibc.dual && __hostlibc.errno_location) {
    __host_enter();
    res = __hostlibc.errno_location();
  }
  return res;
}

// the host libc's errno numbers are its kernel's, or on Windows the C
// runtime's own
static int dlerrno_ours(int e) {
  if (IsXnu())
    return __errno_xnu2linux(e);
  if (IsWindows())
    return __host_crt_errno(e);
  return e;
}

/**
 * Returns the host libc's errno for the calling thread, as our number.
 *
 * @return errno, or 0 if the host libc isn't loaded or reachable
 */
int cosmo_dlgeterrno(void) {
  int *p;
  if (!(p = cosmo_dlerrno()) || !*p)
    return 0;
  return dlerrno_ours(*p);
}

/**
 * Sets the host libc's errno for the calling thread to our number `e`.
 */
void cosmo_dlseterrno(int e) {
  int *p, h = e;
  if (!(p = cosmo_dlerrno()))
    return;
  if (IsWindows()) {
    h = __host_crt_errno_of(e);
  } else if (IsXnu() && e) {
    for (h = 1; h < 256 && dlerrno_ours(h) != e; ++h) {
    }
    if (h == 256)
      h = e;
  }
  *p = h;
}

/**
 * Adds a directory the dependencies of a dll cosmo_dlopen() loads are
 * looked for in, like AddDllDirectory() and Python's
 * os.add_dll_directory(). Only Windows has this.
 *
 * @return cookie for cosmo_dlremovedir(), or NULL w/ errno
 * @raise ENOTSUP if the host isn't Windows
 */
void *cosmo_dladddir(const char *path) {
  void *cookie = 0;
  if (IsWindows()) {
    char16_t path16[PATH_MAX];
    if (__mkntpath(path, path16) == -1)
      return 0;
    if ((cookie = AddDllDirectory(path16)))
      atomic_fetch_add(&dlopen_nt_userdirs, 1);
    else
      errno = __errno_host2linux(GetLastError());
  } else {
    errno = ENOTSUP;
  }
  return cookie;
}

/**
 * Removes a directory cosmo_dladddir() added.
 *
 * @return 0 on success, or -1 w/ errno
 */
int cosmo_dlremovedir(void *cookie) {
  if (!IsWindows())
    return enotsup();
  if (!RemoveDllDirectory(cookie)) {
    errno = __errno_host2linux(GetLastError());
    return -1;
  }
  atomic_fetch_sub(&dlopen_nt_userdirs, 1);
  return 0;
}

/**
 * Returns what the host knows file descriptor `fd` as.
 *
 * That's a Win32 HANDLE on Windows, and `fd` itself anywhere else.
 *
 * @return handle, or -1 w/ errno if `fd` isn't open
 */
intptr_t cosmo_dlhandle(int fd) {
  if (IsWindows()) {
    struct Fds *fds = &__get_pib()->fds;
    if (fd < 0 || fd >= fds->n || !fds->p[fd].kind) {
      ebadf();
      return -1;
    }
    return fds->p[fd].handle;
  }
  return fd;
}
