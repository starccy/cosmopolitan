#include "libc/atomic.h"
#include "libc/dce.h"
#include "libc/dlopen/dlfcn.h"
#include "libc/dlopen/templates.internal.h"
#include "libc/errno.h"
#include "libc/intrin/atomic.h"
#include "libc/intrin/kprintf.h"
#include "libc/intrin/strace.h"
#include "libc/mem/mem.h"
#include "libc/runtime/runtime.h"
#include "libc/serialize.h"
#include "libc/thread/thread.h"
#include "ape/sections.internal.h"
#include "libc/str/str.h"
#include "libc/nt/memory.h"
#include "libc/nt/enum/pageflags.h"
#include "libc/nt/struct/memorybasicinformation.h"

// a library the program was linked against with -l, which the linker
// only found as a host shared object. the names are lists of strings
// ended by an empty one
struct HostLinkLib {
  _Atomic(void *) handle;
  const char *linux_names;
  const char *xnu_names;
  const char *nt_names;
  const char *name;  // as in -l<name>
  // its variables to sync around calls, null for none; the wrappers
  // `cargo xtask build` makes check this before calling
  _Atomic(struct HostLinkSync *) sync;
  uint64_t flags;
};

#define HOSTLINK_NOSYNC 1  // flags: only sync variables when it loads

// a variable the program and the library each have a copy of
struct HostLinkVar {
  char *ours, *theirs, *last;
  size_t size;
};

struct HostLinkSync {
  size_t n;
  struct HostLinkVar v[];
};

// every HostLinkLib in the program, see hostlink_lazy.S
extern struct HostLinkLib *const __hostlink_libs[];
extern struct HostLinkLib *const __hostlink_libs_end[];

void __dlerror_set(const char *);

// a function of that library the program calls, through `slot`
struct HostLinkSym {
  _Atomic(void *) *slot;
  struct HostLinkLib *lib;
  const char *name;
};

static const char *hostlink_names(struct HostLinkLib *lib) {
  if (IsWindows())
    return lib->nt_names;
  if (IsXnu())
    return lib->xnu_names;
  return lib->linux_names;
}

static void hostlink_list(const char *names) {
  for (const char *n = names; *n; n += strlen(n) + 1)
    kprintf(" %s", n);
}

static wontreturn void hostlink_nolib(struct HostLinkLib *lib,
                                      const char *err) {
  const char *names = hostlink_names(lib);
  if (!*names) {
    kprintf("%s: the library -l%s isn't for this host\n",
            program_invocation_name, lib->name);
    _Exit(127);
  }
  kprintf("%s: can't load a shared library this program needs, tried",
          program_invocation_name);
  hostlink_list(names);
  kprintf("\n%s\n", err ? err : "not found");
  _Exit(127);
}

// a variable of a library the program uses, registered at startup by
// what Rust side made of the crate declaring it
struct HostLinkData {
  struct HostLinkLib *lib;
  const char *name;
  char *addr;
  size_t size;
  struct HostLinkData *next;
};

static struct HostLinkData *hostlink_data;

// loading a library and setting up its variables happen together; the
// same thread may load another library from a callback meanwhile
static pthread_mutex_t hostlink_lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;


/**
 * Registers `addr`, where the program keeps the variable `name` of `lib`,
 * which is `size` bytes in the library.
 *
 * On Linux the library is made to use the program's copy when it's
 * loaded, so both sides see each other's changes. Elsewhere there are two
 * copies, and when it's loaded one is copied to the other: the library's
 * to the program's, unless the program already wrote to its own.
 */
void __hostlink_data(struct HostLinkLib *lib, const char *name, void *addr,
                     size_t size) {
  struct HostLinkData *d;
  if (!(d = malloc(sizeof(*d))))
    return;
  *d = (struct HostLinkData){lib, name, addr, size, 0};
  pthread_mutex_lock(&hostlink_lock);
  d->next = hostlink_data;
  hostlink_data = d;
  pthread_mutex_unlock(&hostlink_lock);
}

static bool hostlink_zero(const char *p, size_t n) {
  for (size_t i = 0; i < n; ++i)
    if (p[i])
      return false;
  return true;
}

// before the library is loaded: on Linux, a library of our own that
// defines its variables at the program's addresses, loaded first so the
// library binds to those
static void hostlink_data_before(struct HostLinkLib *lib) {
  size_t n = 0, i = 0;
  struct HostLinkData *d;
  if (!IsLinux())
    return;
  for (d = hostlink_data; d; d = d->next)
    n += d->lib == lib;
  if (!n)
    return;
  struct CosmoDlexport2 *syms = malloc(n * sizeof(*syms));
  if (syms) {
    for (d = hostlink_data; d; d = d->next)
      if (d->lib == lib) {
        syms[i].name = d->name;
        syms[i].addr = d->addr;
        syms[i].size = d->size;
        syms[i].kind = COSMO_DLEXPORT_DATA;
        syms[i].va = 0;
        ++i;
      }
    char name[128];
    ksnprintf(name, sizeof(name), "hostlink-data-%s", lib->name);
    if (!cosmo_dlexport2(name, syms, n))
      kprintf("%s: -l%s's variables won't be shared: %s\n",
              program_invocation_name, lib->name, cosmo_dlerror());
  }
  free(syms);
}

// whether the library can change the variable at `p`; a constant can't
// have changed since it loaded, so it isn't synced
static bool hostlink_writable(const void *p) {
#ifdef __x86_64__
  if (IsWindows()) {
    struct NtMemoryBasicInformation mbi;
    if (!VirtualQuery(p, &mbi, sizeof(mbi)))
      return true;
    return !!(mbi.Protect & (kNtPageReadwrite | kNtPageWritecopy |
                             kNtPageExecuteReadwrite |
                             kNtPageExecuteWritecopy));
  }
#endif
#ifdef __aarch64__
  if (IsXnu()) {
    // the segment holding it, found through its image's load commands
    struct {
      uint32_t magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds,
          flags, reserved;
    } *mh;
    struct {
      uint32_t cmd, cmdsize;
      char segname[16];
      uint64_t vmaddr, vmsize, fileoff, filesize;
      int32_t maxprot, initprot;
      uint32_t nsects, flags;
    } *seg;
    Dl_info info;
    int (*dladdr_)(const void *, Dl_info *);
    if (!(dladdr_ = cosmo_dlsym((void *)-2, "dladdr")) ||
        !dladdr_(p, &info) || !(mh = info.dli_fbase))
      return true;
    intptr_t slide = 0;
    char *lc = (char *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; ++i, lc += seg->cmdsize) {
      seg = (void *)lc;
      if (seg->cmd == 0x19 && !strncmp(seg->segname, "__TEXT", 16))
        slide = (intptr_t)mh - seg->vmaddr;
    }
    lc = (char *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; ++i, lc += seg->cmdsize) {
      seg = (void *)lc;
      if (seg->cmd != 0x19 || (uintptr_t)p < seg->vmaddr + slide ||
          (uintptr_t)p >= seg->vmaddr + slide + seg->vmsize)
        continue;
      return (seg->initprot & 2) && !(seg->flags & 0x10) &&
             strncmp(seg->segname, "__DATA_CONST", 16) &&
             strncmp(seg->segname, "__AUTH_CONST", 16);
    }
  }
#endif
  return true;
}

// after: the library's initial values where it hasn't got ours. where
// there are two copies, the ones it can change are kept in step with
// ours around every call into it by the wrappers `cargo xtask build`
// makes, which read HostLinkLib's sync
static void hostlink_data_after(struct HostLinkLib *lib, void *h) {
  size_t n = 0;
  struct HostLinkData *d;
  struct HostLinkSync *sync = 0;
  for (d = hostlink_data; d; d = d->next)
    n += d->lib == lib;
  if (n && !IsLinux() && !(lib->flags & HOSTLINK_NOSYNC) &&
      (sync = malloc(sizeof(*sync) + n * sizeof(sync->v[0]))))
    sync->n = 0;
  for (d = hostlink_data; d; d = d->next) {
    char *theirs;
    if (d->lib != lib || !(theirs = cosmo_dlsym(h, d->name)) ||
        theirs == d->addr)
      continue;
    if (hostlink_zero(d->addr, d->size))
      memcpy(d->addr, theirs, d->size);
    else if (!IsLinux())
      memcpy(theirs, d->addr, d->size);
    char *last;
    if (sync && hostlink_writable(theirs) && (last = malloc(d->size))) {
      memcpy(last, d->addr, d->size);
      sync->v[sync->n++] = (struct HostLinkVar){d->addr, theirs, last, d->size};
    }
  }
  if (sync && sync->n)
    atomic_store_explicit(&lib->sync, sync, memory_order_release);
  else
    free(sync);
}

// the library's handle, or null with the first name's error in `err`,
// which says the most since the later names are fallbacks
static void *hostlink_open(struct HostLinkLib *lib, char **err) {
  void *h;
  if ((h = atomic_load_explicit(&lib->handle, memory_order_acquire)))
    return h;
  pthread_mutex_lock(&hostlink_lock);
  if ((h = atomic_load_explicit(&lib->handle, memory_order_acquire))) {
    pthread_mutex_unlock(&hostlink_lock);
    return h;
  }
  hostlink_data_before(lib);
  *err = 0;
  const char *names = hostlink_names(lib);
  for (const char *n = names; *n; n += strlen(n) + 1) {
    if ((h = cosmo_dlopen(n, RTLD_LAZY | RTLD_GLOBAL)))
      break;
    if (!*err)
      *err = strdup(cosmo_dlerror() ?: "");
  }
  if (h) {
    free(*err);
    *err = 0;
    hostlink_data_after(lib, h);
    atomic_store_explicit(&lib->handle, h, memory_order_release);
  }
  pthread_mutex_unlock(&hostlink_lock);
  return h;
}

/**
 * Loads a library the program was linked against with `-l<name>`.
 *
 * `cargo xtask build` links a library that only exists as a host shared
 * object through stubs, which load it the first time one of its
 * functions is called, and end the program if it isn't there. Calling
 * this first lets a program find out and say something more helpful.
 *
 * @param name is the library as in `-l<name>`, e.g. "gtk-3"
 * @return its handle, which cosmo_dlsym() takes, or NULL w/ dlerror()
 *     if it can't be loaded or wasn't linked from the host
 */
void *cosmo_hostlink(const char *name) {
  char *err;
  void *h = 0;
  struct HostLinkLib *const *p;
  for (p = __hostlink_libs; p < __hostlink_libs_end; ++p)
    if (!strcmp((*p)->name, name))
      break;
  if (p == __hostlink_libs_end) {
    char msg[128];
    ksnprintf(msg, sizeof(msg), "-l%s isn't linked from the host", name);
    __dlerror_set(msg);
  } else if (!(h = hostlink_open(*p, &err))) {
    __dlerror_set(err ? err : "not found");
    free(err);
  }
  STRACE("cosmo_hostlink(%#s) → %p", name, h);
  return h;
}

/**
 * Returns the address of function `name` in a library the program links
 * from the host, as the host sees it.
 *
 * This is for the wrappers `cargo xtask build` makes out of a crate's
 * `extern` declarations, which call the function themselves with the
 * host's convention. `lib` is the library's `__hostlink_lib_<name>` in
 * its archive of stubs. A library or function that can't be found ends
 * the program, as with the stubs.
 */
void *__hostlink_resolve(struct HostLinkLib *lib, const char *name) {
  char *err;
  void *h, *f;
  if (!(h = hostlink_open(lib, &err)))
    hostlink_nolib(lib, err);
  if (!(f = cosmo_dlsym(h, name))) {
    kprintf("%s: symbol %s not found in", program_invocation_name, name);
    hostlink_list(hostlink_names(lib));
    kprintf("\n");
    _Exit(127);
  }
  STRACE("__hostlink_resolve(%s) → %p", name, f);
  return f;
}

/**
 * Binds a function the program calls in a host library, the first time
 * it's called.
 *
 * `cargo xtask build` turns a `-l` the linker can only satisfy with a
 * host shared object into stubs that jump through a slot per function.
 * The slot starts out pointing at code that calls this, which loads the
 * library, looks the function up, and points the slot at a trampoline
 * for it. A library or function that can't be found ends the program,
 * as the host's own loader would have done at startup.
 *
 * @return what the slot now holds, which the caller jumps to
 */
void *__hostlink_bind(struct HostLinkSym *sym) {
  char *err;
  void *h, *f, *t;
  struct HostLinkLib *lib = sym->lib;
  if (!(h = hostlink_open(lib, &err)))
    hostlink_nolib(lib, err);
  if (!(f = cosmo_dlsym(h, sym->name))) {
    kprintf("%s: symbol %s not found in", program_invocation_name,
            sym->name);
    hostlink_list(hostlink_names(lib));
    kprintf("\n");
    _Exit(127);
  }
  if (!(t = cosmo_dltramp(f))) {
    kprintf("%s: out of memory binding %s\n", program_invocation_name,
            sym->name);
    _Exit(127);
  }
  atomic_store_explicit(sym->slot, t, memory_order_release);
  STRACE("__hostlink_bind(%s) → %p", sym->name, f);
  return t;
}

// the layout __hostlink_nt2sysv() hands __hostlink_nt2sysv_layout()
struct HostLinkCall {
  uint64_t xmm[4];  // xmm0-3 as the host passed them
  uint64_t gp[6];
  uint64_t fp[8];
  uint64_t nstack;
  uint64_t nfp;
  uint64_t stack[32];
};

// a callback signature: bits 0-5 count the arguments, bit 6 says they're
// unknown, bits 8-39 mark the floating point ones. from bit 40 two bits
// per argument, for the first eleven, say what a Windows DLL passes
// narrower: 1 a `long`, 2 an `unsigned long`, 3 a `wchar_t`; bits 62-63
// say the same of the return value
#define HOSTLINK_UNKNOWN 64

// `v` as a DLL passed it, widened from the width it gave it
static uint64_t hostlink_widen(uint64_t v, int mark) {
  switch (mark) {
    case 1:
      return (int64_t)(int32_t)v;
    case 2:
      return (uint32_t)v;
    case 3:
      return (uint16_t)v;
    default:
      return v;
  }
}

/**
 * Widens what a host function returned to a thunk __hostlink_thunk()
 * made, when the signature `desc` says it's a type the DLL gives in
 * fewer than 64 bits.
 */
uint64_t __hostlink_widen_ret(uint64_t v, uint64_t desc) {
  return hostlink_widen(v, desc >> 62);
}

void *__dlopen_code(size_t);
void __hostlink_nt2sysv(void);

/**
 * Lays out the arguments a host function passed one of our callbacks in
 * Microsoft's x64 convention, `args[i]` for the i-th, the way the System
 * V convention wants them. A callback of unknown signature, like a
 * GCallback, gets up to 12 integers, which is right for all the ones
 * that only take integers and pointers.
 */
void __hostlink_nt2sysv_layout(const uint64_t *args, uint64_t desc,
                               struct HostLinkCall *c) {
  bool unknown = desc & HOSTLINK_UNKNOWN;
  int n = unknown ? 12 : desc & 63;
  int ngp = 0, nfp = 0, ns = 0;
  for (int i = 0; i < n; ++i) {
    bool fl = !unknown && ((desc >> (8 + i)) & 1);
    uint64_t v = fl && i < 4 ? c->xmm[i] : args[i];
    if (!unknown && !fl && i < 11)
      v = hostlink_widen(v, (desc >> (40 + 2 * i)) & 3);
    if (fl && nfp < 8)
      c->fp[nfp++] = v;
    else if (!fl && ngp < 6)
      c->gp[ngp++] = v;
    else if (ns < 32)
      c->stack[ns++] = v;
  }
  c->nstack = ns;
  c->nfp = nfp;
}

#ifdef __x86_64__
static struct {
  pthread_mutex_t lock;
  size_t n, cap;
  struct {
    void *fn;
    uint64_t desc;
    void *thunk;
  } *p;
} hostlink_callbacks = {PTHREAD_MUTEX_INITIALIZER};
#endif

/**
 * Returns what to hand a Windows DLL for callback `fn`, a function of
 * this program with signature `desc`, so the DLL can call it with its own
 * convention. Anything that isn't one of our functions, such as null, a
 * sentinel like SQLite's -1 or a function of the host's, comes back as it
 * is, and so does everything anywhere but Windows.
 */
void *__hostlink_callback(void *fn, uint64_t desc) {
#ifdef __x86_64__
  if (!IsWindows() || (char *)fn < (char *)__executable_start ||
      (char *)fn >= (char *)_end)
    return fn;
  void *t = 0;
  pthread_mutex_lock(&hostlink_callbacks.lock);
  for (size_t i = 0; i < hostlink_callbacks.n; ++i)
    if (hostlink_callbacks.p[i].fn == fn &&
        hostlink_callbacks.p[i].desc == desc) {
      t = hostlink_callbacks.p[i].thunk;
      break;
    }
  if (!t && hostlink_callbacks.n == hostlink_callbacks.cap) {
    size_t cap = hostlink_callbacks.cap ? hostlink_callbacks.cap * 2 : 16;
    void *p = realloc(hostlink_callbacks.p, cap * sizeof(*hostlink_callbacks.p));
    if (p) {
      hostlink_callbacks.p = p;
      hostlink_callbacks.cap = cap;
    }
  }
  if (!t && hostlink_callbacks.n < hostlink_callbacks.cap &&
      (t = __dlopen_code(TMPL_SIZE(__tmpl_hostlink_thunk)))) {
    TMPL_PUT(t, __tmpl_hostlink_thunk, desc, (uintptr_t)fn,
             (uintptr_t)__hostlink_nt2sysv);
    hostlink_callbacks.p[hostlink_callbacks.n].fn = fn;
    hostlink_callbacks.p[hostlink_callbacks.n].desc = desc;
    hostlink_callbacks.p[hostlink_callbacks.n].thunk = t;
    ++hostlink_callbacks.n;
  }
  pthread_mutex_unlock(&hostlink_callbacks.lock);
  if (!t) {
    kprintf("%s: out of memory making a callback\n", program_invocation_name);
    _Exit(127);
  }
  STRACE("__hostlink_callback(%p, %#lx) → %p", fn, desc, t);
  return t;
#else
  return fn;
#endif
}

// registers and stack for a call __hostlink_vcall() makes
struct HostLinkRegs {
  uint64_t gp[8];
  uint64_t fp[8];
  uint64_t nstack;
  uint64_t nfp;
  uint64_t stack[64];
};

// what came back in the first integer and floating point registers
struct HostLinkRet {
  uint64_t x;
  uint64_t f;
};

struct HostLinkRet __hostlink_callregs(void *, struct HostLinkRegs *);
struct HostLinkRet __hostlink_callregs_nt(void *, struct HostLinkRegs *);

/**
 * Calls a variadic host function the way the host we're on passes the
 * arguments, which a compiler couldn't do for us since that's decided at
 * runtime. `args[i]` holds the i-th argument's bits, a set bit i in
 * `floats` makes it floating point (a double, or a float for a fixed
 * argument), and the first `nfixed` are the ones before the `...`.
 *
 * `f` is the function as the host sees it on Windows, and behind cosmo's
 * trampoline anywhere else.
 */
struct HostLinkRet __hostlink_vcall(void *f, const uint64_t *args, size_t n,
                                    size_t nfixed, uint64_t floats) {
  struct HostLinkRegs r;
  int ngp = 0, nfp = 0, ns = 0;
  bzero(&r, sizeof(r));
  if (n > 64) {
    kprintf("%s: too many arguments to a variadic host function\n",
            program_invocation_name);
    _Exit(127);
  }
  for (size_t i = 0; i < n; ++i) {
    bool fl = (floats >> i) & 1;
    uint64_t v = args[i];
    if (IsWindows()) {
      // one slot per argument, whatever its type; a variadic double goes
      // in both registers since the callee reads it from the integer one
      if (i < 4) {
        if (fl)
          r.fp[i] = v;
        if (!fl || i >= nfixed)
          r.gp[i] = v;
      } else {
        r.stack[ns++] = v;
      }
    } else if (IsXnu() && i >= nfixed) {
      // apple passes everything after the ... on the stack
      r.stack[ns++] = v;
    } else if (fl && nfp < 8) {
      r.fp[nfp++] = v;
    } else if (!fl && ngp < (IsAarch64() ? 8 : 6)) {
      r.gp[ngp++] = v;
    } else {
      r.stack[ns++] = v;
    }
  }
  r.nstack = ns;
  r.nfp = nfp;
#ifdef __x86_64__
  if (IsWindows())
    return __hostlink_callregs_nt(f, &r);
#endif
  return __hostlink_callregs(f, &r);
}

#ifdef __x86_64__
void __hostlink_sysv2nt(void);

// where this program is, for the thunk to tell our callers from the host's
const uintptr_t __hostlink_bounds[2] = {(uintptr_t)__executable_start,
                                       (uintptr_t)_end};

// the frame __hostlink_sysv2nt makes has room for one after its registers
_Static_assert(sizeof(struct HostLinkRegs) == 0x290, "");

/**
 * Lays out the arguments one of our callers passed a thunk in the
 * System V convention, `gp[i]` the i-th integer register, `fp[i]` the
 * i-th floating point one and `stack[i]` the i-th slot above the return
 * address, the way Microsoft's convention wants them for a function of
 * signature `desc`.
 */
void __hostlink_sysv2nt_layout(const uint64_t *gp, const uint64_t *fp,
                               const uint64_t *stack, uint64_t desc,
                               struct HostLinkRegs *r) {
  bool unknown = desc & HOSTLINK_UNKNOWN;
  int n = unknown ? 14 : desc & 63;
  int ngp = 0, nfp = 0, ns = 0, nsrc = 0;
  bzero(r, sizeof(*r));
  for (int i = 0; i < n; ++i) {
    bool fl = !unknown && ((desc >> (8 + i)) & 1);
    uint64_t v;
    if (fl)
      v = nfp < 8 ? fp[nfp++] : stack[nsrc++];
    else
      v = ngp < 6 ? gp[ngp++] : stack[nsrc++];
    if (i >= 4)
      r->stack[ns++] = v;
    else if (fl)
      r->fp[i] = v;
    else
      r->gp[i] = v;
  }
  r->nstack = ns;
}

static struct {
  pthread_mutex_t lock;
  size_t n, cap;
  struct {
    void *fn;
    uint64_t desc;
    void *thunk;
  } *p;
} hostlink_thunks = {PTHREAD_MUTEX_INITIALIZER};
#endif

/**
 * Returns what to call `fn`, a function pointer a host library handed
 * back, as an ordinary function of ours: on Windows a thunk that lays
 * the arguments out in Microsoft's convention, which needs to know
 * the signature `desc` (as __hostlink_callback() takes it) once a
 * floating point argument is among them. One of our own functions, and
 * everything on hosts whose convention is already ours, comes back as
 * it is. A signature of only integers goes through cosmo_dlthunk().
 */
void *__hostlink_thunk(void *fn, uint64_t desc) {
#ifdef __x86_64__
  if (!fn || !IsWindows() ||
      ((char *)fn >= (char *)__executable_start && (char *)fn < (char *)_end))
    return fn;
  // what __hostlink_callback() made of one of our functions is that
  // function again
  void *t = 0;
  pthread_mutex_lock(&hostlink_callbacks.lock);
  for (size_t i = 0; i < hostlink_callbacks.n; ++i)
    if (hostlink_callbacks.p[i].thunk == fn) {
      t = hostlink_callbacks.p[i].fn;
      break;
    }
  pthread_mutex_unlock(&hostlink_callbacks.lock);
  if (t)
    return t;
  if ((desc & HOSTLINK_UNKNOWN) || !(desc >> 8))
    return cosmo_dlthunk(fn);
  pthread_mutex_lock(&hostlink_thunks.lock);
  for (size_t i = 0; i < hostlink_thunks.n; ++i)
    if (hostlink_thunks.p[i].fn == fn && hostlink_thunks.p[i].desc == desc) {
      t = hostlink_thunks.p[i].thunk;
      break;
    }
  if (!t && hostlink_thunks.n == hostlink_thunks.cap) {
    size_t cap = hostlink_thunks.cap ? hostlink_thunks.cap * 2 : 16;
    void *p = realloc(hostlink_thunks.p, cap * sizeof(*hostlink_thunks.p));
    if (p) {
      hostlink_thunks.p = p;
      hostlink_thunks.cap = cap;
    }
  }
  if (!t && hostlink_thunks.n < hostlink_thunks.cap &&
      (t = __dlopen_code(TMPL_SIZE(__tmpl_hostlink_thunk)))) {
    TMPL_PUT(t, __tmpl_hostlink_thunk, desc, (uintptr_t)fn,
             (uintptr_t)__hostlink_sysv2nt);
    hostlink_thunks.p[hostlink_thunks.n].fn = fn;
    hostlink_thunks.p[hostlink_thunks.n].desc = desc;
    hostlink_thunks.p[hostlink_thunks.n].thunk = t;
    ++hostlink_thunks.n;
  }
  pthread_mutex_unlock(&hostlink_thunks.lock);
  if (!t) {
    kprintf("%s: out of memory making a thunk\n", program_invocation_name);
    _Exit(127);
  }
  STRACE("__hostlink_thunk(%p, %#lx) → %p", fn, desc, t);
  return t;
#else
  return fn;
#endif
}
