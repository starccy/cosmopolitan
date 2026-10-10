#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/cosmo.h"
#include "libc/dce.h"
#include "libc/dlopen/hostfile.internal.h"
#include "libc/macros.h"
#include "libc/intrin/hostlibc.h"
#include "libc/intrin/strace.h"
#include "libc/mem/mem.h"
#include "libc/nt/dll.h"
#include "libc/nt/enum/pageflags.h"
#include "libc/nt/memory.h"
#include "libc/nt/pedef.internal.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/imagedatadirectory.internal.h"
#include "libc/nt/struct/imagedosheader.internal.h"
#include "libc/nt/struct/imageimportdescriptor.internal.h"
#include "libc/nt/struct/imagentheaders.internal.h"
#include "libc/nt/struct/imageoptionalheader.internal.h"
#include "libc/nt/struct/ldr.h"
#include "libc/nt/struct/ldrdatatableentry.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/runtime/internal.h"
#include "libc/runtime/runtime.h"
#include "libc/runtime/syslib.internal.h"
#include "libc/str/str.h"
#include "libc/thread/thread.h"

// Keeps the environment of the host libc and ours the same, once a host
// library is loaded. On Linux the dlopen helper routes the host libc's
// setenv() and friends to ours, see helper.c. Elsewhere that can't be
// done, so this file does it.
//
// On macOS our environ array is libSystem's as well. A change that
// replaces or removes a variable happens in place, where both see it.
// Adding one makes libSystem move to a bigger array of its own, which
// we copy and share again the next time our environment is used, or
// when a host function declared through ape::host_library! returns.
//
// On Windows the host keeps its variables in the process environment
// block, in UTF-16 with DOS paths, and each C runtime keeps a copy. We
// write our changes to the block and the Universal CRT and msvcrt
// copies. The other way, every loaded module's imports of
// SetEnvironmentVariable are pointed at a function that reads the block
// back into our environment after the call, and so are modules loaded
// later. The file functions of hostfile.c get patched the same way.

// set while we're the ones changing the host's variables
static _Thread_local bool quiet;

#ifdef __aarch64__

static char ***xnu_env;
static char **xnu_last;  // what libSystem was last given
static char *xnu_empty[1];

static void xnu_publish(void) {
  *xnu_env = xnu_last = environ ? environ : xnu_empty;
}

// only a new array on libSystem's side is news; a new one on ours is
// published by whoever made it
static void xnu_pull(void) {
  char **h, **c;
  size_t n = 0;
  if ((h = *xnu_env) == xnu_last)
    return;
  // libSystem may realloc its array, so we keep a copy of our own
  if (h)
    while (h[n])
      ++n;
  if (!(c = cosmo_permalloc((n + 1) * sizeof(char *))))
    return;
  memcpy(c, h, n * sizeof(char *));
  c[n] = 0;
  environ = c;
  *xnu_env = xnu_last = c;
}

static void xnu_init(void) {
  char ***(*get)(void);
  if (!(get = __syslib->__dlsym((void *)-2, "_NSGetEnviron")))
    return;
  xnu_env = get();
  xnu_publish();
  __hostlibc.envsync = true;
}

#endif /* __aarch64__ */

#ifdef __x86_64__

typedef bool32 __msabi (*SetEnvW)(const char16_t *, const char16_t *);
typedef bool32 __msabi (*SetEnvA)(const char *, const char *);
typedef int __msabi (*PutEnvS)(const char16_t *, const char16_t *);

static intptr_t nt_self;
static intptr_t nt_system[3];

__msabi static bool32 nt_hook_w(const char16_t *, const char16_t *);
__msabi static bool32 nt_hook_a(const char *, const char *);

static struct HostNtHook nt_env_hooks[] = {
    {"SetEnvironmentVariableW", nt_hook_w},
    {"SetEnvironmentVariableA", nt_hook_a},
    {0},
};

// every hook, the environment's and those in hostfile.c
static struct HostNtHook *const nt_hooks[] = {nt_env_hooks,
                                              __host_nt_file_hooks};

#define nt_real_w ((SetEnvW)nt_env_hooks[0].real)
#define nt_real_a ((SetEnvA)nt_env_hooks[1].real)

static void nt_pull(void);

__msabi static bool32 nt_hook_w(const char16_t *name, const char16_t *value) {
  bool32 ok = nt_real_w(name, value);
  if (ok && !quiet)
    nt_pull();
  return ok;
}

__msabi static bool32 nt_hook_a(const char *name, const char *value) {
  bool32 ok = nt_real_a(name, value);
  if (ok && !quiet)
    nt_pull();
  return ok;
}

// writes one of our variables to the host, or removes it
static void nt_push(const char *name, const char *value) {
  char *dos = 0;
  char16_t *name16, *value16 = 0;
  size_t n = strlen(name) + 1;
  if (!(name16 = malloc(n * sizeof(char16_t))))
    return;
  tprecode8to16(name16, n, name);
  if (value) {
    if (value[0] == '/') {
      size_t m = strlen(value) * 2 + 16;
      if ((dos = malloc(m)) && __unixtodospath(value, dos, m) != -1)
        value = dos;
    }
    n = strlen(value) + 1;
    if (!(value16 = malloc(n * sizeof(char16_t)))) {
      free(dos);
      free(name16);
      return;
    }
    tprecode8to16(value16, n, value);
  }
  bool old = quiet;
  quiet = true;
  nt_real_w(name16, value16);
  static const char16_t *crts[] = {u"ucrtbase.dll", u"msvcrt.dll"};
  for (int i = 0; i < 2; ++i) {
    intptr_t h;
    PutEnvS f;
    if ((h = GetModuleHandleW(crts[i])) &&
        (f = (PutEnvS)GetProcAddress(h, "_wputenv_s")))
      f(name16, value16 ? value16 : u"");
  }
  quiet = old;
  free(value16);
  free(dos);
  free(name16);
}

// finds our variable called `name`, in any case, as Windows compares
static char *nt_find(const char *name, size_t k) {
  for (char **p = environ; p && *p; ++p)
    if (!strncasecmp(*p, name, k) && ((*p)[k] == '=' || !(*p)[k]))
      return *p;
  return 0;
}

// reads the host's variables into ours
static void nt_pull(void) {
  char16_t *blk;
  char *buf, **vars;
  size_t bufsize = 32767 * 3, max = 8192;
  int i, n;
  if (!(blk = GetEnvironmentStrings()))
    return;
  buf = malloc(bufsize);
  vars = malloc(max * sizeof(char *));
  if (buf && vars) {
    n = GetDosEnviron(blk, buf, bufsize, vars, max - 1, __getcosmosdrive());
    bool old = quiet;
    quiet = true;
    for (i = 0; i < n; ++i) {
      char *eq = strchr(vars[i], '=');
      if (!eq || eq == vars[i])
        continue;
      size_t k = eq - vars[i];
      char *have = nt_find(vars[i], k);
      if (have && have[k] == '=' && !strcmp(have + k + 1, eq + 1))
        continue;
      // keeps the spelling of the name we already have
      char name[k + 1];
      memcpy(name, have ? have : vars[i], k);
      name[k] = 0;
      setenv(name, eq + 1, 1);
    }
    // ours that the host no longer has
    for (char **p = environ; p && *p;) {
      char *eq = strchr(*p, '=');
      size_t k = eq ? eq - *p : strlen(*p);
      bool found = false;
      for (i = 0; i < n && !found; ++i)
        found = !strncasecmp(vars[i], *p, k) && vars[i][k] == '=';
      if (!found && k) {
        char name[k + 1];
        memcpy(name, *p, k);
        name[k] = 0;
        unsetenv(name);
      } else {
        ++p;
      }
    }
    quiet = old;
  }
  free(vars);
  free(buf);
  FreeEnvironmentStrings(blk);
}

static void nt_patch(char *base) {
  intptr_t b = (intptr_t)base;
  if (!base || b == nt_self || b == nt_system[0] || b == nt_system[1] ||
      b == nt_system[2])
    return;
  __host_crt_patch(base);
  struct NtImageDosHeader *dos = (void *)base;
  if (dos->e_magic != 0x5a4d)
    return;
  struct NtImageNtHeaders *nt = (void *)(base + dos->e_lfanew);
  struct NtImageDataDirectory *dir =
      &nt->OptionalHeader.DataDirectory[kNtImageDirectoryEntryImport];
  if (!dir->VirtualAddress || !dir->Size)
    return;
  struct NtImageImportDescriptor *d = (void *)(base + dir->VirtualAddress);
  for (; d->DllNameRva; ++d) {
    void **iat = (void **)(base + d->ImportAddressTable);
    for (; *iat; ++iat) {
      void *hook = 0;
      for (int t = 0; t < ARRAYLEN(nt_hooks) && !hook; ++t)
        for (struct HostNtHook *h = nt_hooks[t]; h->name && !hook; ++h)
          for (int i = 0; i < 2; ++i)
            if (h->targets[i] && *iat == h->targets[i])
              hook = h->hook;
      if (!hook)
        continue;
      uint32_t old;
      if (VirtualProtect(iat, sizeof(*iat), kNtPageReadwrite, &old)) {
        *iat = hook;
        VirtualProtect(iat, sizeof(*iat), old, &old);
      }
    }
  }
}

__msabi static void nt_notify(uint32_t reason, void *data, void *ctx) {
  // LDR_DLL_NOTIFICATION_REASON_LOADED, whose data has the base 4th
  if (reason == 1)
    nt_patch(((char **)data)[3]);
}

static void nt_patch_all(void) {
  char *peb, *ldr;
  asm("mov\t%%gs:0x60,%0" : "=r"(peb));
  ldr = *(char **)(peb + 0x18);
  struct NtLinkedList *head = &((struct NtLdr *)ldr)->InLoadOrderModuleList;
  for (struct NtLinkedList *e = head->Next; e != head; e = e->Next)
    nt_patch(((struct NtLdrDataTableEntry *)e)->DllBase);
}

static void nt_init(void) {
  intptr_t k32, kb;
  k32 = GetModuleHandleW(u"kernel32.dll");
  kb = GetModuleHandleW(u"kernelbase.dll");
  nt_self = GetModuleHandleW(0);
  nt_system[0] = GetModuleHandleW(u"ntdll.dll");
  nt_system[1] = k32;
  nt_system[2] = kb;
  for (int t = 0; t < ARRAYLEN(nt_hooks); ++t) {
    for (struct HostNtHook *h = nt_hooks[t]; h->name; ++h) {
      if (kb)
        h->targets[0] = GetProcAddress(kb, h->name);
      if (k32)
        h->targets[1] = GetProcAddress(k32, h->name);
      h->real = h->targets[0] ? h->targets[0] : h->targets[1];
    }
  }
  if (!nt_real_w || !nt_real_a)
    return;

  // the block starts out as ours, changes made before now included
  char16_t *blk;
  if ((blk = GetEnvironmentStrings())) {
    char *buf = malloc(32767 * 3);
    char **vars = malloc(8192 * sizeof(char *));
    if (buf && vars) {
      int n = GetDosEnviron(blk, buf, 32767 * 3, vars, 8191,
                            __getcosmosdrive());
      for (int i = 0; i < n; ++i) {
        char *eq = strchr(vars[i], '=');
        if (!eq)
          continue;
        if (eq != vars[i] && !nt_find(vars[i], eq - vars[i])) {
          *eq = 0;
          nt_push(vars[i], 0);
          *eq = '=';
        }
      }
    }
    free(vars);
    free(buf);
    FreeEnvironmentStrings(blk);
  }
  for (char **p = environ; p && *p; ++p) {
    char *eq = strchr(*p, '=');
    if (!eq || eq == *p)
      continue;
    size_t k = eq - *p;
    char name[k + 1];
    memcpy(name, *p, k);
    name[k] = 0;
    nt_push(name, eq + 1);
  }

  nt_patch_all();
  long (*__msabi reg)(uint32_t, void *, void *, void **);
  intptr_t ntdll = nt_system[0];
  void *cookie;
  if (ntdll && (reg = GetProcAddress(ntdll, "LdrRegisterDllNotification")))
    reg(0, nt_notify, 0, &cookie);
  __hostlibc.envsync = true;
}

#endif /* __x86_64__ */

/**
 * Starts keeping the host libc's environment the same as ours. Called
 * by cosmo_dlopen() before it loads the first host library.
 */
void __host_env_init(void) {
  static pthread_once_t once = PTHREAD_ONCE_INIT;
#ifdef __x86_64__
  if (IsWindows())
    pthread_once(&once, nt_init);
#elif defined(__aarch64__)
  if (IsXnuSilicon())
    pthread_once(&once, xnu_init);
#endif
}

/**
 * Tells the host libc about a variable of ours that changed, or was
 * removed if `value` is null.
 */
void __host_setenv(const char *name, const char *value) {
  if (quiet)
    return;
#ifdef __aarch64__
  // a null name is clearenv()
  if (!name) {
    if (__hostlibc.envsync && IsXnuSilicon())
      xnu_publish();
    return;
  }
#else
  if (!name)
    return;
#endif
  if (IsLinux()) {
    if (__hostlibc.dual)
      __host_setenv_glibc(name, value);
#ifdef __x86_64__
  } else if (IsWindows()) {
    if (__hostlibc.envsync)
      nt_push(name, value);
#elif defined(__aarch64__)
  } else if (IsXnuSilicon()) {
    if (__hostlibc.envsync)
      xnu_publish();
#endif
  }
}

/**
 * Brings in changes the host libc made to its environment, where that
 * isn't seen as it happens.
 */
void __host_env_pull(void) {
#ifdef __aarch64__
  if (__hostlibc.envsync && IsXnuSilicon())
    xnu_pull();
#endif
}

/**
 * Brings the environment up to date with the host libc's, for callers
 * that read `environ` directly after running host code.
 */
void cosmo_envsync(void) {
  __host_env_pull();
}

/**
 * Returns whether `func` is one of the hooks here, which take the host's
 * calling convention.
 */
bool __host_env_hook(const void *func) {
#ifdef __x86_64__
  for (int t = 0; t < ARRAYLEN(nt_hooks); ++t)
    for (struct HostNtHook *h = nt_hooks[t]; h->name; ++h)
      if (h->hook == func)
        return true;
#endif
  return false;
}

/**
 * Returns the host's version of `sym` in place of an address of the
 * host's own, for the functions this file keeps an eye on.
 */
void *__host_env_sym(void *sym) {
#ifdef __x86_64__
  if (IsWindows() && sym)
    for (int t = 0; t < ARRAYLEN(nt_hooks); ++t)
      for (struct HostNtHook *h = nt_hooks[t]; h->name; ++h)
        for (int i = 0; i < 2; ++i)
          if (h->real && sym == h->targets[i])
            return h->hook;
#endif
  return sym;
}
