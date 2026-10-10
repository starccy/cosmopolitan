// The program cosmo_dlopen() loads, with the host's own ld.so, into an
// APE process on Linux and the BSDs. It never runs by itself: its main()
// hands the host libc's functions back to the APE and longjmps away. See
// foreign_setup() in libc/dlopen/dlopen.c.
//
// build.sh compiles this ahead of time for glibc and musl hosts. Other
// hosts compile the same text with their own cc at runtime, which is
// why it has to build cleanly with nothing but a C compiler and libc.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __GLIBC__
#include <dirent.h>
#include <ftw.h>
#include <glob.h>
#include <limits.h>
#include <locale.h>
#include <pthread.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <time.h>
#endif

#define HELPER_ABI 2

#define EXPORT __attribute__((__visibility__("default")))

#ifdef __GLIBC__

// The helper is the main program as far as ld.so can tell, so the
// allocator defined here replaces glibc's for every library the APE
// loads, and for glibc's own internal allocations too. Until the APE
// fills in `heap` a bump arena covers ld.so and libc starting up. What
// lands in the arena is never given back.

struct Heap {
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
  int (*sigaction)(int, const struct sigaction *, struct sigaction *);
  const char *(*pathmap)(const char *, char *, size_t);
  int remaps;
};

static struct Heap heap;
static _Alignas(64) char arena[1 << 20];
static size_t arena_used;

static int in_arena(void *p) {
  return (char *)p >= arena && (char *)p < arena + sizeof(arena);
}

static void *arena_alloc(size_t align, size_t n) {
  size_t p;
  if (align < 16)
    align = 16;
  if (n > sizeof(arena) || align > sizeof(arena))
    return 0;
  p = (arena_used + sizeof(size_t) + align - 1) & -align;
  if (p + n > sizeof(arena))
    return 0;
  arena_used = p + n;
  ((size_t *)(arena + p))[-1] = n;
  return arena + p;
}

static void copy(char *d, const char *s, size_t n) {
  while (n--)
    *d++ = *s++;
}

EXPORT void *malloc(size_t n) {
  void *p;
  if (heap.malloc)
    return heap.malloc(n);
  if (!(p = arena_alloc(16, n)))
    errno = ENOMEM;
  return p;
}

EXPORT void free(void *p) {
  if (p && !in_arena(p) && heap.free)
    heap.free(p);
}

EXPORT void *calloc(size_t n, size_t m) {
  size_t z;
  if (__builtin_mul_overflow(n, m, &z)) {
    errno = ENOMEM;
    return 0;
  }
  if (heap.calloc)
    return heap.calloc(n, m);
  return malloc(z);
}

EXPORT void *realloc(void *p, size_t n) {
  void *q;
  size_t old;
  if (p && in_arena(p)) {
    old = ((size_t *)p)[-1];
    if ((q = malloc(n)))
      copy(q, p, old < n ? old : n);
    return q;
  }
  if (heap.realloc)
    return heap.realloc(p, n);
  return malloc(n);
}

EXPORT void *memalign(size_t align, size_t n) {
  void *p;
  if (heap.memalign)
    return heap.memalign(align, n);
  if (!(p = arena_alloc(align, n)))
    errno = ENOMEM;
  return p;
}

EXPORT void *__libc_memalign(size_t align, size_t n) {
  return memalign(align, n);
}

EXPORT void *aligned_alloc(size_t align, size_t n) {
  return memalign(align, n);
}

EXPORT int posix_memalign(void **pp, size_t align, size_t n) {
  void *p;
  if (!align || (align & (align - 1)) || align % sizeof(void *))
    return EINVAL;
  if (!(p = memalign(align, n)))
    return ENOMEM;
  *pp = p;
  return 0;
}

EXPORT void *valloc(size_t n) {
  return memalign(getpagesize(), n);
}

EXPORT void *pvalloc(size_t n) {
  size_t ps = getpagesize();
  return memalign(ps, (n + ps - 1) & -ps);
}

EXPORT size_t malloc_usable_size(void *p) {
  if (!p)
    return 0;
  if (in_arena(p))
    return ((size_t *)p)[-1];
  return heap.usable(p);
}

// a library calling exit() gets the APE's exit(), which runs the APE's
// atexit handlers and then comes back to glibc's for the rest

static void (*real_exit)(int);

EXPORT void exit(int rc) {
  if (heap.exit)
    heap.exit(rc);
  real_exit(rc);
  __builtin_unreachable();
}

// glibc hands a new thread the thread block of a dead one out of its
// stack cache, with the word where the APE keeps its per-thread state
// (see libc/sysv/tlsasm.S) still set. So threads started through here begin by
// clearing it. The APE turns the stack cache off for the threads glibc
// starts internally.

struct Start {
  void *(*func)(void *);
  void *arg;
};

static int (*real_pthread_create)(pthread_t *, const pthread_attr_t *,
                                  void *(*)(void *), void *);
void *__libc_malloc(size_t);
void __libc_free(void *);

static void *start(void *p) {
  struct Start s = *(struct Start *)p;
  __libc_free(p);
#ifdef __x86_64__
  __asm__ volatile("movq\t$0,%%fs:0x38" : : : "memory");
#elif defined(__aarch64__)
  void **tp;
  __asm__ volatile("mrs\t%0, tpidr_el0" : "=r"(tp));
  tp[1] = 0;
#endif
  return s.func(s.arg);
}

EXPORT int pthread_create(pthread_t *th, const pthread_attr_t *attr,
                          void *(*func)(void *), void *arg) {
  int rc;
  struct Start *s;
  if (!(s = __libc_malloc(sizeof(*s))))
    return EAGAIN;
  s->func = func;
  s->arg = arg;
  if ((rc = real_pthread_create(th, attr, start, s)))
    __libc_free(s);
  return rc;
}

// there's one environment and one signal table, the APE's, which copies
// changes back into glibc's environ for the libraries to read

static int (*real_setenv)(const char *, const char *, int);
static int (*real_unsetenv)(const char *);
static int (*real_putenv)(char *);
static int (*real_sigaction)(int, const struct sigaction *,
                             struct sigaction *);

EXPORT int setenv(const char *name, const char *value, int overwrite) {
  if (heap.setenv)
    return heap.setenv(name, value, overwrite);
  return real_setenv(name, value, overwrite);
}

EXPORT int unsetenv(const char *name) {
  if (heap.unsetenv)
    return heap.unsetenv(name);
  return real_unsetenv(name);
}

EXPORT int putenv(char *s) {
  if (heap.putenv)
    return heap.putenv(s);
  return real_putenv(s);
}

extern char **environ;

// glibc's clearenv() drops environ without going through unsetenv(),
// so the variables are removed one by one, through ours
EXPORT int clearenv(void) {
  char name[256];
  if (!heap.unsetenv) {
    environ = 0;
    return 0;
  }
  while (environ && *environ) {
    const char *e = *environ;
    size_t n = strcspn(e, "=");
    char **before = environ;
    const char *first = *environ;
    if (n >= sizeof(name)) {
      environ = 0;
      break;
    }
    memcpy(name, e, n);
    name[n] = 0;
    heap.unsetenv(name);
    if (environ == before && environ && *environ == first)
      real_unsetenv(name);
    if (environ == before && environ && *environ == first)
      break;
  }
  return 0;
}

EXPORT int sigaction(int sig, const struct sigaction *act,
                     struct sigaction *old) {
  if (heap.sigaction)
    return heap.sigaction(sig, act, old);
  return real_sigaction(sig, act, old);
}

static void (*install(int sig, void (*h)(int), int flags))(int) {
  struct sigaction sa, old;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = h;
  sa.sa_flags = flags;
  if (!(flags & SA_NODEFER))
    sigaddset(&sa.sa_mask, sig);
  if (sigaction(sig, &sa, &old) == -1)
    return SIG_ERR;
  return old.sa_handler;
}

EXPORT void (*signal(int sig, void (*h)(int)))(int) {
  return install(sig, h, SA_RESTART);
}

EXPORT void (*bsd_signal(int sig, void (*h)(int)))(int) {
  return install(sig, h, SA_RESTART);
}

EXPORT void (*sysv_signal(int sig, void (*h)(int)))(int) {
  return install(sig, h, SA_RESETHAND | SA_NODEFER);
}

// libraries see the APE's zip store: the APE hands a path it serves
// back as /proc/self/fd/N, which glibc then opens as usual. only paths
// under /zip are asked about, unless the APE maps other paths there too

#define MAP(path)                                                 \
  char mapbuf_[4096];                                             \
  if (heap.pathmap && path && path[0] == '/' &&                   \
      (heap.remaps || (path[1] == 'z' && path[2] == 'i' &&        \
                       path[3] == 'p' && (!path[4] || path[4] == '/')))) { \
    const char *m_ = heap.pathmap(path, mapbuf_, sizeof(mapbuf_)); \
    if (m_)                                                       \
      path = m_;                                                  \
  }

#define WRITES(flags) ((flags) & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC))

#define MAP_FOR_OPEN(path, flags)            \
  const char *orig_ = path;                  \
  MAP(path);                                 \
  if (path != orig_ && WRITES(flags)) {      \
    errno = EROFS;                           \
    return -1;                               \
  }

static int (*real_open)(const char *, int, ...);
static int (*real_openat)(int, const char *, int, ...);
static FILE *(*real_fopen)(const char *, const char *);
static int (*real_access)(const char *, int);
static char *(*real_realpath)(const char *, char *);
static int (*real_faccessat)(int, const char *, int, int);
static DIR *(*real_opendir)(const char *);
static int (*real_scandir)(const char *, struct dirent ***,
                           int (*)(const struct dirent *),
                           int (*)(const struct dirent **,
                                   const struct dirent **));
static int (*real_scandir64)(const char *, struct dirent64 ***,
                             int (*)(const struct dirent64 *),
                             int (*)(const struct dirent64 **,
                                     const struct dirent64 **));
static int (*real_nftw)(const char *,
                        int (*)(const char *, const struct stat *, int,
                                struct FTW *),
                        int, int);
static int (*real_nftw64)(const char *,
                          int (*)(const char *, const struct stat64 *, int,
                                  struct FTW *),
                          int, int);
static int (*real_glob)(const char *, int, int (*)(const char *, int),
                        glob_t *);
static int (*real_glob64)(const char *, int, int (*)(const char *, int),
                          glob64_t *);
static int (*real_fstatat)(int, const char *, struct stat *, int);
static int (*real_fxstatat)(int, int, const char *, struct stat *, int);
#ifdef STATX_TYPE
static int (*real_statx)(int, const char *, int, unsigned, struct statx *);
#endif
static int (*real_stat)(const char *, struct stat *);
static int (*real_lstat)(const char *, struct stat *);
static int (*real_xstat)(int, const char *, struct stat *);
static int (*real_lxstat)(int, const char *, struct stat *);

static int getmode(int flags, va_list va) {
  if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE)
    return va_arg(va, int);
  return 0;
}

EXPORT int open(const char *path, int flags, ...) {
  va_list va;
  va_start(va, flags);
  int mode = getmode(flags, va);
  va_end(va);
  MAP_FOR_OPEN(path, flags);
  return real_open(path, flags, mode);
}

EXPORT int open64(const char *path, int flags, ...) {
  va_list va;
  va_start(va, flags);
  int mode = getmode(flags, va);
  va_end(va);
  MAP_FOR_OPEN(path, flags);
  return real_open(path, flags, mode);
}

EXPORT int __open_2(const char *path, int flags) {
  MAP_FOR_OPEN(path, flags);
  return real_open(path, flags);
}

EXPORT int __open64_2(const char *path, int flags) {
  MAP_FOR_OPEN(path, flags);
  return real_open(path, flags);
}

EXPORT int openat(int dirfd, const char *path, int flags, ...) {
  va_list va;
  va_start(va, flags);
  int mode = getmode(flags, va);
  va_end(va);
  MAP_FOR_OPEN(path, flags);
  return real_openat(dirfd, path, flags, mode);
}

EXPORT int openat64(int dirfd, const char *path, int flags, ...) {
  va_list va;
  va_start(va, flags);
  int mode = getmode(flags, va);
  va_end(va);
  MAP_FOR_OPEN(path, flags);
  return real_openat(dirfd, path, flags, mode);
}

EXPORT int __openat_2(int dirfd, const char *path, int flags) {
  MAP_FOR_OPEN(path, flags);
  return real_openat(dirfd, path, flags);
}

EXPORT int __openat64_2(int dirfd, const char *path, int flags) {
  MAP_FOR_OPEN(path, flags);
  return real_openat(dirfd, path, flags);
}

static FILE *map_fopen(const char *path, const char *mode) {
  const char *orig = path;
  MAP(path);
  if (path != orig && mode[0] != 'r') {
    errno = EROFS;
    return 0;
  }
  return real_fopen(path, mode);
}

EXPORT FILE *fopen(const char *path, const char *mode) {
  return map_fopen(path, mode);
}

EXPORT FILE *fopen64(const char *path, const char *mode) {
  return map_fopen(path, mode);
}

// a path the zip store serves resolves to itself, since the file the
// host sees behind it is a copy with a /proc path
EXPORT char *realpath(const char *path, char *resolved) {
  const char *orig_ = path;
  MAP(path);
  if (path != orig_) {
    size_t n = strlen(orig_) + 1;
    if (n > PATH_MAX) {
      errno = ENAMETOOLONG;
      return 0;
    }
    if (!resolved && !(resolved = malloc(PATH_MAX)))
      return 0;
    memcpy(resolved, orig_, n);
    return resolved;
  }
  return real_realpath(path, resolved);
}

EXPORT int access(const char *path, int how) {
  const char *orig_ = path;
  MAP(path);
  if (path != orig_ && (how & W_OK)) {
    errno = EROFS;
    return -1;
  }
  return real_access(path, how);
}

EXPORT int faccessat(int dirfd, const char *path, int how, int flags) {
  const char *orig_ = path;
  MAP(path);
  if (path != orig_ && (how & W_OK)) {
    errno = EROFS;
    return -1;
  }
  return real_faccessat(dirfd, path, how, flags);
}

// glibc's own directory walkers open what they're given internally,
// past the open() above, so each gets the path already mapped

EXPORT DIR *opendir(const char *path) {
  MAP(path);
  return real_opendir(path);
}

EXPORT int scandir(const char *path, struct dirent ***list,
                   int (*sel)(const struct dirent *),
                   int (*cmp)(const struct dirent **, const struct dirent **)) {
  MAP(path);
  return real_scandir(path, list, sel, cmp);
}

EXPORT int scandir64(const char *path, struct dirent64 ***list,
                     int (*sel)(const struct dirent64 *),
                     int (*cmp)(const struct dirent64 **,
                                const struct dirent64 **)) {
  MAP(path);
  return real_scandir64(path, list, sel, cmp);
}

EXPORT int nftw(const char *path,
                int (*fn)(const char *, const struct stat *, int,
                          struct FTW *),
                int fds, int flags) {
  MAP(path);
  return real_nftw(path, fn, fds, flags);
}

EXPORT int nftw64(const char *path,
                  int (*fn)(const char *, const struct stat64 *, int,
                            struct FTW *),
                  int fds, int flags) {
  MAP(path);
  return real_nftw64(path, fn, fds, flags);
}

// a pattern is mapped by the directory before its first wildcard
static const char *map_pattern(const char *pat, char *buf, size_t size) {
  char dir[4096];
  size_t n = strcspn(pat, "*?[");
  if (pat[0] != '/' || !pat[n] || n >= sizeof(dir))
    return pat;
  while (n && pat[n - 1] != '/')
    --n;
  if (n <= 1)
    return pat;
  memcpy(dir, pat, n - 1);
  dir[n - 1] = 0;
  const char *d = dir;
  MAP(d);
  if (d == dir || strlen(d) + strlen(pat + n - 1) >= size)
    return pat;
  strcpy(buf, d);
  strcat(buf, pat + n - 1);
  return buf;
}

EXPORT int glob(const char *pat, int flags, int (*err)(const char *, int),
                glob_t *g) {
  char buf[4096];
  return real_glob(map_pattern(pat, buf, sizeof(buf)), flags, err, g);
}

EXPORT int glob64(const char *pat, int flags, int (*err)(const char *, int),
                  glob64_t *g) {
  char buf[4096];
  return real_glob64(map_pattern(pat, buf, sizeof(buf)), flags, err, g);
}

EXPORT int fstatat(int dirfd, const char *path, struct stat *st, int flags) {
  MAP(path);
  if (real_fstatat)
    return real_fstatat(dirfd, path, st, flags);
  return real_fxstatat(1, dirfd, path, st, flags);
}

EXPORT int fstatat64(int dirfd, const char *path, struct stat64 *st,
                     int flags) {
  return fstatat(dirfd, path, (struct stat *)st, flags);
}

EXPORT int __fxstatat(int ver, int dirfd, const char *path, struct stat *st,
                      int flags) {
  MAP(path);
  return real_fxstatat(ver, dirfd, path, st, flags);
}

EXPORT int __fxstatat64(int ver, int dirfd, const char *path,
                        struct stat64 *st, int flags) {
  return __fxstatat(ver, dirfd, path, (struct stat *)st, flags);
}

#ifdef STATX_TYPE
EXPORT int statx(int dirfd, const char *path, int flags, unsigned mask,
                 struct statx *st) {
  MAP(path);
  return real_statx(dirfd, path, flags, mask, st);
}
#endif

EXPORT int stat(const char *path, struct stat *st) {
  MAP(path);
  if (real_stat)
    return real_stat(path, st);
  return real_xstat(1, path, st);
}

EXPORT int stat64(const char *path, struct stat64 *st) {
  return stat(path, (struct stat *)st);
}

EXPORT int lstat(const char *path, struct stat *st) {
  MAP(path);
  if (real_lstat)
    return real_lstat(path, st);
  return real_lxstat(1, path, st);
}

EXPORT int lstat64(const char *path, struct stat64 *st) {
  return lstat(path, (struct stat *)st);
}

EXPORT int __xstat(int ver, const char *path, struct stat *st) {
  MAP(path);
  return real_xstat(ver, path, st);
}

EXPORT int __xstat64(int ver, const char *path, struct stat *st) {
  return __xstat(ver, path, st);
}

EXPORT int __lxstat(int ver, const char *path, struct stat *st) {
  MAP(path);
  return real_lxstat(ver, path, st);
}

EXPORT int __lxstat64(int ver, const char *path, struct stat *st) {
  return __lxstat(ver, path, st);
}

// a library that dlopen()s a path the zip store serves gets the copy
// the APE made of it. any other path goes to glibc's dlopen() by a tail
// call, since glibc searches the caller's RUNPATH and has to see the
// library as the caller

static void *(*real_dlopen)(const char *, int);

#if defined(__has_attribute) && __has_attribute(musttail)
#define MUSTTAIL __attribute__((musttail))
#else
#define MUSTTAIL
#endif

__attribute__((__noinline__)) static void *dlopen_mapped(const char *path,
                                                         int mode) {
  const char *orig_ = path;
  MAP(path);
  if (path == orig_)
    return (void *)-1;
  return real_dlopen(path, mode);
}

EXPORT void *dlopen(const char *path, int mode) {
  if (heap.pathmap && path && path[0] == '/') {
    void *h = dlopen_mapped(path, mode);
    if (h != (void *)-1)
      return h;
  }
  MUSTTAIL return real_dlopen(path, mode);
}

extern void *__dso_handle;
int __register_atfork(void (*)(void), void (*)(void), void (*)(void), void *);

static int atfork(void (*prepare)(void), void (*parent)(void),
                  void (*child)(void)) {
  return __register_atfork(prepare, parent, child, __dso_handle);
}

#endif /* __GLIBC__ */

static void say(const char *s) {
  (void)!write(2, s, strlen(s));
}

int main(int argc, char **argv) {
  long addr = 0;
  const char *p;
  if (argc != 2) {
    say(argv[0]);
    say(": not intended to be run directly\n");
    return 1;
  }
  for (p = argv[1]; *p; ++p) {
    if (*p < '0' || *p > '9') {
      say(argv[0]);
      say(": invalid function address\n");
      return 2;
    }
    addr = addr * 10 + (*p - '0');
  }
#ifdef __GLIBC__
  real_dlopen = dlsym(RTLD_NEXT, "dlopen");
  real_exit = (void (*)(int))dlsym(RTLD_NEXT, "exit");
  real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
  real_setenv = dlsym(RTLD_NEXT, "setenv");
  real_unsetenv = dlsym(RTLD_NEXT, "unsetenv");
  real_putenv = dlsym(RTLD_NEXT, "putenv");
  real_sigaction = dlsym(RTLD_NEXT, "sigaction");
  real_open = dlsym(RTLD_NEXT, "open");
  real_openat = dlsym(RTLD_NEXT, "openat");
  real_fopen = dlsym(RTLD_NEXT, "fopen");
  real_access = dlsym(RTLD_NEXT, "access");
  real_realpath = dlsym(RTLD_NEXT, "realpath");
  real_faccessat = dlsym(RTLD_NEXT, "faccessat");
  real_opendir = dlsym(RTLD_NEXT, "opendir");
  real_scandir = dlsym(RTLD_NEXT, "scandir");
  real_scandir64 = dlsym(RTLD_NEXT, "scandir64");
  real_nftw = dlsym(RTLD_NEXT, "nftw");
  real_nftw64 = dlsym(RTLD_NEXT, "nftw64");
  real_glob = dlsym(RTLD_NEXT, "glob");
  real_glob64 = dlsym(RTLD_NEXT, "glob64");
  real_fstatat = dlsym(RTLD_NEXT, "fstatat");  // glibc 2.33+
  real_fxstatat = dlsym(RTLD_NEXT, "__fxstatat");
#ifdef STATX_TYPE
  real_statx = dlsym(RTLD_NEXT, "statx");
#endif
  real_stat = dlsym(RTLD_NEXT, "stat");      // glibc 2.33+
  real_lstat = dlsym(RTLD_NEXT, "lstat");
  real_xstat = dlsym(RTLD_NEXT, "__xstat");  // before that
  real_lxstat = dlsym(RTLD_NEXT, "__lxstat");
#endif
  void *handoff[] = {
      (void *)HELPER_ABI,
#ifdef __GLIBC__
      real_dlopen,
#else
      dlopen,
#endif
      dlsym,
      dlclose,
      dlerror,
#ifdef __GLIBC__
      (void *)1,
      real_pthread_create,
      pthread_attr_init,
      pthread_attr_setstack,
      pthread_attr_setstacksize,
      pthread_attr_setdetachstate,
      pthread_attr_destroy,
      pthread_key_create,
      pthread_setspecific,
      pthread_getattr_np,
      pthread_attr_getstack,
      pthread_self,
      atfork,
      __errno_location,
      fork,
      real_exit,
      real_setenv,
      real_unsetenv,
      setlocale,
      tzset,
      fflush,
      setvbuf,
      &stdout,
      &heap,
#else
      (void *)2,
#endif
  };
  return ((int (*)(void **))addr)(handoff);
}
