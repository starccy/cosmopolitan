#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/dce.h"
#include "libc/dlopen/hostfile.internal.h"
#include "libc/limits.h"
#include "libc/macros.h"
#include "libc/mem/mem.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/runtime/syslib.internal.h"
#include "libc/str/str.h"
#include "libc/thread/thread.h"

// Lets host libraries open what the zip store serves, by the same paths
// we use. On Linux the dlopen helper does it, see helper.c. Here that's
// done by pointing the host library's imports of the file functions at
// ours, which give the host the path of a copy, see hostpath.c.
//
// On Windows every module but ours and the system's own gets its import
// address table entries patched, along with the rest, in hostenv.c. The
// paths looked at are the ones rooted without a drive, like /zip/x or
// \zip\x, which the C runtime passes to CreateFileW() as they are.
//
// On MacOS the library's symbol pointers are rebound, for each image
// dyld loads that isn't part of the shared cache.

const char *__host_pathmap(const char *, char *, size_t);
bool __host_pathmap_remaps(void);

// whether paths outside /zip can map into the zip store, see zipos-remap.c
static bool file_remaps;

// maps a unix path, where a last component with wildcards in it is kept
// as it is and the directory before it is mapped
static dontinline bool file_map(char *path, char out[PATH_MAX]) {
  char *slash;
  if (__host_pathmap(path, out, PATH_MAX))
    return true;
  if (!(slash = strrchr(path, '/')) || !strpbrk(slash + 1, "*?"))
    return false;
  *slash = 0;
  bool ok = slash > path && __host_pathmap(path, out, PATH_MAX);
  *slash = '/';
  if (!ok || strlen(out) + strlen(slash) >= PATH_MAX)
    return false;
  strcat(out, slash);
  return true;
}

#ifdef __x86_64__

typedef int64_t __msabi (*CreateFileW_f)(const char16_t *, uint32_t, uint32_t,
                                         void *, uint32_t, uint32_t, int64_t);
typedef int64_t __msabi (*CreateFileA_f)(const char *, uint32_t, uint32_t,
                                         void *, uint32_t, uint32_t, int64_t);
typedef int64_t __msabi (*CreateFile2_f)(const char16_t *, uint32_t, uint32_t,
                                         uint32_t, void *);
typedef uint32_t __msabi (*GetAttrW_f)(const char16_t *);
typedef uint32_t __msabi (*GetAttrA_f)(const char *);
typedef bool32 __msabi (*GetAttrExW_f)(const char16_t *, int, void *);
typedef bool32 __msabi (*GetAttrExA_f)(const char *, int, void *);
typedef int64_t __msabi (*FindFirstW_f)(const char16_t *, void *);
typedef int64_t __msabi (*FindFirstExW_f)(const char16_t *, int, void *, int,
                                          void *, uint32_t);
typedef uint32_t __msabi (*FullPathW_f)(const char16_t *, uint32_t,
                                        char16_t *, char16_t **);
typedef int64_t __msabi (*LoadW_f)(const char16_t *);
typedef int64_t __msabi (*LoadA_f)(const char *);
typedef int64_t __msabi (*LoadExW_f)(const char16_t *, int64_t, uint32_t);
typedef int64_t __msabi (*LoadExA_f)(const char *, int64_t, uint32_t);

enum {
  kCreateFileW,
  kCreateFileA,
  kCreateFile2,
  kGetAttrW,
  kGetAttrA,
  kGetAttrExW,
  kGetAttrExA,
  kFindFirstW,
  kFindFirstExW,
  kFullPathW,
  kLoadW,
  kLoadA,
  kLoadExW,
  kLoadExA,
};

#define REAL(i, T) ((T)__host_nt_file_hooks[i].real)

// whether the host could mean a path the zip store serves: one rooted
// without a drive, and not a unc or device path
static bool nt_maybe16(const char16_t *p) {
  if (!p || (p[0] != '/' && p[0] != '\\') || p[1] == '/' || p[1] == '\\')
    return false;
  return file_remaps || (p[1] == 'z' && p[2] == 'i' && p[3] == 'p' &&
                         (!p[4] || p[4] == '/' || p[4] == '\\'));
}

static bool nt_maybe8(const char *p) {
  if (!p || (p[0] != '/' && p[0] != '\\') || p[1] == '/' || p[1] == '\\')
    return false;
  return file_remaps || (p[1] == 'z' && p[2] == 'i' && p[3] == 'p' &&
                         (!p[4] || p[4] == '/' || p[4] == '\\'));
}

// the copy's dos path, in utf-16, for the unix path in `u`
static dontinline bool nt_map(char u[PATH_MAX], char16_t out[PATH_MAX]) {
  char m[PATH_MAX], d[PATH_MAX];
  for (char *q = u; *q; ++q)
    if (*q == '\\')
      *q = '/';
  if (!file_map(u, m))
    return false;
  int n = __unixtodospath(m, d, sizeof(d));
  if (n == -1 || n >= PATH_MAX)
    return false;
  d[n] = 0;
  return tprecode8to16(out, PATH_MAX, d).ax < PATH_MAX - 1;
}

static dontinline bool nt_map16(const char16_t *p, char16_t out[PATH_MAX]) {
  char u[PATH_MAX];
  if (tprecode16to8(u, sizeof(u), p).ax >= PATH_MAX - 1)
    return false;
  return nt_map(u, out);
}

static dontinline bool nt_map8(const char *p, char16_t out[PATH_MAX]) {
  char u[PATH_MAX];
  if (strlcpy(u, p, sizeof(u)) >= sizeof(u))
    return false;
  return nt_map(u, out);
}

__msabi static int64_t nt_CreateFileW(const char16_t *p, uint32_t a,
                                      uint32_t s, void *sa, uint32_t d,
                                      uint32_t f, int64_t t) {
  char16_t b[PATH_MAX];
  if (nt_maybe16(p) && nt_map16(p, b))
    p = b;
  return REAL(kCreateFileW, CreateFileW_f)(p, a, s, sa, d, f, t);
}

__msabi static int64_t nt_CreateFileA(const char *p, uint32_t a, uint32_t s,
                                      void *sa, uint32_t d, uint32_t f,
                                      int64_t t) {
  char16_t b[PATH_MAX];
  if (nt_maybe8(p) && nt_map8(p, b))
    return REAL(kCreateFileW, CreateFileW_f)(b, a, s, sa, d, f, t);
  return REAL(kCreateFileA, CreateFileA_f)(p, a, s, sa, d, f, t);
}

__msabi static int64_t nt_CreateFile2(const char16_t *p, uint32_t a,
                                      uint32_t s, uint32_t d, void *x) {
  char16_t b[PATH_MAX];
  if (nt_maybe16(p) && nt_map16(p, b))
    p = b;
  return REAL(kCreateFile2, CreateFile2_f)(p, a, s, d, x);
}

__msabi static uint32_t nt_GetAttrW(const char16_t *p) {
  char16_t b[PATH_MAX];
  if (nt_maybe16(p) && nt_map16(p, b))
    p = b;
  return REAL(kGetAttrW, GetAttrW_f)(p);
}

__msabi static uint32_t nt_GetAttrA(const char *p) {
  char16_t b[PATH_MAX];
  if (nt_maybe8(p) && nt_map8(p, b))
    return REAL(kGetAttrW, GetAttrW_f)(b);
  return REAL(kGetAttrA, GetAttrA_f)(p);
}

__msabi static bool32 nt_GetAttrExW(const char16_t *p, int l, void *x) {
  char16_t b[PATH_MAX];
  if (nt_maybe16(p) && nt_map16(p, b))
    p = b;
  return REAL(kGetAttrExW, GetAttrExW_f)(p, l, x);
}

// WIN32_FILE_ATTRIBUTE_DATA has no strings, so the w function will do
__msabi static bool32 nt_GetAttrExA(const char *p, int l, void *x) {
  char16_t b[PATH_MAX];
  if (nt_maybe8(p) && nt_map8(p, b))
    return REAL(kGetAttrExW, GetAttrExW_f)(b, l, x);
  return REAL(kGetAttrExA, GetAttrExA_f)(p, l, x);
}

__msabi static int64_t nt_FindFirstW(const char16_t *p, void *x) {
  char16_t b[PATH_MAX];
  if (nt_maybe16(p) && nt_map16(p, b))
    p = b;
  return REAL(kFindFirstW, FindFirstW_f)(p, x);
}

__msabi static int64_t nt_FindFirstExW(const char16_t *p, int l, void *x,
                                       int o, void *f, uint32_t g) {
  char16_t b[PATH_MAX];
  if (nt_maybe16(p) && nt_map16(p, b))
    p = b;
  return REAL(kFindFirstExW, FindFirstExW_f)(p, l, x, o, f, g);
}

__msabi static uint32_t nt_FullPathW(const char16_t *p, uint32_t n,
                                     char16_t *out, char16_t **part) {
  char16_t b[PATH_MAX];
  if (nt_maybe16(p) && nt_map16(p, b))
    p = b;
  return REAL(kFullPathW, FullPathW_f)(p, n, out, part);
}

// a path of ours, rooted without a drive, in the dos way. the other file
// functions take forward slashes, the loader doesn't
static dontinline bool nt_dos(const char *u, char16_t out[PATH_MAX]) {
  char d[PATH_MAX];
  if (u[0] != '/' || u[1] == '/' || strchr(u, ':'))
    return false;
  int n = __unixtodospath(u, d, sizeof(d));
  if (n == -1 || n >= PATH_MAX)
    return false;
  return tprecode8to16(out, PATH_MAX, d).ax < PATH_MAX - 1;
}

static dontinline bool nt_load16(const char16_t *p, char16_t out[PATH_MAX]) {
  char u[PATH_MAX];
  if (!p || p[0] != '/')
    return false;
  if (nt_maybe16(p) && nt_map16(p, out))
    return true;
  return tprecode16to8(u, sizeof(u), p).ax < PATH_MAX - 1 && nt_dos(u, out);
}

static dontinline bool nt_load8(const char *p, char16_t out[PATH_MAX]) {
  if (!p || p[0] != '/')
    return false;
  if (nt_maybe8(p) && nt_map8(p, out))
    return true;
  return nt_dos(p, out);
}

__msabi static int64_t nt_LoadW(const char16_t *p) {
  char16_t b[PATH_MAX];
  if (nt_load16(p, b))
    p = b;
  return REAL(kLoadW, LoadW_f)(p);
}

__msabi static int64_t nt_LoadA(const char *p) {
  char16_t b[PATH_MAX];
  if (nt_load8(p, b))
    return REAL(kLoadW, LoadW_f)(b);
  return REAL(kLoadA, LoadA_f)(p);
}

__msabi static int64_t nt_LoadExW(const char16_t *p, int64_t h, uint32_t f) {
  char16_t b[PATH_MAX];
  if (nt_load16(p, b))
    p = b;
  return REAL(kLoadExW, LoadExW_f)(p, h, f);
}

__msabi static int64_t nt_LoadExA(const char *p, int64_t h, uint32_t f) {
  char16_t b[PATH_MAX];
  if (nt_load8(p, b))
    return REAL(kLoadExW, LoadExW_f)(b, h, f);
  return REAL(kLoadExA, LoadExA_f)(p, h, f);
}

struct HostNtHook __host_nt_file_hooks[] = {
    [kCreateFileW] = {"CreateFileW", nt_CreateFileW},
    [kCreateFileA] = {"CreateFileA", nt_CreateFileA},
    [kCreateFile2] = {"CreateFile2", nt_CreateFile2},
    [kGetAttrW] = {"GetFileAttributesW", nt_GetAttrW},
    [kGetAttrA] = {"GetFileAttributesA", nt_GetAttrA},
    [kGetAttrExW] = {"GetFileAttributesExW", nt_GetAttrExW},
    [kGetAttrExA] = {"GetFileAttributesExA", nt_GetAttrExA},
    [kFindFirstW] = {"FindFirstFileW", nt_FindFirstW},
    [kFindFirstExW] = {"FindFirstFileExW", nt_FindFirstExW},
    [kFullPathW] = {"GetFullPathNameW", nt_FullPathW},
    [kLoadW] = {"LoadLibraryW", nt_LoadW},
    [kLoadA] = {"LoadLibraryA", nt_LoadA},
    [kLoadExW] = {"LoadLibraryExW", nt_LoadExW},
    [kLoadExA] = {"LoadLibraryExA", nt_LoadExA},
    {0},
};

#endif /* __x86_64__ */

#ifdef __aarch64__

struct XnuHeader {
  uint32_t magic;
  int32_t cputype;
  int32_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
  uint32_t reserved;
};

struct XnuLoadCommand {
  uint32_t cmd;
  uint32_t cmdsize;
};

struct XnuSegment {
  uint32_t cmd;
  uint32_t cmdsize;
  char segname[16];
  uint64_t vmaddr;
  uint64_t vmsize;
  uint64_t fileoff;
  uint64_t filesize;
  int32_t maxprot;
  int32_t initprot;
  uint32_t nsects;
  uint32_t flags;
};

struct XnuSection {
  char sectname[16];
  char segname[16];
  uint64_t addr;
  uint64_t size;
  uint32_t offset;
  uint32_t align;
  uint32_t reloff;
  uint32_t nreloc;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;
  uint32_t reserved3;
};

struct XnuSymtab {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t symoff;
  uint32_t nsyms;
  uint32_t stroff;
  uint32_t strsize;
};

struct XnuDysymtab {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t ilocalsym, nlocalsym;
  uint32_t iextdefsym, nextdefsym;
  uint32_t iundefsym, nundefsym;
  uint32_t tocoff, ntoc;
  uint32_t modtaboff, nmodtab;
  uint32_t extrefsymoff, nextrefsyms;
  uint32_t indirectsymoff, nindirectsyms;
  uint32_t extreloff, nextrel;
  uint32_t locreloff, nlocrel;
};

struct XnuNlist {
  uint32_t n_strx;
  uint8_t n_type;
  uint8_t n_sect;
  uint16_t n_desc;
  uint64_t n_value;
};

#define XNU_MH_DYLIB            6
#define XNU_MH_BUNDLE           8
#define XNU_MH_DYLIB_IN_CACHE   0x80000000u
#define XNU_LC_SEGMENT_64       0x19
#define XNU_LC_SYMTAB           0x2
#define XNU_LC_DYSYMTAB         0xb
#define XNU_S_NON_LAZY_POINTERS 0x6
#define XNU_S_LAZY_POINTERS     0x7
#define XNU_INDIRECT_LOCAL      0x80000000u
#define XNU_INDIRECT_ABS        0x40000000u
#define XNU_SG_READ_ONLY        0x10

typedef int (*open_f)(const char *, int, long, long, long, long, long, long,
                      long);
typedef int (*openat_f)(int, const char *, int, long, long, long, long, long,
                        long);
typedef void *(*fopen_f)(const char *, const char *);
typedef int (*stat_f)(const char *, void *);
typedef int (*fstatat_f)(int, const char *, void *, int);
typedef int (*access_f)(const char *, int);
typedef int (*faccessat_f)(int, const char *, int, int);
typedef void *(*opendir_f)(const char *);
typedef int (*scandir_f)(const char *, void *, void *, void *);
typedef char *(*realpath_f)(const char *, char *);

enum {
  kOpen,
  kOpenat,
  kFopen,
  kStat,
  kLstat,
  kFstatat,
  kAccess,
  kFaccessat,
  kOpendir,
  kScandir,
  kRealpath,
  kDlopen,
  kXnuHooks,
};

static struct {
  const char *sym;  // as the image's symbol table spells it
  void *hook;
  void *real;
} xnu_hooks[kXnuHooks];

static int (*xnu_mprotect)(void *, size_t, int);

#define XREAL(i, T) ((T)xnu_hooks[i].real)

static bool xnu_maybe(const char *p) {
  return p && p[0] == '/' &&
         (file_remaps || (p[1] == 'z' && p[2] == 'i' && p[3] == 'p' &&
                          (!p[4] || p[4] == '/')));
}

static dontinline bool xnu_map(const char *p, char out[PATH_MAX]) {
  char u[PATH_MAX];
  if (strlcpy(u, p, sizeof(u)) >= sizeof(u))
    return false;
  return file_map(u, out);
}

// open() and openat() take the mode as a variadic argument, which the
// host's arm64 abi passes on the stack. the ninth argument of a
// function that isn't variadic lands there as well
static int xnu_open(const char *p, int f, long r2, long r3, long r4, long r5,
                    long r6, long r7, long mode) {
  char b[PATH_MAX];
  if (xnu_maybe(p) && xnu_map(p, b))
    p = b;
  return XREAL(kOpen, open_f)(p, f, 0, 0, 0, 0, 0, 0, mode);
}

static int xnu_openat(int fd, const char *p, int f, long r3, long r4, long r5,
                      long r6, long r7, long mode) {
  char b[PATH_MAX];
  if (xnu_maybe(p) && xnu_map(p, b))
    p = b;
  return XREAL(kOpenat, openat_f)(fd, p, f, 0, 0, 0, 0, 0, mode);
}

static void *xnu_fopen(const char *p, const char *m) {
  char b[PATH_MAX];
  if (xnu_maybe(p) && xnu_map(p, b))
    p = b;
  return XREAL(kFopen, fopen_f)(p, m);
}

static int xnu_stat(const char *p, void *st) {
  char b[PATH_MAX];
  if (xnu_maybe(p) && xnu_map(p, b))
    p = b;
  return XREAL(kStat, stat_f)(p, st);
}

static int xnu_lstat(const char *p, void *st) {
  char b[PATH_MAX];
  if (xnu_maybe(p) && xnu_map(p, b))
    p = b;
  return XREAL(kLstat, stat_f)(p, st);
}

static int xnu_fstatat(int fd, const char *p, void *st, int f) {
  char b[PATH_MAX];
  if (xnu_maybe(p) && xnu_map(p, b))
    p = b;
  return XREAL(kFstatat, fstatat_f)(fd, p, st, f);
}

static int xnu_access(const char *p, int m) {
  char b[PATH_MAX];
  if (xnu_maybe(p) && xnu_map(p, b))
    p = b;
  return XREAL(kAccess, access_f)(p, m);
}

static int xnu_faccessat(int fd, const char *p, int m, int f) {
  char b[PATH_MAX];
  if (xnu_maybe(p) && xnu_map(p, b))
    p = b;
  return XREAL(kFaccessat, faccessat_f)(fd, p, m, f);
}

static void *xnu_opendir(const char *p) {
  char b[PATH_MAX];
  if (xnu_maybe(p) && xnu_map(p, b))
    p = b;
  return XREAL(kOpendir, opendir_f)(p);
}

static int xnu_scandir(const char *p, void *l, void *s, void *c) {
  char b[PATH_MAX];
  if (xnu_maybe(p) && xnu_map(p, b))
    p = b;
  return XREAL(kScandir, scandir_f)(p, l, s, c);
}

static char *xnu_realpath(const char *p, char *r) {
  char b[PATH_MAX];
  if (xnu_maybe(p) && xnu_map(p, b))
    p = b;
  return XREAL(kRealpath, realpath_f)(p, r);
}

// paths handed to dlopen() have to outlive the call, so each one mapped
// is kept
static struct Kept {
  struct Kept *next;
  char path[];
} *xnu_kept;
static pthread_mutex_t xnu_kept_lock = PTHREAD_MUTEX_INITIALIZER;

const char *__xnu_dlopen_map(const char *p) {
  char b[PATH_MAX];
  struct Kept *k;
  if (!xnu_maybe(p) || !xnu_map(p, b))
    return 0;
  pthread_mutex_lock(&xnu_kept_lock);
  for (k = xnu_kept; k; k = k->next)
    if (!strcmp(k->path, b))
      break;
  if (!k && (k = malloc(sizeof(*k) + strlen(b) + 1))) {
    strcpy(k->path, b);
    k->next = xnu_kept;
    xnu_kept = k;
  }
  pthread_mutex_unlock(&xnu_kept_lock);
  return k ? k->path : 0;
}

void *__xnu_real_dlopen;
void __xnu_hook_dlopen(void);

// dyld finds the calling image for @rpath and @loader_path by the
// return address, so the call to the real dlopen() is a tail call made
// from the caller's frame
__asm__(".text\n"
        ".balign\t4\n"
        "__xnu_hook_dlopen:\n\t"
        "stp\tx29,x30,[sp,#-32]!\n\t"
        "mov\tx29,sp\n\t"
        "stp\tx0,x1,[sp,#16]\n\t"
        "bl\t__xnu_dlopen_map\n\t"
        "mov\tx2,x0\n\t"
        "ldp\tx0,x1,[sp,#16]\n\t"
        "cbz\tx2,1f\n\t"
        "mov\tx0,x2\n"
        "1:\tldp\tx29,x30,[sp],#32\n\t"
        "adrp\tx16,__xnu_real_dlopen\n\t"
        "ldr\tx16,[x16,#:lo12:__xnu_real_dlopen]\n\t"
        "br\tx16\n");

static void xnu_patch(void **slot, bool readonly, void *hook) {
  uintptr_t page = (uintptr_t)slot & -16384ul;
  if (*slot == hook)
    return;
  if (readonly && xnu_mprotect((void *)page, 16384, 3))
    return;
  __atomic_store_n(slot, hook, __ATOMIC_RELAXED);
  if (readonly)
    xnu_mprotect((void *)page, 16384, 1);
}

// points the image's symbol pointers for the functions above at ours
static void xnu_rebind(const struct XnuHeader *mh, intptr_t slide) {
  const struct XnuSegment *linkedit = 0;
  const struct XnuSymtab *symtab = 0;
  const struct XnuDysymtab *dysymtab = 0;
  const struct XnuLoadCommand *lc;
  uint32_t i;
  if (mh->filetype != XNU_MH_DYLIB && mh->filetype != XNU_MH_BUNDLE)
    return;
  if (mh->flags & XNU_MH_DYLIB_IN_CACHE)
    return;
  lc = (const void *)(mh + 1);
  for (i = 0; i < mh->ncmds; ++i) {
    if (lc->cmd == XNU_LC_SEGMENT_64 &&
        !strncmp(((const struct XnuSegment *)lc)->segname, "__LINKEDIT", 16))
      linkedit = (const void *)lc;
    else if (lc->cmd == XNU_LC_SYMTAB)
      symtab = (const void *)lc;
    else if (lc->cmd == XNU_LC_DYSYMTAB)
      dysymtab = (const void *)lc;
    lc = (const void *)((const char *)lc + lc->cmdsize);
  }
  if (!linkedit || !symtab || !dysymtab || !dysymtab->nindirectsyms)
    return;
  const char *base = (const char *)slide + linkedit->vmaddr - linkedit->fileoff;
  const struct XnuNlist *syms = (const void *)(base + symtab->symoff);
  const char *strs = base + symtab->stroff;
  const uint32_t *indirect = (const void *)(base + dysymtab->indirectsymoff);
  lc = (const void *)(mh + 1);
  for (i = 0; i < mh->ncmds; ++i) {
    if (lc->cmd == XNU_LC_SEGMENT_64) {
      const struct XnuSegment *seg = (const void *)lc;
      const struct XnuSection *sec = (const void *)(seg + 1);
      // dyld makes these read-only once it has bound them, whatever
      // the load command says
      bool readonly = !(seg->initprot & 2) || (seg->flags & XNU_SG_READ_ONLY) ||
                      !strncmp(seg->segname, "__DATA_CONST", 16) ||
                      !strncmp(seg->segname, "__AUTH_CONST", 16);
      for (uint32_t j = 0; j < seg->nsects; ++j, ++sec) {
        uint32_t type = sec->flags & 0xff;
        if (type != XNU_S_NON_LAZY_POINTERS && type != XNU_S_LAZY_POINTERS)
          continue;
        void **slots = (void **)(slide + sec->addr);
        for (uint64_t k = 0; k < sec->size / sizeof(void *); ++k) {
          if (sec->reserved1 + k >= dysymtab->nindirectsyms)
            break;
          uint32_t s = indirect[sec->reserved1 + k];
          if ((s & (XNU_INDIRECT_LOCAL | XNU_INDIRECT_ABS)) ||
              s >= symtab->nsyms)
            continue;
          const char *name = strs + syms[s].n_strx;
          for (int h = 0; h < kXnuHooks; ++h)
            if (xnu_hooks[h].real && !strcmp(name, xnu_hooks[h].sym))
              xnu_patch(slots + k, readonly, xnu_hooks[h].hook);
        }
      }
    }
    lc = (const void *)((const char *)lc + lc->cmdsize);
  }
}

static void xnu_init(void) {
  static const struct {
    int i;
    const char *sym;
    void *hook;
  } kHooks[] = {
      {kOpen, "_open", xnu_open},
      {kOpenat, "_openat", xnu_openat},
      {kFopen, "_fopen", xnu_fopen},
      {kStat, "_stat", xnu_stat},
      {kLstat, "_lstat", xnu_lstat},
      {kFstatat, "_fstatat", xnu_fstatat},
      {kAccess, "_access", xnu_access},
      {kFaccessat, "_faccessat", xnu_faccessat},
      {kOpendir, "_opendir", xnu_opendir},
      {kScandir, "_scandir", xnu_scandir},
      {kRealpath, "_realpath$DARWIN_EXTSN", xnu_realpath},
      {kDlopen, "_dlopen", __xnu_hook_dlopen},
  };
  void (*reg)(void (*)(const struct XnuHeader *, intptr_t));
  if (!(xnu_mprotect = __syslib->__dlsym((void *)-2, "mprotect")))
    return;
  if (!(reg = __syslib->__dlsym((void *)-2,
                                "_dyld_register_func_for_add_image")))
    return;
  for (int i = 0; i < ARRAYLEN(kHooks); ++i) {
    xnu_hooks[kHooks[i].i].sym = kHooks[i].sym;
    xnu_hooks[kHooks[i].i].hook = kHooks[i].hook;
    // the real function goes by the name without dyld's underscore
    xnu_hooks[kHooks[i].i].real =
        __syslib->__dlsym((void *)-2, kHooks[i].sym + 1);
  }
  __xnu_real_dlopen = xnu_hooks[kDlopen].real;
  if (!__xnu_real_dlopen)
    xnu_hooks[kDlopen].real = 0;
  // runs for the images already loaded, then for each one loaded later
  reg(xnu_rebind);
}

#endif /* __aarch64__ */

/**
 * Starts giving host libraries copies of what the zip store serves when
 * they open its paths themselves. Called by cosmo_dlopen() before it
 * loads the first host library.
 */
void __host_file_init(void) {
  static pthread_once_t once = PTHREAD_ONCE_INIT;
  file_remaps = __host_pathmap_remaps();
#ifdef __aarch64__
  if (IsXnuSilicon())
    pthread_once(&once, xnu_init);
#else
  (void)once;
#endif
}
