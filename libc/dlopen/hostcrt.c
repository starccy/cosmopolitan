#include "libc/calls/calls.h"
#include "libc/calls/state.internal.h"
#include "libc/calls/struct/stat.h"
#include "libc/calls/struct/timespec.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/dce.h"
#include "libc/dlopen/dlfcn.h"
#include "libc/dlopen/hostfile.internal.h"
#include "libc/errno.h"
#include "libc/intrin/fds.h"
#include "libc/intrin/strace.h"
#include "libc/limits.h"
#include "libc/macros.h"
#include "libc/mem/mem.h"
#include "libc/nt/createfile.h"
#include "libc/nt/dll.h"
#include "libc/nt/enum/creationdisposition.h"
#include "libc/nt/enum/accessmask.h"
#include "libc/nt/enum/filesharemode.h"
#include "libc/nt/enum/filemovemethod.h"
#include "libc/nt/enum/filetype.h"
#include "libc/nt/enum/lockfile.h"
#include "libc/nt/enum/pageflags.h"
#include "libc/nt/files.h"
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
#include "libc/nt/struct/overlapped.h"
#include "libc/nt/synchronization.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/runtime/internal.h"
#include "libc/sysv/consts/f.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/s.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#include "libc/thread/thread.h"

// File descriptors shared with the C runtimes of host libraries.
//
// On Windows a host library keeps descriptors in its C runtime's table,
// where ours don't exist. So in every module that isn't part of Windows,
// the imports of the Universal CRT and msvcrt functions that take or give
// out a descriptor are pointed at the ones here, and the descriptors that
// module sees are ours:
//
// - read(), write(), lseek(), fstat() and the like are ours
// - the open functions open with the C runtime, then the handle it got
//   moves over to a descriptor of ours
// - _fdopen() gives the C runtime a handle to the file our descriptor
//   has open, reopened for synchronous i/o if need be, so a FILE and
//   the descriptor move one file position
// - _fileno() of a stream the C runtime opened is a descriptor of ours
//   for the same file, which fclose() closes
//
// The C runtimes' descriptors 0, 1 and 2 are their own, as stdin and
// such use them without asking us. Those follow ours instead: close()
// and dup2() on 0, 1 or 2 do the same to them, and to the process's
// standard handles.

#if defined(__x86_64__) && SupportsWindows()

// the C runtimes' numbers for what isn't the same as ours
#define CRT_O_APPEND   0x0008
#define CRT_O_NOINHERIT 0x0080
#define CRT_O_TEXT     0x4000
#define CRT_O_BINARY   0x8000
#define CRT_LK_UNLCK   0
#define CRT_LK_LOCK    1
#define CRT_LK_RLCK    3

#define CRT_UNPACK(...) __VA_ARGS__

// X(name the dll exports, what implements it, return, params, args)
#define CRT_HOOKS(X)                                                        \
  X(_read, _read, int, (int fd, void *b, unsigned n), (fd, b, n))           \
  X(read, _read, int, (int fd, void *b, unsigned n), (fd, b, n))            \
  X(_write, _write, int, (int fd, const void *b, unsigned n), (fd, b, n))   \
  X(write, _write, int, (int fd, const void *b, unsigned n), (fd, b, n))    \
  X(_close, _close, int, (int fd), (fd))                                    \
  X(close, _close, int, (int fd), (fd))                                     \
  X(_lseek, _lseek, int32_t, (int fd, int32_t o, int w), (fd, o, w))        \
  X(lseek, _lseek, int32_t, (int fd, int32_t o, int w), (fd, o, w))         \
  X(_lseeki64, _lseeki64, int64_t, (int fd, int64_t o, int w), (fd, o, w))  \
  X(_tell, _tell, int32_t, (int fd), (fd))                                  \
  X(tell, _tell, int32_t, (int fd), (fd))                                   \
  X(_telli64, _telli64, int64_t, (int fd), (fd))                            \
  X(_eof, _eof, int, (int fd), (fd))                                        \
  X(eof, _eof, int, (int fd), (fd))                                         \
  X(_commit, _commit, int, (int fd), (fd))                                  \
  X(_chsize, _chsize, int, (int fd, int32_t n), (fd, n))                    \
  X(chsize, _chsize, int, (int fd, int32_t n), (fd, n))                     \
  X(_chsize_s, _chsize_s, int, (int fd, int64_t n), (fd, n))                \
  X(_filelength, _filelength, int32_t, (int fd), (fd))                      \
  X(filelength, _filelength, int32_t, (int fd), (fd))                       \
  X(_filelengthi64, _filelengthi64, int64_t, (int fd), (fd))                \
  X(_isatty, _isatty, int, (int fd), (fd))                                  \
  X(isatty, _isatty, int, (int fd), (fd))                                   \
  X(_setmode, _setmode, int, (int fd, int m), (fd, m))                      \
  X(setmode, _setmode, int, (int fd, int m), (fd, m))                       \
  X(_locking, _locking, int, (int fd, int m, int32_t n), (fd, m, n))        \
  X(locking, _locking, int, (int fd, int m, int32_t n), (fd, m, n))         \
  X(_futime32, _futime32, int, (int fd, void *t), (fd, t))                  \
  X(_futime, _futime32, int, (int fd, void *t), (fd, t))                    \
  X(_futime64, _futime64, int, (int fd, void *t), (fd, t))                  \
  X(_fstat32, _fstat32, int, (int fd, void *st), (fd, st))                  \
  X(_fstat, _fstat32, int, (int fd, void *st), (fd, st))                    \
  X(_fstat32i64, _fstat32i64, int, (int fd, void *st), (fd, st))            \
  X(_fstati64, _fstat32i64, int, (int fd, void *st), (fd, st))              \
  X(_fstat64, _fstat64, int, (int fd, void *st), (fd, st))                  \
  X(_fstat64i32, _fstat64i32, int, (int fd, void *st), (fd, st))            \
  X(_get_osfhandle, _get_osfhandle, intptr_t, (int fd), (fd))               \
  X(_dup, _dup, int, (int fd), (fd))                                        \
  X(dup, _dup, int, (int fd), (fd))                                         \
  X(_dup2, _dup2, int, (int a, int b), (a, b))                              \
  X(dup2, _dup2, int, (int a, int b), (a, b))                               \
  X(_open_osfhandle, _open_osfhandle, int, (intptr_t h, int fl), (h, fl))   \
  X(_open, _open, int, (const char *p, int fl, int pm), (p, fl, pm))        \
  X(open, _open, int, (const char *p, int fl, int pm), (p, fl, pm))         \
  X(_wopen, _wopen, int, (const char16_t *p, int fl, int pm), (p, fl, pm))  \
  X(_sopen, _sopen, int, (const char *p, int fl, int sh, int pm),           \
    (p, fl, sh, pm))                                                        \
  X(sopen, _sopen, int, (const char *p, int fl, int sh, int pm),            \
    (p, fl, sh, pm))                                                        \
  X(_wsopen, _wsopen, int, (const char16_t *p, int fl, int sh, int pm),     \
    (p, fl, sh, pm))                                                        \
  X(_sopen_s, _sopen_s, int,                                                \
    (int *out, const char *p, int fl, int sh, int pm), (out, p, fl, sh, pm)) \
  X(_wsopen_s, _wsopen_s, int,                                              \
    (int *out, const char16_t *p, int fl, int sh, int pm),                  \
    (out, p, fl, sh, pm))                                                   \
  X(_sopen_dispatch, _sopen_dispatch, int,                                  \
    (const char *p, int fl, int sh, int pm, int *out, int sec),             \
    (p, fl, sh, pm, out, sec))                                              \
  X(_wsopen_dispatch, _wsopen_dispatch, int,                                \
    (const char16_t *p, int fl, int sh, int pm, int *out, int sec),         \
    (p, fl, sh, pm, out, sec))                                              \
  X(_creat, _creat, int, (const char *p, int pm), (p, pm))                  \
  X(creat, _creat, int, (const char *p, int pm), (p, pm))                   \
  X(_wcreat, _wcreat, int, (const char16_t *p, int pm), (p, pm))            \
  X(_pipe, _pipe, int, (int *fds, unsigned n, int m), (fds, n, m))          \
  X(_fdopen, _fdopen, void *, (int fd, const char *m), (fd, m))             \
  X(fdopen, _fdopen, void *, (int fd, const char *m), (fd, m))              \
  X(_wfdopen, _wfdopen, void *, (int fd, const char16_t *m), (fd, m))       \
  X(_fileno, _fileno, int, (void *fp), (fp))                                \
  X(fileno, _fileno, int, (void *fp), (fp))                                 \
  X(fclose, fclose, int, (void *fp), (fp))                                  \
  X(_fcloseall, _fcloseall, int, (void), (0))                               \
  X(freopen, freopen, void *, (const char *p, const char *m, void *fp),     \
    (p, m, fp))                                                             \
  X(_wfreopen, _wfreopen, void *,                                           \
    (const char16_t *p, const char16_t *m, void *fp), (p, m, fp))           \
  X(freopen_s, freopen_s, int,                                              \
    (void **out, const char *p, const char *m, void *fp), (out, p, m, fp))  \
  X(_wfreopen_s, _wfreopen_s, int,                                          \
    (void **out, const char16_t *p, const char16_t *m, void *fp),           \
    (out, p, m, fp))

#define CRT_ENUM(id, ...) k_##id,
enum { CRT_HOOKS(CRT_ENUM) kCrtHooks };

#define CRT_DECLARE(id, impl, ret, params, args) \
  __msabi static ret ucrt_##id params;           \
  __msabi static ret msvcrt_##id params;
CRT_HOOKS(CRT_DECLARE)

struct Crt {
  const char16_t *dll;
  _Atomic(uintptr_t) lo;  // where the dll is, once it's loaded
  uintptr_t hi;
  int *__msabi (*errnop)(void);
  void *std[3];                // its stdin, stdout and stderr
  _Atomic(bool) stdopen[3];    // whether its 0, 1 and 2 are open
  void *real[kCrtHooks];
};

static struct Crt crts[2] = {{u"ucrtbase.dll"}, {u"msvcrt.dll"}};

#define CRT_NAME(id, ...) #id,
static const char *const crt_names[kCrtHooks] = {CRT_HOOKS(CRT_NAME)};

#define CRT_UCRT(id, ...)   ucrt_##id,
#define CRT_MSVCRT(id, ...) msvcrt_##id,
static void *const crt_hooks[2][kCrtHooks] = {{CRT_HOOKS(CRT_UCRT)},
                                              {CRT_HOOKS(CRT_MSVCRT)}};

// the C runtime's own function, typed as the hook for it is
#define REAL(c, id) ((typeof(&ucrt_##id))(c)->real[k_##id])

// streams that have a descriptor of ours: one _fdopen() was given, or
// one _fileno() made for a stream the C runtime opened
struct CrtStream {
  struct Crt *crt;
  void *fp;
  int fd;
};

static struct {
  pthread_mutex_t lock;
  size_t n, c;
  struct CrtStream *p;
} crt_streams = {PTHREAD_MUTEX_INITIALIZER};

static char16_t crt_windir[PATH_MAX];
static size_t crt_windirlen;

// the C runtimes' errno numbers that aren't ours. up to ERANGE they're
// the same, except that ENOTBLK is missing and ETXTBSY moved
static const struct {
  short crt, ours;
} crt_errnos[] = {
    {36, EDEADLK},        {38, ENAMETOOLONG},    {39, ENOLCK},
    {40, ENOSYS},         {41, ENOTEMPTY},       {42, EILSEQ},
    {100, EADDRINUSE},    {101, EADDRNOTAVAIL},  {102, EAFNOSUPPORT},
    {103, EALREADY},      {104, EBADMSG},        {105, ECANCELED},
    {106, ECONNABORTED},  {107, ECONNREFUSED},   {108, ECONNRESET},
    {109, EDESTADDRREQ},  {110, EHOSTUNREACH},   {111, EIDRM},
    {112, EINPROGRESS},   {113, EISCONN},        {114, ELOOP},
    {115, EMSGSIZE},      {116, ENETDOWN},       {117, ENETRESET},
    {118, ENETUNREACH},   {119, ENOBUFS},        {120, ENODATA},
    {121, ENOLINK},       {122, ENOMSG},         {123, ENOPROTOOPT},
    {124, ENOSR},         {125, ENOSTR},         {126, ENOTCONN},
    {127, ENOTRECOVERABLE}, {128, ENOTSOCK},     {129, ENOTSUP},
    {130, EOPNOTSUPP},    {132, EOVERFLOW},      {133, EOWNERDEAD},
    {134, EPROTO},        {135, EPROTONOSUPPORT}, {136, EPROTOTYPE},
    {137, ETIME},         {138, ETIMEDOUT},      {139, ETXTBSY},
};

static int crt_errnum(int e) {
  if (e > 0 && e <= 34 && e != ENOTBLK && e != ETXTBSY)
    return e;
  for (int i = 0; i < ARRAYLEN(crt_errnos); ++i)
    if (crt_errnos[i].ours == e)
      return crt_errnos[i].crt;
  return 22;
}

/**
 * Returns the C runtime's errno number `e` as ours.
 */
int __host_crt_errno(int e) {
  if (e >= 0 && e <= 34 && e != 15 && e != 26)
    return e;
  for (int i = 0; i < ARRAYLEN(crt_errnos); ++i)
    if (crt_errnos[i].crt == e)
      return crt_errnos[i].ours;
  return EINVAL;
}

/**
 * Returns our errno number `e` as the C runtime's.
 */
int __host_crt_errno_of(int e) {
  return e ? crt_errnum(e) : 0;
}

static int crt_fail(struct Crt *c, int e) {
  if (c->errnop)
    *c->errnop() = crt_errnum(e);
  return -1;
}

static int crt_check(struct Crt *c, int rc) {
  return rc == -1 ? crt_fail(c, errno) : rc;
}

static int crt__read(struct Crt *c, int fd, void *b, unsigned n) {
  if (n > INT_MAX)
    return crt_fail(c, EINVAL);
  return crt_check(c, read(fd, b, n));
}

static int crt__write(struct Crt *c, int fd, const void *b, unsigned n) {
  if (n > INT_MAX)
    return crt_fail(c, EINVAL);
  return crt_check(c, write(fd, b, n));
}

static int crt__close(struct Crt *c, int fd) {
  return crt_check(c, close(fd));
}

static int64_t crt__lseeki64(struct Crt *c, int fd, int64_t off, int whence) {
  int64_t rc;
  if ((rc = lseek(fd, off, whence)) == -1)
    crt_fail(c, errno);
  return rc;
}

static int32_t crt__lseek(struct Crt *c, int fd, int32_t off, int whence) {
  int64_t rc;
  if ((rc = crt__lseeki64(c, fd, off, whence)) > INT32_MAX)
    return crt_fail(c, EINVAL);
  return rc;
}

static int64_t crt__telli64(struct Crt *c, int fd) {
  return crt__lseeki64(c, fd, 0, SEEK_CUR);
}

static int32_t crt__tell(struct Crt *c, int fd) {
  return crt__lseek(c, fd, 0, SEEK_CUR);
}

static int64_t crt__filelengthi64(struct Crt *c, int fd) {
  struct stat st;
  if (fstat(fd, &st))
    return crt_fail(c, errno);
  return st.st_size;
}

static int32_t crt__filelength(struct Crt *c, int fd) {
  int64_t n;
  if ((n = crt__filelengthi64(c, fd)) > INT32_MAX)
    return crt_fail(c, EINVAL);
  return n;
}

static int crt__eof(struct Crt *c, int fd) {
  int64_t pos, size;
  if ((pos = crt__telli64(c, fd)) == -1 ||
      (size = crt__filelengthi64(c, fd)) == -1)
    return -1;
  return pos >= size;
}

static int crt__commit(struct Crt *c, int fd) {
  return crt_check(c, fsync(fd));
}

static int crt__chsize_s(struct Crt *c, int fd, int64_t n) {
  if (ftruncate(fd, n)) {
    int e = errno;
    crt_fail(c, e);
    return crt_errnum(e);
  }
  return 0;
}

static int crt__chsize(struct Crt *c, int fd, int32_t n) {
  return crt__chsize_s(c, fd, n) ? -1 : 0;
}

static int crt__isatty(struct Crt *c, int fd) {
  int e = errno;
  if (isatty(fd))
    return 1;
  if (errno == EBADF)
    crt_fail(c, EBADF);
  errno = e;
  return 0;
}

static int crt__setmode(struct Crt *c, int fd, int mode) {
  // the modes of 0, 1 and 2 are for the C runtime's stdin and so on
  if (fd >= 0 && fd <= 2 && REAL(c, _setmode))
    return c->stdopen[fd] ? REAL(c, _setmode)(fd, mode) : crt_fail(c, EBADF);
  if (fcntl(fd, F_GETFD) == -1)
    return crt_fail(c, errno);
  return CRT_O_BINARY;
}

static int crt__locking(struct Crt *c, int fd, int mode, int32_t n) {
  int64_t h, pos;
  if ((h = cosmo_dlhandle(fd)) == -1 || (pos = lseek(fd, 0, SEEK_CUR)) == -1)
    return crt_fail(c, errno);
  if (n < 0)
    return crt_fail(c, EINVAL);
  struct NtOverlapped ov = {.Pointer = pos};
  if (mode == CRT_LK_UNLCK)
    return UnlockFileEx(h, 0, n, 0, &ov) ? 0 : crt_fail(c, EACCES);
  uint32_t flags = kNtLockfileFailImmediately;
  if (mode != CRT_LK_RLCK && mode != 4)
    flags |= kNtLockfileExclusiveLock;
  // _LK_LOCK and _LK_RLCK try once a second, ten times
  int tries = mode == CRT_LK_LOCK || mode == CRT_LK_RLCK ? 10 : 1;
  for (int i = 0; i < tries; ++i) {
    if (i)
      SleepEx(1000, false);
    if (LockFileEx(h, flags, 0, n, 0, &ov))
      return 0;
  }
  return crt_fail(c, tries > 1 ? EDEADLK : EACCES);
}

static int crt_futime(struct Crt *c, int fd, int64_t atime, int64_t mtime,
                      bool now) {
  struct timespec ts[2] = {{atime}, {mtime}};
  return crt_check(c, futimens(fd, now ? 0 : ts));
}

static int crt__futime32(struct Crt *c, int fd, void *t) {
  int32_t *p = t;
  return crt_futime(c, fd, p ? p[0] : 0, p ? p[1] : 0, !p);
}

static int crt__futime64(struct Crt *c, int fd, void *t) {
  int64_t *p = t;
  return crt_futime(c, fd, p ? p[0] : 0, p ? p[1] : 0, !p);
}

#define CRT_STAT(name, off_t_, time_t_) \
  struct name {                         \
    uint32_t dev;                       \
    uint16_t ino;                       \
    uint16_t mode;                      \
    int16_t nlink;                      \
    int16_t uid;                        \
    int16_t gid;                        \
    uint32_t rdev;                      \
    off_t_ size;                        \
    time_t_ atime;                      \
    time_t_ mtime;                      \
    time_t_ ctime;                      \
  }

CRT_STAT(CrtStat32, int32_t, int32_t);
CRT_STAT(CrtStat32i64, int64_t, int32_t);
CRT_STAT(CrtStat64i32, int32_t, int64_t);
CRT_STAT(CrtStat64, int64_t, int64_t);

#define CRT_FSTAT(name, type)                                              \
  static int crt_##name(struct Crt *c, int fd, void *out) {                \
    struct stat st;                                                        \
    struct type *p = out;                                                  \
    if (fstat(fd, &st))                                                    \
      return crt_fail(c, errno);                                           \
    if (st.st_size != (typeof(p->size))st.st_size)                         \
      return crt_fail(c, EOVERFLOW);                                       \
    unsigned m = st.st_mode;                                               \
    if (S_ISSOCK(m))                                                       \
      m = (m & ~S_IFMT) | S_IFIFO;                                         \
    else if (S_ISLNK(m))                                                   \
      m = (m & ~S_IFMT) | S_IFREG;                                         \
    *p = (struct type){.mode = m & (S_IFMT | 0777),                        \
                       .nlink = st.st_nlink,                               \
                       .size = st.st_size,                                 \
                       .atime = st.st_atim.tv_sec,                         \
                       .mtime = st.st_mtim.tv_sec,                         \
                       .ctime = st.st_ctim.tv_sec};                        \
    return 0;                                                              \
  }

CRT_FSTAT(_fstat32, CrtStat32)
CRT_FSTAT(_fstat32i64, CrtStat32i64)
CRT_FSTAT(_fstat64i32, CrtStat64i32)
CRT_FSTAT(_fstat64, CrtStat64)

static intptr_t crt__get_osfhandle(struct Crt *c, int fd) {
  intptr_t h;
  if ((h = cosmo_dlhandle(fd)) == -1)
    crt_fail(c, errno);
  return h;
}

static int crt__dup(struct Crt *c, int fd) {
  return crt_check(c, dup(fd));
}

static int crt__dup2(struct Crt *c, int a, int b) {
  return dup2(a, b) == -1 ? crt_fail(c, errno) : 0;
}

// takes over a handle the host has, as the C runtime would. the access
// the handle has is what counts, the C runtime keeps no mode for it
static int crt__open_osfhandle(struct Crt *c, intptr_t h, int fl) {
  int flags = O_RDWR;
  if (fl & CRT_O_APPEND)
    flags |= O_APPEND;
  if (fl & CRT_O_NOINHERIT)
    flags |= O_CLOEXEC;
  return crt_check(c, cosmo_dlfd(h, flags));
}

// moves the handle behind the C runtime's descriptor `u` to one of ours
static int crt_adopt(struct Crt *c, int u, int fl) {
  int fd;
  int64_t h, dup;
  if (u == -1)
    return -1;
  if ((h = REAL(c, _get_osfhandle)(u)) == -1 ||
      !DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &dup, 0,
                       true, kNtDuplicateSameAccess)) {
    REAL(c, _close)(u);
    return crt_fail(c, EMFILE);
  }
  REAL(c, _close)(u);
  if ((fd = crt__open_osfhandle(c, dup, fl)) == -1)
    CloseHandle(dup);
  return fd;
}

static int crt__open(struct Crt *c, const char *p, int fl, int pm) {
  return crt_adopt(c, REAL(c, _open)(p, fl, pm), fl);
}

static int crt__wopen(struct Crt *c, const char16_t *p, int fl, int pm) {
  return crt_adopt(c, REAL(c, _wopen)(p, fl, pm), fl);
}

static int crt__sopen(struct Crt *c, const char *p, int fl, int sh, int pm) {
  return crt_adopt(c, REAL(c, _sopen)(p, fl, sh, pm), fl);
}

static int crt__wsopen(struct Crt *c, const char16_t *p, int fl, int sh,
                       int pm) {
  return crt_adopt(c, REAL(c, _wsopen)(p, fl, sh, pm), fl);
}

static int crt_adopt_s(struct Crt *c, int err, int u, int fl, int *out) {
  if (err) {
    *out = -1;
    return err;
  }
  if ((*out = crt_adopt(c, u, fl)) == -1)
    return c->errnop ? *c->errnop() : 22;
  return 0;
}

static int crt__sopen_s(struct Crt *c, int *out, const char *p, int fl,
                        int sh, int pm) {
  int u = -1;
  return crt_adopt_s(c, REAL(c, _sopen_s)(&u, p, fl, sh, pm), u, fl, out);
}

static int crt__wsopen_s(struct Crt *c, int *out, const char16_t *p, int fl,
                         int sh, int pm) {
  int u = -1;
  return crt_adopt_s(c, REAL(c, _wsopen_s)(&u, p, fl, sh, pm), u, fl, out);
}

static int crt__sopen_dispatch(struct Crt *c, const char *p, int fl, int sh,
                               int pm, int *out, int sec) {
  int u = -1;
  return crt_adopt_s(c, REAL(c, _sopen_dispatch)(p, fl, sh, pm, &u, sec), u,
                     fl, out);
}

static int crt__wsopen_dispatch(struct Crt *c, const char16_t *p, int fl,
                                int sh, int pm, int *out, int sec) {
  int u = -1;
  return crt_adopt_s(c, REAL(c, _wsopen_dispatch)(p, fl, sh, pm, &u, sec), u,
                     fl, out);
}

static int crt__creat(struct Crt *c, const char *p, int pm) {
  return crt_adopt(c, REAL(c, _creat)(p, pm), 0);
}

static int crt__wcreat(struct Crt *c, const char16_t *p, int pm) {
  return crt_adopt(c, REAL(c, _wcreat)(p, pm), 0);
}

static int crt__pipe(struct Crt *c, int *fds, unsigned n, int mode) {
  int u[2];
  if (REAL(c, _pipe)(u, n, mode))
    return -1;
  if ((fds[0] = crt_adopt(c, u[0], mode)) == -1) {
    REAL(c, _close)(u[1]);
    return -1;
  }
  if ((fds[1] = crt_adopt(c, u[1], mode)) == -1) {
    close(fds[0]);
    return -1;
  }
  return 0;
}

// the file `f` has open, reopened for synchronous i/o. win32 keeps a
// file position for those, which the C runtime uses, and our i/o on a
// synchronous handle uses it too, see __nt_syncio(). `f` and every
// descriptor dup()ed from it, which share its position, move over
static void crt_syncio(struct Fds *fds, struct Fd *f) {
  int64_t h;
  uint32_t access;
  switch (f->flags & O_ACCMODE) {
    case O_RDONLY:
      access = kNtGenericRead;
      break;
    case O_WRONLY:
      access = kNtGenericWrite | kNtFileReadAttributes;
      break;
    default:
      access = kNtGenericRead | kNtGenericWrite;
      break;
  }
  if ((h = ReOpenFile(f->handle, access,
                      kNtFileShareRead | kNtFileShareWrite |
                          kNtFileShareDelete,
                      0)) == -1)
    return;
  SetHandleInformation(h, kNtHandleFlagInherit, kNtHandleFlagInherit);
  struct Cursor *cur = f->cursor;
  if (cur)
    __cursor_lock(cur);
  SetFilePointerEx(h, cur ? cur->shared->pointer : 0, 0, kNtFileBegin);
  for (unsigned i = 0; i < fds->n; ++i) {
    struct Fd *g = fds->p + i;
    int64_t mine = h;
    if (g != f && (!cur || g->cursor != cur || g->kind != kFdFile))
      continue;
    if (g != f && !DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(),
                                   &mine, 0, true, kNtDuplicateSameAccess))
      continue;
    // a standard handle we were started with stays the process's, and
    // the C runtimes' until close() or dup2() moves them off it
    if (i > 2 || g->handle != GetStdHandle(kNtStdio[i]))
      CloseHandle(g->handle);
    g->handle = mine;
    g->syncio = 1;
  }
  if (cur)
    __cursor_unlock(cur);
}

// a handle for the C runtime to own, to the file `fd` has open
static int64_t crt_share(int fd) {
  int64_t h, dup;
  struct Fds *fds = &__get_pib()->fds;
  __fds_lock();
  if (fd < 0 || fd >= fds->n) {
    __fds_unlock();
    return ebadf();
  }
  struct Fd *f = fds->p + fd;
  switch (f->kind) {
    case kFdFile:
      if (GetFileType(f->handle) == kNtFileTypeDisk && !__nt_syncio(f))
        crt_syncio(fds, f);
      break;
    case kFdConsole:
    case kFdSocket:
      break;
    default:
      // the zip store, /dev/null and such have no handle to give
      __fds_unlock();
      return f->kind ? enotsup() : ebadf();
  }
  h = f->handle;
  __fds_unlock();
  if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &dup, 0,
                       false, kNtDuplicateSameAccess))
    return __winerr();
  return dup;
}

static int crt_stream_find(void *fp) {
  for (size_t i = 0; i < crt_streams.n; ++i)
    if (crt_streams.p[i].fp == fp)
      return crt_streams.p[i].fd;
  return -1;
}

static void crt_stream_add(struct Crt *c, void *fp, int fd) {
  if (crt_streams.n == crt_streams.c) {
    size_t n = crt_streams.c ? crt_streams.c * 2 : 16;
    struct CrtStream *p = realloc(crt_streams.p, n * sizeof(*p));
    if (!p)
      return;
    crt_streams.p = p;
    crt_streams.c = n;
  }
  crt_streams.p[crt_streams.n++] = (struct CrtStream){c, fp, fd};
}

// forgets the stream `fp`, returning its descriptor of ours
static int crt_stream_remove(void *fp) {
  int fd = -1;
  pthread_mutex_lock(&crt_streams.lock);
  for (size_t i = 0; i < crt_streams.n; ++i) {
    if (crt_streams.p[i].fp == fp) {
      fd = crt_streams.p[i].fd;
      crt_streams.p[i] = crt_streams.p[--crt_streams.n];
      break;
    }
  }
  pthread_mutex_unlock(&crt_streams.lock);
  return fd;
}

static void crt_close_quietly(int fd) {
  int e = errno;
  if (fd != -1)
    close(fd);
  errno = e;
}

static void *crt_fdopen(struct Crt *c, int fd, const char *m8,
                        const char16_t *m16) {
  int u, fl = 0;
  int64_t h;
  void *fp;
  for (int i = 0; m8 ? m8[i] : m16[i]; ++i) {
    switch (m8 ? m8[i] : m16[i]) {
      case 'a':
        fl |= i ? 0 : CRT_O_APPEND;
        break;
      case 'b':
        fl |= CRT_O_BINARY;
        break;
      case 't':
        fl |= CRT_O_TEXT;
        break;
      case ',':
        goto done;  // ccs=
      default:
        break;
    }
  }
done:
  if ((h = crt_share(fd)) == -1) {
    crt_fail(c, errno);
    return 0;
  }
  if ((u = REAL(c, _open_osfhandle)(h, fl)) == -1) {
    CloseHandle(h);
    return 0;
  }
  fp = m8 ? REAL(c, _fdopen)(u, m8) : REAL(c, _wfdopen)(u, m16);
  if (!fp) {
    REAL(c, _close)(u);
    return 0;
  }
  pthread_mutex_lock(&crt_streams.lock);
  crt_stream_add(c, fp, fd);
  pthread_mutex_unlock(&crt_streams.lock);
  return fp;
}

static void *crt__fdopen(struct Crt *c, int fd, const char *m) {
  return crt_fdopen(c, fd, m, 0);
}

static void *crt__wfdopen(struct Crt *c, int fd, const char16_t *m) {
  return crt_fdopen(c, fd, 0, m);
}

static int crt__fileno(struct Crt *c, void *fp) {
  int u, fd;
  int64_t h, dup;
  pthread_mutex_lock(&crt_streams.lock);
  if ((fd = crt_stream_find(fp)) == -1) {
    // stdin, stdout and stderr keep their numbers, which are ours too
    if ((u = REAL(c, _fileno)(fp)) <= 2) {
      fd = u;
    } else if ((h = REAL(c, _get_osfhandle)(u)) != -1 &&
               DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(),
                               &dup, 0, true, kNtDuplicateSameAccess)) {
      if ((fd = cosmo_dlfd(dup, O_RDWR)) != -1) {
        crt_stream_add(c, fp, fd);
      } else {
        crt_fail(c, errno);
        CloseHandle(dup);
      }
    } else {
      fd = crt_fail(c, EBADF);
    }
  }
  pthread_mutex_unlock(&crt_streams.lock);
  return fd;
}

// msvcrt has no way to keep a descriptor that isn't open from ending
// the process, so whether 0, 1 and 2 are is kept track of here
static void crt_std_gone(struct Crt *c, void *fp) {
  for (int n = 0; n < 3; ++n)
    if (fp && fp == c->std[n])
      c->stdopen[n] = false;
}

static int crt_fclose(struct Crt *c, void *fp) {
  int fd = crt_stream_remove(fp);
  int rc = REAL(c, fclose)(fp);
  crt_std_gone(c, fp);
  crt_close_quietly(fd);
  return rc;
}

static int crt__fcloseall(struct Crt *c, int unused) {
  int rc = REAL(c, _fcloseall)();
  pthread_mutex_lock(&crt_streams.lock);
  for (size_t i = 0; i < crt_streams.n;) {
    if (crt_streams.p[i].crt == c) {
      crt_close_quietly(crt_streams.p[i].fd);
      crt_streams.p[i] = crt_streams.p[--crt_streams.n];
    } else {
      ++i;
    }
  }
  pthread_mutex_unlock(&crt_streams.lock);
  return rc;
}

static void *crt_freopen(struct Crt *c, const char *p, const char *m,
                         void *fp) {
  crt_close_quietly(crt_stream_remove(fp));
  crt_std_gone(c, fp);
  return REAL(c, freopen)(p, m, fp);
}

static void *crt__wfreopen(struct Crt *c, const char16_t *p,
                           const char16_t *m, void *fp) {
  crt_close_quietly(crt_stream_remove(fp));
  crt_std_gone(c, fp);
  return REAL(c, _wfreopen)(p, m, fp);
}

static int crt_freopen_s(struct Crt *c, void **out, const char *p,
                         const char *m, void *fp) {
  crt_close_quietly(crt_stream_remove(fp));
  crt_std_gone(c, fp);
  return REAL(c, freopen_s)(out, p, m, fp);
}

static int crt__wfreopen_s(struct Crt *c, void **out, const char16_t *p,
                           const char16_t *m, void *fp) {
  crt_close_quietly(crt_stream_remove(fp));
  crt_std_gone(c, fp);
  return REAL(c, _wfreopen_s)(out, p, m, fp);
}

#define CRT_DEFINE(id, impl, ret, params, args)             \
  __msabi static ret ucrt_##id params {                     \
    return crt_##impl(crts + 0, CRT_UNPACK args);           \
  }                                                         \
  __msabi static ret msvcrt_##id params {                   \
    return crt_##impl(crts + 1, CRT_UNPACK args);           \
  }
CRT_HOOKS(CRT_DEFINE)

static bool crt_resolve(struct Crt *c) {
  intptr_t m;
  if (atomic_load_explicit(&c->lo, memory_order_acquire))
    return true;
  if (!(m = GetModuleHandleW(c->dll)))
    return false;
  struct NtImageDosHeader *dos = (void *)m;
  struct NtImageNtHeaders *nt = (void *)(m + dos->e_lfanew);
  c->hi = m + nt->OptionalHeader.SizeOfImage;
  c->errnop = GetProcAddress(m, "_errno");
  for (int k = 0; k < kCrtHooks; ++k)
    c->real[k] = GetProcAddress(m, crt_names[k]);
  // FILE is 48 bytes in msvcrt, whose streams are an array
  void *__msabi (*iob)(unsigned) = GetProcAddress(m, "__acrt_iob_func");
  char *__msabi (*iob_msvcrt)(void) = GetProcAddress(m, "__iob_func");
  for (int n = 0; n < 3; ++n) {
    c->std[n] = iob ? iob(n) : iob_msvcrt ? iob_msvcrt() + n * 48 : 0;
    c->stdopen[n] = true;
  }
  atomic_store_explicit(&c->lo, m, memory_order_release);
  return true;
}

// whether the module at `base` is part of windows, from its path
static bool crt_is_system(char *base) {
  char16_t path[PATH_MAX];
  uint32_t n;
  if (!crt_windirlen)
    return true;
  n = GetModuleFileName((intptr_t)base, path, ARRAYLEN(path));
  if (!n || n >= ARRAYLEN(path) || n < crt_windirlen)
    return true;
  for (size_t i = 0; i < crt_windirlen; ++i) {
    char16_t a = path[i], b = crt_windir[i];
    if (a >= 'A' && a <= 'Z')
      a += 'a' - 'A';
    if (b >= 'A' && b <= 'Z')
      b += 'a' - 'A';
    if (a != b)
      return false;
  }
  return true;
}

// C:\Windows\, from where kernel32.dll is
static void crt_windir_init(void) {
  size_t n;
  int slashes = 0;
  intptr_t k32 = GetModuleHandleW(u"kernel32.dll");
  n = GetModuleFileName(k32, crt_windir, ARRAYLEN(crt_windir));
  if (!n || n >= ARRAYLEN(crt_windir))
    return;
  while (n && slashes < 2)
    if (crt_windir[--n] == '\\')
      ++slashes;
  if (slashes == 2)
    crt_windirlen = n + 1;
}

/**
 * Returns whether `func` is one of the hooks here.
 */
bool __host_crt_hook(const void *func) {
  for (int i = 0; i < 2; ++i)
    for (int k = 0; k < kCrtHooks; ++k)
      if (crt_hooks[i][k] == func)
        return true;
  return false;
}

/**
 * Points the C runtime imports of the module at `base` at ours.
 */
void __host_crt_patch(char *base) {
  static pthread_once_t once = PTHREAD_ONCE_INIT;
  bool any = false;
  if (!IsWindows() || !base)
    return;
  pthread_once(&once, crt_windir_init);
  for (int i = 0; i < ARRAYLEN(crts); ++i)
    any |= crt_resolve(crts + i);
  if (!any || crt_is_system(base))
    return;
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
      uintptr_t v = (uintptr_t)*iat;
      void *hook = 0;
      for (int i = 0; i < ARRAYLEN(crts) && !hook; ++i) {
        struct Crt *c = crts + i;
        uintptr_t lo = atomic_load_explicit(&c->lo, memory_order_acquire);
        if (!lo || v < lo || v >= c->hi)
          continue;
        for (int k = 0; k < kCrtHooks && !hook; ++k)
          if (c->real[k] == (void *)v)
            hook = crt_hooks[i][k];
      }
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

/**
 * Patches every module loaded so far, see __host_crt_patch().
 */
void __host_crt_patch_all(void) {
  char *peb, *ldr;
  if (!IsWindows())
    return;
  asm("mov\t%%gs:0x60,%0" : "=r"(peb));
  ldr = *(char **)(peb + 0x18);
  struct NtLinkedList *head = &((struct NtLdr *)ldr)->InLoadOrderModuleList;
  for (struct NtLinkedList *e = head->Next; e != head; e = e->Next)
    __host_crt_patch(((struct NtLdrDataTableEntry *)e)->DllBase);
}

// the process's standard handles we set, which are copies of ours
static _Atomic(int64_t) std_owned[3];

static void crt_protect(const int64_t keep[3], bool on) {
  for (int i = 0; i < 3; ++i)
    if (keep[i])
      SetHandleInformation(keep[i], kNtHandleFlagProtectFromClose,
                           on ? kNtHandleFlagProtectFromClose : 0);
}

// points the C runtime's descriptor `n` at `h`, which it then owns. the
// handles in `keep` are ours, and the C runtime may have had one of them
// as its `n`, which it mustn't close
static void crt_std_point(struct Crt *c, int n, int64_t h, bool text,
                          const int64_t keep[3]) {
  int u;
  if ((u = REAL(c, _open_osfhandle)(h, text ? CRT_O_TEXT : CRT_O_BINARY)) ==
      -1) {
    CloseHandle(h);
    return;
  }
  if (u == n) {
    c->stdopen[n] = true;
    return;
  }
  crt_protect(keep, true);
  if (!REAL(c, _dup2)(u, n))
    c->stdopen[n] = true;
  crt_protect(keep, false);
  REAL(c, _close)(u);
}

static int64_t std_handle_of(int n) {
  struct Fd *f = __get_pib()->fds.p + n;
  switch (f->kind) {
    case kFdFile:
    case kFdConsole:
    case kFdSocket:
      return f->handle;
    default:
      return 0;
  }
}

/**
 * Called by close() before it lets go of our descriptor `n`, one of 0,
 * 1 and 2. The C runtimes' `n` is pointed at NUL, and the process's
 * standard handle is cleared, so nothing is left using the handle once
 * it's closed, or whatever gets its number next. A C runtime whose
 * stdout isn't open would end the process on the next printf().
 */
void __host_std_closing(int n) {
  int64_t h, owned, nul;
  if (!IsWindows() || n < 0 || n > 2)
    return;
  h = std_handle_of(n);
  owned = atomic_exchange(std_owned + n, 0);
  int64_t keep[3] = {h, owned, 0};
  for (int i = 0; i < ARRAYLEN(crts); ++i) {
    if (!atomic_load_explicit(&crts[i].lo, memory_order_acquire))
      continue;
    if ((nul = CreateFile(u"NUL", kNtGenericRead | kNtGenericWrite,
                          kNtFileShareRead | kNtFileShareWrite, 0,
                          kNtOpenExisting, 0, 0)) != -1)
      crt_std_point(crts + i, n, nul, false, keep);
  }
  SetStdHandle(kNtStdio[n], 0);
  if (owned)
    CloseHandle(owned);
}

/**
 * Called by dup2() and friends once our descriptor `n`, one of 0, 1 and
 * 2, is something new. The process's standard handle and the C
 * runtimes' descriptor `n` become that too, so what a host library
 * prints goes where ours does.
 */
void __host_std_opened(int n) {
  int64_t h, mine, old, dup;
  if (!IsWindows() || n < 0 || n > 2)
    return;
  bool console = __get_pib()->fds.p[n].kind == kFdConsole;
  // a file of ours becomes synchronous here, for whoever writes to the
  // standard handle to do so at our position
  if ((h = crt_share(n)) == -1)
    return;
  if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &mine, 0,
                       true, kNtDuplicateSameAccess))
    mine = 0;
  old = atomic_exchange(std_owned + n, mine);
  SetStdHandle(kNtStdio[n], mine);
  int64_t keep[3] = {std_handle_of(n), mine, old};
  for (int i = 0; i < ARRAYLEN(crts); ++i)
    if (atomic_load_explicit(&crts[i].lo, memory_order_acquire) &&
        DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &dup, 0,
                        false, kNtDuplicateSameAccess))
      crt_std_point(crts + i, n, dup, console, keep);
  CloseHandle(h);
  if (old)
    CloseHandle(old);
}

/**
 * Flushes what the C runtimes of host libraries have buffered.
 *
 * A program built against them has their exit() flush every stream,
 * and ours goes straight to ExitProcess(), where a runtime loaded as a
 * DLL leaves its buffers behind. Called by exit().
 */
void __host_crt_exit(void) {
  if (!IsWindows())
    return;
  for (int i = 0; i < ARRAYLEN(crts); ++i) {
    intptr_t m = atomic_load_explicit(&crts[i].lo, memory_order_acquire);
    if (!m)
      continue;
    int __msabi (*flushall)(void) = GetProcAddress(m, "_flushall");
    if (flushall)
      flushall();
  }
}

#else

void __host_crt_patch(char *base) {
}

void __host_crt_exit(void) {
}

void __host_crt_patch_all(void) {
}

bool __host_crt_hook(const void *func) {
  return false;
}

void __host_std_closing(int n) {
}

void __host_std_opened(int n) {
}

int __host_crt_errno(int e) {
  return e;
}

int __host_crt_errno_of(int e) {
  return e;
}

#endif /* __x86_64__ && SupportsWindows() */
