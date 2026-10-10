#include "libc/dce.h"
#include "libc/dlopen/dlfcn.h"
#include "libc/intrin/dll.h"
#include "libc/intrin/strace.h"
#include "libc/nt/dll.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/runtime/syslib.internal.h"
#include "libc/stdio/internal.h"

/**
 * Tells if `f` is a FILE of the host's C library rather than ours.
 *
 * A library cosmo_dlopen() loaded gets its FILE objects, such as its
 * `stdout`, from its own libc, and may pass one to a function of this
 * program that takes a FILE. Our stdio can't operate on those; see
 * cosmo_dlfwrite().
 *
 * @return nonzero if `f` isn't one of this program's streams
 */
int cosmo_dlhostfile(const void *f) {
  struct Dll *e;
  int found = 0;
  if (!f)
    return 0;
  __stdio_lock();
  for (e = dll_first(__stdio.files); e; e = dll_next(__stdio.files, e)) {
    if (FILE_CONTAINER(e) == f) {
      found = 1;
      break;
    }
  }
  __stdio_unlock();
  return !found;
}

#ifdef __x86_64__
typedef size_t __msabi fwrite_nt_f(const void *, size_t, size_t, void *);

// msvcrt's standard streams sit in its exported _iob array, 48 bytes
// each; any other FILE is taken to be the universal crt's, which is
// what msvc and mingw-w64's ucrt toolchains link against
static fwrite_nt_f *fwrite_nt(const void *f) {
  uintptr_t ucrt, msvcrt;
  const char *iob;
  ucrt = GetModuleHandle("ucrtbase.dll");
  msvcrt = GetModuleHandle("msvcrt.dll");
  if (msvcrt && (iob = (const char *)GetProcAddress(msvcrt, "_iob")) &&
      (const char *)f >= iob && (const char *)f < iob + 20 * 48)
    return (fwrite_nt_f *)GetProcAddress(msvcrt, "fwrite");
  if (ucrt)
    return (fwrite_nt_f *)GetProcAddress(ucrt, "fwrite");
  if (msvcrt)
    return (fwrite_nt_f *)GetProcAddress(msvcrt, "fwrite");
  return 0;
}
#endif

/**
 * Calls the host C library's fwrite() on a FILE of its own.
 *
 * On Windows that's the universal CRT, or msvcrt when `f` is one of
 * msvcrt's standard streams. The data lands in that FILE's buffer, so
 * it stays in order with whatever the library itself writes there.
 *
 * @return number of items written, which is 0 if the host C library
 *     can't be reached
 * @see cosmo_dlhostfile()
 */
size_t cosmo_dlfwrite(const void *p, size_t size, size_t n, void *f) {
  size_t rc = 0;
  if (IsWindows()) {
#ifdef __x86_64__
    fwrite_nt_f *fw;
    if ((fw = fwrite_nt(f)))
      rc = fw(p, size, n, f);
#endif
  } else if (IsXnuSilicon()) {
    size_t (*fw)(const void *, size_t, size_t, void *);
    if ((fw = __syslib->__dlsym((void *)-2, "fwrite")))
      rc = fw(p, size, n, f);
  } else {
    static size_t (*fw)(const void *, size_t, size_t, void *);
    if (!fw) {
      void *sym;
      if ((sym = cosmo_dlsym(RTLD_DEFAULT, "fwrite")))
        fw = cosmo_dltramp(sym);
    }
    if (fw)
      rc = fw(p, size, n, f);
  }
  STRACE("cosmo_dlfwrite(%p, %zu, %zu, %p) → %zu", p, size, n, f, rc);
  return rc;
}
