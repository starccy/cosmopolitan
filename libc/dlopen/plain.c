#include "libc/dlopen/dlfcn.h"
#include "libc/intrin/strace.h"


extern char __dlopen_self[1];

/**
 * Opens a host shared library, like cosmo_dlopen().
 */
void *dlopen(const char *path, int mode) {
  void *res;
  if (path) {
    res = cosmo_dlopen(path, mode);
  } else {
    res = __dlopen_self;
  }
  STRACE("dlopen(%#s, %d) → %p", path, mode, res);
  return res;
}

/**
 * Closes a library dlopen() returned.
 */
int dlclose(void *handle) {
  if (handle == __dlopen_self)
    return 0;
  return cosmo_dlclose(handle);
}
