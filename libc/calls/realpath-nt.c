#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/limits.h"
#include "libc/nt/createfile.h"
#include "libc/nt/enum/creationdisposition.h"
#include "libc/nt/enum/fileflagandattributes.h"
#include "libc/nt/enum/filesharemode.h"
#include "libc/nt/files.h"
#include "libc/nt/runtime.h"
#include "libc/str/str.h"
#include "libc/str/tab.h"

// whether `path` is `tree` or under it
static bool Under(const char *path, const char *tree) {
  size_t n = strlen(tree);
  return !strncmp(path, tree, n) && (!path[n] || path[n] == '/');
}

// folds "." and ".." and repeated slashes out of an absolute path in
// place, never climbing above the root; returns the new length
static size_t Fold(char *p) {
  size_t j = 0;
  for (size_t i = 0; p[i];) {
    while (p[i] == '/')
      ++i;
    if (!p[i])
      break;
    size_t k = i;
    while (p[k] && p[k] != '/')
      ++k;
    size_t n = k - i;
    if (n == 1 && p[i] == '.') {
      // nothing
    } else if (n == 2 && p[i] == '.' && p[i + 1] == '.') {
      while (j > 1 && p[j - 1] != '/')
        --j;
      if (j > 1)
        --j;
    } else {
      if (!j || p[j - 1] != '/')
        p[j++] = '/';
      if (j != i)
        for (size_t t = 0; t < n; ++t)
          p[j + t] = p[i + t];
      j += n;
    }
    i = k;
  }
  if (!j)
    p[j++] = '/';
  p[j] = 0;
  return j;
}

// the path without the cosmos drive letter, which __mkunixpath() drops
// from some spellings and keeps in others
static const char *PastDrive(const char *p) {
  if (p[0] == '/' && kToLower[p[1] & 255] == kToLower[__getcosmosdrive() & 255] &&
      (!p[2] || p[2] == '/'))
    return p[2] ? p + 2 : "/";
  return p;
}

// whether two folded spellings name the same object: case-insensitive,
// and the cosmos drive letter may be present on one side only
static bool SameObject(const char *a, const char *b) {
  const char *x = PastDrive(a), *y = PastDrive(b);
  if (x != a && y != b)
    x = a, y = b;
  size_t m = strlen(x), n = strlen(y);
  if (m != n)
    return false;
  for (size_t i = 0; i < m; ++i)
    if (kToLower[x[i] & 255] != kToLower[y[i] & 255])
      return false;
  return true;
}

/**
 * Resolves an absolute path the way win32 itself follows links.
 *
 * One open stands in for the component walk realpath() does with
 * readlink(). The caller's spelling is kept when no link was involved,
 * so the answer matches the walk's; otherwise it's the final path as
 * win32 reports it.
 *
 * @return length of `out`, -1 with errno, or -2 for the walk to decide
 *     (a virtual tree, a device, something win32 wouldn't open)
 */
textwindows int __realpath_nt(const char *path, char out[PATH_MAX]) {
  if (Under(path, "/proc") || Under(path, "/sys") || Under(path, "/dev") ||
      Under(path, "/zip"))
    return -2;
  char16_t path16[PATH_MAX];
  if (__mkntpath(path, path16) == -1)
    return -2;
  // the caller's spelling, folded, in `out` for now
  if (strlen(path) >= PATH_MAX)
    return -2;
  strcpy(out, path);
  Fold(out);
  int64_t h = CreateFile(
      path16, 0, kNtFileShareRead | kNtFileShareWrite | kNtFileShareDelete, 0,
      kNtOpenExisting, kNtFileFlagBackupSemantics, 0);
  if (h == -1)
    return -2;
  uint32_t n = GetFinalPathNameByHandle(h, path16, PATH_MAX,
                                        kNtFileNameNormalized | kNtVolumeNameDos);
  CloseHandle(h);
  if (!n || n >= PATH_MAX)
    return -2;
  char final[PATH_MAX];
  if (__mkunixpath(path16, final) == -1)
    return -2;
  size_t fn = strlen(final);
  while (fn > 1 && final[fn - 1] == '/')
    final[--fn] = 0;
  if (SameObject(out, final))
    return strlen(out);
  memcpy(out, final, fn + 1);
  return fn;
}
