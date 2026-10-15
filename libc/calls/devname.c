#include "libc/calls/internal.h"
#include "libc/str/str.h"

/**
 * Returns what `path` names under /dev, for the devices windows makes up.
 *
 * Trailing slashes are dropped, so "/dev" and "/dev/" give "", and
 * "/dev/pts/" gives "pts". Returns NULL when path isn't under /dev or
 * the name doesn't fit.
 */
const char *__devname(const char *path, char buf[32]) {
  if (!startswith(path, "/dev"))
    return 0;
  const char *p = path + 4;
  if (*p && *p != '/')
    return 0;
  while (*p == '/')
    ++p;
  size_t n = strlen(p);
  while (n && p[n - 1] == '/')
    --n;
  if (n >= 32)
    return 0;
  memcpy(buf, p, n);
  buf[n] = 0;
  return buf;
}
