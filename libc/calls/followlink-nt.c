#include "libc/calls/calls.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/limits.h"
#include "libc/nt/enum/fileflagandattributes.h"
#include "libc/nt/files.h"
#include "libc/str/str.h"
#include "libc/sysv/errfuns.h"

// a symlink windows could not follow, which is what a link into one of
// cosmo's virtual trees (/proc, /sys) is. the longest prefix of `path`
// that exists is read as a link and the rest of the path put after its
// target, for the caller to look up again the ordinary way. `deep`
// looks at the parents too, which a "not a directory" answer calls
// for; a missing final component only needs the component itself.
//
// returns 1 with the path to try in `out`, 0 when no link is involved,
// or -1 with errno set. `out` is the scratch space too: the prefix is
// built at its start and the link read in after it

textwindows int __follow_link_nt(int dirfd, const char *path, bool deep,
                                 char out[PATH_MAX]) {
  char16_t p16[PATH_MAX];
  size_t n = strlen(path);
  if (!n || n >= PATH_MAX)
    return 0;
  memcpy(out, path, n + 1);
  while (n > 1 && out[n - 1] == '/')
    out[--n] = 0;
  for (;;) {
    uint32_t attr = -1u;
    if (__mkntpathat(dirfd, out, p16) != -1)
      attr = GetFileAttributes(p16);
    if (attr != -1u) {
      if (!(attr & kNtFileAttributeReparsePoint))
        return 0;
      break;
    }
    if (!deep)
      return 0;
    char *s = strrchr(out, '/');
    if (!s || s == out)
      return 0;
    while (s > out && s[-1] == '/')
      --s;
    *s = 0;
    n = s - out;
  }
  char *target = out + n + 1;
  size_t room = PATH_MAX - n - 1;
  ssize_t t = readlinkat(dirfd, out, target, room - 1);
  if (t <= 0)
    return 0;
  target[t] = 0;
  const char *rest = path + n;
  size_t dirlen = 0;
  if (target[0] != '/') {
    const char *s = strrchr(out, '/');
    dirlen = s ? s - out + 1 : 0;
  }
  size_t restlen = strlen(rest);
  if (dirlen + t + restlen >= PATH_MAX)
    return enametoolong();
  memmove(out + dirlen, target, t);
  memcpy(out + dirlen + t, rest, restlen + 1);
  if (!strcmp(out, path))
    return eloop();
  return 1;
}
