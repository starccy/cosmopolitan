#include "libc/calls/calls.h"
#include "libc/calls/struct/stat.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/limits.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/at.h"
#include "libc/sysv/consts/s.h"
#include "libc/sysv/errfuns.h"

// the unix side of __follow_link_nt(): a symlink into one of cosmo's
// virtual trees (/proc, /sys) on a host that has no such tree, xnu.
// the longest prefix of `path` that exists is read as a link and the
// rest of the path put after its target, for the caller to look up
// again. `deep` looks at the parents too, which ENOTDIR calls for; a
// missing final component only needs the component itself.
//
// returns 1 with the path to try in `out`, 0 when no link is involved,
// or -1 with errno set. `out` is the scratch space too

_Thread_local int __follow_link_depth;

int __follow_link(int dirfd, const char *path, bool deep, char out[PATH_MAX]) {
  struct stat st;
  size_t n = strlen(path);
  if (!n || n >= PATH_MAX)
    return 0;
  memcpy(out, path, n + 1);
  while (n > 1 && out[n - 1] == '/')
    out[--n] = 0;
  for (;;) {
    if (!fstatat(dirfd, out, &st, AT_SYMLINK_NOFOLLOW)) {
      if (!S_ISLNK(st.st_mode))
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
