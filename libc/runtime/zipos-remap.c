#include "libc/atomic.h"
#include "libc/calls/calls.h"
#include "libc/calls/internal.h"
#include "libc/calls/state.internal.h"
#include "libc/calls/struct/stat.h"
#include "libc/intrin/atomic.h"
#include "libc/intrin/strace.h"
#include "libc/runtime/zipos.internal.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/at.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#include "libc/thread/thread.h"
#include "libc/zip.h"

// Serving unix data paths out of the zip store.
//
// A binary may carry files under paths its libraries read on Linux
// (/usr/share/zoneinfo, /etc/ssl/certs, ...) and a manifest at
// /zip/.bundle-info, one `prefix=/zip/path` line per mapping. A mapping
// is active when the host has nothing at the prefix; that is probed once,
// when the table loads on the first lookup, and never again. Lookups of
// an absolute path under an active prefix are rewritten to the zip path.
// Matching is lexical on a normalized spelling, and relative paths are
// never rewritten. Everything is read-only, so a write lands on EROFS.
//
// The same entry point makes a zip directory usable as a dirfd: a relative
// path against one becomes the absolute /zip path, which the rest of the
// lookup chain already knows how to serve.

#define MANIFEST "/zip/.bundle-info"
#define MAX_MAPS 64
#define MAX_TEXT 16384

enum { kUnloaded, kLoading, kLoaded };

struct Remap {
  const char *from;
  const char *to;
  unsigned fromlen;
  unsigned tolen;
};

static struct {
  pthread_mutex_t lock;
  atomic_int state;
  int count;
  struct Remap maps[MAX_MAPS];
  char text[MAX_TEXT];
} g_remap = {PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP};

static bool IsZipPath(const char *path) {
  return path[0] == '/' && path[1] == 'z' && path[2] == 'i' && path[3] == 'p' &&
         (!path[4] || path[4] == '/');
}

// absolute path folded lexically: no doubled slashes, no dot components,
// no trailing slash; returns the length, or cap when it did not fit
static size_t Normalize(const char *s, char *d, size_t cap) {
  size_t n = 0;
  if (cap < 2)
    return cap;
  d[n++] = '/';
  while (*s) {
    while (*s == '/')
      s++;
    if (!*s)
      break;
    const char *seg = s;
    while (*s && *s != '/')
      s++;
    size_t len = s - seg;
    if (len == 1 && seg[0] == '.')
      continue;
    if (len == 2 && seg[0] == '.' && seg[1] == '.') {
      while (n > 1 && d[n - 1] != '/')
        n--;
      if (n > 1)
        n--;
      continue;
    }
    if (n > 1)
      d[n++] = '/';
    if (n + len + 1 > cap)
      return cap;
    memcpy(d + n, seg, len);
    n += len;
  }
  d[n] = 0;
  return n;
}

// strips trailing slashes; a prefix must be absolute and below the root
static char *TrimPrefix(char *s) {
  size_t n = strlen(s);
  while (n > 1 && s[n - 1] == '/')
    s[--n] = 0;
  if (n < 2 || s[0] != '/')
    return 0;
  return s;
}

static void AddMap(char *from, char *to) {
  struct stat st;
  if (g_remap.count == MAX_MAPS)
    return;
  if (!(from = TrimPrefix(from)) || !(to = TrimPrefix(to)))
    return;
  if (!fstatat(AT_FDCWD, from, &st, 0)) {
    STRACE("zipos remap %s inactive, host has it", from);
    return;
  }
  STRACE("zipos remap %s → %s", from, to);
  struct Remap *m = g_remap.maps + g_remap.count++;
  m->from = from;
  m->fromlen = strlen(from);
  m->to = to;
  m->tolen = strlen(to);
}

// reads the manifest and probes the host for each prefix. the probe goes
// through fstatat, which comes back here on the same thread; the recursive
// lock lets that call through with the table reported as not ready. the
// manifest read is what first maps the zip store, and __zipos_init()'s
// own open of the executable comes back here too; __zipos_remap() lets
// that through while the initializer runs
static bool Load(void) {
  pthread_mutex_lock(&g_remap.lock);
  int state = atomic_load_explicit(&g_remap.state, memory_order_relaxed);
  if (state == kLoading) {
    pthread_mutex_unlock(&g_remap.lock);
    return false;
  }
  if (state == kLoaded) {
    pthread_mutex_unlock(&g_remap.lock);
    return true;
  }
  atomic_store_explicit(&g_remap.state, kLoading, memory_order_relaxed);
  int fd = openat(AT_FDCWD, MANIFEST, O_RDONLY | O_CLOEXEC, 0);
  if (fd != -1) {
    size_t n = 0;
    for (;;) {
      ssize_t got = read(fd, g_remap.text + n, MAX_TEXT - 1 - n);
      if (got <= 0)
        break;
      n += got;
      if (n == MAX_TEXT - 1)
        break;
    }
    close(fd);
    g_remap.text[n] = 0;
    char *line = g_remap.text;
    while (line && *line) {
      char *next = strchr(line, '\n');
      if (next)
        *next++ = 0;
      char *eq = strchr(line, '=');
      if (line[0] && line[0] != '#' && eq) {
        *eq = 0;
        AddMap(line, eq + 1);
      }
      line = next;
    }
  }
  atomic_store_explicit(&g_remap.state, kLoaded, memory_order_release);
  pthread_mutex_unlock(&g_remap.lock);
  return true;
}

/**
 * Rewrites an absolute path the manifest maps into the zip store.
 *
 * @return `buf` holding the zip path, or `path` itself when no active
 *     mapping covers it
 */
const char *__zipos_remap(const char *path, char *buf, size_t bufsz) {
  if (path[0] != '/' || IsZipPath(path))
    return path;
  if (atomic_load_explicit(&g_remap.state, memory_order_acquire) != kLoaded) {
    if (__vforked || __zipos_initializing() || !Load())
      return path;
  }
  if (!g_remap.count)
    return path;
  size_t len = Normalize(path, buf, bufsz);
  if (len >= bufsz)
    return path;
  for (int i = 0; i < g_remap.count; ++i) {
    struct Remap *m = g_remap.maps + i;
    if (len < m->fromlen || memcmp(buf, m->from, m->fromlen) ||
        (len > m->fromlen && buf[m->fromlen] != '/'))
      continue;
    size_t rest = len - m->fromlen;
    if (m->tolen + rest + 1 > bufsz)
      return path;
    memmove(buf + m->tolen, buf + m->fromlen, rest + 1);
    memcpy(buf, m->to, m->tolen);
    return buf;
  }
  return path;
}

/**
 * Resolves the path a lookup against `*dirfd` names, for the zip store.
 *
 * An absolute path goes through the remap table. A relative path against
 * a zip directory descriptor becomes the absolute `/zip/...` path of that
 * entry. Anything else comes back unchanged. A zip descriptor is never
 * handed to the host, so `*dirfd` becomes `AT_FDCWD` once the path that
 * comes back is absolute.
 *
 * @return `path` or `buf`, or null with ENAMETOOLONG
 */
const char *__zipos_atpath(int *dirfd, const char *path, char *buf,
                           size_t bufsz) {
  int fd = *dirfd;
  bool zipfd = fd != AT_FDCWD && __isfdkind(fd, kFdZip);
  if (path[0] == '/') {
    if (zipfd)
      *dirfd = AT_FDCWD;
    return __zipos_remap(path, buf, bufsz);
  }
  if (!zipfd)
    return path;
  *dirfd = AT_FDCWD;
  struct ZiposHandle *h =
      (struct ZiposHandle *)(intptr_t)__get_pib()->fds.p[fd].handle;
  const char *dir;
  size_t dirlen;
  if (h->cfile == ZIPOS_SYNTHETIC_DIRECTORY) {
    dir = (const char *)h->data;
    dirlen = strlen(dir);
  } else {
    dir = ZIP_CFILE_NAME(h->zipos->map + h->cfile);
    dirlen = ZIP_CFILE_NAMESIZE(h->zipos->map + h->cfile);
  }
  size_t pathlen = strlen(path);
  if (5 + dirlen + 1 + pathlen + 1 > bufsz) {
    enametoolong();
    return 0;
  }
  char *p = buf;
  memcpy(p, "/zip/", 5), p += 5;
  memcpy(p, dir, dirlen), p += dirlen;
  *p++ = '/';
  memcpy(p, path, pathlen + 1);
  return buf;
}
