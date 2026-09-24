#include "libc/atomic.h"
#include "libc/calls/calls.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/dce.h"
#include "libc/fmt/itoa.h"
#include "libc/limits.h"
#include "libc/nt/createfile.h"
#include "libc/nt/dll.h"
#include "libc/nt/enum/accessmask.h"
#include "libc/nt/enum/creationdisposition.h"
#include "libc/nt/enum/fileflagandattributes.h"
#include "libc/nt/enum/filesharemode.h"
#include "libc/nt/errors.h"
#include "libc/nt/files.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/filetime.h"
#include "libc/nt/struct/win32finddata.h"
#include "libc/nt/synchronization.h"
#include "libc/nt/systeminfo.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/runtime/runtime.h"
#include "libc/ctype.h"
#include "libc/str/str.h"
#include "libc/thread/thread.h"

/**
 * @fileoverview A server's share list as a directory, on Windows.
 *
 * NT has no "\\server" directory, so "//server" (what ".." from a share
 * root reaches, and what a file picker walks up to) was ENOENT. Here the
 * shares are enumerated over the network instead, and a directory with
 * one empty subdirectory per disk share is materialized under the temp
 * directory; __mkntpath() diverts the "//server" spelling there, so stat,
 * opendir and chdir all see a plain directory. Only a path naming the
 * server and nothing else is diverted; real share paths are untouched.
 * Special shares (IPC$, ADMIN$, drive letters) and anything that isn't a
 * disk share are left out. An unreachable name costs a network lookup
 * before it fails.
 *
 * The directory can be the cwd (cd .. from a share root lands there),
 * which takes two more pieces: getcwd() reports it as "//server", and a
 * relative path resolved from inside it is joined back onto "//server",
 * so a share name reaches the real share rather than its placeholder.
 * The same join serves ".." climbing out of a share root, which NT would
 * otherwise clamp at the root.
 *
 * Every "//server/share" this process names or has as its cwd is also
 * remembered, since POSIX leaves a leading "//" implementation-defined
 * and unix path code (realpath-style normalizers, Rust's Path) collapses
 * it to "/server/share/x", which NT reads as a path on the current
 * drive: on a share cwd that is the share root itself, so a file saved
 * under the collapsed cwd landed in <share>/server/share/x with the
 * directories quietly created. A single-slash path whose first two
 * components match a remembered share gets its second slash back. A
 * remembered pair is required, so /usr/x is never touched.
 */

#define STALE_SECS 3600
#define PREFIX     u"cosmo-unc-"
#define PREFIXLEN  10

struct share_info_1 {
  char16_t *netname;
  uint32_t type;
  char16_t *remark;
};

typedef uint32_t (__msabi *NetShareEnumF)(char16_t *, uint32_t, uint8_t **,
                                          uint32_t, uint32_t *, uint32_t *,
                                          uint32_t *);
typedef uint32_t (__msabi *NetApiBufferFreeF)(void *);

static pthread_mutex_t __unc_lock = PTHREAD_MUTEX_INITIALIZER;
static char16_t __unc_root[PATH_MAX];  // win32, no trailing backslash
static size_t __unc_rootlen;
static char __unc_root_unix[PATH_MAX];  // the same as getcwd() spells it
static size_t __unc_root_unixlen;
static bool __unc_seen;  // a unc path or cwd has come through here

// share roots seen, as "server/share" in the spelling first seen;
// matched ascii case-insensitively like NT does. writers take the
// spinlock; a reader sees an entry once the count publishing it is
// stored, so lookups take no lock
#define UNC_ROOT_MAX 16
#define UNC_ROOT_LEN 256
static char __unc_roots[UNC_ROOT_MAX][UNC_ROOT_LEN];
static int __unc_count;
static int __unc_spin;

static bool IsSlash(int c) {
  return c == '/' || c == '\\';
}

static bool IsDots(const char16_t *s) {
  return s[0] == '.' && (!s[1] || (s[1] == '.' && !s[2]));
}

// length of the "server/share" prefix at p (which follows the leading
// slashes), or 0 when there isn't one; device namespaces aren't shares
static size_t UncRootLen(const char *p) {
  size_t i = 0;
  if (!p[0] || IsSlash(p[0]) || p[0] == '?' || p[0] == '.')
    return 0;
  while (p[i] && !IsSlash(p[i]))
    i++;
  if (!IsSlash(p[i]) || !p[i + 1] || IsSlash(p[i + 1]))
    return 0;
  i++;
  size_t share = i;
  while (p[i] && !IsSlash(p[i]))
    i++;
  if (p[share] == '.' &&
      (i - share == 1 || (i - share == 2 && p[share + 1] == '.')))
    return 0;
  return i;
}

static bool UncRootEquals(const char *root, const char *p, size_t n) {
  for (size_t i = 0; i < n; i++) {
    int a = root[i], b = p[i];
    if (IsSlash(a) && IsSlash(b))
      continue;
    if (tolower(a) != tolower(b))
      return false;
  }
  return !root[n];
}

static bool UncRootKnown(const char *p, size_t n) {
  int count = atomic_load_explicit(&__unc_count, memory_order_acquire);
  for (int i = 0; i < count; i++)
    if (UncRootEquals(__unc_roots[i], p, n))
      return true;
  return false;
}

// remembers the share a "//server/share/..." path names
static void UncNote(const char *path) {
  if (!IsSlash(path[0]) || !IsSlash(path[1]))
    return;
  const char *p = path + 2;
  size_t n = UncRootLen(p);
  if (!n || n >= UNC_ROOT_LEN || UncRootKnown(p, n))
    return;
  while (atomic_exchange_explicit(&__unc_spin, 1, memory_order_acquire))
    ;
  int count = __unc_count;
  if (!UncRootKnown(p, n) && count < UNC_ROOT_MAX) {
    memcpy(__unc_roots[count], p, n);
    __unc_roots[count][n] = 0;
    atomic_store_explicit(&__unc_count, count + 1, memory_order_release);
  }
  atomic_store_explicit(&__unc_spin, 0, memory_order_release);
}

// true when some remembered share lives on this server
static bool UncServerKnown(const char *p, size_t n) {
  int count = atomic_load_explicit(&__unc_count, memory_order_acquire);
  for (int i = 0; i < count; i++) {
    const char *r = __unc_roots[i];
    size_t k = 0;
    while (k < n && r[k] && tolower(r[k]) == tolower(p[k]))
      k++;
    if (k == n && IsSlash(r[k]))
      return true;
  }
  return false;
}

// true for "/server/share..." naming a remembered share, i.e. a unc
// path whose leading "//" was collapsed. a bare "/server" counts when
// a share on it is remembered, which is what the parent of a collapsed
// share root looks like
static bool IsCollapsedUnc(const char *path) {
  if (!IsSlash(path[0]) || IsSlash(path[1]))
    return false;
  if (isalpha(path[1]) && (IsSlash(path[2]) || !path[2]))
    return false;  // a /c/... drive path
  if (!atomic_load_explicit(&__unc_count, memory_order_acquire))
    return false;
  size_t n = UncRootLen(path + 1);
  if (n)
    return UncRootKnown(path + 1, n);
  size_t k = 1;
  while (path[k] && !IsSlash(path[k]))
    k++;
  if (path[k] && (!IsSlash(path[k]) || path[k + 1]))
    return false;
  return UncServerKnown(path + 1, k - 1);
}

/**
 * Tells realpath() a "/server/share" path is a collapsed share path,
 * which must not be resolved against the cwd.
 */
textwindows int __unc_collapsed(const char *path) {
  return path && IsCollapsedUnc(path);
}

// removes path (a win32 directory) and everything under it. path needs
// PATH_MAX of room and is restored on return
dontinline textwindows static void RmTree(char16_t *path, size_t n) {
  struct NtWin32FindData fd;
  if (n + 3 > PATH_MAX)
    return;
  path[n] = '\\';
  path[n + 1] = '*';
  path[n + 2] = 0;
  int64_t h = FindFirstFile(path, &fd);
  if (h != -1) {
    do {
      if (IsDots(fd.cFileName))
        continue;
      size_t k = strlen16(fd.cFileName);
      if (n + 1 + k + 1 > PATH_MAX)
        continue;
      memcpy(path + n + 1, fd.cFileName, (k + 1) * sizeof(char16_t));
      if (fd.dwFileAttributes & kNtFileAttributeDirectory) {
        RmTree(path, n + 1 + k);
      } else {
        DeleteFile(path);
      }
    } while (FindNextFile(h, &fd));
    FindClose(h);
  }
  path[n] = 0;
  RemoveDirectory(path);
}

textwindows static void Cleanup(void) {
  if (__unc_rootlen)
    RmTree(__unc_root, __unc_rootlen);
}

// trees left behind by processes that died without cleaning up
dontinline textwindows static void SweepStale(const char16_t *base, size_t n) {
  char16_t pat[PATH_MAX];
  struct NtWin32FindData fd;
  struct NtFileTime now;
  if (n + 1 + PREFIXLEN + 2 > PATH_MAX)
    return;
  memcpy(pat, base, n * sizeof(char16_t));
  pat[n] = '\\';
  memcpy(pat + n + 1, PREFIX, PREFIXLEN * sizeof(char16_t));
  pat[n + 1 + PREFIXLEN] = '*';
  pat[n + 2 + PREFIXLEN] = 0;
  int64_t h = FindFirstFile(pat, &fd);
  if (h == -1)
    return;
  GetSystemTimeAsFileTime(&now);
  uint64_t t = (uint64_t)now.dwHighDateTime << 32 | now.dwLowDateTime;
  do {
    if (!(fd.dwFileAttributes & kNtFileAttributeDirectory))
      continue;
    uint64_t m = (uint64_t)fd.ftLastWriteTime.dwHighDateTime << 32 |
                 fd.ftLastWriteTime.dwLowDateTime;
    if (t - m < (uint64_t)STALE_SECS * 10000000)
      continue;
    size_t k = strlen16(fd.cFileName);
    if (n + 1 + k + 1 > PATH_MAX)
      continue;
    memcpy(pat + n + 1, fd.cFileName, (k + 1) * sizeof(char16_t));
    if (!strcmp16(pat, __unc_root))
      continue;
    RmTree(pat, n + 1 + k);
  } while (FindNextFile(h, &fd));
  FindClose(h);
}

dontinline textwindows static bool EnsureRoot(void) {
  if (__unc_rootlen)
    return true;
  char16_t base[PATH_MAX];
  uint32_t n = GetTempPath(PATH_MAX, base);
  if (!n || n >= PATH_MAX)
    return false;
  while (n > 3 && IsSlash(base[n - 1]))
    base[--n] = 0;
  char pid[12];
  size_t pidlen = FormatUint32(pid, getpid()) - pid;
  if (n + 1 + PREFIXLEN + pidlen + 1 > PATH_MAX)
    return false;
  memcpy(__unc_root, base, n * sizeof(char16_t));
  size_t o = n;
  __unc_root[o++] = '\\';
  memcpy(__unc_root + o, PREFIX, PREFIXLEN * sizeof(char16_t));
  o += PREFIXLEN;
  for (size_t i = 0; i < pidlen; i++)
    __unc_root[o++] = pid[i];
  __unc_root[o] = 0;
  RmTree(__unc_root, o);
  SweepStale(base, n);
  if (!CreateDirectory(__unc_root, 0) &&
      GetLastError() != kNtErrorAlreadyExists)
    return false;
  __unc_rootlen = o;
  int m = __mkunixpath(__unc_root, __unc_root_unix);
  if (m > 0)
    __unc_root_unixlen = m;
  atexit(Cleanup);
  return true;
}

// materializes <root>\<server>\<share>\ for every disk share the server
// offers. false when the server can't be enumerated
dontinline textwindows static bool Populate(const char *server, size_t n,
                                 const char16_t *dir, size_t dirlen) {
  static NetShareEnumF enumf;
  static NetApiBufferFreeF freef;
  if (!enumf) {
    int64_t mod = LoadLibrary(u"netapi32.dll");
    if (!mod)
      return false;
    enumf = (NetShareEnumF)GetProcAddress(mod, "NetShareEnum");
    freef = (NetApiBufferFreeF)GetProcAddress(mod, "NetApiBufferFree");
  }
  if (!enumf || !freef)
    return false;
  char name8[260];
  if (n + 3 > sizeof(name8))
    return false;
  name8[0] = '\\';
  name8[1] = '\\';
  memcpy(name8 + 2, server, n);
  name8[n + 2] = 0;
  char16_t name16[260];
  if (tprecode8to16(name16, 260, name8).ax >= 259)
    return false;
  // NetShareEnum reports an unreachable server by way of an RPC
  // exception, which our vectored handler turns into SIGSEGV before
  // the RPC runtime can catch it. The IPC$ share is reachable exactly
  // when the server is, and asking for its attributes is a plain call.
  char16_t ipc16[280];
  size_t nl = strlen16(name16);
  memcpy(ipc16, name16, nl * sizeof(char16_t));
  memcpy(ipc16 + nl, u"\\IPC$", 6 * sizeof(char16_t));
  int64_t h = CreateFile(
      ipc16, kNtFileReadAttributes,
      kNtFileShareRead | kNtFileShareWrite | kNtFileShareDelete, 0,
      kNtOpenExisting, kNtFileFlagBackupSemantics, 0);
  if (h == -1)
    return false;
  CloseHandle(h);
  uint8_t *buf = 0;
  uint32_t got = 0, total = 0, resume = 0;
  if (enumf(name16, 1, &buf, 0xffffffff, &got, &total, &resume))
    return false;
  if (!CreateDirectory(dir, 0) && GetLastError() != kNtErrorAlreadyExists) {
    freef(buf);
    return false;
  }
  const struct share_info_1 *si = (const struct share_info_1 *)buf;
  for (uint32_t i = 0; i < got; i++) {
    if (si[i].type & 0x80000000u)
      continue;  // special (IPC$, C$, ...)
    if (si[i].type & 3)
      continue;  // print, device, ipc
    size_t k = strlen16(si[i].netname);
    char16_t sub[PATH_MAX];
    if (dirlen + 1 + k + 1 > PATH_MAX)
      continue;
    memcpy(sub, dir, dirlen * sizeof(char16_t));
    sub[dirlen] = '\\';
    memcpy(sub + dirlen + 1, si[i].netname, (k + 1) * sizeof(char16_t));
    CreateDirectory(sub, 0);
  }
  freef(buf);
  return true;
}

// the materialized directory for "//server" (server is n bytes, not
// nul-terminated) as a win32 path, or 0 when the server has no listable
// shares. a server's list is reused for a few seconds, since one
// directory walk asks for it many times over and each answer is a
// network round trip
dontinline textwindows static int ServerDir(const char *server, size_t n, char *out,
                                 size_t outsz) {
  static struct {
    char name[256];
    int64_t when;
    bool ok;
  } cache[8];
  static int next;
  for (size_t i = 0; i < n; i++)
    if (IsSlash(server[i]) || server[i] == ':')
      return 0;
  char16_t dir[PATH_MAX];
  int ok = 0;
  pthread_mutex_lock(&__unc_lock);
  if (EnsureRoot() && __unc_rootlen + 1 + n + 1 <= PATH_MAX) {
    memcpy(dir, __unc_root, __unc_rootlen * sizeof(char16_t));
    dir[__unc_rootlen] = '\\';
    size_t dirlen = __unc_rootlen + 1;
    for (size_t i = 0; i < n; i++)
      dir[dirlen++] = server[i] & 255;
    dir[dirlen] = 0;
    int64_t now = time(0);
    int slot = -1;
    for (int i = 0; i < 8; i++)
      if (cache[i].when && strlen(cache[i].name) == n &&
          !strncasecmp(cache[i].name, server, n))
        slot = i;
    if (slot >= 0 && now - cache[slot].when <= 5) {
      ok = cache[slot].ok;
    } else {
      ok = Populate(server, n, dir, dirlen);
      if (slot < 0 && n < sizeof(cache[0].name)) {
        slot = next++ % 8;
        memcpy(cache[slot].name, server, n);
        cache[slot].name[n] = 0;
      }
      if (slot >= 0) {
        cache[slot].when = now;
        cache[slot].ok = ok;
      }
    }
    if (ok)
      ok = tprecode16to8(out, outsz, dir).ax < outsz - 1;
  }
  pthread_mutex_unlock(&__unc_lock);
  return ok;
}

// whether a unix-spelled path is inside the materialized tree; rest then
// points at "server[/share/...]"
static bool UnderRoot(const char *path, const char **rest) {
  size_t n = __unc_root_unixlen;
  if (!n || strncasecmp(path, __unc_root_unix, n) || path[n] != '/' ||
      !path[n + 1])
    return false;
  *rest = path + n + 1;
  return true;
}

static bool HasDotDot(const char *p) {
  while (*p) {
    while (IsSlash(*p))
      p++;
    if (p[0] == '.' && p[1] == '.' && (!p[2] || IsSlash(p[2])))
      return true;
    while (*p && !IsSlash(*p))
      p++;
  }
  return false;
}

// a relative path joined onto the cwd, where NT would resolve it wrong:
// from a share, ".." must be able to reach the server directory (NT
// clamps it at the share root), and from the materialized server
// directory every name must map to the real share, not the empty
// placeholder. 0 when NT's own resolution is right, which is every
// process that never saw a share
dontinline textwindows static int Relative(const char *path, char *out, size_t outsz) {
  if (!__unc_root_unixlen && !__unc_seen)
    return 0;
  char16_t cwd16[PATH_MAX];
  uint32_t n = GetCurrentDirectory(PATH_MAX, cwd16);
  if (!n || n >= PATH_MAX)
    return 0;
  char cwd[PATH_MAX];
  if (__mkunixpath(cwd16, cwd) < 0)
    return 0;
  const char *rest;
  if (UnderRoot(cwd, &rest)) {
    // "//server/rest/path" with "." and ".." resolved on a stack that
    // never pops the server, since there's no "//" to climb into
    size_t srv = 0;
    while (rest[srv] && rest[srv] != '/')
      srv++;
    if (srv + 3 > outsz)
      return 0;
    out[0] = '/';
    out[1] = '/';
    memcpy(out + 2, rest, srv);
    size_t o = srv + 2, base = o;
    const char *parts[2] = {rest + srv, path};
    bool trailing = false;
    for (int k = 0; k < 2; k++) {
      const char *p = parts[k];
      while (*p) {
        while (IsSlash(*p))
          p++;
        const char *q = p;
        while (*q && !IsSlash(*q))
          q++;
        size_t len = (size_t)(q - p);
        trailing = len && IsSlash(*q);
        if (len == 1 && p[0] == '.') {
        } else if (len == 2 && p[0] == '.' && p[1] == '.') {
          while (o > base && out[o - 1] != '/')
            o--;
          if (o > base)
            o--;
        } else if (len) {
          if (o + len + 2 > outsz)
            return 0;
          out[o++] = '/';
          memcpy(out + o, p, len);
          o += len;
        }
        p = q;
      }
    }
    if (trailing && o > base && o + 1 < outsz)
      out[o++] = '/';
    out[o] = 0;
    return 1;
  }
  if (cwd[0] == '/' && cwd[1] == '/' && HasDotDot(path)) {
    size_t a = strlen(cwd), b = strlen(path);
    if (a + 1 + b + 1 > outsz)
      return 0;
    memcpy(out, cwd, a);
    out[a] = '/';
    memcpy(out + a + 1, path, b + 1);
    return 1;
  }
  return 0;
}

// "//srv/share/rest" whose rest climbs out of the share with ".." is
// resolved the way "/x/.." is "/" on unix: the climb lands in the
// server directory, with whatever remained joined onto "//srv". false
// when there's no climb, or the server has no such directory (the path
// then stays clamped at the share root)
dontinline textwindows static bool Climb(const char *path, char *out, size_t outsz) {
  size_t root = UncRootLen(path + 2);
  if (!root)
    return false;
  const char *rest = path + 2 + root;
  if (!strstr(rest, ".."))
    return false;
  char tail[PATH_MAX];
  size_t o = 0;
  bool climbed = false;
  const char *p = rest;
  while (*p) {
    while (IsSlash(*p))
      p++;
    const char *q = p;
    while (*q && !IsSlash(*q))
      q++;
    size_t len = (size_t)(q - p);
    if (len == 1 && p[0] == '.') {
    } else if (len == 2 && p[0] == '.' && p[1] == '.') {
      if (o) {
        while (o && tail[o - 1] != '/')
          o--;
        if (o)
          o--;
      } else {
        climbed = true;
      }
    } else if (len) {
      if (o + 1 + len + 1 > sizeof(tail))
        return false;
      tail[o++] = '/';
      memcpy(tail + o, p, len);
      o += len;
    }
    p = q;
  }
  if (!climbed)
    return false;
  tail[o] = 0;
  size_t srv = 0;
  while (srv < root && !IsSlash(path[2 + srv]))
    srv++;
  char dir[PATH_MAX];
  if (!ServerDir(path + 2, srv, dir, sizeof(dir)))
    return false;
  if (2 + srv + o + 1 > outsz)
    return false;
  out[0] = '/';
  out[1] = '/';
  memcpy(out + 2, path + 2, srv);
  memcpy(out + 2 + srv, tail, o + 1);
  return true;
}

/**
 * Rewrites a unix path where a server's share list stands in for the
 * "\\server" directory NT doesn't have.
 *
 * Runs on every path __mkntpath() converts. Returns 1 with the path to
 * convert instead in `out`, or 0 to leave the path alone.
 */
textwindows int __unc_fixpath(const char *path, char *out, size_t outsz) {
  const char *cur = path;
  char relbuf[PATH_MAX];
  if (cur[0] && !IsSlash(cur[0]) && !(isalpha(cur[0]) && cur[1] == ':') &&
      Relative(cur, relbuf, sizeof(relbuf)))
    cur = relbuf;
  char uncbuf[PATH_MAX];
  if (IsSlash(cur[0]) && IsSlash(cur[1])) {
    UncNote(cur);
  } else if (IsCollapsedUnc(cur)) {
    size_t len = strlen(cur);
    if (len + 2 <= sizeof(uncbuf)) {
      uncbuf[0] = '/';
      memcpy(uncbuf + 1, cur, len + 1);
      cur = uncbuf;
    }
  }
  if (!IsSlash(cur[0]) || !IsSlash(cur[1]) || !cur[2] || IsSlash(cur[2]) ||
      cur[2] == '?' || cur[2] == '.') {
    if (cur == path)
      return 0;
    goto Done;
  }
  __unc_seen = true;
  char climbbuf[PATH_MAX];
  if (Climb(cur, climbbuf, sizeof(climbbuf)))
    cur = climbbuf;
  // "//server" alone is diverted to the share list
  size_t k = 2;
  while (cur[k] && !IsSlash(cur[k]))
    k++;
  if ((!cur[k] || !cur[k + 1]) && ServerDir(cur + 2, k - 2, out, outsz))
    return 1;
  if (cur == path)
    return 0;
Done:
  size_t len = strlen(cur);
  if (len + 1 > outsz)
    return 0;
  memcpy(out, cur, len + 1);
  return 1;
}

/**
 * Reports a cwd inside the materialized tree as "//server[/...]".
 *
 * Rewrites buf in place. Returns the new length including the nul, or
 * 0 when the cwd is somewhere else.
 */
textwindows int __unc_cwd(char *buf, size_t size) {
  const char *rest;
  if (buf[0] == '/' && buf[1] == '/') {
    __unc_seen = true;
    UncNote(buf);
  }
  if (!__unc_root_unixlen || !UnderRoot(buf, &rest))
    return 0;
  size_t n = strlen(rest);
  if (n + 3 > size)
    return 0;
  memmove(buf + 2, rest, n + 1);
  buf[0] = '/';
  buf[1] = '/';
  __unc_seen = true;
  return (int)n + 3;
}

