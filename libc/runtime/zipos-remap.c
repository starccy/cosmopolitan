#include "libc/atomic.h"
#include "libc/calls/calls.h"
#include "libc/calls/internal.h"
#include "libc/calls/state.internal.h"
#include "libc/calls/struct/dirent.h"
#include "libc/calls/struct/stat.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/fmt/itoa.h"
#include "libc/intrin/atomic.h"
#include "libc/intrin/kprintf.h"
#include "libc/limits.h"
#include "libc/mem/alg.h"
#include "libc/nt/files.h"
#include "libc/runtime/zipos.internal.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/at.h"
#include "libc/sysv/consts/dt.h"
#include "libc/sysv/consts/map.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/prot.h"
#include "libc/sysv/consts/s.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#include "libc/thread/thread.h"
#include "libc/zip.h"

// Serving unix data paths out of the zip store.
//
// A binary may carry files under paths its libraries read on Linux
// (/usr/share/zoneinfo, /etc/ssl/certs, ...) and a manifest at
// /zip/.bundle-info, one `prefix=/zip/path` line per mapping. The
// manifest becomes an immutable index of the active prefixes and their
// ancestors, loaded on the first lookup. A prefix is active when the
// host has nothing at it and nothing in the way above it; that is
// sampled once, when the index loads, and never again. An ancestor the
// host lacks is served as a virtual directory holding the index's
// children; one the host has stays the host's, and its listing gets
// the index's children merged in. Lookups walk the index by hash,
// one probe per path level, from the longest prefix down.
//
// A descriptor on a directory the index knows remembers its node in
// the fd table, lazily: zipdir is 0 until asked, then 1 for none, or
// the node plus one. Relative lookups against it and its listing go
// through the index with that.

enum { kUnloaded, kLoading, kLoaded, kFailed };
enum { kHost, kZip, kVirtual, kError = -1 };

struct Remap {
  const char *path, *target;
  size_t len, name;  // name: offset of the last component
  size_t parent, child, next;  // one-based, child/next list the children
  size_t npresent;  // children that are present
  uint64_t presentmask;  // bit = name length of a present child, 63 = more
  unsigned mode;
  bool virtual;  // neither the host nor a mapped tree has it
  bool covered;  // it or an ancestor is mapped or virtual
  bool isroot;   // covered, with no covered ancestor
  bool present;  // the parent's own listing shows it as well
};

struct Probe {
  const char *path;
  size_t len;
  unsigned mode;
  bool exists, blocked;
};

// the host's own spelling of a directory the index knows, as a
// descriptor or the working directory reports it: /private/etc for
// /etc on macos, a symlinked /lib on linux
struct Alias {
  const char *canon;
  size_t len, id;
};

static struct {
  pthread_mutex_t lock;
  atomic_int state;
  int error;
  size_t count;
  struct Remap *nodes;
  size_t *slots, *nameslots;  // open addressing, one-based node indices
  size_t mask, namemask;
  uint64_t firstmask;  // bit = first byte of a covered root's first component
  struct Alias *aliases;
  size_t naliases;
} g_remap = {PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP};

static bool FdPath(int fd, char *buf, size_t cap);

int __zipos_bundle_state;

// the working directory while chdir() has it inside the zip store or a
// mapped tree: the public absolute spelling, folded, no trailing slash.
// the host's own working directory stays where it was
static char g_zipcwd[ZIPOS_PATH_MAX];
bool __zipos_incwd;

static bool IsZipPath(const char *p) {
  return !strncmp(p, "/zip", 4) && (!p[4] || p[4] == '/');
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

static int Compare(const void *a, const void *b) {
  const struct Remap *x = a, *y = b;
  size_t n = x->len < y->len ? x->len : y->len;
  int d = memcmp(x->path, y->path, n);
  return d ? d : (x->len > y->len) - (x->len < y->len);
}

static int CompareProbe(const void *a, const void *b) {
  const struct Probe *x = a, *y = b;
  size_t n = x->len < y->len ? x->len : y->len;
  int d = memcmp(x->path, y->path, n);
  return d ? d : (x->len > y->len) - (x->len < y->len);
}

#define FNV_OFFSET 0xcbf29ce484222325ull
#define FNV_PRIME  0x100000001b3ull

static uint64_t Hash(const char *s, size_t n) {
  uint64_t h = FNV_OFFSET;
  for (size_t i = 0; i < n; ++i) {
    h ^= (unsigned char)s[i];
    h *= FNV_PRIME;
  }
  return h;
}

// one-based node index, or zero
static size_t Lookup(const size_t *slots, size_t mask, uint64_t h,
                     const char *s, size_t n, bool byname) {
  for (size_t i = h & mask;; i = (i + 1) & mask) {
    size_t id = slots[i];
    if (!id)
      return 0;
    const struct Remap *m = g_remap.nodes + id - 1;
    if (byname ? m->len - m->name == n && !memcmp(m->path + m->name, s, n)
               : m->len == n && !memcmp(m->path, s, n))
      return id;
  }
}

static void Insert(size_t *slots, size_t mask, uint64_t h, size_t id) {
  size_t i = h & mask;
  while (slots[i])
    i = (i + 1) & mask;
  slots[i] = id;
}

static size_t Find(const char *path, size_t len) {
  if (!g_remap.count)
    return 0;
  return Lookup(g_remap.slots, g_remap.mask, Hash(path, len), path, len,
                false);
}

// whether some node's last component is `s`, of `n` bytes
static bool HasName(const char *s, size_t n) {
  if (!g_remap.count)
    return false;
  return Lookup(g_remap.nameslots, g_remap.namemask, Hash(s, n), s, n,
                true) != 0;
}

// the longest node that is `path` or a prefix of it, by one scan that
// hashes every level; a trailing slash is ignored. the root is never
// asked for, it's the host's
static size_t Deepest(const char *path, size_t len) {
  uint64_t hs[64], h = FNV_OFFSET;
  size_t ls[64], k = 0;
  for (size_t i = 0; i < len; ++i) {
    if (i && path[i] == '/' && k < 64) {
      hs[k] = h;
      ls[k] = i;
      ++k;
    }
    h ^= (unsigned char)path[i];
    h *= FNV_PRIME;
  }
  if (len > 1 && path[len - 1] != '/' && k < 64) {
    hs[k] = h;
    ls[k] = len;
    ++k;
  }
  while (k--) {
    size_t id = Lookup(g_remap.slots, g_remap.mask, hs[k], path, ls[k], false);
    if (id)
      return id;
  }
  return 0;
}

// whether a mapping or virtual directory is `path` or above it. the
// path has no dot components; doubled or trailing slashes are fine
static bool Covered(const char *path, size_t len) {
  if (!(g_remap.firstmask & (1ull << ((unsigned char)path[1] & 63))))
    return false;
  size_t id = Deepest(path, len);
  return id && g_remap.nodes[id - 1].covered;
}

static bool HasDots(const char *path) {
  for (const char *p = path; (p = strstr(p, "/.")); ++p) {
    if (!p[2] || p[2] == '/' || (p[2] == '.' && (!p[3] || p[3] == '/')))
      return true;
  }
  return false;
}

// whether a component of `path` is some node's name, or, with dots
// counted, a dot component that could stand for one. the cwd is never
// inside a mapped or virtual tree, so a relative path reaches one only
// through the name of a node
static bool NamesNode(const char *path, bool dots) {
  for (const char *p = path; *p;) {
    size_t n = strcspn(p, "/");
    bool dot = (n == 1 && p[0] == '.') || (n == 2 && p[0] == '.' && p[1] == '.');
    if (n && dot ? dots : HasName(p, n))
      return true;
    p += n;
    if (*p)
      ++p;
  }
  return false;
}

static void *Allocate(size_t n) {
  void *p = mmap(0, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                 -1, 0);
  return p == MAP_FAILED ? 0 : p;
}

static size_t TableSize(size_t n) {
  size_t m = 8;
  while (m < 2 * n)
    m *= 2;
  return m;
}

static size_t Parent(const char *path, size_t len) {
  while (len > 1 && path[len - 1] != '/')
    --len;
  if (len > 1)
    --len;
  return len;
}

static const struct Probe *FindProbe(const struct Probe *probes, size_t n,
                                     const char *path, size_t len) {
  struct Probe key = {.path = path, .len = len};
  size_t l = 0, r = n;
  while (l < r) {
    size_t m = l + (r - l) / 2;
    int d = CompareProbe(&key, probes + m);
    if (!d)
      return probes + m;
    if (d < 0)
      r = m;
    else
      l = m + 1;
  }
  return 0;
}

// adds the path and every ancestor as nodes; the mapping gets the target
static size_t AddNodes(struct Remap *nodes, size_t count, char *line,
                       size_t len, const char *target, unsigned mode) {
  nodes[count++] = (struct Remap){.path = line, .len = len, .target = target,
                                  .mode = mode};
  for (size_t j = 1; j < len; ++j)
    if (line[j] == '/')
      nodes[count++] = (struct Remap){.path = line, .len = j};
  return count;
}

static bool ReadMaps(void) {
  int fd, e;
  struct stat st;
  char *text = 0, *pool = 0;
  const char *bad = 0;
  struct Remap *nodes = 0;
  struct Probe *probes = 0;
  size_t bytes = 0, capacity = 1, count = 0, allocsize = 0, unique = 0,
         probesize = 0, nprobes = 0, slotsize = 0, aliassize = 0,
         poolsize = 0;
  fd = openat(AT_FDCWD, "/zip/.bundle-info", O_RDONLY | O_CLOEXEC, 0);
  if (fd == -1) {
    if (errno != ENOENT)
      goto Fail;
    atomic_store_explicit(&__zipos_bundle_state, 1, memory_order_relaxed);
    return true;
  }
  if (fstat(fd, &st))
    goto Fail;
  if (st.st_size < 0 || (uint64_t)st.st_size >= SIZE_MAX) {
    einval();
    goto Fail;
  }
  bytes = st.st_size + 1;
  if (!(text = Allocate(bytes)))
    goto Fail;
  size_t n = 0;
  while (n + 1 < bytes) {
    ssize_t got = read(fd, text + n, bytes - n - 1);
    if (got < 0 && errno == EINTR)
      continue;
    if (got <= 0) {
      if (!got)
        eio();
      goto Fail;
    }
    n += got;
  }
  close(fd);
  fd = -1;
  if (memchr(text, 0, n)) {
    einval();
    goto Fail;
  }
  text[n] = 0;
  for (size_t i = 0; i < n; ++i)
    if (text[i] == '/')
      ++capacity;
  if (capacity > SIZE_MAX / sizeof(*nodes)) {
    enomem();
    goto Fail;
  }
  allocsize = capacity * sizeof(*nodes);
  probesize = capacity * sizeof(*probes);
  if (!(nodes = Allocate(allocsize)) || !(probes = Allocate(probesize)))
    goto Fail;

  // every path the manifest names, each probed on the host once. a
  // host object, including a dangling symlink, always owns its name,
  // and a permission or non-directory error isn't absence either
  char normalized[ZIPOS_PATH_MAX];
  for (char *line = text, *next; line; line = next) {
    next = strchr(line, '\n');
    if (next)
      *next++ = 0;
    if (!*line || *line == '#')
      continue;
    bad = line;
    char *eq = strchr(line, '=');
    if (!eq) {
      einval();
      goto Fail;
    }
    *eq++ = 0;
    size_t len = strlen(line);
    if (len < 2 || len >= sizeof(normalized) || line[0] != '/' ||
        IsZipPath(line) ||
        Normalize(line, normalized, sizeof(normalized)) != len ||
        strcmp(line, normalized) || strncmp(eq, "/zip/", 5)) {
      einval();
      goto Fail;
    }
    for (const char *part = line + 1; *part;) {
      const char *end = strchr(part, '/');
      size_t component = end ? end - part : strlen(part);
      if (component > 255) {
        enametoolong();
        goto Fail;
      }
      part += component;
      if (*part)
        ++part;
    }
    for (size_t j = len; j > 1; j = Parent(line, j))
      probes[nprobes++] = (struct Probe){.path = line, .len = j};
  }
  bad = 0;
  qsort(probes, nprobes, sizeof(*probes), CompareProbe);
  size_t uprobes = 0;
  for (size_t i = 0; i < nprobes; ++i) {
    if (uprobes && !CompareProbe(probes + uprobes - 1, probes + i))
      continue;
    struct Probe *p = probes + uprobes++;
    *p = probes[i];
    memcpy(normalized, p->path, p->len);
    normalized[p->len] = 0;
    if (!fstatat(AT_FDCWD, normalized, &st, 0)) {
      p->exists = true;
      p->mode = st.st_mode;
    } else if (errno != ENOENT ||
               !fstatat(AT_FDCWD, normalized, &st, AT_SYMLINK_NOFOLLOW)) {
      p->blocked = true;
    }
  }
  nprobes = uprobes;

  // the active mappings and their ancestors are the index. the first
  // pass left each line split at its '=', the target right after it
  for (char *line = text; line < text + n; line += strlen(line) + 1) {
    if (!*line || *line == '#') {
      // a comment or blank line holds its own newline-split text
      continue;
    }
    const char *target = line + strlen(line) + 1;
    size_t len = strlen(line);
    const struct Probe *p = FindProbe(probes, nprobes, line, len);
    if (p->exists || p->blocked) {
      line = (char *)target;
      continue;
    }
    bool blocked = false;
    for (size_t j = Parent(line, len); j > 1; j = Parent(line, j))
      if (FindProbe(probes, nprobes, line, j)->blocked)
        blocked = true;
    if (!blocked) {
      bad = line;
      if (stat(target, &st))
        goto Fail;
      count = AddNodes(nodes, count, line, len, target, st.st_mode);
    }
    line = (char *)target;
  }
  bad = 0;
  qsort(nodes, count, sizeof(*nodes), Compare);
  unique = 0;
  for (size_t i = 0; i < count; ++i) {
    if (unique && !Compare(nodes + unique - 1, nodes + i)) {
      if (nodes[i].target) {
        if (nodes[unique - 1].target) {
          bad = nodes[i].path;
          einval();
          goto Fail;
        }
        nodes[unique - 1] = nodes[i];
      }
    } else {
      nodes[unique++] = nodes[i];
    }
  }
  g_remap.nodes = nodes;
  g_remap.count = unique;
  if (!unique)
    goto Done;
  g_remap.mask = TableSize(unique) - 1;
  g_remap.namemask = g_remap.mask;
  slotsize = (g_remap.mask + 1) * sizeof(size_t);
  if (!(g_remap.slots = Allocate(slotsize)) ||
      !(g_remap.nameslots = Allocate(slotsize)))
    goto Fail;
  for (size_t i = 0; i < unique; ++i) {
    struct Remap *m = nodes + i;
    m->name = m->len;
    while (m->name > 1 && m->path[m->name - 1] != '/')
      --m->name;
    Insert(g_remap.slots, g_remap.mask, Hash(m->path, m->len), i + 1);
    Insert(g_remap.nameslots, g_remap.namemask,
           Hash(m->path + m->name, m->len - m->name), i + 1);
  }

  // what the host has at each node, and the parent links. parents sort
  // before their children, so `covered` flows down in one pass
  for (size_t i = 0; i < unique; ++i) {
    struct Remap *m = nodes + i;
    if (!m->target) {
      const struct Probe *p = FindProbe(probes, nprobes, m->path, m->len);
      if (p->exists) {
        m->mode = p->mode;
      } else {
        m->mode = S_IFDIR | 0555;
        m->virtual = true;
      }
    }
    m->covered = m->target || m->virtual;
    if (m->len > 1) {
      size_t parent = Find(m->path, Parent(m->path, m->len));
      if (parent) {
        struct Remap *pm = nodes + parent - 1;
        if (pm->target && !S_ISDIR(pm->mode)) {
          bad = pm->path;
          enotdir();
          goto Fail;
        }
        m->parent = parent;
        m->next = pm->child;
        pm->child = i + 1;
        m->isroot = m->covered && !pm->covered;
        m->covered |= pm->covered;
      } else {
        m->isroot = m->covered;
      }
    } else {
      m->isroot = m->covered;
    }
  }

  // a node below a mapping is what the mapped tree has there: a file
  // there blocks the explicit descendant, a directory gives the node its
  // mode, nothing keeps it virtual. what the tree has, the mapped
  // directory's listing shows, so such a node is present there
  for (size_t i = 0; i < unique; ++i) {
    struct Remap *m = nodes + i;
    size_t t = m->parent;
    while (t && !nodes[t - 1].target)
      t = nodes[t - 1].parent;
    if (!t)
      continue;
    const struct Remap *tm = nodes + t - 1;
    size_t tl = strlen(tm->target), tail = m->len - tm->len;
    if (tl + tail + 1 > sizeof(normalized)) {
      enametoolong();
      goto Fail;
    }
    memcpy(normalized, tm->target, tl);
    memcpy(normalized + tl, m->path + tm->len, tail);
    normalized[tl + tail] = 0;
    if (!stat(normalized, &st)) {
      if (!S_ISDIR(st.st_mode)) {
        bad = normalized;
        enotdir();
        goto Fail;
      }
      if (!m->target) {
        m->mode = st.st_mode;
        m->virtual = false;
      }
      m->present = !nodes[m->parent - 1].virtual;
    } else if (errno != ENOENT) {
      bad = normalized;
      goto Fail;
    }
  }

  // under a host directory, the host's own directories are present; a
  // mapped prefix or a virtual directory never is. a listing without
  // present children needs no name check per entry
  for (size_t i = 0; i < unique; ++i) {
    struct Remap *m = nodes + i;
    if (m->isroot)
      g_remap.firstmask |= 1ull << ((unsigned char)m->path[1] & 63);
    if (!m->parent)
      continue;
    struct Remap *pm = nodes + m->parent - 1;
    if (!pm->covered)
      m->present = !m->target && !m->virtual;
    if (m->present) {
      size_t len = m->len - m->name;
      pm->presentmask |= 1ull << (len < 63 ? len : 63);
      ++pm->npresent;
    }
  }

  // host directories above the mappings, under the names the host
  // itself reports for them when they differ
  size_t hostdirs = 0;
  for (size_t i = 0; i < unique; ++i)
    if (!nodes[i].covered && nodes[i].len > 1 && S_ISDIR(nodes[i].mode))
      ++hostdirs;
  if (hostdirs) {
    aliassize = hostdirs * sizeof(struct Alias);
    poolsize = hostdirs * PATH_MAX;
    if (!(g_remap.aliases = Allocate(aliassize)) ||
        !(pool = Allocate(poolsize)))
      goto Fail;
    size_t used = 0;
    char canon[PATH_MAX];
    for (size_t i = 0; i < unique; ++i) {
      struct Remap *m = nodes + i;
      if (m->covered || m->len <= 1 || !S_ISDIR(m->mode))
        continue;
      memcpy(normalized, m->path, m->len);
      normalized[m->len] = 0;
      e = errno;
      int dfd = openat(AT_FDCWD, normalized,
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
      if (dfd == -1) {
        errno = e;
        continue;
      }
      bool got = FdPath(dfd, canon, sizeof(canon));
      close(dfd);
      errno = e;
      if (!got || !strcmp(canon, normalized))
        continue;
      size_t n = strlen(canon);
      memcpy(pool + used, canon, n + 1);
      g_remap.aliases[g_remap.naliases++] =
          (struct Alias){pool + used, n, i + 1};
      used += n + 1;
    }
  }
Done:
  munmap(probes, probesize);
  atomic_store_explicit(&__zipos_bundle_state, unique ? 2 : 1,
                        memory_order_relaxed);
  // the index lives as long as the process, in storage of its own
  return true;
Fail:
  e = errno;
  // every absolute lookup fails from here on, so say why once
  kprintf("error: /zip/.bundle-info rejected%s%s:% m\n", bad ? " at " : "",
          bad ? bad : "");
  if (fd != -1)
    close(fd);
  if (text)
    munmap(text, bytes);
  if (nodes)
    munmap(nodes, allocsize);
  if (probes)
    munmap(probes, probesize);
  if (g_remap.slots)
    munmap(g_remap.slots, slotsize);
  if (g_remap.nameslots)
    munmap(g_remap.nameslots, slotsize);
  if (g_remap.aliases)
    munmap(g_remap.aliases, aliassize);
  if (pool)
    munmap(pool, poolsize);
  g_remap.aliases = 0;
  g_remap.naliases = 0;
  g_remap.slots = g_remap.nameslots = 0;
  g_remap.nodes = 0;
  g_remap.count = 0;
  g_remap.firstmask = 0;
  atomic_store_explicit(&__zipos_bundle_state, 2, memory_order_relaxed);
  errno = e;
  return false;
}

static bool Ready(void) {
  int state = atomic_load_explicit(&g_remap.state, memory_order_acquire);
  if (state == kLoaded)
    return true;
  if (state == kFailed) {
    errno = g_remap.error;
    return false;
  }
  if (__vforked || __zipos_initializing())
    return false;
  pthread_mutex_lock(&g_remap.lock);
  state = atomic_load_explicit(&g_remap.state, memory_order_relaxed);
  if (state == kUnloaded) {
    int e = errno;
    atomic_store_explicit(&g_remap.state, kLoading, memory_order_relaxed);
    bool ok = ReadMaps();
    g_remap.error = ok ? 0 : errno;
    state = ok ? kLoaded : kFailed;
    atomic_store_explicit(&g_remap.state, state, memory_order_release);
    errno = ok ? e : g_remap.error;
  }
  pthread_mutex_unlock(&g_remap.lock);
  if (state == kFailed)
    errno = g_remap.error;
  return state == kLoaded;
}

bool __zipos_remap_active(void) {
  return Ready() && g_remap.count;
}

// the /zip spelling of a normalized path below the mapping `t`
static int MapPath(const struct Remap *t, const char *norm, size_t len,
                   bool slash, char *buf, size_t cap) {
  size_t tl = strlen(t->target), tail = len - t->len;
  if (tl + tail + slash + 1 > cap || tl + tail + slash - 5 >= ZIPOS_PATH_MAX) {
    enametoolong();
    return -1;
  }
  memcpy(buf, t->target, tl);
  memcpy(buf + tl, norm + t->len, tail);
  if (slash && buf[tl + tail - 1] != '/')
    buf[tl + tail++] = '/';
  buf[tl + tail] = 0;
  return 0;
}

// a slash after a mapped regular file is ENOTDIR, even when a following
// dot component would remove that file from the normalized spelling
static bool Traversable(const char *path) {
  char prefix[ZIPOS_PATH_MAX], normalized[ZIPOS_PATH_MAX];
  for (const char *p = path + 1; *p; ++p) {
    if (*p != '/')
      continue;
    size_t len = p - path;
    if (len >= sizeof(prefix))
      break;
    memcpy(prefix, path, len);
    prefix[len] = 0;
    len = Normalize(prefix, normalized, sizeof(normalized));
    if (len >= sizeof(normalized))
      continue;
    size_t id = Deepest(normalized, len);
    if (!id || !g_remap.nodes[id - 1].covered)
      continue;
    if (g_remap.nodes[id - 1].len == len && g_remap.nodes[id - 1].virtual)
      continue;
    size_t t = id;
    while (t && !g_remap.nodes[t - 1].target)
      t = g_remap.nodes[t - 1].parent;
    if (!t)
      continue;
    char mapped[ZIPOS_PATH_MAX + 8];
    if (MapPath(g_remap.nodes + t - 1, normalized, len, false, mapped,
                sizeof(mapped)) == -1)
      return false;
    struct stat st;
    if (stat(mapped, &st))
      return false;
    if (!S_ISDIR(st.st_mode)) {
      enotdir();
      return false;
    }
  }
  return true;
}

// resolves an absolute host-spelled path against the index. kZip fills
// `out` with the zip path, the normalized public spelling in `buf` as
// its alias, and its node; kVirtual the public spelling and its node
static int Resolve(const char *path, char *buf, size_t cap,
                   struct ZiposUri *out) {
  out->node = 0;
  out->alias = 0;
  out->isvirtual = false;
  if (!Ready())
    return g_remap.error ? kError : kHost;
  if (!g_remap.count)
    return kHost;
  size_t rawlen = strlen(path);
  bool dots = HasDots(path);
  if (!dots && !strstr(path, "//") && !Covered(path, rawlen))
    return kHost;
  if (dots && !Traversable(path))
    return kError;
  char norm[ZIPOS_PATH_MAX];
  size_t len = Normalize(path, norm, sizeof(norm));
  if (len >= sizeof(norm)) {
    if (!Covered(path, rawlen))
      return kHost;
    enametoolong();
    return kError;
  }
  size_t id = Deepest(norm, len);
  if (!id || !g_remap.nodes[id - 1].covered)
    return kHost;
  const struct Remap *m = g_remap.nodes + id - 1;
  if (m->len == len)
    out->node = id;
  if (m->len == len && m->virtual) {
    memcpy(out->path, norm, len + 1);
    out->len = len;
    out->isvirtual = true;
    return kVirtual;
  }
  size_t t = id;
  while (t && !g_remap.nodes[t - 1].target)
    t = g_remap.nodes[t - 1].parent;
  if (!t)
    return kHost;
  char zp[ZIPOS_PATH_MAX + 8];
  if (MapPath(g_remap.nodes + t - 1, norm, len, path[rawlen - 1] == '/', zp,
              sizeof(zp)) == -1)
    return kError;
  out->len = __zipos_normpath(out->path, zp + 5, sizeof(out->path));
  if (out->len >= sizeof(out->path) || len + 1 > cap) {
    enametoolong();
    return kError;
  }
  memcpy(buf, norm, len + 1);
  out->alias = buf;
  return kZip;
}

/**
 * Rewrites an absolute path the manifest maps into the zip store.
 *
 * @return `buf` holding the zip path, `path` itself when no mapping
 *     covers it, or null with errno
 */
const char *__zipos_remap(const char *path, char *buf, size_t cap) {
  if (path[0] != '/' || IsZipPath(path))
    return path;
  struct ZiposUri u;
  char alias[ZIPOS_PATH_MAX];
  int r = Resolve(path, alias, sizeof(alias), &u);
  if (r == kError)
    return 0;
  if (r != kZip)
    return path;
  if (5 + u.len + 1 > cap) {
    enametoolong();
    return 0;
  }
  memcpy(buf, "/zip/", 5);
  memcpy(buf + 5, u.path, u.len + 1);
  return buf;
}

/**
 * Resolves an absolute host-spelled path for __zipos_parseuri().
 *
 * @return 1 with `out` filled, 0 when the host owns the path, or -1
 *     with errno; the alias in `out` is cleared since it would point
 *     at this frame
 */
int __zipos_lookup(const char *path, struct ZiposUri *out) {
  char alias[ZIPOS_PATH_MAX];
  int r = Resolve(path, alias, sizeof(alias), out);
  out->alias = 0;
  return r == kError ? -1 : r != kHost;
}

static int ParseZip(const char *p, struct ZiposUri *out) {
  if (!__zipos_get())
    return 0;
  out->len = __zipos_normpath(out->path, p + 4 + !!p[4], sizeof(out->path));
  return out->len < sizeof(out->path);
}

// the host's spelling of the file open on a descriptor
static bool FdPath(int fd, char *buf, size_t cap) {
  int e = errno;
  bool ok = false;
  if (IsWindows()) {
    if (__isfdkind(fd, kFdFile)) {
      char16_t w[PATH_MAX];
      uint32_t n = GetFinalPathNameByHandle(
          __get_pib()->fds.p[fd].handle, w, ARRAYLEN(w),
          kNtFileNameNormalized | kNtVolumeNameDos);
      if (n && n < ARRAYLEN(w)) {
        char u8[PATH_MAX];
        int m = __mkunixpath(w, u8);
        if (m >= 0 && (size_t)m < cap) {
          memcpy(buf, u8, m + 1);
          ok = true;
        }
      }
    }
  } else if (IsXnu()) {
    char p[1024];
    if (__sys_fcntl(fd, 50 /* F_GETPATH */, p) != -1 && strlen(p) < cap) {
      strcpy(buf, p);
      ok = true;
    }
  } else if (IsLinux()) {
    char link[32] = "/proc/self/fd/";
    FormatInt32(link + 14, fd);
    ssize_t n = sys_readlinkat(AT_FDCWD, link, buf, cap - 1);
    if (n > 0 && (size_t)n < cap && buf[0] == '/') {
      buf[n] = 0;
      ok = true;
    }
  }
  errno = e;
  return ok;
}

// a path the host reported, respelled the way the index knows it when
// it starts with an aliased directory; `buf` holds the result
static const char *HostToIndex(const char *path, char *buf, size_t cap) {
  const struct Alias *best = 0;
  for (size_t i = 0; i < g_remap.naliases; ++i) {
    const struct Alias *a = g_remap.aliases + i;
    if ((!best || a->len > best->len) && !strncmp(path, a->canon, a->len) &&
        (!path[a->len] || path[a->len] == '/'))
      best = a;
  }
  if (!best)
    return path;
  const struct Remap *m = g_remap.nodes + best->id - 1;
  size_t rest = strlen(path + best->len);
  if (m->len + rest + 1 > cap)
    return path;
  memcpy(buf, m->path, m->len);
  memcpy(buf + m->len, path + best->len, rest + 1);
  return buf;
}

static void SetFdNode(int fd, size_t id) {
  __fds_lock();
  if (__ensurefds_unlocked(fd) != -1)
    __get_pib()->fds.p[fd].zipdir = id + 1;
  __fds_unlock();
}

static size_t DirNode(const char *path) {
  char norm[ZIPOS_PATH_MAX];
  size_t len = Normalize(path, norm, sizeof(norm));
  if (len >= sizeof(norm))
    return 0;
  size_t id = Find(norm, len);
  return id && S_ISDIR(g_remap.nodes[id - 1].mode) ? id : 0;
}

/**
 * Returns the index node a directory descriptor is open on, or zero.
 *
 * The answer is kept in the fd table; the first call asks the host for
 * the descriptor's path.
 */
size_t __zipos_fdnode(int fd) {
  if (fd < 0 || !Ready() || !g_remap.count)
    return 0;
  size_t v = (unsigned)fd < __get_pib()->fds.n ? __get_pib()->fds.p[fd].zipdir
                                                : 0;
  if (v)
    return v - 1;
  size_t id = 0;
  char path[PATH_MAX], alt[PATH_MAX];
  if (FdPath(fd, path, sizeof(path)))
    id = DirNode(HostToIndex(path, alt, sizeof(alt)));
  SetFdNode(fd, id);
  return id;
}

/**
 * Records the node of a directory just opened by path, when it's known
 * from the path alone; otherwise __zipos_fdnode() asks the host later.
 */
void __zipos_setfdnode(int fd, int dirfd, const char *path) {
  if (__vforked || __isfdkind(fd, kFdZip) || !Ready() || !g_remap.count)
    return;
  if (path[0] == '/') {
    SetFdNode(fd, DirNode(path));
  } else if (dirfd == AT_FDCWD && !NamesNode(path, true)) {
    SetFdNode(fd, 0);
  }
}

/**
 * Resolves a path for openat() and friends.
 *
 * @param dirfd becomes AT_FDCWD when `*path` is rewritten absolute
 * @param path is replaced by `buf` when rewritten
 * @return 1 with `out` describing the zip object, 0 when the host
 *     serves the path, or -1 with errno
 */
int __zipos_resolve_slow(int *dirfd, const char **pathp, char *buf,
                         size_t cap, struct ZiposUri *out) {
  const char *path = *pathp;
  int fd = *dirfd, r;
  out->node = 0;
  out->alias = 0;
  out->isvirtual = false;
  if (path[0] == '/') {
    if (IsZipPath(path))
      return ParseZip(path, out);
    r = Resolve(path, buf, cap, out);
    return r == kError ? -1 : r != kHost;
  }
  if (!*path)
    return 0;
  char abs[ZIPOS_PATH_MAX + 8];
  if (fd == AT_FDCWD && __zipos_incwd) {
    if (!__zipos_cwdjoin(path, buf, cap))
      return -1;
    *pathp = buf;
    if (IsZipPath(buf))
      return ParseZip(buf, out);
    r = Resolve(buf, buf, cap, out);
    return r == kError ? -1 : r != kHost;
  }
  if (__isfdkind(fd, kFdZip)) {
    struct ZiposHandle *h =
        (struct ZiposHandle *)(intptr_t)__get_pib()->fds.p[fd].handle;
    // a directory the index knows, or one below a mapping, has its
    // public spelling; a plain zip directory has only its zip name
    size_t node = __get_pib()->fds.p[fd].zipdir;
    node = node > 1 ? node - 1 : 0;
    char base[ZIPOS_PATH_MAX];
    const char *alias = 0;
    if (node) {
      alias = __zipos_dirpath(node, base, sizeof(base));
    } else if (h->aliasoff) {
      alias = (const char *)h->data + h->aliasoff - 1;
    }
    if (alias) {
      size_t n = strlen(alias), p = strlen(path);
      if (n + 1 + p + 1 > sizeof(abs)) {
        enametoolong();
        return -1;
      }
      memcpy(abs, alias, n);
      abs[n] = '/';
      memcpy(abs + n + 1, path, p + 1);
      r = Resolve(abs, buf, cap, out);
      if (r == kError)
        return -1;
      if (r == kHost) {
        // a lookup that left the mapped tree, for the host to serve by
        // the folded spelling: the directory itself isn't the host's
        if (Normalize(abs, buf, cap) >= cap) {
          enametoolong();
          return -1;
        }
        *pathp = buf;
        *dirfd = AT_FDCWD;
        return 0;
      }
      return 1;
    }
    const char *name = h->cfile ? ZIP_CFILE_NAME(h->zipos->map + h->cfile)
                                : (const char *)h->data;
    size_t n = h->cfile ? ZIP_CFILE_NAMESIZE(h->zipos->map + h->cfile)
                        : strlen(name);
    if (5 + n + 1 + strlen(path) + 1 > cap) {
      enametoolong();
      return -1;
    }
    memcpy(buf, "/zip/", 5);
    memcpy(buf + 5, name, n);
    buf[5 + n] = '/';
    strcpy(buf + 6 + n, path);
    *pathp = buf;
    *dirfd = AT_FDCWD;
    return ParseZip(buf, out);
  }
  if (!Ready())
    return g_remap.error ? -1 : 0;
  if (!g_remap.count || !NamesNode(path, false))
    return 0;
  char base[ZIPOS_PATH_MAX];
  const char *b = base;
  if (fd == AT_FDCWD) {
    int e = errno;
    if (__getcwd(base, sizeof(base)) == -1) {
      errno = e;
      return 0;
    }
    b = HostToIndex(base, buf, cap);
  } else {
    size_t id = __zipos_fdnode(fd);
    if (id ? !__zipos_dirpath(id, base, sizeof(base))
           : !FdPath(fd, base, sizeof(base)))
      return 0;
    if (!id)
      b = HostToIndex(base, buf, cap);
  }
  size_t n = strlen(b), p = strlen(path);
  if (n + 1 + p + 1 > sizeof(abs))
    return 0;
  memcpy(abs, b, n);
  abs[n] = '/';
  memcpy(abs + n + 1, path, p + 1);
  r = Resolve(abs, buf, cap, out);
  return r == kError ? -1 : r != kHost;
}

/**
 * Joins a relative path onto the working directory inside the zip.
 *
 * @return `buf` holding the folded absolute path, or null with errno
 */
const char *__zipos_cwdjoin(const char *path, char *buf, size_t cap) {
  char abs[ZIPOS_PATH_MAX + 8];
  size_t n = strlen(g_zipcwd), p = strlen(path);
  if (n + 1 + p + 1 > sizeof(abs)) {
    enametoolong();
    return 0;
  }
  memcpy(abs, g_zipcwd, n);
  abs[n] = '/';
  memcpy(abs + n + 1, path, p + 1);
  if (Normalize(abs, buf, cap) >= cap) {
    enametoolong();
    return 0;
  }
  return buf;
}

// the public spelling of a directory open on a zip descriptor
static bool ZipFdPath(int fd, char *buf, size_t cap) {
  struct ZiposHandle *h =
      (struct ZiposHandle *)(intptr_t)__get_pib()->fds.p[fd].handle;
  size_t node = __get_pib()->fds.p[fd].zipdir;
  node = node > 1 ? node - 1 : 0;
  if (node)
    return !!__zipos_dirpath(node, buf, cap);
  if (h->aliasoff) {
    const char *alias = (const char *)h->data + h->aliasoff - 1;
    size_t n = strlen(alias);
    if (n + 1 > cap)
      return false;
    memcpy(buf, alias, n + 1);
    return true;
  }
  const char *name = h->cfile ? ZIP_CFILE_NAME(h->zipos->map + h->cfile)
                              : (const char *)h->data;
  size_t n = h->cfile ? ZIP_CFILE_NAMESIZE(h->zipos->map + h->cfile)
                      : strlen(name);
  if (5 + n + 1 > cap)
    return false;
  memcpy(buf, "/zip/", 5);
  memcpy(buf + 5, name, n);
  buf[5 + n] = 0;
  return true;
}

// records `path` folded as the working directory inside the zip
static int SetZipCwd(const char *path) {
  char norm[ZIPOS_PATH_MAX];
  if (Normalize(path, norm, sizeof(norm)) >= sizeof(norm))
    return enametoolong();
  memcpy(g_zipcwd, norm, strlen(norm) + 1);
  __zipos_incwd = true;
  return 0;
}

/**
 * Moves the working directory into the zip store or a mapped tree.
 *
 * The host's working directory is left alone. A relative path that
 * leaves the zip comes back absolute in `buf` for the host to take.
 *
 * @return 1 when the working directory is now inside the zip, 0 when
 *     the host owns the path, or -1 with errno
 */
int __zipos_chdir(const char **pathp, char *buf, size_t cap) {
  int dirfd = AT_FDCWD;
  struct ZiposUri u;
  struct stat st;
  int r = __zipos_resolve_slow(&dirfd, pathp, buf, cap, &u);
  if (r != 1)
    return r;
  if (__zipos_stat(&u, &st) == -1)
    return -1;
  if (!S_ISDIR(st.st_mode))
    return enotdir();
  char pub[ZIPOS_PATH_MAX + 8];
  const char *spelling;
  if (u.alias) {
    spelling = u.alias;
  } else if (u.isvirtual) {
    spelling = u.path;
  } else {
    if (5 + u.len + 1 > sizeof(pub))
      return enametoolong();
    memcpy(pub, "/zip/", 5);
    memcpy(pub + 5, u.path, u.len + 1);
    spelling = pub;
  }
  if (SetZipCwd(spelling) == -1)
    return -1;
  return 1;
}

/**
 * Moves the working directory to the directory open on a zip descriptor.
 */
int __zipos_fchdir(int fd) {
  struct stat st;
  struct ZiposHandle *h =
      (struct ZiposHandle *)(intptr_t)__get_pib()->fds.p[fd].handle;
  if (__zipos_fstat(h, &st) == -1)
    return -1;
  if (!S_ISDIR(st.st_mode))
    return enotdir();
  char pub[ZIPOS_PATH_MAX + 8];
  if (!ZipFdPath(fd, pub, sizeof(pub)))
    return enametoolong();
  return SetZipCwd(pub);
}

/**
 * Reports the working directory when it's inside the zip.
 *
 * @return bytes copied including the nul, -1 with ERANGE, or 0 when
 *     the host owns the working directory
 */
int __zipos_getcwd(char *buf, size_t size) {
  if (!__zipos_incwd)
    return 0;
  size_t n = strlen(g_zipcwd);
  if (n + 1 > size)
    return erange();
  memcpy(buf, g_zipcwd, n + 1);
  return n + 1;
}

// Public logical path for a directory opened through the bundle namespace.
const char *__zipos_dirpath(size_t id, char *buf, size_t cap) {
  if (!id || id > g_remap.count)
    return 0;
  struct Remap *m = g_remap.nodes + id - 1;
  if (m->len + 1 > cap)
    return 0;
  memcpy(buf, m->path, m->len);
  buf[m->len] = 0;
  return buf;
}

/**
 * Returns whether a node's own listing can show any of its index
 * children, in which case readdir() has to check names for duplicates.
 */
bool __zipos_present(size_t id) {
  return id && id <= g_remap.count && g_remap.nodes[id - 1].npresent;
}

/**
 * Returns whether `name` is an index child of node `id` that the node's
 * own listing shows as well.
 */
bool __zipos_ischild(size_t id, const char *name) {
  if (!id || id > g_remap.count)
    return false;
  const struct Remap *parent = g_remap.nodes + id - 1;
  size_t len = strlen(name);
  if (!(parent->presentmask & (1ull << (len < 63 ? len : 63))))
    return false;
  for (size_t i = parent->child; i; i = g_remap.nodes[i - 1].next) {
    const struct Remap *child = g_remap.nodes + i - 1;
    if (child->present && child->len - child->name == len &&
        !memcmp(child->path + child->name, name, len))
      return true;
  }
  return false;
}

/**
 * Fills `ent` with the index child of node `id` after `prev`.
 *
 * @return the child's node, or zero after the last; a child the host
 *     or zip store no longer has is skipped
 */
size_t __zipos_child(size_t id, size_t prev, struct dirent *ent) {
  if (!id || id > g_remap.count)
    return 0;
  size_t child = prev ? g_remap.nodes[prev - 1].next : g_remap.nodes[id - 1].child;
  for (; child; child = g_remap.nodes[child - 1].next) {
    const struct Remap *m = g_remap.nodes + child - 1;
    size_t len = m->len - m->name;
    if (len >= sizeof(ent->d_name))
      continue;
    struct stat st;
    char path[ZIPOS_PATH_MAX];
    __zipos_dirpath(child, path, sizeof(path));
    if (stat(path, &st))
      continue;
    memcpy(ent->d_name, m->path + m->name, len);
    ent->d_name[len] = 0;
    ent->d_ino = st.st_ino;
    ent->d_type = (st.st_mode & S_IFMT) >> 12;
    return child;
  }
  return 0;
}
