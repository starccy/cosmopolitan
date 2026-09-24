#include "libc/procfs/internal.h"

// The path model: what a /proc path names, which of them are directories,
// links and content files, and how a caller's spelling (absolute, or
// relative to a descriptor of the tree) becomes a virtual path.

bool pc_is_proc(const char *path) {
  return !strncmp(path, "/proc", 5) && (!path[5] || path[5] == '/');
}

bool pc_is_sys(const char *path) {
  return !strncmp(path, "/sys", 4) && (!path[4] || path[4] == '/');
}

static size_t comp(const char *s, char *out, size_t cap) {
  size_t i = 0;
  while (s[i] && s[i] != '/') {
    if (i < cap - 1)
      out[i] = s[i];
    i++;
  }
  out[i < cap - 1 ? i : cap - 1] = 0;
  return i;
}

void pc_parse(const char *sub, struct node *n) {
  memset(n, 0, sizeof *n);
  while (*sub == '/')
    sub++;
  if (!*sub) {
    n->kind = K_ROOT;
    return;
  }
  char first[64];
  size_t len = comp(sub, first, sizeof first);
  const char *rest = sub + len;
  while (*rest == '/')
    rest++;

  if (!strcmp(first, "self")) {
    n->was_self = true;
    n->pid = pfs_self_pid();
  } else if (first[0] >= '0' && first[0] <= '9') {
    n->pid = (uint32_t)strtoul(first, 0, 10);
    // the spoofed cosmo pid (see pfs_self_pid) is an alias of ourselves
    if (n->pid == (uint32_t)getpid()) {
      n->was_self = true;
      n->pid = pfs_self_pid();
    }
  } else if (!strcmp(first, "net")) {
    if (!*rest) {
      n->kind = K_NET_DIR;
    } else {
      n->kind = K_NET_FILE;
      comp(rest, n->name, sizeof n->name);
    }
    return;
  } else if (!strcmp(first, "sys")) {
    n->kind = K_SYS;
    snprintf(n->rest, sizeof n->rest, "%s", rest);
    return;
  } else {
    n->kind = *rest ? K_OTHER : K_TOP;
    snprintf(n->name, sizeof n->name, "%s", first);
    return;
  }

  if (!*rest) {
    n->kind = K_PID_DIR;
    return;
  }
  n->kind = K_PID_SUB;
  size_t nl = comp(rest, n->name, sizeof n->name);
  const char *deeper = rest + nl;
  while (*deeper == '/')
    deeper++;
  snprintf(n->rest, sizeof n->rest, "%s", deeper);
}

// Whether `sub` (what follows "/proc") is spelled with the "self" alias.
// pc_parse also folds /proc/<getpid()> into self so its content resolves,
// but only the literal spelling is a symlink; the pid directory is a
// directory.
bool pc_spelled_self(const char *sub) {
  while (*sub == '/')
    sub++;
  return !strncmp(sub, "self", 4) && (!sub[4] || sub[4] == '/');
}

// exe, cwd and root of /proc/<pid> and of /proc/<pid>/task/<tid>, where
// Linux shows the process's own, or 0.
const char *pc_link_name(const struct node *n) {
  if (n->kind != K_PID_SUB)
    return 0;
  const char *name = n->name;
  if (!strcmp(name, "task")) {
    name = strchr(n->rest, '/');
    if (!name || strchr(name + 1, '/'))
      return 0;
    name++;
  } else if (n->rest[0]) {
    return 0;
  }
  if (!strcmp(name, "exe") || !strcmp(name, "cwd") || !strcmp(name, "root"))
    return name;
  return 0;
}

// The permission bits of `vpath` when it names one of the tree's symlinks,
// 0 otherwise. Pure parsing, no host call.
unsigned pc_link_mode(const char *vpath) {
  if (!pc_is_proc(vpath))
    return 0;
  struct node n;
  pc_parse(vpath + 5, &n);
  if (n.kind == K_PID_DIR && pc_spelled_self(vpath + 5)) {
    // /proc/self itself, and only spelled with that one component
    const char *after = vpath + 5;
    while (*after == '/')
      after++;
    while (*after && *after != '/')
      after++;
    while (*after == '/')
      after++;
    return *after ? 0 : 0777;
  }
  if (n.kind != K_PID_SUB)
    return 0;
  if (pc_link_name(&n))
    return 0777;
  if (!strcmp(n.name, "fd") && n.rest[0] && !strchr(n.rest, '/'))
    return 0700;  // lrwx------ on Linux
  return 0;
}

// Whether a parsed path names a directory of the tree.
bool pc_is_dir_node(const struct node *n) {
  switch (n->kind) {
    case K_ROOT:
    case K_PID_DIR:
    case K_NET_DIR:
      return true;
    case K_PID_SUB:
      if (!strcmp(n->name, "fd") || !strcmp(n->name, "net"))
        return !n->rest[0];
      if (!strcmp(n->name, "task"))
        return !n->rest[0] || !strchr(n->rest, '/');
      return false;
    case K_SYS: {
      if (!n->rest[0])
        return true;
      for (int i = 0; pfs_sys_dirs[i]; i++)
        if (!strcmp(pfs_sys_dirs[i], n->rest))
          return true;
      return false;
    }
    default:
      return false;
  }
}

// Whether a parsed path names a content file that exists right now.
bool pc_content_exists(const struct node *n) {
  switch (n->kind) {
    case K_TOP:
      for (int i = 0; pfs_top_files[i]; i++)
        if (!strcmp(pfs_top_files[i], n->name))
          return true;
      return false;
    case K_NET_FILE:
      for (int i = 0; pfs_net_files[i]; i++)
        if (!strcmp(pfs_net_files[i], n->name))
          return true;
      return false;
    case K_SYS:
      for (int i = 0; pfs_sys_files[i]; i++)
        if (!strcmp(pfs_sys_files[i], n->rest))
          return true;
      return false;
    case K_PID_SUB: {
      if (!pfs_proc_find(n->pid))
        return false;
      const char *file = 0;
      if (!n->rest[0]) {
        file = n->name;
      } else if (!strcmp(n->name, "task")) {
        const char *f = strchr(n->rest, '/');
        if (f && !strchr(f + 1, '/'))
          file = f + 1;
      } else if (!strcmp(n->name, "net") && !strchr(n->rest, '/')) {
        for (int i = 0; pfs_net_files[i]; i++)
          if (!strcmp(pfs_net_files[i], n->rest))
            return true;
        return false;
      }
      if (!file)
        return false;
      for (int i = 0; pfs_pid_volatile[i]; i++)
        if (!strcmp(pfs_pid_volatile[i], file))
          return true;
      for (int i = 0; pfs_pid_stable[i]; i++)
        if (!strcmp(pfs_pid_stable[i], file))
          return true;
      return false;
    }
    default:
      return false;
  }
}

uint64_t pc_fnv64(const void *data, size_t n, uint64_t h) {
  const uint8_t *b = data;
  for (size_t i = 0; i < n; i++) {
    h ^= b[i];
    h *= 0x100000001b3ull;
  }
  return h;
}

uint64_t pc_inode(const char *vpath) {
  return pc_fnv64(vpath, strlen(vpath), 0xcbf29ce484222325ull) | 1;
}

// Collapses "//", "." and ".." in an absolute path, in place semantics:
// `in` to `out`, which may not alias. Returns false when it will not fit.
static bool normalize(const char *in, char *out, size_t outsz) {
  size_t k = 0;
  const char *p = in;
  while (*p) {
    while (*p == '/')
      p++;
    if (!*p)
      break;
    const char *q = p;
    while (*q && *q != '/')
      q++;
    size_t len = (size_t)(q - p);
    if (len == 1 && p[0] == '.') {
      // stays
    } else if (len == 2 && p[0] == '.' && p[1] == '.') {
      while (k && out[k - 1] != '/')
        k--;
      if (k)
        k--;
    } else {
      if (k + 1 + len + 1 > outsz)
        return false;
      out[k++] = '/';
      memcpy(out + k, p, len);
      k += len;
    }
    p = q;
  }
  if (!k)
    out[k++] = '/';
  out[k] = 0;
  return true;
}

int pc_resolve(int dirfd, const char *path, char *out, size_t outsz) {
  if (!PC_HOSTED() || pc_busy || !path)
    return 0;
  char joined[PATH_MAX];
  const char *p;
  if (path[0] == '/') {
    p = path;
  } else {
    char base[PC_PATH_MAX];
    if (dirfd == AT_FDCWD || !pc_fd_vpath(dirfd, base, sizeof base))
      return 0;
    if (!path[0]) {
      p = base;
    } else {
      int len = snprintf(joined, sizeof joined, "%s/%s", base, path);
      if (len <= 0 || (size_t)len >= sizeof joined)
        return enametoolong();
      p = joined;
    }
  }
  if (!normalize(p, out, outsz))
    return enametoolong();
  if (pc_is_proc(out) || pc_is_sys(out))
    return 1;
  // a path that started in the tree and left it through ".." goes to the
  // host normalized: the kernel would walk through a /proc it does not have
  if (path[0] == '/' && !pc_is_proc(path) && !pc_is_sys(path))
    return 0;
  return 2;
}

int pc_through_link(const struct node *n, const char *vpath, char *out,
                    size_t outsz) {
  if (n->kind != K_PID_SUB || !n->rest[0])
    return 0;
  if (strcmp(n->name, "cwd") && strcmp(n->name, "root") &&
      strcmp(n->name, "exe"))
    return 0;
  char target[PATH_MAX];
  long r;
  pc_enter();
  r = pfs_pid_link(n->pid, n->name, target, sizeof target - 1);
  pc_leave();
  if (r <= 0)
    return enoent();
  target[r] = 0;
  int len = snprintf(out, outsz, "%s/%s", target, n->rest);
  if (len <= 0 || (size_t)len >= outsz)
    return enametoolong();
  return 1;
}
