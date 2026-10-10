#include "libc/procfs/internal.h"

// Directory listings, served from memory. A monitor enumerates /proc and
// every /proc/<pid>/task on each refresh; the whole answer is built at
// opendir and walked without a host call per entry.

static void add_num(struct pc_list *l, uint32_t v) {
  char name[16];
  snprintf(name, sizeof name, "%u", v);
  pc_list_add(l, name, DT_DIR);
}

static void add_num64(struct pc_list *l, uint64_t v) {
  char name[24];
  snprintf(name, sizeof name, "%llu", (unsigned long long)v);
  pc_list_add(l, name, DT_DIR);
}

static void dots(struct pc_list *l) {
  pc_list_add(l, ".", DT_DIR);
  pc_list_add(l, "..", DT_DIR);
}

// The files of a process directory; a thread's directory has the same
// files but no task/, net/, fd/ or fdinfo/ of its own.
static void pid_entries(struct pc_list *l, bool thread) {
  dots(l);
  for (int i = 0; pfs_pid_volatile[i]; i++)
    pc_list_add(l, pfs_pid_volatile[i], DT_REG);
  for (int i = 0; pfs_pid_stable[i]; i++)
    pc_list_add(l, pfs_pid_stable[i], DT_REG);
  pc_list_add(l, "exe", DT_LNK);
  pc_list_add(l, "cwd", DT_LNK);
  pc_list_add(l, "root", DT_LNK);
  if (thread)
    return;
  pc_list_add(l, "task", DT_DIR);
  pc_list_add(l, "net", DT_DIR);
  pc_list_add(l, "fd", DT_DIR);
  pc_list_add(l, "fdinfo", DT_DIR);
}

static void root_entries(struct pc_list *l) {
  dots(l);
  const struct pfs_proc *procs;
  int n = pfs_procs(&procs);
  for (int i = 0; i < n; i++)
    add_num(l, procs[i].pid);
  pc_list_add(l, "self", DT_LNK);
  for (int i = 0; pfs_top_files[i]; i++)
    pc_list_add(l, pfs_top_files[i], DT_REG);
  pc_list_add(l, "net", DT_DIR);
  pc_list_add(l, "sys", DT_DIR);
}

static void net_entries(struct pc_list *l) {
  dots(l);
  for (int i = 0; pfs_net_files[i]; i++)
    pc_list_add(l, pfs_net_files[i], DT_REG);
}

// /proc/sys and its subdirectories, from the static name tables.
static void sys_entries(struct pc_list *l, const char *rest) {
  dots(l);
  size_t len = strlen(rest);
  for (int i = 0; pfs_sys_dirs[i]; i++) {
    const char *d = pfs_sys_dirs[i];
    if (len && (strncmp(d, rest, len) || d[len] != '/'))
      continue;
    const char *leaf = len ? d + len + 1 : d;
    if (strchr(leaf, '/'))
      continue;
    pc_list_add(l, leaf, DT_DIR);
  }
  for (int i = 0; pfs_sys_files[i]; i++) {
    const char *f = pfs_sys_files[i];
    if (len && (strncmp(f, rest, len) || f[len] != '/'))
      continue;
    const char *leaf = len ? f + len + 1 : f;
    if (strchr(leaf, '/'))
      continue;
    pc_list_add(l, leaf, DT_REG);
  }
}

// The descriptors of a process, as fd/ (links) or fdinfo/ (files) names
// them. On NT another process's directory only knows its sockets, densely
// numbered from the socket tables.
static void fd_entries(struct pc_list *l, uint32_t pid, unsigned char type) {
  dots(l);
  char name[16];
  struct pfs_fdent *ents;
  int nf = pid == pfs_self_pid() ? pfs_self_fds(&ents)
                                 : pfs_other_fds(pid, &ents);
  if (nf >= 0) {
    for (int i = 0; i < nf; i++) {
      snprintf(name, sizeof name, "%d", ents[i].fd);
      pc_list_add(l, name, type);
    }
    free(ents);
    return;
  }
  uint64_t *inodes;
  nf = pfs_net_fds_of(pid, &inodes);
  for (int i = 0; i < nf; i++) {
    snprintf(name, sizeof name, "%d", i);
    pc_list_add(l, name, type);
  }
  free(inodes);
}

// -1: not a directory listed here. -2: one, but for a process that is
// gone. Otherwise fills l.
static int list_node(const struct node *n, struct pc_list *l) {
  switch (n->kind) {
    case K_ROOT:
      root_entries(l);
      return 0;
    case K_NET_DIR:
      net_entries(l);
      return 0;
    case K_SYS:
      if (!pc_is_dir_node(n))
        return -1;
      sys_entries(l, n->rest);
      return 0;
    case K_PID_DIR:
      if (!pfs_proc_find(n->pid))
        return -2;
      pid_entries(l, false);
      return 0;
    case K_PID_SUB:
      if (!strcmp(n->name, "task")) {
        if (!pfs_proc_find(n->pid))
          return -2;
        if (!n->rest[0]) {
          dots(l);
          uint64_t *tids;
          int nt = pfs_threads_of(n->pid, &tids);
          if (!nt)
            add_num(l, n->pid);
          for (int i = 0; i < nt; i++)
            add_num64(l, tids[i]);
          free(tids);
          return 0;
        }
        if (!strchr(n->rest, '/')) {
          pid_entries(l, true);
          return 0;
        }
        return -1;
      }
      if (!strcmp(n->name, "net") && !n->rest[0]) {
        if (!pfs_proc_find(n->pid))
          return -2;
        net_entries(l);
        return 0;
      }
      if (!strcmp(n->name, "fd") && !n->rest[0]) {
        if (!pfs_proc_find(n->pid))
          return -2;
        fd_entries(l, n->pid, DT_LNK);
        return 0;
      }
      if (!strcmp(n->name, "fdinfo") && !n->rest[0]) {
        if (!pfs_proc_find(n->pid))
          return -2;
        fd_entries(l, n->pid, DT_REG);
        return 0;
      }
      return -1;
    default:
      return -1;
  }
}

int pc_list_dir(const char *vpath, struct pfs_virtent **out) {
  struct pc_list l = {0};
  int rc;
  pc_enter();
  if (pc_is_sys(vpath)) {
    rc = pc_sysfs_list(vpath, &l);
  } else {
    struct node n;
    pc_parse(vpath + 5, &n);
    rc = list_node(&n, &l);
  }
  pc_leave();
  if (rc < 0 || l.oom) {
    free(l.p);
    return rc < 0 ? rc : -1;
  }
  *out = l.p;
  return l.n;
}
