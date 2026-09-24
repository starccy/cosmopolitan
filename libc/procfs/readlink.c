#include "libc/procfs/internal.h"

// readlink() of the tree's symlinks: /proc/self, and exe, cwd, root and
// fd/<n> of a process or one of its threads. -2 sends the caller to the
// host.

#define MAX_FDS  512
#define MAX_SOCK 256

static ssize_t put(char *buf, size_t bufsiz, const char *text) {
  size_t n = strlen(text);
  if (n > bufsiz)
    n = bufsiz;
  memcpy(buf, text, n);
  return (ssize_t)n;
}

static ssize_t link_of_node(const struct node *n, const char *sub, char *buf,
                            size_t bufsiz) {
  if (n->kind == K_PID_DIR && pc_spelled_self(sub)) {
    char num[16];
    snprintf(num, sizeof num, "%u", n->pid);
    return put(buf, bufsiz, num);
  }
  if (n->kind != K_PID_SUB)
    return einval();
  const char *link = pc_link_name(n);
  if (link) {
    char target[PATH_MAX];
    long r = pfs_pid_link(n->pid, link, target, sizeof target - 1);
    if (r < 0)
      return enoent();
    target[r] = 0;
    return put(buf, bufsiz, target);
  }
  if (!strcmp(n->name, "fd") && n->rest[0] && !strchr(n->rest, '/')) {
    int k = atoi(n->rest);
    static struct pfs_fdent ents[MAX_FDS];  // under pc_lock
    int nfd = n->pid == pfs_self_pid() ? pfs_self_fds(ents, MAX_FDS)
                                       : pfs_other_fds(n->pid, ents, MAX_FDS);
    if (nfd >= 0) {
      for (int i = 0; i < nfd; i++)
        if (ents[i].fd == k)
          return put(buf, bufsiz, ents[i].text);
      return enoent();
    }
    // NT: only the socket tables see into other processes
    static uint64_t inodes[MAX_SOCK];
    nfd = pfs_net_fds_of(n->pid, inodes, MAX_SOCK);
    if (k < 0 || k >= nfd)
      return enoent();
    char text[64];
    snprintf(text, sizeof text, "socket:[%llu]", (unsigned long long)inodes[k]);
    return put(buf, bufsiz, text);
  }
  return einval();
}

ssize_t __procfs_readlink(int dirfd, const char *path, char *buf,
                          size_t bufsiz) {
  // the descriptor itself, when it names a link
  if (path && !path[0] && __isfdkind(dirfd, kFdProc)) {
    struct ProcfsHandle *h =
        (struct ProcfsHandle *)(intptr_t)__get_pib()->fds.p[dirfd].handle;
    if (!h->link)
      return einval();
    return put(buf, bufsiz, h->p);
  }
  char vpath[PATH_MAX];
  int r = pc_resolve(dirfd, path, vpath, sizeof vpath);
  if (r == 0)
    return -2;
  if (r < 0)
    return -1;
  if (r == 2)
    return readlinkat(AT_FDCWD, vpath, buf, bufsiz);
  if (pc_is_sys(vpath)) {
    pc_enter();
    int k = pc_sysfs_kind(vpath);
    pc_leave();
    return k < 0 ? enoent() : einval();
  }
  struct node n;
  pc_parse(vpath + 5, &n);
  if (n.pid && !pc_spelled_self(vpath + 5)) {
    pc_enter();
    bool live = !!pfs_proc_find(n.pid);
    pc_leave();
    if (!live)
      return enoent();
  }
  if (!pc_link_mode(vpath)) {
    struct stat st;
    if (__procfs_stat(AT_FDCWD, vpath, &st, AT_SYMLINK_NOFOLLOW))
      return -1;
    return einval();
  }
  pc_enter();
  ssize_t rc = link_of_node(&n, vpath + 5, buf, bufsiz);
  pc_leave();
  return rc;
}
