#include "libc/intrin/strace.h"
#include "libc/procfs/internal.h"

// open() of a path in the tree. -2 sends the caller to the host.

static bool wants_write(int flags) {
  return (flags & O_ACCMODE) != O_RDONLY || (flags & O_TRUNC);
}

// A link opened as a file means "open the target"; with O_NOFOLLOW the
// link itself, which only _O_PATH may name.
static int open_link(const char *vpath, int flags) {
  if (flags & O_NOFOLLOW) {
    if (!(flags & _O_PATH))
      return eloop();
    char target[PATH_MAX];
    ssize_t r = __procfs_readlink(AT_FDCWD, vpath, target, sizeof target - 1);
    if (r < 0)
      return -1;
    target[r] = 0;
    struct ProcfsHandle *h = pc_handle_new(vpath);
    if (!h)
      return enomem();
    h->link = true;
    strlcpy(h->vpath, vpath, sizeof h->vpath);  // the link as spelled
    h->p = strdup(target);
    h->n = (size_t)r;
    return pc_handle_fd(h, flags, S_IFLNK | pc_link_mode(vpath));
  }
  char target[PATH_MAX];
  ssize_t r = __procfs_readlink(AT_FDCWD, vpath, target, sizeof target - 1);
  if (r < 0)
    return -1;
  target[r] = 0;
  if (target[0] == '/')
    return openat(AT_FDCWD, target, flags, 0);
  if (target[0] >= '0' && target[0] <= '9') {
    // /proc/self: the pid directory
    char dir[64];
    snprintf(dir, sizeof dir, "/proc/%.20s", target);
    return openat(AT_FDCWD, dir, flags, 0);
  }
  // a descriptor link that is not a path (a socket, a pipe)
  return enxio();
}

static int open_proc(const char *vpath, int flags) {
  struct node n;
  pc_parse(vpath + 5, &n);
  char real[PATH_MAX];
  int r = pc_through_link(&n, vpath, real, sizeof real);
  if (r < 0)
    return -1;
  if (r)
    return openat(AT_FDCWD, real, flags, 0);
  if (pc_link_mode(vpath))
    return open_link(vpath, flags);
  pc_enter();
  bool live = !n.pid || pfs_proc_find(n.pid);
  bool dir = pc_is_dir_node(&n);
  bool file = !dir && pc_content_exists(&n);
  pc_leave();
  if (!live || (!dir && !file))
    return enoent();
  if (dir) {
    if (wants_write(flags))
      return eisdir();
    return pc_open_dir(vpath, flags);
  }
  if (flags & O_DIRECTORY)
    return enotdir();
  if (wants_write(flags))
    return eacces();
  return pc_open_content(vpath, flags);
}

static int open_sys(const char *vpath, int flags) {
  pc_enter();
  int k = pc_sysfs_kind(vpath);
  pc_leave();
  if (k < 0)
    return enoent();
  if (k == 1) {
    if (wants_write(flags))
      return eisdir();
    return pc_open_dir(vpath, flags);
  }
  if (flags & O_DIRECTORY)
    return enotdir();
  if (wants_write(flags))
    return eacces();
  return pc_open_content(vpath, flags);
}

int __procfs_open(int dirfd, const char *path, int flags, unsigned mode) {
  char vpath[PATH_MAX];
  int r = pc_resolve(dirfd, path, vpath, sizeof vpath);
  if (r == 0)
    return -2;
  if (r < 0)
    return -1;
  if (r == 2)
    return openat(AT_FDCWD, vpath, flags, mode);
  int rc = pc_is_sys(vpath) ? open_sys(vpath, flags) : open_proc(vpath, flags);
  STRACE("procfs open(%#s) → %d% m", vpath, rc);
  return rc;
}
