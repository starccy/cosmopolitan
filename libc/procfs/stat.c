#include "libc/procfs/internal.h"
#include "libc/sysv/consts/ok.h"

// stat() and access() of a path in the tree, the answer a kernel /proc
// would have given. -2 sends the caller to the host.

static void fill(struct stat *st, const char *vpath, unsigned mode) {
  memset(st, 0, sizeof *st);
  st->st_mode = mode;
  st->st_nlink = S_ISDIR(mode) ? 2 : 1;
  st->st_blksize = 4096;
  st->st_dev = 0x70726f63;  // "proc"
  st->st_ino = pc_inode(vpath);
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  st->st_atim = st->st_mtim = st->st_ctim = now;
}

// The target of one of the tree's links, followed.
static int stat_link_target(const char *vpath, struct stat *st) {
  char target[PATH_MAX];
  ssize_t r = __procfs_readlink(AT_FDCWD, vpath, target, sizeof target - 1);
  if (r <= 0)
    return enoent();
  target[r] = 0;
  if (target[0] == '/' && target[1])
    return fstatat(AT_FDCWD, target, st, 0);
  // fd targets that are not paths stat as what they stand for; a
  // descriptor of our own is the descriptor
  const char *fdpart = strstr(vpath, "/fd/");
  if (fdpart && !strncmp(vpath, "/proc/self/", 11)) {
    int fd = atoi(fdpart + 4);
    if (fd >= 0 && !fstat(fd, st))
      return 0;
  }
  if (!strncmp(target, "socket:", 7)) {
    fill(st, vpath, S_IFSOCK | 0777);
    return 0;
  }
  if (!strncmp(target, "pipe:", 5)) {
    fill(st, vpath, S_IFIFO | 0600);
    return 0;
  }
  if (!strncmp(target, "anon_inode:", 11)) {
    fill(st, vpath, S_IFREG | 0600);
    return 0;
  }
  // "/", or /proc/self's "<pid>": a directory either way
  fill(st, vpath, S_IFDIR | 0555);
  return 0;
}

static int stat_proc(const char *vpath, struct stat *st, bool nofollow) {
  struct node n;
  pc_parse(vpath + 5, &n);
  char real[PATH_MAX];
  int r = pc_through_link(&n, vpath, real, sizeof real);
  if (r < 0)
    return -1;
  if (r)
    return fstatat(AT_FDCWD, real, st, nofollow ? AT_SYMLINK_NOFOLLOW : 0);
  unsigned lmode = pc_link_mode(vpath);
  if (lmode) {
    if (nofollow) {
      fill(st, vpath, S_IFLNK | lmode);
      return 0;
    }
    return stat_link_target(vpath, st);
  }
  pc_enter();
  bool live = !n.pid || pfs_proc_find(n.pid);
  bool dir = pc_is_dir_node(&n);
  bool file = !dir && pc_content_exists(&n);
  pc_leave();
  if (!live || (!dir && !file))
    return enoent();
  fill(st, vpath, dir ? S_IFDIR | 0555 : S_IFREG | 0444);
  return 0;
}

static int stat_sys(const char *vpath, struct stat *st) {
  pc_enter();
  int k = pc_sysfs_kind(vpath);
  pc_leave();
  if (k < 0)
    return enoent();
  fill(st, vpath, k == 1 ? S_IFDIR | 0555 : S_IFREG | 0444);
  return 0;
}

int __procfs_stat(int dirfd, const char *path, struct stat *st, int flags) {
  char vpath[PATH_MAX];
  int r = pc_resolve(dirfd, path, vpath, sizeof vpath);
  if (r == 0)
    return -2;
  if (r < 0)
    return -1;
  if (r == 2)
    return fstatat(AT_FDCWD, vpath, st, flags);
  if (pc_is_sys(vpath))
    return stat_sys(vpath, st);
  return stat_proc(vpath, st, !!(flags & AT_SYMLINK_NOFOLLOW));
}

// Everything readable, directories searchable, nothing writable, absent
// things absent.
int __procfs_access(int dirfd, const char *path, int amode) {
  char vpath[PATH_MAX];
  int r = pc_resolve(dirfd, path, vpath, sizeof vpath);
  if (r == 0)
    return -2;
  if (r < 0)
    return -1;
  if (r == 2)
    return faccessat(AT_FDCWD, vpath, amode, 0);
  struct stat st;
  if (__procfs_stat(AT_FDCWD, vpath, &st, 0))
    return -1;
  if (amode & W_OK)
    return eacces();
  if ((amode & X_OK) && !S_ISDIR(st.st_mode))
    return eacces();
  return 0;
}
