#include "libc/calls/calls.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/calls/struct/dirent.h"
#include "libc/calls/struct/stat.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/fmt/conv.h"
#include "libc/fmt/itoa.h"
#include "libc/limits.h"
#include "libc/mem/mem.h"
#include "libc/nt/createfile.h"
#include "libc/nt/enum/accessmask.h"
#include "libc/nt/enum/creationdisposition.h"
#include "libc/nt/enum/filesharemode.h"
#include "libc/runtime/runtime.h"
#include "libc/runtime/zipos.internal.h"
#include "libc/stdio/stdio.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/at.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/s.h"
#include "libc/temp.h"
#include "libc/thread/thread.h"
#include "libc/proc/posix_spawn.internal.h"

// Host libraries loaded by cosmo_dlopen() open files with the host's
// libc, which knows nothing of the zip store. On Linux the dlopen helper
// sends the paths the zip store serves here first: anything under /zip,
// and the unix data paths /zip/.bundle-info maps into it. Elsewhere the
// program asks, through cosmo_hostpath(), before it hands a path over.
//
// What the host gets back is a real path, under a private directory
// that holds copies of what the zip store serves: a file on its own, a
// directory with everything beneath it, and a shared library along
// with the rest of its directory, so that $ORIGIN, @loader_path or the
// dll search finds its siblings.
// The copies are made the first time something asks, and the directory
// is removed when the process that made it exits. One left behind by a
// process that crashed is removed by the next one to make its own.

struct Done {
  struct Done *next;
  bool tree;
  char path[];
};

static struct {
  pthread_mutex_t lock;
  int owner;
  char *root;
  struct Done *done;
} __hostpath = {PTHREAD_MUTEX_INITIALIZER};

static bool is_zip(const char *p) {
  return p[0] == '/' && p[1] == 'z' && p[2] == 'i' && p[3] == 'p' &&
         (!p[4] || p[4] == '/');
}

static bool is_lib(const char *p) {
  const char *b = strrchr(p, '/') + 1;
  return strstr(b, ".so.") || endswith(b, ".so") || endswith(b, ".dylib") ||
         endswith(b, ".dll") || endswith(b, ".DLL");
}

// removes a tree on the real filesystem, relative to dfd
static void remove_tree(int dfd, const char *name) {
  int fd;
  DIR *d;
  struct dirent *e;
  if (!unlinkat(dfd, name, 0))
    return;
  if (errno != EISDIR && errno != EPERM)
    return;
  if ((fd = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) != -1) {
    if ((d = fdopendir(fd))) {
      while ((e = readdir(d)))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
          remove_tree(dirfd(d), e->d_name);
      closedir(d);
    } else {
      close(fd);
    }
  }
  unlinkat(dfd, name, AT_REMOVEDIR);
}

static void remove_root(void) {
  if (__hostpath.root && getpid() == __hostpath.owner)
    remove_tree(AT_FDCWD, __hostpath.root);
}

// removes directories other processes left behind when they crashed
static void sweep(const char *tmp) {
  DIR *d;
  struct stat st;
  struct dirent *e;
  if (!(d = opendir(tmp)))
    return;
  while ((e = readdir(d))) {
    if (strncmp(e->d_name, "cosmo-zip-", 10))
      continue;
    int pid = atoi(e->d_name + 10);
    if (pid <= 0 || pid == getpid() || !kill(pid, 0) || errno != ESRCH)
      continue;
    if (fstatat(dirfd(d), e->d_name, &st, AT_SYMLINK_NOFOLLOW) ||
        !S_ISDIR(st.st_mode) || st.st_uid != getuid())
      continue;
    remove_tree(dirfd(d), e->d_name);
  }
  closedir(d);
}

static const char *get_root(void) {
  if (__hostpath.root && __hostpath.owner == getpid())
    return __hostpath.root;
  // a forked child makes its own, since the parent removes its copies
  // when it exits
  const char *tmp = __get_tmpdir();
  char *r, *p;
  if (!(r = malloc(strlen(tmp) + 48)))
    return 0;
  p = stpcpy(stpcpy(r, tmp), "cosmo-zip-");
  p = FormatInt32(p, getpid());
  stpcpy(p, "-XXXXXX");
  if (!mkdtemp(r)) {
    free(r);
    return 0;
  }
  if (!__hostpath.root)
    atexit(remove_root);
  __hostpath.root = r;
  __hostpath.owner = getpid();
  while (__hostpath.done) {
    struct Done *d = __hostpath.done;
    __hostpath.done = d->next;
    free(d);
  }
  sweep(tmp);
  return r;
}

static bool is_done(const char *zpath, bool tree) {
  size_t n;
  struct Done *d;
  for (d = __hostpath.done; d; d = d->next) {
    if (!strcmp(d->path, zpath) && (d->tree || !tree))
      return true;
    n = strlen(d->path);
    if (d->tree && !strncmp(d->path, zpath, n) && zpath[n] == '/')
      return true;
  }
  return false;
}

static void set_done(const char *zpath, bool tree) {
  struct Done *d;
  if ((d = malloc(sizeof(*d) + strlen(zpath) + 1))) {
    d->tree = tree;
    strcpy(d->path, zpath);
    d->next = __hostpath.done;
    __hostpath.done = d;
  }
}

// makes the directories leading up to `path`, which is under the root
static void make_parents(char *path) {
  char *p = path + strlen(__hostpath.root) + 1;
  while ((p = strchr(p, '/'))) {
    *p = 0;
    mkdir(path, 0700);
    *p++ = '/';
  }
}

static int copy_file(const char *zpath, const char *dst, int mode) {
  char *buf;
  ssize_t got = -1;
  int zfd, fd, rc = -1;
  if ((zfd = open(zpath, O_RDONLY | O_CLOEXEC)) == -1)
    return -1;
  if ((fd = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600)) != -1) {
    if ((buf = malloc(65536))) {
      while ((got = read(zfd, buf, 65536)) > 0)
        if (write(fd, buf, got) != got) {
          got = -1;
          break;
        }
      free(buf);
    }
    // read-only, keeping the execute bits a shared library needs
    fchmod(fd, (mode & 0555) | 0400);
    if (!close(fd) && !got)
      rc = 0;
    if (rc)
      unlink(dst);
  } else if (errno == EEXIST) {
    rc = 0;
  }
  close(zfd);
  return rc;
}

static int copy_tree(char *zpath, char *dst) {
  DIR *d;
  struct stat st;
  struct dirent *e;
  size_t n, zn = strlen(zpath), dn = strlen(dst);
  if (mkdir(dst, 0700) && errno != EEXIST)
    return -1;
  if (!(d = opendir(zpath)))
    return -1;
  while ((e = readdir(d))) {
    if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
      continue;
    n = strlen(e->d_name);
    if (zn + 1 + n >= PATH_MAX || dn + 1 + n >= PATH_MAX)
      continue;
    zpath[zn] = '/';
    memcpy(zpath + zn + 1, e->d_name, n + 1);
    dst[dn] = '/';
    memcpy(dst + dn + 1, e->d_name, n + 1);
    if (zpath && !stat(zpath, &st)) {
      if (S_ISDIR(st.st_mode)) {
        copy_tree(zpath, dst);
      } else if (S_ISREG(st.st_mode)) {
        copy_file(zpath, dst, st.st_mode);
      }
    }
    zpath[zn] = 0;
    dst[dn] = 0;
  }
  closedir(d);
  return 0;
}

static int copy_out(const char *zpath, const char *dst, struct stat *st) {
  char z[PATH_MAX], t[PATH_MAX];
  if (S_ISDIR(st->st_mode)) {
    if (is_done(zpath, true))
      return 0;
    strlcpy(z, zpath, sizeof(z));
    strlcpy(t, dst, sizeof(t));
    make_parents(t);
    if (copy_tree(z, t))
      return -1;
    set_done(zpath, true);
    return 0;
  }
  if (!S_ISREG(st->st_mode))
    return -1;
  if (is_lib(zpath)) {
    // the whole directory, for the libraries it may need
    struct stat pst;
    strlcpy(z, zpath, sizeof(z));
    *strrchr(z, '/') = 0;
    if (strlen(z) > 4 && !stat(z, &pst) && S_ISDIR(pst.st_mode)) {
      strlcpy(t, dst, sizeof(t));
      *strrchr(t, '/') = 0;
      return copy_out(z, t, &pst);
    }
  }
  if (is_done(zpath, false))
    return 0;
  strlcpy(t, dst, sizeof(t));
  make_parents(t);
  if (copy_file(zpath, t, st->st_mode))
    return -1;
  set_done(zpath, false);
  return 0;
}

/**
 * Maps a path a host library is about to use onto the zip store.
 *
 * @return `buf` holding the path of a copy the host can use, or null if
 *     the zip store doesn't serve `path`
 */
dontinline const char *__host_pathmap(const char *path, char *buf,
                                      size_t size) {
  char tmp[PATH_MAX];
  const char *zpath = path, *root, *res = 0;
  struct stat st;
  int olderr = errno;
  if (!path || path[0] != '/')
    return 0;
  if (!is_zip(path) && (zpath = __zipos_remap(path, tmp, sizeof(tmp))) == path)
    return 0;
  if (zpath && !stat(zpath, &st)) {
    pthread_mutex_lock(&__hostpath.lock);
    if ((root = get_root()) && strlen(root) + strlen(zpath + 4) < size) {
      stpcpy(stpcpy(buf, root), zpath + 4);
      if (!copy_out(zpath, buf, &st))
        res = buf;
    }
    pthread_mutex_unlock(&__hostpath.lock);
  }
  errno = olderr;
  return res;
}

/**
 * Returns true if paths outside /zip may map into the zip store too.
 */
bool __host_pathmap_remaps(void) {
  return __zipos_remap_active();
}

// the host copies of programs this process has run, each held open on
// windows so that nothing can write to the file while it's in use
static struct Held {
  struct Held *next;
  char path[];
} *__host_held;

static void hold_program(const char *path) {
  struct Held *h;
  for (h = __host_held; h; h = h->next)
    if (!strcmp(h->path, path))
      return;
  if (IsWindows()) {
    char16_t path16[PATH_MAX];
    if (__mkntpath(path, path16) == -1)
      return;
    int64_t fh = CreateFile(path16, kNtGenericRead,
                            kNtFileShareRead | kNtFileShareDelete, 0,
                            kNtOpenExisting, 0, 0);
    if (fh == -1)
      return;
  }
  if ((h = malloc(sizeof(*h) + strlen(path) + 1))) {
    strcpy(h->path, path);
    h->next = __host_held;
    __host_held = h;
  }
}

/**
 * Maps a program the zip store serves onto a copy the host can run.
 *
 * posix_spawn() and execve() ask through a weak reference, so this
 * takes effect in programs that link the host path code, which any use
 * of cosmo_dlopen() or cosmo_hostpath() does. The copy is readable and
 * executable by its owner only. On Windows it stays open for the life
 * of the process with writing shared with nobody, since the private
 * directory it's in inherits whatever the temporary directory allows.
 *
 * @return `buf` holding the path of the copy, or null if the zip store
 *     doesn't serve `path`
 */
const char *__host_execmap(const char *path, char *buf, size_t size) {
  int olderr = errno;
  if (!__host_pathmap(path, buf, size))
    return 0;
  chmod(buf, 0500);
  pthread_mutex_lock(&__hostpath.lock);
  hold_program(buf);
  pthread_mutex_unlock(&__hostpath.lock);
  errno = olderr;
  return buf;
}

/**
 * Returns the path a host library should be given for `path`.
 *
 * A path the zip store serves becomes that of a read-only copy, made
 * the first time it's asked for; see __host_pathmap(). Any path is then
 * spelled the host's way.
 *
 * @return `buf`, or null w/ errno
 * @raise ENOENT if `path` is under /zip and the zip store hasn't it
 * @raise ERANGE if `size` is too small
 */
char *cosmo_hostpath(const char *path, char *buf, size_t size) {
  char tmp[PATH_MAX];
  const char *p;
  size_t n;
  if (!path || !buf) {
    errno = EINVAL;
    return 0;
  }
  if (!(p = __host_pathmap(path, tmp, sizeof(tmp)))) {
    if (is_zip(path)) {
      errno = ENOENT;
      return 0;
    }
    p = path;
  }
  if (IsWindows() && p[0] == '/') {
    int k;
    char fixed[PATH_MAX];
    // "/tmp" and the other spellings open() would take
    if (!(p = __rewriteunixpath(p, fixed)))
      return 0;
    if ((k = __unixtodospath(p, buf, size)) == -1 || (size_t)k >= size) {
      errno = ERANGE;
      return 0;
    }
    buf[k] = 0;
    return buf;
  }
  if ((n = strlen(p)) >= size) {
    errno = ERANGE;
    return 0;
  }
  memmove(buf, p, n + 1);
  return buf;
}
