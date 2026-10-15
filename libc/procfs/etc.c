#include "libc/calls/calls.h"
#include "libc/calls/struct/stat.h"
#include "libc/calls/struct/utsname.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/mem/mem.h"
#include "libc/procfs/internal.h"
#include "libc/procfs/xnu.internal.h"
#include "libc/str/str.h"
#include "libc/stdio/stdio.h"
#include "libc/sysv/consts/at.h"
#include "libc/sysv/consts/dt.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/ok.h"
#include "libc/sysv/consts/s.h"
#include "libc/sysv/errfuns.h"
#include "libc/time.h"
#include "third_party/musl/passwd.h"

// /etc/passwd and /etc/group on windows, the same text getpwent() and
// getgrent() read there, for programs that parse the files themselves;
// /etc/os-release on windows and macos, which name the host system the
// way a linux distribution's file does; and the system trust store under
// the names the linux distributions give it, which is where a program
// built for linux looks for it (openssl-probe, go, curl and python all
// carry this list): on windows every name serves the ROOT certificate
// store (certs-nt.c), on macos, which ships only /etc/ssl/cert.pem, the
// other names serve that file. The directories those names live in can
// be stat'ed and listed. A real file or directory at the path wins.

static const char *const kCertFiles[] = {
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/cacert.pem",
    0,
};

#define XNU_CERTS "/etc/ssl/cert.pem"

enum { ETC_NONE, ETC_FILE, ETC_CERT, ETC_CERT_DIR };

static bool on_disk(const char *path) {
  struct stat st;
  int e = errno;
  pc_busy = 1;
  bool found = !fstatat(AT_FDCWD, path, &st, 0) || errno != ENOENT;
  pc_busy = 0;
  errno = e;
  return found;
}

// whether path names a directory on the way to one of the trust store
// files, /etc itself excluded
static bool is_cert_dir(const char *path) {
  size_t n = strlen(path);
  if (n < 6)
    return false;
  for (int i = 0; kCertFiles[i]; ++i)
    if (!strncmp(kCertFiles[i], path, n) && kCertFiles[i][n] == '/')
      return true;
  return false;
}

static bool is_cert_file(const char *path) {
  for (int i = 0; kCertFiles[i]; ++i)
    if (!strcmp(kCertFiles[i], path))
      return true;
  return false;
}

static int etc_kind(const char *path) {
  if (pc_busy || !path || strncmp(path, "/etc/", 5))
    return ETC_NONE;
  int kind;
  if (!strcmp(path, "/etc/os-release")) {
    if (!IsWindows() && !IsXnu())
      return ETC_NONE;
    kind = ETC_FILE;
  } else if (!strcmp(path, "/etc/passwd") || !strcmp(path, "/etc/group")) {
    if (!IsWindows())
      return ETC_NONE;
    kind = ETC_FILE;
  } else if (is_cert_file(path)) {
    kind = ETC_CERT;
  } else if (is_cert_dir(path)) {
    kind = ETC_CERT_DIR;
  } else {
    return ETC_NONE;
  }
  if (kind != ETC_FILE) {
    if (IsWindows()) {
    } else if (IsXnu()) {
      if (!on_disk(XNU_CERTS))
        return ETC_NONE;
    } else {
      return ETC_NONE;
    }
  }
  return on_disk(path) ? ETC_NONE : kind;
}

// NAME, VERSION and ID as uname() reports them, with macos named after
// its product rather than the darwin kernel
static char *os_release_text(void) {
  struct utsname u;
  char name[64], version[64], id[64];
  if (uname(&u))
    return 0;
  strlcpy(name, u.sysname, sizeof(name));
  strlcpy(version, u.release, sizeof(version));
  if (IsXnu()) {
    size_t len = sizeof(version);
    strcpy(name, "macOS");
    if (pfs_xnu_sysctl("kern.osproductversion", version, &len) < 0)
      strlcpy(version, u.release, sizeof(version));
  }
  for (size_t i = 0; i < sizeof(id); ++i)
    if (!(id[i] = name[i] >= 'A' && name[i] <= 'Z' ? name[i] + 32 : name[i]))
      break;
  id[sizeof(id) - 1] = 0;
  char *s;
  if (asprintf(&s,
               "NAME=\"%s\"\nVERSION=\"%s\"\nID=%s\nVERSION_ID=\"%s\"\n"
               "PRETTY_NAME=\"%s %s\"\n",
               name, version, id, version, name, version) == -1)
    return 0;
  return s;
}

static char *etc_text(const char *path, size_t *n) {
  char *s = path[5] == 'o'   ? os_release_text()
            : path[5] == 'p' ? __create_synthetic_passwd_file()
                             : __create_synthetic_group_file();
  if (!s && !(s = strdup("")))
    return 0;
  *n = strlen(s);
  return s;
}

// the whole of the macos cert.pem
static char *xnu_certs_text(size_t *n) {
  struct stat st;
  char *s = 0;
  int e = errno;
  pc_busy = 1;
  int fd = openat(AT_FDCWD, XNU_CERTS, O_RDONLY | O_CLOEXEC);
  if (fd != -1) {
    if (!fstat(fd, &st) && (s = malloc(st.st_size + 1))) {
      ssize_t got = pread(fd, s, st.st_size, 0);
      if (got < 0) {
        free(s);
        s = 0;
      } else {
        s[got] = 0;
        *n = got;
      }
    }
    close(fd);
  }
  pc_busy = 0;
  errno = e;
  return s;
}

static char *certs_text(size_t *n) {
  char *s = IsWindows() ? __nt_ca_bundle(n) : xnu_certs_text(n);
  if (!s && (s = strdup("")))
    *n = 0;
  return s;
}

// the size without the text, which a bundle asks for from a priority 10
// constructor where malloc isn't up yet
static size_t certs_size(void) {
  if (IsWindows()) {
    ssize_t len = __nt_ca_bundle_size();
    return len > 0 ? len : 0;
  }
  struct stat st;
  int e = errno;
  pc_busy = 1;
  int rc = fstatat(AT_FDCWD, XNU_CERTS, &st, 0);
  pc_busy = 0;
  errno = e;
  return rc ? 0 : st.st_size;
}

// the entries of a directory on the way to the trust store files: dots,
// then the next path component of every file below it
static int cert_dir_list(const char *path, struct pfs_virtent **out) {
  struct pc_list l = {0};
  size_t n = strlen(path);
  pc_list_add(&l, ".", DT_DIR);
  pc_list_add(&l, "..", DT_DIR);
  for (int i = 0; kCertFiles[i]; ++i) {
    const char *f = kCertFiles[i];
    if (strncmp(f, path, n) || f[n] != '/')
      continue;
    const char *leaf = f + n + 1;
    const char *slash = strchr(leaf, '/');
    char name[32];
    size_t len = slash ? (size_t)(slash - leaf) : strlen(leaf);
    if (len >= sizeof name)
      continue;
    memcpy(name, leaf, len);
    name[len] = 0;
    bool seen = false;
    for (int j = 0; j < l.n && !seen; ++j)
      seen = !strcmp(l.p[j].name, name);
    if (!seen)
      pc_list_add(&l, name, slash ? DT_DIR : DT_REG);
  }
  if (l.oom) {
    free(l.p);
    return -1;
  }
  *out = l.p;
  return l.n;
}

int pc_etc_open(int dirfd, const char *path, int flags) {
  int kind = etc_kind(path);
  if (kind == ETC_NONE)
    return -2;
  if (kind == ETC_CERT_DIR) {
    if ((flags & O_ACCMODE) != O_RDONLY || (flags & (O_CREAT | O_TRUNC)))
      return eisdir();
    struct pfs_virtent *ents;
    int n = cert_dir_list(path, &ents);
    if (n < 0)
      return enomem();
    struct ProcfsHandle *h = pc_handle_new(path);
    if (!h) {
      free(ents);
      return enomem();
    }
    h->dir = true;
    h->ents = ents;
    h->nents = n;
    return pc_handle_fd(h, flags, S_IFDIR | 0555);
  }
  if ((flags & O_ACCMODE) != O_RDONLY || (flags & (O_CREAT | O_TRUNC)))
    return -2;
  if (flags & O_DIRECTORY)
    return enotdir();
  size_t n;
  char *text;
  struct ProcfsHandle *h;
  text = kind == ETC_CERT ? certs_text(&n) : etc_text(path, &n);
  if (!text || !(h = pc_handle_new(path))) {
    free(text);
    return enomem();
  }
  h->p = text;
  h->n = n;
  h->fixed = true;
  return pc_handle_fd(h, flags, S_IFREG | 0444);
}

int pc_etc_stat(int dirfd, const char *path, struct stat *st) {
  size_t n = 0;
  int kind = etc_kind(path);
  if (kind == ETC_NONE)
    return -2;
  memset(st, 0, sizeof *st);
  if (kind == ETC_CERT_DIR) {
    st->st_mode = S_IFDIR | 0555;
    st->st_nlink = 2;
  } else {
    if (kind == ETC_CERT)
      n = certs_size();
    else
      free(etc_text(path, &n));
    st->st_mode = S_IFREG | 0444;
    st->st_nlink = 1;
    st->st_size = n;
  }
  st->st_blksize = 4096;
  st->st_ino = pc_inode(path);
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  st->st_atim = st->st_mtim = st->st_ctim = now;
  return 0;
}

int pc_etc_access(int dirfd, const char *path, int amode) {
  int kind = etc_kind(path);
  if (kind == ETC_NONE)
    return -2;
  if (amode & W_OK)
    return eacces();
  if ((amode & X_OK) && kind != ETC_CERT_DIR)
    return eacces();
  return 0;
}
