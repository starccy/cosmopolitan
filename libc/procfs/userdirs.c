#include "libc/calls/calls.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/limits.h"
#include "libc/mem/mem.h"
#include "libc/nt/dll.h"
#include "libc/nt/struct/guid.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/procfs/internal.h"
#include "libc/runtime/runtime.h"
#include "libc/stdio/stdio.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/at.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/ok.h"
#include "libc/sysv/consts/s.h"
#include "libc/sysv/errfuns.h"

// The file xdg-user-dirs writes on Linux, $XDG_CONFIG_HOME/user-dirs.dirs
// or ~/.config/user-dirs.dirs, saying where the desktop, documents,
// downloads and the like are. The dirs crate, glib and whatever else
// follows the XDG convention read it. Windows and macOS keep those
// folders in places of their own and have no such file, so when it
// isn't on disk its text is made from what the host says. One on disk
// wins, and opening it to write goes to the disk, where the file it
// creates then wins.

#define NAME "/user-dirs.dirs"

struct udbuf {
  char *p;
  size_t n, c;
};

static void ud_add(struct udbuf *b, const char *s, size_t n) {
  if (b->n + n + 1 > b->c) {
    size_t c = (b->n + n + 1) * 2;
    char *p = realloc(b->p, c);
    if (!p)
      return;
    b->p = p;
    b->c = c;
  }
  memcpy(b->p + b->n, s, n);
  b->n += n;
  b->p[b->n] = 0;
}

// XDG_<key>_DIR="<dir>", quoted the way the file's reader unquotes it
static void ud_line(struct udbuf *b, const char *key, const char *dir) {
  if (!dir || *dir != '/')
    return;
  ud_add(b, "XDG_", 4);
  ud_add(b, key, strlen(key));
  ud_add(b, "_DIR=\"", 6);
  for (const char *s = dir; *s; ++s) {
    if (*s == '"' || *s == '\\' || *s == '$' || *s == '`')
      ud_add(b, "\\", 1);
    ud_add(b, s, 1);
  }
  ud_add(b, "\"\n", 2);
}

#ifdef __x86_64__
// what SHGetKnownFolderPath() says, loaded the first time it's asked,
// so programs that never read the file don't load shell32 at startup
static void ud_known(struct udbuf *b, const char *key, struct NtGuid id) {
  static int32_t __msabi (*get)(const struct NtGuid *, uint32_t, intptr_t,
                                char16_t **);
  static void __msabi (*free16)(void *);
  if (!get) {
    int64_t shell32 = LoadLibrary(u"shell32.dll");
    int64_t ole32 = LoadLibrary(u"ole32.dll");
    if (!shell32 || !ole32)
      return;
    free16 = (void *)GetProcAddress(ole32, "CoTaskMemFree");
    get = (void *)GetProcAddress(shell32, "SHGetKnownFolderPath");
    if (!get || !free16)
      return;
  }
  char16_t *path16 = 0;
  char path[PATH_MAX];
  if (!get(&id, 0, 0, &path16) && __mkunixpath(path16, path) != -1)
    ud_line(b, key, path);
  if (path16)
    free16(path16);
}
#endif

static char *ud_text(size_t *n) {
  struct udbuf b = {0};
  ud_add(&b, "", 0);
  if (IsWindows()) {
#ifdef __x86_64__
    ud_known(&b, "DESKTOP", (struct NtGuid){0xB4BFCC3A, 0xDB2C, 0x424C, {0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41}});
    ud_known(&b, "DOWNLOAD", (struct NtGuid){0x374DE290, 0x123F, 0x4565, {0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B}});
    ud_known(&b, "TEMPLATES", (struct NtGuid){0xA63293E8, 0x664E, 0x48DB, {0xA0, 0x79, 0xDF, 0x75, 0x9E, 0x05, 0x09, 0xF7}});
    ud_known(&b, "PUBLICSHARE", (struct NtGuid){0xDFDF76A2, 0xC82A, 0x4D63, {0x90, 0x6A, 0x56, 0x44, 0xAC, 0x45, 0x73, 0x85}});
    ud_known(&b, "DOCUMENTS", (struct NtGuid){0xFDD39AD0, 0x238F, 0x46AF, {0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7}});
    ud_known(&b, "MUSIC", (struct NtGuid){0x4BD8D571, 0x6D19, 0x48D3, {0xBE, 0x97, 0x42, 0x22, 0x20, 0x08, 0x0E, 0x43}});
    ud_known(&b, "PICTURES", (struct NtGuid){0x33E28130, 0x4E1E, 0x4676, {0x83, 0x5A, 0x98, 0x39, 0x5C, 0x3B, 0xC3, 0xBB}});
    ud_known(&b, "VIDEOS", (struct NtGuid){0x18989B1D, 0x99B5, 0x455B, {0x84, 0x1C, 0xAB, 0x7C, 0x74, 0xE4, 0xDD, 0xFC}});
#endif
  } else {
    // the folder names on disk are the same in every language; Finder
    // shows them translated
    static const char *const kDirs[][2] = {
        {"DESKTOP", "Desktop"},     {"DOWNLOAD", "Downloads"},
        {"PUBLICSHARE", "Public"},  {"DOCUMENTS", "Documents"},
        {"MUSIC", "Music"},         {"PICTURES", "Pictures"},
        {"VIDEOS", "Movies"},
    };
    const char *home = getenv("HOME");
    char dir[PATH_MAX];
    for (size_t i = 0; home && i < sizeof(kDirs) / sizeof(*kDirs); ++i)
      if (snprintf(dir, sizeof dir, "%s/%s", home, kDirs[i][1]) <
          (int)sizeof dir)
        ud_line(&b, kDirs[i][0], dir);
  }
  *n = b.n;
  return b.p;
}

// where the file would be, from the environment
static bool ud_where(char *out, size_t n) {
  const char *dir;
  size_t len;
  int r;
  if ((dir = getenv("XDG_CONFIG_HOME")) && *dir == '/') {
    len = strlen(dir);
    while (len > 1 && dir[len - 1] == '/')
      --len;
    r = snprintf(out, n, "%.*s" NAME, (int)len, dir);
  } else if ((dir = getenv("HOME")) && *dir == '/') {
    r = snprintf(out, n, "%s/.config" NAME, dir);
  } else {
    return false;
  }
  return r > 0 && (size_t)r < n;
}

// whether `path` is the file and there's none on disk
static bool ud_is(int dirfd, const char *path) {
  size_t len;
  char want[PATH_MAX];
  if (!(IsWindows() || IsXnuSilicon()) || pc_busy || !path ||
      path[0] != '/' || (len = strlen(path)) < sizeof(NAME) - 1 ||
      strcmp(path + len - (sizeof(NAME) - 1), NAME) || !ud_where(want, sizeof want) ||
      strcmp(path, want))
    return false;
  // our own stat of it goes to the disk
  struct stat st;
  int e = errno;
  pc_busy = 1;
  bool missing = fstatat(AT_FDCWD, path, &st, 0) == -1 && errno == ENOENT;
  pc_busy = 0;
  errno = e;
  return missing;
}

int pc_userdirs_open(int dirfd, const char *path, int flags) {
  if ((flags & O_ACCMODE) != O_RDONLY || (flags & (O_CREAT | O_TRUNC)) ||
      !ud_is(dirfd, path))
    return -2;
  if (flags & O_DIRECTORY)
    return enotdir();
  size_t n;
  char *text;
  struct ProcfsHandle *h;
  if (!(text = ud_text(&n)) || !(h = pc_handle_new(path))) {
    free(text);
    return enomem();
  }
  h->p = text;
  h->n = n;
  h->fixed = true;
  return pc_handle_fd(h, flags, S_IFREG | 0444);
}

int pc_userdirs_stat(int dirfd, const char *path, struct stat *st) {
  size_t n;
  if (!ud_is(dirfd, path))
    return -2;
  free(ud_text(&n));
  memset(st, 0, sizeof *st);
  st->st_mode = S_IFREG | 0444;
  st->st_nlink = 1;
  st->st_size = n;
  st->st_blksize = 4096;
  st->st_ino = pc_inode(path);
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  st->st_atim = st->st_mtim = st->st_ctim = now;
  return 0;
}

int pc_userdirs_access(int dirfd, const char *path, int amode) {
  if ((amode & (W_OK | X_OK)) || !ud_is(dirfd, path))
    return -2;
  return 0;
}
