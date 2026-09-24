// Copyright 2025 Justine Alexandra Roberts Tunney
//
// Permission to use, copy, modify, and/or distribute this software for
// any purpose with or without fee is hereby granted, provided that the
// above copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
// WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
// AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
// DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
// PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
// TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
// PERFORMANCE OF THIS SOFTWARE.

#include "libc/atomic.h"
#include "libc/calls/internal.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/ctype.h"
#include "libc/intrin/weaken.h"
#include "libc/limits.h"
#include "libc/nt/enum/fileflagandattributes.h"
#include "libc/nt/files.h"
#include "libc/nt/systeminfo.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/at.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"

int __ape_shim_ntpath_rewrite(const char *, char *, size_t);

textwindows static size_t __normunixpath(char16_t *p, size_t n) {
  size_t i, j;
  for (j = i = 0; i < n; ++i) {
    int c = p[i];
    if (j > 1 && c == '/' && p[j - 1] == '/') {
      // matched "^/" or "//" but not "^//"
    } else if ((!j || (j && p[j - 1] == '/')) &&  //
               c == '.' &&                        //
               (i + 1 == n || p[i + 1] == '/')) {
      // matched "^./" or "/./" or "/.$"
      i += !(i + 1 == n);
    } else if ((j && p[j - 1] == '/') &&          //
               c == '.' &&                        //
               (i + 1 < n && p[i + 1] == '.') &&  //
               (i + 2 == n || p[i + 2] == '/')) {
      // matched "/../" or "/..$"
      while (j && p[j - 1] == '/')
        --j;
      if (j && p[j - 1] == '.') {
        // matched "." before
        if (j >= 2 && p[j - 2] == '.' &&  //
            (j == 2 || p[j - 3] == '/')) {
          // matched "^.." or "/.." before
          p[++j] = '.';
          ++j;
          continue;
        } else if (j == 1 || p[j - 2] == '/') {
          // matched "^." or "/." before
          continue;
        }
      }
      while (j && p[j - 1] != '/')
        --j;
    } else {
      p[j++] = c;
    }
  }
  while (j && p[j - 1] == '/')
    --j;
  p[j] = 0;
  return j;
}

textwindows static int __pfxdrive(char16_t p[static PATH_MAX], int n, char d,
                                  int i) {
  if (n > i) {
    memmove(p + 7, p + i, (n - i) * sizeof(char16_t));
    n = __normunixpath(p + 7, n - i);
    for (i = 0; i < n; ++i)
      if (p[7 + i] == '/')
        p[7 + i] = '\\';
  } else {
    n = 0;
  }
  p[0] = '\\';
  p[1] = '\\';
  p[2] = '?';
  p[3] = '\\';
  p[4] = d;
  p[5] = ':';
  p[6] = '\\';
  p[7 + n] = 0;
  return 7 + n;
}

textwindows static int __retntpath(char16_t *p, int n) {
  for (int i = 0; i < n; ++i)
    if (p[i] == '/')
      p[i] = '\\';
  return n;
}

/**
 * Returns true if drive letter exists.
 *
 * The drive bitmap is cached so the common "/C/..." costs nothing; a
 * letter not in it asks the os again, so a drive attached after startup
 * is still found.
 */
textwindows bool __ntdriveexists(int letter) {
  static uint32_t drives;
  uint32_t bit = 1u << ((letter | 32) - 'a');
  if (__atomic_load_n(&drives, __ATOMIC_RELAXED) & bit)
    return true;
  uint32_t now = GetLogicalDrives();
  __atomic_store_n(&drives, now, __ATOMIC_RELAXED);
  return now & bit;
}

// length of the "//srv/share" or "//?/UNC/srv/share" prefix of a slashed
// path, or 0 when it isn't a unc share path
textwindows static int __uncrootlen(const char16_t *p, int n) {
  int i = 2;
  if (n < 5 || p[0] != '/' || p[1] != '/')
    return 0;
  if (p[2] == '?' && p[3] == '/' &&        //
      (p[4] == 'U' || p[4] == 'u') &&      //
      (p[5] == 'N' || p[5] == 'n') &&      //
      (p[6] == 'C' || p[6] == 'c') &&      //
      p[7] == '/') {
    i = 8;
  } else if (p[2] == '?' || p[2] == '.' || p[2] == '/') {
    return 0;
  }
  int srv = i;
  while (i < n && p[i] != '/')
    ++i;
  if (i == srv || i >= n)
    return 0;
  int share = ++i;
  while (i < n && p[i] != '/')
    ++i;
  if (i == share)
    return 0;
  return i;
}

// turns "//srv/share/foo" into "\\?\UNC\srv\share\foo". what follows
// the share is normalized on its own, so ".." stops at the share root
// the way "/.." stays at "/". the prefix goes away again in
// __mkntpathath() when the path is short enough to not need it.
textwindows static int __pfxunc(char16_t *p, int n) {
  int root = __uncrootlen(p, n);
  if (!root)
    return __retntpath(p, n);
  if (n + 6 + 1 > PATH_MAX)
    return enametoolong();
  memmove(p + 8, p + 2, (n - 2 + 1) * sizeof(char16_t));
  p[2] = '?';
  p[3] = '/';
  p[4] = 'U';
  p[5] = 'N';
  p[6] = 'C';
  p[7] = '/';
  n += 6;
  root += 6;
  while (n - root > 1 && p[root] == '/' && p[root + 1] == '/') {
    memmove(p + root, p + root + 1, (n - root) * sizeof(char16_t));
    --n;
  }
  n = root + __normunixpath(p + root, n - root);
  return __retntpath(p, n);
}

textwindows static int __normdospath(int64_t dirhand, const char *path,
                                     char16_t path16[static PATH_MAX],
                                     bool used_explicit_drive_letter) {

  // empty paths aren't a thing
  if (!*path)
    return enoent();

  // thwart overlong nul in conversion
  if (!isutf8(path, -1))
    return eilseq();

  // windows just straight up doesn't allow control codes. this will
  // normally raise EINVAL, but it's more informative to say EILSEQ.
  // this check is already performed on the last component in open()
  // mkdir() etc. but let's prevent EINVAL here too.
  for (int i = 0; path[i]; ++i)
    if ((path[i] & 255) < 32)
      return eilseq();

  // turn utf-8 into utf-16
  // make sure it isn't truncated and we'll have room to prepend
  char16_t *p = path16;
  int n = tprecode8to16(p, PATH_MAX, path).ax;
  if (n + 7 + 1 > PATH_MAX)
    return enametoolong();

  // turn backslash into forward slash
  for (int i = 0; i < n; ++i)
    if (p[i] == '\\')
      p[i] = '/';

  // forbid dos drive relative paths
  if (isalpha(p[0]) && p[1] == ':' && p[2] != '/')
    return enotsup();

  // a spelled out drive letter always means that drive, whereas "/c"
  // below only does when drive c exists
  bool spelled_drive = isalpha(p[0]) && p[1] == ':';

  // don't do anything to new technology paths
  if (p[0] == '/' && p[1] == '?' && p[2] == '?' && p[3] == '/')
    return __retntpath(p, n);

  // is this already a device or unc path?
  if (p[0] == '/' && p[1] == '/') {
    // turn "//?/c:/foo" into "c:/foo"
    if ((p[2] == '?' || p[2] == '.') && p[3] == '/' && isalpha(p[4]) &&
        p[5] == ':') {
      memmove(p, p + 4, (n - 4 + 1) * sizeof(char16_t));
      n -= 4;
    } else if (p[2] == '?' || p[2] == '.') {
      // otherwise return paths like \\?\pipe\cosmo\... as is
      return __retntpath(p, n);
    } else {
      // "//srv/share/foo" is a network share path
      return __pfxunc(p, n);
    }
  }

  // turn "c:/foo" into "/c/foo"
  if (isalpha(p[0]) && p[1] == ':' && p[2] == '/') {
    p[1] = p[0];
    p[0] = '/';
  }

  // turn root path "/" into "\\?\c:\" depending on $SYSTEMDRIVE
  if (p[0] == '/' && !p[1])
    return __pfxdrive(p, 0, __getcosmosdrive(), 0);

  // turn "/c" into "\\?\c:\"
  // "/x" for a drive that doesn't exist is an ordinary name like "/bin"
  if (p[0] == '/' && isalpha(p[1]) && !p[2] &&
      (spelled_drive || __ntdriveexists(p[1])))
    return __pfxdrive(p, 0, p[1], 0);

  // turn "/c/foo" into "\\?\c:\foo"
  if (p[0] == '/' && isalpha(p[1]) && p[2] == '/' &&
      (spelled_drive || __ntdriveexists(p[1])))
    return __pfxdrive(p, n, p[1], 3);

  // turn "/foo" into "\\?\c:\foo" depending on $SYSTEMDRIVE
  if (p[0] == '/')
    return __pfxdrive(p, n, __getcosmosdrive(), 1);

  // strip trailing slashes
  while (p[n - 1] == '/')
    p[--n] = 0;

  char16_t *file = p;
  int filelen = n;
  char16_t dir[PATH_MAX];
  int dirlen;

  // we have a relative path
  if (dirhand == AT_FDCWD) {

    // ensure stat("C") means stat("C:/") if we chdir("/")
    struct CosmoPib *pib = __get_pib();
    if (pib->cwd[0] == '/' && !pib->cwd[1])
      if (isalpha(p[0]) && (n == 1 || p[1] == '/'))
        return __pfxdrive(p, n, p[0], 2);

    // resolve against current directory
    dirlen = GetCurrentDirectory(PATH_MAX, dir);
  } else {

    // resolve against dirfd
    dirlen = GetFinalPathNameByHandle(dirhand, dir, PATH_MAX,
                                      kNtFileNameNormalized | kNtVolumeNameDos);

    // ensure fstatat(open("/"), "C") means stat("C:/")
    if (!used_explicit_drive_letter &&  //
        dirlen == 7 && isalpha(p[0]) && (n == 1 || p[1] == '/')) {
      char16_t cosmosdrive[7] = u"\\\\?\\C:\\";
      cosmosdrive[4] = __getcosmosdrive();
      if (!memcmp(dir, cosmosdrive, 7 * 2))
        return __pfxdrive(p, n, p[0], 2);
    }
  }
  if (!dirlen)
    return __winerr();
  if (dirlen + 1 > PATH_MAX)
    return enametoolong();

  // turn backslash into forward slash, again
  for (int i = 0; i < dirlen; ++i)
    if (dir[i] == '\\')
      dir[i] = '/';

  // GetCurrentDirectory() can give us a lot of weird paths
  if (dir[0] == '/') {
    if (dir[1] == '/') {
      if (dir[2] == '?' && dir[3] == '/') {
        // we want the //?/ prefix
      } else if (dir[2] == '.' && dir[3] == '/') {
        // turn //./ device prefix into //?/
        dir[2] = '?';
      } else if (dir[2] != '/') {
        // add //?/UNC/ prefix to "//srv/share/..." network share path
        if (dirlen + 6 + 1 > PATH_MAX)
          return enametoolong();
        memmove(dir + 8, dir + 2, (dirlen - 2 + 1) * sizeof(char16_t));
        dir[2] = '?';
        dir[3] = '/';
        dir[4] = 'U';
        dir[5] = 'N';
        dir[6] = 'C';
        dir[7] = '/';
        dirlen += 6;
      }
    }
    if (dir[1] == '?' && dir[2] == '?' && dir[3] == '/' && isalpha(dir[4]) &&
        dir[5] == ':') {
      // turn /??/C:/... into //?/C:/...
      dir[1] = '/';
    }
  } else if (isalpha(dir[0]) && dir[1] == ':' && dir[2] == '/') {
    // add //?/ prefix to DOS absolute path
    if (4 + dirlen + 1 > PATH_MAX)
      return enametoolong();
    memmove(dir + 4, dir, (dirlen + 1) * sizeof(char16_t));
    dir[0] = '/';
    dir[1] = '/';
    dir[2] = '?';
    dir[3] = '/';
    dirlen += 4;
  }

  // join paths
  if (dirlen + 1 + filelen + 1 > PATH_MAX)
    return enametoolong();
  dir[dirlen] = u'/';
  memcpy(dir + dirlen + 1, file, (filelen + 1) * sizeof(char16_t));
  memcpy(file, dir, (dirlen + 1 + filelen + 1) * sizeof(char16_t));
  filelen = dirlen + 1 + filelen;

  // shouldn't be possible
  if (filelen < 2)
    return enoent();

  // normalize user path combined with current location path
  // windows requires that unc paths be properly normalized!
  // on a network share ".." must not climb out of the share
  int root = __uncrootlen(file, filelen);
  if (root < 2)
    root = 2;
  filelen = root + __normunixpath(file + root, filelen - root);

  // then turn back to dos
  for (int i = 0; i < filelen; ++i)
    if (file[i] == '/')
      file[i] = '\\';

  // we're done
  return filelen;
}

// the host's temp directory as a unix path with a trailing slash, from
// GetTempPath() (%TMP%, %TEMP%, %USERPROFILE%, the windows directory)
textwindows static const char *__tmpdirpath(size_t *len) {
  static char dir[PATH_MAX];
  static size_t dirlen;
  if (!atomic_load_explicit(&dirlen, memory_order_acquire)) {
    char16_t dir16[PATH_MAX];
    char tmp[PATH_MAX];
    uint32_t n = GetTempPath(PATH_MAX, dir16);
    if (!n || n >= PATH_MAX)
      return 0;
    int m = __mkunixpath(dir16, tmp);
    if (m <= 0 || m >= PATH_MAX - 1)
      return 0;
    if (tmp[m - 1] != '/')
      tmp[m++] = '/', tmp[m] = 0;
    memcpy(dir, tmp, m + 1);
    atomic_store_explicit(&dirlen, m, memory_order_release);
  }
  *len = dirlen;
  return dir;
}

// "/tmp" and everything under it is the host's temp directory, which
// is where programs written against unix expect a writable scratch
// directory to be; the cosmos drive has no /tmp of its own
textwindows static int __tmpfixpath(const char *path, char *out,
                                    size_t outsz) {
  if (path[0] != '/' || path[1] != 't' || path[2] != 'm' || path[3] != 'p' ||
      (path[4] && path[4] != '/' && path[4] != '\\'))
    return 0;
  size_t dirlen;
  const char *dir = __tmpdirpath(&dirlen);
  if (!dir)
    return 0;
  const char *rest = path + 4;
  while (*rest == '/' || *rest == '\\')
    rest++;
  size_t restlen = strlen(rest);
  if (dirlen + restlen + 1 > outsz)
    return enametoolong();
  memcpy(out, dir, dirlen);
  memcpy(out + dirlen, rest, restlen + 1);
  return 1;
}

// the rewrites a unix path goes through before conversion: "/tmp", the
// shim's, if one is linked in, then the "\\server" directory and the
// share roots of uncserver.c. returns the path to convert (path itself,
// or buf), or null with errno
dontinline textwindows static const char *__rewritepath(const char *path,
                                                        char *buf) {
  char tmp[PATH_MAX];
  int rc = __tmpfixpath(path, tmp, sizeof(tmp));
  if (rc == -1)
    return 0;
  if (rc) {
    memcpy(buf, tmp, strlen(tmp) + 1);
    path = buf;
  }
  if (_weaken(__ape_shim_ntpath_rewrite)) {
    int rc = _weaken(__ape_shim_ntpath_rewrite)(path, tmp, sizeof(tmp));
    if (rc == -1)
      return 0;
    if (rc) {
      memcpy(buf, tmp, strlen(tmp) + 1);
      path = buf;
    }
  }
  if (__unc_fixpath(path, tmp, sizeof(tmp))) {
    memcpy(buf, tmp, strlen(tmp) + 1);
    path = buf;
  }
  return path;
}

textwindows int __mkntpathath(int64_t dirhand, const char *path,
                              char16_t file[static PATH_MAX],
                              bool used_explicit_drive_letter) {

  char rewritten[PATH_MAX];
  if (!(path = __rewritepath(path, rewritten)))
    return -1;

  // __mkntpath() normalizes away the trailing slash, so we need to
  // check if the user wanted it there early on in the process here
  int len = strlen(path);
  bool isdirpath = len && (path[len - 1] == '/' || path[len - 1] == '\\');

  // convert the path.
  if ((len = __normdospath(dirhand, path, file, used_explicit_drive_letter)) ==
      -1)
    return -1;

  // UNC paths break some software so we don't use the magic \\?\ prefix
  // unless we're 100% certain it's necessary. For example look at this:
  //
  //     "CMD.EXE was started with the above path as the current
  //      directory. UNC paths are not supported. Defaulting to Windows
  //      directory. Access is denied." -Quoth CMD.EXE
  //
  // The limit is officially 260 for DOS style paths. We play it safe by
  // assuming the limit is 244. It's because APIs like CreateDirectory()
  // want to be able to append stuff like "\\ffffffff.xxx\0" which is an
  // "8.3 filename" from the DOS days, which reduces a limit at least 13
  if (len < 244 &&         //
      file[0] == '\\' &&   //
      file[1] == '\\' &&   //
      file[2] == '?' &&    //
      file[3] == '\\' &&   //
      isalpha(file[4]) &&  //
      file[5] == ':') {
    memmove(file, file + 4, (len - 4 + 1) * sizeof(char16_t));
    len -= 4;
  } else if (len - 6 < 244 &&
             len > 8 &&
             file[0] == '\\' &&
             file[1] == '\\' &&
             file[2] == '?' &&
             file[3] == '\\' &&
             file[4] == 'U' &&
             file[5] == 'N' &&
             file[6] == 'C' &&
             file[7] == '\\') {
    // \\?\UNC\srv\share\x -> \\srv\share\x
    memmove(file + 2, file + 8, (len - 8 + 1) * sizeof(char16_t));
    len -= 6;
  }

  // now reject paths that windows might change silently
  if (len > 0)
    if (file[len - 1] == ' ' || file[len - 1] == '.')
      return eilseq();

  // if path ends with a slash, then we need to manually do what linux
  // does and check to make sure it's a directory, and return ENOTDIR,
  // since WIN32 will reject the path with EINVAL if we don't do this.
  if (isdirpath) {
    uint32_t dwFileAttrs;
    if ((dwFileAttrs = GetFileAttributes(file)) != -1u)
      if (!(dwFileAttrs & kNtFileAttributeDirectory))
        return enotdir();
  }

  return len;
}

/**
 * Converts UNIX filesystem path for use in WIN32 UNICODE APIs.
 *
 * This function does the following chores:
 *
 * 1. Converting UTF-8 to UTF-16
 * 2. Replacing forward-slashes with backslashes
 * 3. Change /foo to /C/foo based on $SYSTEMDRIVE
 * 4. Fixing drive letter paths, e.g. `/c/` → `c:\`
 * 5. Add `\\?\` prefix for paths exceeding 260 chars
 * 6. Removing `\\?\` prefix for paths beneath 260 chars
 * 7. Make allowances for users to supply dos-style paths
 * 8. Raise ENOTDIR based on trailing slash and then remove it
 *
 * The result of this function, is an absolute normalized path is placed
 * in `path16` that's going to be safe to pass to 99% of WIN32 APIs. The
 * unicode or "W" suffixed APIs are preferred, even though our UNIX APIs
 * always use UTF-8. So the first thing UNIX system call wrappers do, on
 * Windows, is call this function.
 *
 * This function does pure normalization. UNIX kernels normally do i/o
 * checks as they're normalizing a path. For example, if `foo` is a
 * regular file, and you try to open `foo/bar/../` then Cosmo Windows
 * will pretend nothing's wrong, since this routine normalized it away,
 * however a UNIX kernel would notice that `bar` isn't an existant dir
 * during the normalization process. Cosmopolitan doesn't polyfill this
 * error checking. However an exception is made for one particularly
 * important case, which is paths that have a trailing slash. If you
 * pass this function `"foo/"` rather than `"foo"` then a quick i/o
 * check will be performed to ensure `foo` is either a directory or a
 * directory symlink; otherwise ENOTDIR will be raised.
 *
 * You should use UNIX style paths with Cosmopolitan's UNIX system call
 * wrappers. However this routine ensures you can pass DOS or UNC style
 * paths if the need arises. For example, open("C:\\foo\\bar") is the
 * same as saying open("/C/foo/bar"). This function essentially treats
 * forward slash and backslash as the same thing, so you could even say
 * open("C:/foo/bar") and it would have the same effect. You can prefix
 * these paths like open("\\\\?\\C:\\foo\\bar") however it is not needed
 * because this function determines when that special prefix is / isn't
 * needed, and will add / remove it as necessary automatically.
 *
 * Windows doesn't have a concept of NAME_MAX (which is usually 255 on
 * UNIX systems) so your file and folder names could be 500 characters
 * long or more if you want.
 *
 * This routine does enforce the PATH_MAX limit, which does apply to
 * Windows. As of this writing, it's 1024 characters, which is the
 * minimum required for POSIX conformance. While you can normally get
 * away with using longer paths on systems that support it, Cosmo i/o
 * routines use stack buffers to manipulate paths which will raise
 * ENAMETOOLONG when this limit is violated. The WIN32 API normally
 * imposes a 260 character limit on DOS style paths, but this function
 * works around that by prepending a magic `\\?\` prefix to an absolute
 * normalized DOS-style path only when necessary. Our technique should
 * allow in the future for PATH_MAX to potentially be as high as 32768
 * however we're quite happy keeping the limit at 1024 for now.
 *
 * DOS style drive relative paths are not supported. This means you
 * can't use paths like `A:foo/bar` and expect it to do the right thing.
 * This function will raise an ENOTSUP error if such a path is passed.
 * If your path starts with a letter followed by a colon, then the next
 * character must be a slash or backslash.
 *
 * This function will raise EILSEQ if the final path component ends with
 * the space or period character. UNIX allows such paths, but Windows
 * will remove those trailing characters as part of the normalization
 * process. We reject such paths here because it would otherwise be
 * surprising to create a file like `"foo. "` and `"foo"` is what
 * actually gets created.
 *
 * @param dirfd is file descriptor of open directory, whose path will be
 *     used instead of getcwd() to resolve `path` if it's relative
 * @param path16 is output buffer with `PATH_MAX*2` bytes available
 * @return short count excluding NUL on success, or -1 w/ errno
 * @raise ENOTSUP if last component of `path` had trailing dots or spaces
 * @raise ENOTSUP if `path` is a drive-relative DOS style path
 * @raise ENAMETOOLONG if `path` resolved to be very very long
 * @raise ENOTDIR if `path` ended with slash and wasn't a dir
 * @raise EILSEQ if `path` contains malformed utf-8 sequences
 * @raise ENOENT if `path` is an empty string
 */
textwindows int __mkntpathat(int dirfd, const char *path,
                             char16_t path16[static PATH_MAX]) {
  int64_t dirhand;
  bool used_explicit_drive_letter;
  if (dirfd == AT_FDCWD) {
    dirhand = AT_FDCWD;
    used_explicit_drive_letter = false;
  } else if (__isfdkind(dirfd, kFdFile)) {
    dirhand = __get_pib()->fds.p[dirfd].handle;
    used_explicit_drive_letter =
        __get_pib()->fds.p[dirfd].used_explicit_drive_letter;
  } else {
    return ebadf();
  }
  return __mkntpathath(dirhand, path, path16, used_explicit_drive_letter);
}

/**
 * Converts UNIX filesystem path for use in WIN32 UNICODE APIs.
 *
 * This function is equivalent to saying:
 *
 *     __mkntpathat(AT_FDCWD, path, 0, path16);
 *
 * Refer to __mkntpathat() for further documentation.
 */
textwindows int __mkntpath(const char *path, char16_t path16[static PATH_MAX]) {
  return __mkntpathath(AT_FDCWD, path, path16, false);
}
