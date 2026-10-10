#include "libc/proc/xdgopen.h"
#include "libc/calls/calls.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/ctype.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/str/str.h"

// Programs open a URL or a file with its default application by running
// `xdg-open <what>`, which is what the Rust crates open and webbrowser
// and plenty of C code do on Linux. Windows and macOS have no xdg-open,
// so when a PATH search for it comes up empty there, the host's own
// opener is run in its place: open(1) on macOS, and on Windows rundll32
// with url.dll's FileProtocolHandler, which hands a URL or a path to
// ShellExecute. An xdg-open that is on the PATH is always used as is.

static bool xdg_is_url(const char *s) {
  const char *p = s;
  if (!isalpha(*p))
    return false;
  while (isalnum(*p) || *p == '+' || *p == '-' || *p == '.')
    ++p;
  // two letters at least, so that C: stays a drive
  return *p == ':' && p - s >= 2;
}

// the Windows spelling of a path; relative ones are made absolute first
static bool xdg_dos_path(const char *path, char *buf, char *out) {
  size_t n;
  if (*path == '/') {
    if ((n = strlen(path)) >= PATH_MAX)
      return false;
    memcpy(buf, path, n + 1);
  } else {
    if (__getcwd(buf, PATH_MAX) == -1)
      return false;
    n = strlen(buf);
    if (n + 1 + strlen(path) >= PATH_MAX)
      return false;
    if (n && buf[n - 1] != '/')
      buf[n++] = '/';
    strcpy(buf + n, path);
  }
  int k = __unixtodospath(buf, out, PATH_MAX);
  return k != -1 && k < PATH_MAX;
}

/**
 * Stands in for a missing xdg-open on Windows and macOS.
 *
 * Called by the PATH searching exec and spawn functions after
 * commandv() found nothing for `prog`.
 *
 * @param pathbuf receives the program to run, `size` bytes
 * @param x holds the argument vector to run it with, in `x->argv`
 * @return `pathbuf`, or null with errno unchanged when this doesn't
 *     apply
 */
char *__xdg_open(const char *prog, char *const argv[], char *pathbuf,
                 size_t size, struct XdgOpen *x) {
  if (!IsWindows() && !IsXnu())
    return 0;
  if (errno != ENOENT || strcmp(prog, "xdg-open"))
    return 0;
  if (!argv || !argv[0] || !argv[1] || argv[2])
    return 0;
  const char *what = argv[1];
  int e = errno;
  if (IsXnu()) {
    if (size < sizeof("/usr/bin/open"))
      return 0;
    strcpy(pathbuf, "/usr/bin/open");
    x->argv[0] = "open";
    x->argv[1] = (char *)what;
    x->argv[2] = 0;
    return pathbuf;
  }
  if (!xdg_is_url(what)) {
    // pathbuf is scratch space until rundll32 is looked up
    if (size < PATH_MAX || !xdg_dos_path(what, pathbuf, x->arg)) {
      errno = e;
      return 0;
    }
    what = x->arg;
  }
  if (!commandv("rundll32.exe", pathbuf, size)) {
    errno = e;
    return 0;
  }
  x->argv[0] = "rundll32.exe";
  x->argv[1] = "url.dll,FileProtocolHandler";
  x->argv[2] = (char *)what;
  x->argv[3] = 0;
  return pathbuf;
}
