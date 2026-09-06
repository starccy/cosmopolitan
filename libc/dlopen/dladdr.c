#include "libc/calls/calls.h"
#include "libc/dce.h"
#include "libc/dlopen/dlfcn.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/o.h"

static char g_dladdr_fname[4096];

static int hexval(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

// returns 1 when the line's range contains addr and names a file, 0 otherwise.
// the fields between the range and the path never contain '/', so the first
// '/' starts the path; it runs to end of line, spaces included
static int CheckLine(char *line, uintptr_t addr, Dl_info *info) {
  uintptr_t start = 0, end = 0;
  char *p = line;
  int v;
  while ((v = hexval(*p)) >= 0) {
    start = (start << 4) | (uintptr_t)v;
    p++;
  }
  if (p == line || *p != '-')
    return 0;
  char *q = ++p;
  while ((v = hexval(*p)) >= 0) {
    end = (end << 4) | (uintptr_t)v;
    p++;
  }
  if (p == q || *p != ' ')
    return 0;
  if (addr < start || addr >= end)
    return 0;
  char *path = strchr(p, '/');
  if (!path)
    return 0;
  size_t n = strlen(path);
  if (n >= sizeof(g_dladdr_fname))
    return 0;
  memcpy(g_dladdr_fname, path, n + 1);
  info->dli_fname = g_dladdr_fname;
  info->dli_fbase = (void *)start;
  info->dli_sname = 0;
  info->dli_saddr = 0;
  return 1;
}

/**
 * Finds the file that maps an address.
 *
 * On Linux the answer comes from /proc/self/maps: the mapping containing
 * the address names the file it was mapped from (`dli_fname`) and
 * `dli_fbase` is that mapping's start. The symbol-level fields stay null,
 * which is also what glibc reports for an address it can't pin to a
 * symbol. Every other host answers 0 ("no information").
 *
 * The returned `dli_fname` points into a static buffer overwritten by
 * the next call.
 *
 * @return 1 if info was filled in, 0 otherwise
 */
int dladdr(const void *addr, Dl_info *info) {
  if (!IsLinux())
    return 0;
  int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return 0;

  static char buf[8192];
  size_t len = 0;
  int found = 0, skipping = 0;
  for (;;) {
    ssize_t n = read(fd, buf + len, sizeof(buf) - len);
    if (n <= 0)
      break;
    len += (size_t)n;
    char *line = buf;
    for (;;) {
      char *nl = memchr(line, '\n', len - (size_t)(line - buf));
      if (!nl)
        break;
      *nl = 0;
      if (skipping) {
        skipping = 0;
      } else if (CheckLine(line, (uintptr_t)addr, info)) {
        found = 1;
        break;
      }
      line = nl + 1;
    }
    if (found)
      break;
    len -= (size_t)(line - buf);
    memmove(buf, line, len);
    if (len == sizeof(buf)) {
      len = 0;
      skipping = 1;
    }
  }
  close(fd);
  return found;
}
