#include "libc/calls/calls.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/calls/syscall_support-sysv.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/fmt/itoa.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/at.h"
#include "libc/sysv/consts/o.h"

#define TIOCPTYGRANT 0x20007454
#define TIOCPTYUNLK  0x20007452
#define TIOCPTYGNAME 0x40807453

/**
 * Makes a pty master just opened on xnu behave like linux's /dev/ptmx,
 * whose slave the opener owns from the start. Programs written for
 * linux skip grantpt(), and the unlock here spares the ones that skip
 * unlockpt() as well.
 */
void __ptmx_opened_xnu(int fd) {
  int e = errno;
  sys_ioctl(fd, TIOCPTYGRANT, 0);
  sys_ioctl(fd, TIOCPTYUNLK, 0);
  errno = e;
}

/**
 * Opens the slave of a pty master on xnu, never as the controlling
 * terminal.
 *
 * @return fd of the slave, or -1 w/ errno (ENOTTY if fd isn't a master)
 */
int __ptm_slave_xnu(int fd, int flags) {
  char name[128];
  if (sys_ioctl(fd, TIOCPTYGNAME, name) == -1)
    return -1;
  return sys_openat(AT_FDCWD, name, flags | O_NOCTTY, 0);
}

/**
 * Turns linux's /dev/pts/N into the xnu slave name /dev/ttysNNN.
 *
 * @return true if `out` was filled in
 */
bool __ptsname_xnu(const char *path, char out[64]) {
  if (strncmp(path, "/dev/pts/", 9) || !path[9])
    return false;
  const char *p = path + 9;
  int n = 0;
  for (; *p; ++p) {
    if (*p < '0' || *p > '9' || n >= 100000)
      return false;
    n = n * 10 + (*p - '0');
  }
  char *q = stpcpy(out, "/dev/ttys");
  if (n < 100)
    *q++ = '0';
  if (n < 10)
    *q++ = '0';
  FormatInt32(q, n);
  return true;
}

/**
 * Does a terminal ioctl, on the slave when xnu's pty master refuses it.
 *
 * Linux's master answers termios and window size requests for its
 * slave, where xnu's says ENOTTY; the slave is opened for the call and
 * closed again.
 */
int __ioctl_tty_xnu(int fd, unsigned long request, void *arg) {
  int rc = sys_ioctl(fd, request, arg);
  if (rc == -1 && errno == ENOTTY && IsXnu()) {
    int e = errno;
    int s = __ptm_slave_xnu(fd, O_RDWR);
    if (s == -1) {
      errno = e;
      return -1;
    }
    rc = sys_ioctl(s, request, arg);
    e = errno;
    sys_close(s);
    errno = e;
  }
  return rc;
}
