#include "libc/calls/calls.h"
#include "libc/calls/struct/termios.h"
#include "libc/calls/struct/winsize.h"
#include "libc/calls/termios.h"
#include "libc/errno.h"
#include "libc/intrin/strace.h"
#include "libc/runtime/runtime.h"
#include "libc/runtime/utmp.h"

/**
 * Opens a pseudoteletypewriter and forks a child logged into it.
 *
 * The child gets the slave as stdin, stdout and stderr and becomes a
 * session leader. The parent receives the master in `*amaster`.
 *
 * @return child pid in parent, 0 in child, or -1 w/ errno
 * @see openpty(), login_tty()
 */
int forkpty(int *amaster, char *name, const struct termios *tio,
            const struct winsize *ws) {
  int e, pid, master, slave;
  if (openpty(&master, &slave, name, tio, ws) == -1)
    return -1;
  if ((pid = fork()) == -1) {
    e = errno;
    close(master);
    close(slave);
    errno = e;
    return -1;
  }
  if (!pid) {
    close(master);
    if (login_tty(slave) == -1)
      _Exit(127);
    return 0;
  }
  close(slave);
  *amaster = master;
  STRACE("forkpty([%d], %p, %p, %p) → %d", master, name, tio, ws, pid);
  return pid;
}
