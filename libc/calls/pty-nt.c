#include "libc/calls/calls.h"
#include "libc/calls/internal.h"
#include "libc/calls/pty.internal.h"
#include "libc/calls/state.internal.h"
#include "libc/calls/struct/termios.h"
#include "libc/calls/struct/winsize.h"
#include "libc/calls/syscall-nt.internal.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/fds.h"
#include "libc/runtime/runtime.h"
#include "libc/nt/console.h"
#include "libc/nt/createfile.h"
#include "libc/nt/enum/accessmask.h"
#include "libc/nt/enum/creationdisposition.h"
#include "libc/nt/enum/fileflagandattributes.h"
#include "libc/nt/enum/filesharemode.h"
#include "libc/nt/enum/processcreationflags.h"
#include "libc/nt/errors.h"
#include "libc/nt/files.h"
#include "libc/nt/synchronization.h"
#include "libc/nt/ipc.h"
#include "libc/nt/process.h"
#include "libc/nt/runtime.h"
#include "libc/nt/startupinfo.h"
#include "libc/nt/struct/coord.h"
#include "libc/nt/struct/processinformation.h"
#include "libc/nt/struct/startupinfoex.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/baud.internal.h"
#include "libc/sysv/consts/termios.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/baud.internal.h"
#include "libc/sysv/consts/termios.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#if SupportsWindows()

/**
 * @fileoverview openpty() on Windows, on top of ConPTY.
 *
 * openpty() makes two pipes and a pseudoconsole reading one and writing
 * the other. The console can only be joined by a process created with
 * the HPCON, and the HPCON is only good in the process that made it. A
 * program that forks and then execs (that is std's Command with a
 * pre_exec closure, and every terminal multiplexer) runs the exec in
 * another process, so openpty() also spawns a holder: a copy of this
 * program that does nothing but stay attached to the console. The
 * forked child attaches to the holder's console with AttachConsole()
 * before it creates the real child, which then inherits it.
 *
 * What the console offers is what the child sees: line discipline,
 * echo and VT translation come from conhost, not from here. Reading or
 * writing the slave descriptor directly bypasses all of that.
 */

textwindows static bool SpawnHolder(struct Pty *pty) {
  char16_t exe[PATH_MAX];
  if (!GetModuleFileName(0, exe, PATH_MAX))
    return false;
  alignas(16) char memory[256];
  size_t size = sizeof(memory);
  struct NtProcThreadAttributeList *alist = (void *)memory;
  bool ok = InitializeProcThreadAttributeList(alist, 1, 0, &size) &&
            UpdateProcThreadAttribute(alist, 0,
                                      kNtProcThreadAttributePseudoconsole,
                                      (void *)pty->hpc, sizeof(pty->hpc), 0, 0);
  struct NtStartupInfoEx si = {
      .StartupInfo.cb = sizeof(si),
      .lpAttributeList = alist,
  };
  struct NtProcessInformation pi;
  if (ok) {
    SetEnvironmentVariable(u"__COSMO_PTYHOLD", u"1");
    ok = CreateProcess(exe, 0, 0, 0, false, kNtExtendedStartupinfoPresent, 0,
                       0, &si.StartupInfo, &pi);
    SetEnvironmentVariable(u"__COSMO_PTYHOLD", 0);
  }
  DeleteProcThreadAttributeList(alist);
  if (!ok)
    return false;
  CloseHandle(pi.hThread);
  pty->hold = pi.hProcess;
  pty->holdpid = pi.dwProcessId;
  return true;
}

textwindows int sys_openpty_nt(int *mfd, int *sfd, const struct winsize *wsz) {
  int inp[2], outp[2], live[2];
  if (sys_pipe_nt(inp, 0) == -1)
    return -1;
  if (sys_pipe_nt(outp, 0) == -1) {
    close(inp[0]);
    close(inp[1]);
    return -1;
  }
  if (sys_pipe_nt(live, 0) == -1) {
    close(inp[0]);
    close(inp[1]);
    close(outp[0]);
    close(outp[1]);
    return -1;
  }
  struct Fd *p = __get_pib()->fds.p;
  struct Pty *pty = _mapanon(sizeof(*pty));
  int64_t sh = -1;
  if (!pty)
    goto Fail;
  pty->owner = GetCurrentProcessId();
  pty->ws.ws_col = wsz && wsz->ws_col ? wsz->ws_col : 80;
  pty->ws.ws_row = wsz && wsz->ws_row ? wsz->ws_row : 24;
  struct NtCoord size = {pty->ws.ws_col, pty->ws.ws_row};
  if (CreatePseudoConsole(size, p[inp[0]].handle, p[outp[1]].handle, 0,
                          &pty->hpc)) {
    enotsup();
    goto Fail;
  }
  if (!SpawnHolder(pty)) {
    __winerr();
    goto Fail;
  }
  // writes on the slave go straight to the master
  if (!DuplicateHandle(GetCurrentProcess(), p[outp[1]].handle,
                       GetCurrentProcess(), &sh, 0, true,
                       kNtDuplicateSameAccess)) {
    __winerr();
    goto Fail;
  }
  // conhost holds its own references to its two ends
  close(inp[0]);
  close(outp[1]);
  __fds_lock();
  pty->in_w = p[inp[1]].handle;
  pty->out_w = sh;
  pty->live_r = p[live[0]].handle;
  __releasefd(inp[1]);
  __releasefd(live[0]);
  p[outp[0]].flags = O_RDWR;
  p[outp[0]].mode = 020620;
  p[outp[0]].pty = pty;
  p[outp[0]].ptymaster = true;
  // the slave is the live pipe's write end: as long as anyone holds one,
  // the master hasn't reached the end
  p[live[1]].flags = O_RDWR;
  p[live[1]].mode = 020620;
  p[live[1]].pty = pty;
  pty->refs = 2;
  pty->mrefs = 1;
  __fds_unlock();
  *mfd = outp[0];
  *sfd = live[1];
  return 0;
Fail:;
  int e = errno;
  if (pty) {
    if (pty->hold) {
      TerminateProcess(pty->hold, 0);
      CloseHandle(pty->hold);
    }
    if (pty->hpc)
      ClosePseudoConsole(pty->hpc);
    munmap(pty, sizeof(*pty));
  }
  if (sh != -1)
    CloseHandle(sh);
  close(inp[0]);
  close(inp[1]);
  close(outp[0]);
  close(outp[1]);
  close(live[0]);
  close(live[1]);
  errno = e;
  return -1;
}

textwindows int64_t __pty_write_handle(struct Fd *f) {
  struct Pty *pty = f->pty;
  return f->ptymaster ? pty->in_w : pty->out_w;
}

// whether every slave is gone, which is when the master reads its end
textwindows bool __pty_hangup(struct Fd *f) {
  struct Pty *pty = f->pty;
  uint32_t avail;
  return !PeekNamedPipe(pty->live_r, 0, 0, 0, &avail, 0) &&
         GetLastError() == kNtErrorBrokenPipe;
}

/**
 * Waits for the master to have something to say.
 *
 * @return 1 when output is waiting, 0 at the end, -1 w/ EAGAIN
 */
textwindows int __pty_wait_readable(struct Fd *f, bool nonblock) {
  for (;;) {
    uint32_t avail = 0;
    if (!PeekNamedPipe(f->handle, 0, 0, 0, &avail, 0))
      return 1;  // let the read report the error
    if (avail)
      return 1;
    if (__pty_hangup(f))
      return 0;
    if (nonblock)
      return eagain();
    SleepEx(5, true);
  }
}

textwindows int __pty_close_nt(struct Fd *f) {
  struct Pty *pty = f->pty;
  int rc = 0;
  if (!CloseHandle(f->handle))
    rc = __winerr();
  if (f->ptymaster && !--pty->mrefs) {
    CloseHandle(pty->in_w);
    CloseHandle(pty->out_w);
    CloseHandle(pty->live_r);
    if (pty->owner == GetCurrentProcessId()) {
      ClosePseudoConsole(pty->hpc);
      TerminateProcess(pty->hold, 0);
      CloseHandle(pty->hold);
    }
  }
  if (!--pty->refs)
    munmap(pty, sizeof(*pty));
  f->pty = 0;
  f->ptymaster = false;
  return rc;
}

textwindows int __pty_getwinsize(struct Fd *f, struct winsize *ws) {
  struct Pty *pty = f->pty;
  *ws = pty->ws;
  return 0;
}

textwindows int __pty_setwinsize(struct Fd *f, const struct winsize *ws) {
  struct Pty *pty = f->pty;
  pty->ws = *ws;
  if (pty->owner == GetCurrentProcessId()) {
    struct NtCoord size = {ws->ws_col, ws->ws_row};
    ResizePseudoConsole(pty->hpc, size);
  }
  return 0;
}

// what a fresh linux pty reports
textwindows void __pty_termios(struct termios *tio) {
  bzero(tio, sizeof(*tio));
  tio->c_iflag = ICRNL | IXON | IUTF8;
  tio->c_oflag = OPOST | ONLCR;
  tio->c_cflag = CS8 | CREAD | B38400;
  tio->c_lflag =
      ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN;
  tio->c_cc[VINTR] = 3;
  tio->c_cc[VQUIT] = 28;
  tio->c_cc[VERASE] = 127;
  tio->c_cc[VKILL] = 21;
  tio->c_cc[VEOF] = 4;
  tio->c_cc[VSTART] = 17;
  tio->c_cc[VSTOP] = 19;
  tio->c_cc[VSUSP] = 26;
  tio->c_cc[VMIN] = 1;
  tio->c_cc[VTIME] = 0;
}

/**
 * Gets a child about to be spawned onto its pty.
 *
 * Called by execve() on Windows with the fd table locked. When a slave
 * sits on stdio, returns the HPCON to attach the child with if this is
 * the process that made the console. Otherwise this process joins the
 * console through the holder and its stdio entries become the console's
 * own handles, so they get inherited the ordinary way. Either way the
 * child must not be detached from the console, which is what `clear`
 * asks execve() to drop from the creation flags. A process that joined
 * the console this way must create the child itself, without naming
 * another process as the parent, or the child starts with console
 * handles that don't match its console; `attached` says so.
 *
 * @return HPCON for the child, 0 when there isn't one to pass, or -1
 *     w/ errno when the console couldn't be joined
 */
textwindows int64_t __pty_exec_prepare(uint32_t *clear, bool *attached,
                                       int64_t *live) {
  struct Fd *p = __get_pib()->fds.p;
  struct Pty *pty = 0;
  for (int fd = 0; fd < 3; ++fd)
    if (__isfdopen(fd) && __pty_isslave(p + fd) &&
        !(p[fd].flags & O_CLOEXEC)) {
      pty = p[fd].pty;
      *live = p[fd].handle;  // the child keeps the master alive with it
    }
  if (!pty)
    return 0;
  *clear = kNtDetachedProcess | kNtCreateNoWindow | kNtCreateNewConsole;
  if (pty->owner == GetCurrentProcessId())
    return pty->hpc;
  FreeConsole();
  // the holder may still be starting up right after openpty()
  bool joined = false;
  for (int i = 0; i < 300 && !joined; ++i) {
    joined = AttachConsole(pty->holdpid);
    if (!joined) {
      if (GetLastError() == kNtErrorInvalidParameter)
        break;  // no such process
      SleepEx(10, false);
    }
  }
  if (!joined)
    return eio();
  *attached = true;
  int64_t hin = CreateFile(u"CONIN$", kNtGenericRead | kNtGenericWrite,
                           kNtFileShareRead | kNtFileShareWrite,
                           &kNtIsInheritable, kNtOpenExisting, 0, 0);
  int64_t hout = CreateFile(u"CONOUT$", kNtGenericRead | kNtGenericWrite,
                            kNtFileShareRead | kNtFileShareWrite,
                            &kNtIsInheritable, kNtOpenExisting, 0, 0);
  for (int fd = 0; fd < 3; ++fd) {
    if (!__isfdopen(fd) || !__pty_isslave(p + fd))
      continue;
    p[fd].pty = 0;
    p[fd].handle = fd ? hout : hin;
    p[fd].kind = kFdConsole;
  }
  return 0;
}

#endif /* SupportsWindows() */
