/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2021 Justine Alexandra Roberts Tunney                              │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/
#include "libc/atomic.h"
#include "libc/calls/calls.h"
#include "libc/calls/sig.internal.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/calls/syscall-nt.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/atomic.h"
#include "libc/intrin/dll.h"
#include "libc/intrin/pgrp.h"
#include "libc/intrin/strace.h"
#include "libc/macros.h"
#include "libc/mem/alloca.h"
#include "libc/nt/console.h"
#include "libc/nt/enum/creationdisposition.h"
#include "libc/nt/enum/ctrlevent.h"
#include "libc/nt/enum/processaccess.h"
#include "libc/nt/errors.h"
#include "libc/nt/files.h"
#include "libc/nt/memory.h"
#include "libc/nt/process.h"
#include "libc/nt/nt/process.h"
#include "libc/nt/runtime.h"
#include "libc/proc/proc.h"
#include "libc/sysv/consts/sig.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#if SupportsWindows()

// Sets `sig` pending in the signal file of `pid`, if a process is there
// to read it. A living owner holds a lock on the file, and a file nobody
// holds is a leftover, which gets deleted.
textwindows static bool sys_kill_nt_post(int pid, int sig) {
  bool owned;
  atomic_ulong *sigproc;
  if (!(sigproc = __sig_map_target(pid, &owned)))
    return false;
  if (owned && sig > 0) {
    atomic_fetch_or_explicit(sigproc, 1ull << (sig - 1), memory_order_release);
    __sig_wake_process(pid);
  }
  UnmapViewOfFile(sigproc);
  if (!owned)
    DeleteFile(__sig_process_path(alloca(256), pid));
  return owned;
}

// a group member that isn't our child, which is a cosmo program taking
// the signal through its file, or a host program, stopped and continued
// by suspending it, or terminated
textwindows static void sys_kill_nt_member(struct PgrpMember *m, int sig) {
  if (m->cosmo && sig != 9 && sys_kill_nt_post(m->pid, sig))
    return;
  if (!sig || sig == SIGCHLD || sig == SIGURG || sig == SIGWINCH)
    return;
  bool stop = sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN ||
              sig == SIGTTOU;
  int64_t h;
  if (!(h = OpenProcess(kNtProcessTerminate | kNtProcessSuspendResume, false,
                        m->winpid)))
    return;
  if (stop)
    NtSuspendProcess(h);
  else if (sig == SIGCONT)
    NtResumeProcess(h);
  else
    TerminateProcess(h, sig);
  CloseHandle(h);
}

textwindows int sys_kill_nt(int pid, int sig) {

  // validate api usage
  if (!(0 <= sig && sig <= 64))
    return einval();

  // no support for kill all yet
  if (pid == -1)
    return einval();

  // a process group is our direct children in it, as the process table
  // says, and every process on our console whose published group it is
  // or, for a host program, whose nearest published ancestor's it is
  if (pid <= 0) {
    int pgid = pid ? -pid : __pgrp_self();
    int n, m, pids[64];
    struct PgrpMember mem[64];
    bool self = pgid == __pgrp_self();
    n = __proc_group_pids(pgid, pids, ARRAYLEN(pids));
    m = __pgrp_members(pgid, mem, ARRAYLEN(mem));
    for (int i = 0; i < m; ++i)
      if (mem[i].pid == getpid())
        self = true;
    if (!n && !m && !self)
      return esrch();
    if (!sig)
      return 0;  // ability check passes
    BLOCK_SIGNALS;
    for (int i = 0; i < n; ++i)
      sys_kill_nt(pids[i], sig);
    for (int i = 0; i < m; ++i) {
      bool child = mem[i].pid == getpid();
      for (int j = 0; j < n && !child; ++j)
        child = pids[j] == mem[i].pid;
      if (!child)
        sys_kill_nt_member(mem + i, sig);
    }
    ALLOW_SIGNALS;
    if (self)
      return sys_kill_nt(getpid(), sig);
    return 0;
  }

  // Deliver synchronously when the calling thread can take the signal.
  // Otherwise it belongs to the process, not this thread's pending set:
  // another thread may be waiting for it (e.g. a POSIX timer's SIGALRM).
  if (pid == getpid()) {
    if (!sig)
      return 0;  // ability check passes
    if (sig != SIGKILL && sig != SIGSTOP) {
      bool blocked;
      uint64_t bit = 1ull << (sig - 1);
      BLOCK_SIGNALS;
      blocked = !!(_SigMask & bit);
      if (blocked) {
        __sig_lock();
        if (!__sig_ignored(sig))
          atomic_fetch_or_explicit(__get_pib()->sigpending, bit,
                                   memory_order_release);
        __sig_unlock();
        __sig_wake_process(pid);
      }
      ALLOW_SIGNALS;
      if (blocked)
        return 0;
    }
    return raise(sig);
  }

  // find existing handle we own for process
  //
  // this comes first because it settles an execve() the child may have
  // just done, which decides who owns its signal file
  int64_t handle = __proc_handle(pid), closeme = 0;

  // attempt to signal via shared memory file
  //
  // a file some process owns means a cosmo process that can be trusted
  // to deliver its signal, unless it's a nine exterminations
  if (pid > 0 && sig != 9 && sys_kill_nt_post(pid, sig)) {
    if (sig == SIGCONT && handle)
      __proc_continued(pid);
    return 0;
  }

  if (!handle) {
    if (!(handle = OpenProcess(kNtProcessTerminate | kNtProcessSuspendResume,
                               false, pid)) &&
        !(handle = OpenProcess(kNtProcessTerminate, false, pid)))
      return esrch();
    closeme = handle;
  }

  // a process that takes no signals gets their default action, and for
  // the stop signals that's stopping, which NT can do to a whole process.
  // a child of ours is suspended once however many stops it's sent
  bool stop = sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN ||
              sig == SIGTTOU;
  if (stop || sig == SIGCONT) {
    int rc = 0;
    if (closeme || __proc_native_stop(pid, stop ? sig : 0))
      if ((stop ? NtSuspendProcess(handle) : NtResumeProcess(handle)))
        rc = eperm();
    if (closeme)
      CloseHandle(closeme);
    return rc;
  }

  // the process exists and takes no signals, so the null signal is
  // done, and so is any signal whose default action is to be ignored
  if (!sig || sig == SIGCHLD || sig == SIGURG || sig == SIGWINCH) {
    if (closeme)
      CloseHandle(closeme);
    return 0;
  }

  // perform actual kill
  // process will report WIFSIGNALED with WTERMSIG(sig)
  if (sig != 9)
    STRACE("warning: kill() sending %G via terminate", sig);
  if (!closeme)
    __proc_killed(pid, sig);
  bool32 ok = TerminateProcess(handle, sig);
  if (closeme)
    CloseHandle(closeme);
  if (ok)
    return 0;
  return esrch();
}

#endif /* __x86_64__ */
