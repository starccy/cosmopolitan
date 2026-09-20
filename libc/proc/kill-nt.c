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
#include "libc/intrin/strace.h"
#include "libc/mem/alloca.h"
#include "libc/nt/console.h"
#include "libc/nt/enum/creationdisposition.h"
#include "libc/nt/enum/ctrlevent.h"
#include "libc/nt/enum/processaccess.h"
#include "libc/nt/errors.h"
#include "libc/nt/files.h"
#include "libc/nt/memory.h"
#include "libc/nt/process.h"
#include "libc/nt/runtime.h"
#include "libc/proc/proc.h"
#include "libc/sysv/consts/sig.h"
#include "libc/sysv/errfuns.h"
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

textwindows int sys_kill_nt(int pid, int sig) {

  // validate api usage
  if (!(0 <= sig && sig <= 64))
    return einval();

  // XXX: NT doesn't really have process groups. For instance the
  //      CreateProcess() flag for starting a process group actually
  //      just does an "ignore ctrl-c" internally.
  if (pid < -1)
    pid = -pid;

  // no support for kill all yet
  if (pid == -1)
    return einval();

  // just call raise() if we're targeting self
  if (pid <= 0 || pid == getpid()) {
    if (sig) {
      if (pid <= 0) {
        // if pid is 0 or -1 then kill the processes beneath us too.
        // this isn't entirely right but it's closer to being right.
        // having this behavior is helpful for servers like redbean.
        struct Dll *e;
        BLOCK_SIGNALS;
        __proc_lock();
        for (e = dll_first(__proc.list); e; e = dll_next(__proc.list, e)) {
          struct Proc *pr = PROC_CONTAINER(e);
          if (sig == 9 || !sys_kill_nt_post(pr->pid, sig))
            TerminateProcess(pr->hProcess, sig);
        }
        __proc_unlock();
        ALLOW_SIGNALS;
      }
      return raise(sig);
    } else {
      return 0;  // ability check passes
    }
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
  if (pid > 0 && sig != 9 && sys_kill_nt_post(pid, sig))
    return 0;

  if (!handle) {
    if (!(handle = OpenProcess(kNtProcessTerminate, false, pid)))
      return esrch();
    closeme = handle;
  }

  // the process exists and takes no signals, so the null signal is
  // done, and so is any signal whose default action is to be ignored
  if (!sig || sig == SIGCHLD || sig == SIGURG || sig == SIGWINCH ||
      sig == SIGCONT) {
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
