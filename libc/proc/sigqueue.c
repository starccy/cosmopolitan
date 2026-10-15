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
#include "libc/calls/calls.h"
#include "libc/calls/struct/siginfo.h"
#include "libc/calls/struct/siginfo.internal.h"
#include "libc/calls/struct/sigval.h"
#include "libc/calls/struct/sigval.internal.h"
#include "libc/calls/syscall_support-sysv.internal.h"
#include "libc/dce.h"
#include "libc/calls/sig.internal.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/sig.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#include "libc/sysv/consts/sicode.h"

// linux wants the signal number beside the siginfo; netbsd doesn't
int sys_rt_sigqueueinfo(int, int, const siginfo_t *) asm("sys_sigqueueinfo");

/**
 * Queues a signal with a value, the way sigqueue() does, with `code`
 * as the `si_code` the handler sees. This is how timers and aio notify.
 *
 * Windows and XNU have no sigqueue; there a signal to the calling
 * process carries its value through our own queue and anything else
 * is ENOSYS.
 */
int __sigqueue(int pid, int sig, const union sigval value, int code) {
  siginfo_t info;
  if (IsFreebsd())
    return sys_sigqueue(pid, __linux2sig(sig), value);
  if (IsLinux() || IsNetbsd()) {
    bzero(&info, sizeof(info));
    info.si_signo = __linux2sig(sig);
    info.si_code = code;
    info.si_pid = getpid();
    info.si_uid = geteuid();
    info.si_value = value;
    if (IsLinux())
      return sys_rt_sigqueueinfo(pid, info.si_signo, &info);
    return sys_sigqueueinfo(pid, &info);
  }
  if (pid != getpid())
    return enosys();
  if (sig < 1 || sig > 64)
    return einval();
  // only a handler ever looks at the value
  int32_t rva = __get_pib()->sighandrvas[sig - 1];
  if (rva != (int32_t)(intptr_t)SIG_DFL && rva != (int32_t)(intptr_t)SIG_IGN &&
      !__sig_queue_value(sig, value, code, pid, geteuid()))
    return eagain();
  return kill(pid, sig);
}

/**
 * Sends signal with value to process.
 *
 * @return 0 on success, or -1 w/ errno
 * @raise EAGAIN if too many values are queued
 * @raise ENOSYS on Windows and XNU when `pid` isn't the calling process
 */
int sigqueue(int pid, int sig, const union sigval value) {
  return __sigqueue(pid, sig, value, SI_QUEUE);
}
