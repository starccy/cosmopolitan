#include "libc/calls/calls.h"
#include "libc/calls/internal.h"
#include "libc/calls/sig.internal.h"
#include "libc/calls/syscall-nt.internal.h"
#include "libc/dce.h"
#include "libc/intrin/atomic.h"
#include "libc/intrin/maps.h"
#include "libc/intrin/nomultics.h"
#include "libc/intrin/strace.h"
#include "libc/macros.h"
#include "libc/nt/console.h"
#include "libc/nt/enum/processcreationflags.h"
#include "libc/nt/enum/wait.h"
#include "libc/nt/events.h"
#include "libc/nt/files.h"
#include "libc/nt/memory.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/inputrecord.h"
#include "libc/nt/synchronization.h"
#include "libc/nt/thread.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/proc/proc.h"
#include "libc/sysv/consts/map.h"
#include "libc/sysv/consts/prot.h"
#include "libc/sysv/consts/sig.h"
#include "libc/sysv/pib.h"
#include "libc/thread/tls.h"
#if SupportsWindows()

/**
 * @fileoverview Job control on the Windows console.
 *
 * A terminal driver sends SIGINT, SIGQUIT or SIGTSTP to the foreground
 * process group when ^C, ^\ or ^Z is typed. The console has no such
 * thing, and a cosmo program only sees those keys when it reads the
 * console itself. So while tcsetpgrp() has given the terminal to another
 * group, a thread here watches the console input buffer for them, takes
 * them out, and signals that group, which kill() stops whether they're
 * cosmo programs or native ones.
 */

#define STACK_SIZE 65536

__msabi extern typeof(WaitForMultipleObjects)
    *const __imp_WaitForMultipleObjects;

static struct {
  atomic_int fg;  // the group holding the terminal, 0 when it's ours
  intptr_t thread;
  intptr_t wake;
} __jobctl;

// the signal a key record stands for, or 0
textwindows static int SignalKey(const struct NtInputRecord *r) {
  if (r->EventType != kNtKeyEvent || !r->Event.KeyEvent.bKeyDown)
    return 0;
  int c = r->Event.KeyEvent.uChar.UnicodeChar;
  if (!c)
    return 0;
  if (c == __ttyconf.vintr)
    return SIGINT;
  if (c == __ttyconf.vquit)
    return SIGQUIT;
  if (c == __ttyconf.vsusp)
    return SIGTSTP;
  return 0;
}

textwindows static bool IsSignalKey(const struct NtInputRecord *r) {
  return r->EventType == kNtKeyEvent &&
         (r->Event.KeyEvent.uChar.UnicodeChar == __ttyconf.vintr ||
          r->Event.KeyEvent.uChar.UnicodeChar == __ttyconf.vquit ||
          r->Event.KeyEvent.uChar.UnicodeChar == __ttyconf.vsusp) &&
         r->Event.KeyEvent.uChar.UnicodeChar;
}

// the first signal key waiting in the console input buffer, or 0
textwindows static int SignalKeyPending(int64_t cin) {
  int sig;
  uint32_t n;
  struct NtInputRecord r[64];
  if (!PeekConsoleInput(cin, r, ARRAYLEN(r), &n))
    return 0;
  for (uint32_t i = 0; i < n; ++i)
    if ((sig = SignalKey(r + i)))
      return sig;
  return 0;
}

// takes every signal key out of the console input buffer, leaving the
// rest of the input in order for whoever reads it next
textwindows static void RemoveSignalKeys(int64_t cin) {
  uint32_t n, got, kept = 0, cap = 256;
  struct NtInputRecord *keep, *more;
  if (!(keep = HeapAlloc(GetProcessHeap(), 0, cap * sizeof(*keep))))
    return;
  for (;;) {
    if (!GetNumberOfConsoleInputEvents(cin, &n) || !n)
      break;
    if (kept + n > cap) {
      cap = (kept + n) * 2;
      if (!(more = HeapReAlloc(GetProcessHeap(), 0, keep, cap * sizeof(*keep))))
        break;
      keep = more;
    }
    if (!ReadConsoleInput(cin, keep + kept, n, &got))
      break;
    uint32_t base = kept;
    for (uint32_t i = 0; i < got; ++i)
      if (!IsSignalKey(keep + base + i))
        keep[kept++] = keep[base + i];
  }
  if (kept)
    WriteConsoleInput(cin, keep, kept, &got);
  HeapFree(GetProcessHeap(), 0, keep);
}

textwindows static void EchoSignalKey(int sig) {
  if (!(__ttyconf.magic & kTtySilence) && !(__ttyconf.magic & kTtyEchoRaw)) {
    int c = sig == SIGINT    ? __ttyconf.vintr
            : sig == SIGQUIT ? __ttyconf.vquit
                             : __ttyconf.vsusp;
    char b[2] = {'^', c ^ 0100};
    WriteFile(GetConsoleOutputHandle(), b, 2, 0, 0);
  }
}

textwindows static void SignalForeground(int pgid, int sig) {
  STRACE("%G key on the console: signalling group %d", sig, pgid);
  sys_kill_nt(-pgid, sig);
}

textwindows dontinstrument static uint32_t __jobctl_worker(void *arg) {
  struct CosmoTib tls;
  char *sp = __builtin_frame_address(0);
  __bootstrap_tls(&tls, sp);
  __maps_lock();
  __maps_track(
      (char *)(((uintptr_t)sp + __pagesize - 1) & -__pagesize) - STACK_SIZE,
      STACK_SIZE, PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS | MAP_NOFORK);
  __maps_unlock();
  // input that isn't ^Z stays in the buffer for the foreground job to
  // read, and the handle stays signaled while it's there, so the look is
  // repeated at a growing interval rather than spun on
  uint32_t backoff = 10;
  for (;;) {
    int fg = atomic_load_explicit(&__jobctl.fg, memory_order_acquire);
    if (!fg) {
      WaitForSingleObject(__jobctl.wake, -1u);
      backoff = 10;
      continue;
    }
    int64_t cin = GetConsoleInputHandle();
    intptr_t hands[2] = {cin, __jobctl.wake};
    uint32_t wi = __imp_WaitForMultipleObjects(2, hands, false, -1u);
    if (wi != 0) {
      backoff = 10;
      continue;
    }
    int sig;
    if ((__ttyconf.magic & kTtyNoIsigs) || !(sig = SignalKeyPending(cin))) {
      SleepEx(backoff, false);
      backoff = MIN(backoff * 2, 100);
      continue;
    }
    RemoveSignalKeys(cin);
    EchoSignalKey(sig);
    SignalForeground(fg, sig);
    backoff = 10;
  }
  return 0;
}

// tcsetpgrp() handed the terminal to `pgid`, or took it back with 0
textwindows void __jobctl_foreground(int pgid) {
  atomic_store_explicit(&__jobctl.fg, pgid, memory_order_release);
  if (!pgid && !__jobctl.thread)
    return;
  if (!__jobctl.thread) {
    __jobctl.wake = CreateEvent(0, 0, 0, 0);
    __jobctl.thread = CreateThread(0, STACK_SIZE, __jobctl_worker, 0,
                                   kNtStackSizeParamIsAReservation, 0);
  }
  SetEvent(__jobctl.wake);
}

// a forked child starts without the thread
textwindows void __jobctl_wipe(void) {
  __jobctl.thread = 0;
  __jobctl.wake = 0;
  atomic_store(&__jobctl.fg, 0);
}

#endif /* __x86_64__ */
