/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2024 Justine Alexandra Roberts Tunney                              │
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
#include "libc/calls/sig.internal.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/fmt/internal.h"
#include "libc/intrin/kprintf.h"
#include "libc/nt/createfile.h"
#include "libc/nt/enum/accessmask.h"
#include "libc/nt/enum/creationdisposition.h"
#include "libc/nt/enum/fileflagandattributes.h"
#include "libc/nt/enum/filelockflags.h"
#include "libc/nt/enum/filemapflags.h"
#include "libc/nt/enum/filemovemethod.h"
#include "libc/nt/enum/filesharemode.h"
#include "libc/nt/enum/pageflags.h"
#include "libc/nt/errors.h"
#include "libc/nt/events.h"
#include "libc/nt/files.h"
#include "libc/nt/memory.h"
#include "libc/nt/process.h"
#include "libc/nt/runtime.h"
#include "libc/nt/synchronization.h"
#include "libc/nt/struct/overlapped.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/str/str.h"
#ifdef __x86_64__

#define COSMO_PID_UPPER_BOUND 0x100000  // about one million
#define COSMO_PID_LOWER_BOUND 0x10000   // avoid pids windows likes

// cut back on code size and avoid setting errno
// this code is a mandatory dependency of winmain
__msabi extern typeof(CloseHandle) *const __imp_CloseHandle;
__msabi extern typeof(CreateDirectory) *const __imp_CreateDirectoryW;
__msabi extern typeof(CreateEvent) *const __imp_CreateEventW;
__msabi extern typeof(CreateFile) *const __imp_CreateFileW;
__msabi extern typeof(CreateFileMapping) *const __imp_CreateFileMappingW;
__msabi extern typeof(GetLastError) *const __imp_GetLastError;
__msabi extern typeof(LockFileEx) *const __imp_LockFileEx;
__msabi extern typeof(MapViewOfFileEx) *const __imp_MapViewOfFileEx;
__msabi extern typeof(ResetEvent) *const __imp_ResetEvent;
__msabi extern typeof(SetEndOfFile) *const __imp_SetEndOfFile;
__msabi extern typeof(SetEvent) *const __imp_SetEvent;
__msabi extern typeof(SetFilePointerEx) *const __imp_SetFilePointerEx;
__msabi extern typeof(SleepEx) *const __imp_SleepEx;
__msabi extern typeof(UnlockFileEx) *const __imp_UnlockFileEx;
__msabi extern typeof(UnmapViewOfFile) *const __imp_UnmapViewOfFile;
__msabi extern typeof(WaitForSingleObject)
    *const __imp_WaitForSingleObject;

textwindows static uint32_t ProcessPrng32(void) {
  uint32_t r;
  ProcessPrng(&r, sizeof(r));
  return r;
}

// Daniel Lemire, "Fast Random Integer Generation in an Interval",
// Association for Computing Machinery, ACM Trans. Model. Comput.
// Simul., no. 1, vol. 29, pp. 1--12, New York, NY, USA, January 2019.
textwindows static uint32_t ProcessPrngUniform(uint32_t upper_bound) {
  if (upper_bound <= 1)
    return 0;
  uint64_t product = upper_bound * (uint64_t)ProcessPrng32();
  if ((uint32_t)product < upper_bound) {
    uint32_t threshold = -upper_bound % upper_bound;
    while ((uint32_t)product < threshold)
      product = upper_bound * (uint64_t)ProcessPrng32();
  }
  return product >> 32;
}

textwindows int __generate_pid(atomic_ulong **sigpending) {
  for (;;) {
    int pid =
        ProcessPrngUniform(COSMO_PID_UPPER_BOUND - COSMO_PID_LOWER_BOUND - 1) +
        COSMO_PID_LOWER_BOUND + 1;
    if ((*sigpending = __sig_map_process(pid, kNtCreateNew)))
      return pid;
  }
}

textwindows static bool __sig_makedirs(char16_t *p, char16_t *e) {
  while (e > p) {
    --e;
    if (*e == '\\')
      break;
  }
  if (e - p < 3)
    return true;
  for (;;) {
    char16_t c = *e;
    *e = 0;
    bool32 ok = __imp_CreateDirectoryW(p, 0);
    *e = c;
    if (ok)
      return true;
    uint32_t err = __imp_GetLastError();
    if (err == kNtErrorAlreadyExists)
      return true;
    if (err != kNtErrorPathNotFound)
      return false;
    if (!__sig_makedirs(p, e))
      return false;
  }
}

// Generates C:\ProgramData\cosmo\sig\x\y.pid like path
textwindows char16_t *__sig_process_path(char16_t *path, uint32_t pid) {
  char16_t *p = path;
  *p++ = __getcosmosdrive();
  *p++ = ':';
  *p++ = '\\';
  *p++ = 'P';
  *p++ = 'r';
  *p++ = 'o';
  *p++ = 'g';
  *p++ = 'r';
  *p++ = 'a';
  *p++ = 'm';
  *p++ = 'D';
  *p++ = 'a';
  *p++ = 't';
  *p++ = 'a';
  *p++ = '\\';
  *p++ = 'c';
  *p++ = 'o';
  *p++ = 's';
  *p++ = 'm';
  *p++ = 'o';
  *p++ = '\\';
  *p++ = 's';
  *p++ = 'i';
  *p++ = 'g';
  *p++ = '\\';
  p = __itoa16(p, (pid & 0x000ff800) >> 11);
  *p++ = '\\';
  p = __itoa16(p, pid);
  *p++ = '.';
  *p++ = 'p';
  *p++ = 'i';
  *p++ = 'd';
  *p = 0;
  return path;
}

// Byte a live process holds a shared lock on, so a stale file from a
// recycled pid can be told apart (shared since execve() overlaps pids).
#define SIG_OWNER_BYTE 16

static intptr_t __sig_owner;

// Event another process sets after writing to our signal file. It is
// manual reset, since an execve() leaves two processes on one pid for a
// moment and both wait on it.
static intptr_t __sig_event;

// Opens event of process, creating it if needed.
textwindows static intptr_t __sig_open_event(int pid) {
  char16_t name[32];
  char16_t *p = name;
  *p++ = 'c';
  *p++ = 'o';
  *p++ = 's';
  *p++ = 'm';
  *p++ = 'o';
  *p++ = '.';
  *p++ = 's';
  *p++ = 'i';
  *p++ = 'g';
  *p++ = '.';
  p = __itoa16(p, pid);
  *p = 0;
  return __imp_CreateEventW(0, true, false, name);
}

textwindows static bool __sig_lock_owner(intptr_t hand) {
  struct NtOverlapped ov = {.Pointer = SIG_OWNER_BYTE};
  return __imp_LockFileEx(hand, 0, 0, 1, 0, &ov);
}

textwindows static bool __sig_has_owner(intptr_t hand) {
  struct NtOverlapped ov = {.Pointer = SIG_OWNER_BYTE};
  if (!__imp_LockFileEx(
          hand, kNtLockfileExclusiveLock | kNtLockfileFailImmediately, 0, 1, 0,
          &ov))
    return true;
  __imp_UnlockFileEx(hand, 0, 1, 0, &ov);
  return false;
}

// Maps signal file of process.
//
// When `owner` is given the file is locked as owned, and the handle
// holding that lock is stored there rather than closed. When `owned` is
// given it is told whether some process holds that lock.
textwindows static atomic_ulong *__sig_map(int pid, int disposition,
                                           uint32_t share, intptr_t *owner,
                                           bool *owned) {
  char16_t path[128];
  __sig_process_path(path, pid);
  intptr_t hand;
  for (;;) {
    hand = __imp_CreateFileW(path, kNtGenericRead | kNtGenericWrite, share, 0,
                             disposition, kNtFileAttributeNormal, 0);
    if (hand != -1)
      break;
    if (disposition == kNtOpenAlways || disposition == kNtCreateNew) {
      uint32_t err = __imp_GetLastError();
      if (err == kNtErrorPathNotFound)
        if (__sig_makedirs(path, path + strlen16(path)))
          continue;
    }
    return 0;
  }
  if (owned)
    *owned = __sig_has_owner(hand);
  // an existing file has its size already
  if (disposition != kNtOpenExisting) {
    __imp_SetFilePointerEx(hand, 8, 0, kNtFileBegin);
    __imp_SetEndOfFile(hand);
  }
  intptr_t map = __imp_CreateFileMappingW(hand, 0, kNtPageReadwrite, 0, 8, 0);
  if (!map) {
    __imp_CloseHandle(hand);
    return 0;
  }
  atomic_ulong *sigs =
      __imp_MapViewOfFileEx(map, kNtFileMapRead | kNtFileMapWrite, 0, 0, 8, 0);
  __imp_CloseHandle(map);
  if (sigs && owner && __sig_lock_owner(hand)) {
    *owner = hand;
  } else {
    __imp_CloseHandle(hand);
  }
  return sigs;
}

textwindows atomic_ulong *__sig_map_process(int pid, int disposition) {
  return __sig_map(pid, disposition, kNtFileShareRead | kNtFileShareWrite, 0,
                   0);
}

// Maps signal file of a process to be signalled.
//
// A file can outlive its process, so `owned` says whether a living one
// holds it.
textwindows atomic_ulong *__sig_map_target(int pid, bool *owned) {
  return __sig_map(pid, kNtOpenExisting, kNtFileShareRead | kNtFileShareWrite,
                   0, owned);
}

// Maps signal file of calling process and marks it as owned.
//
// The handle isn't shared for deletion, so nobody can take the file away
// while this process lives.
textwindows atomic_ulong *__sig_own_process(int pid) {
  __sig_owner = 0;  // after fork() this is the parent's, which we don't have
  __sig_event = __sig_open_event(pid);
  return __sig_map(pid, kNtOpenAlways, kNtFileShareRead | kNtFileShareWrite,
                   &__sig_owner, 0);
}

// Tells process there's something new in its signal file.
textwindows void __sig_wake_process(int pid) {
  intptr_t event;
  if ((event = __sig_open_event(pid))) {
    __imp_SetEvent(event);
    __imp_CloseHandle(event);
  }
}

// Sleeps until another process signals us, or a tick goes by.
//
// The tick remains for senders that set no event, and for signals which
// stay pending because every thread blocks them.
textwindows void __sig_pause(void) {
  if (__sig_event) {
    __imp_WaitForSingleObject(__sig_event, POLL_INTERVAL_MS);
    __imp_ResetEvent(__sig_event);
  } else {
    __imp_SleepEx(POLL_INTERVAL_MS, 0);
  }
}

// Gives up ownership so the file can be deleted.
textwindows void __sig_disown_process(void) {
  if (__sig_owner) {
    __imp_CloseHandle(__sig_owner);
    __sig_owner = 0;
  }
}

// Creates signal file of a process being forked, owned on its behalf.
//
// A forked child is a valid target for kill() before it has got around to
// owning its file. The returned handle keeps the file owned until then;
// it is shared for deletion so the child can still remove the file.
textwindows intptr_t __sig_guard_process(int pid) {
  intptr_t guard = 0;
  atomic_ulong *sigs =
      __sig_map(pid, kNtOpenAlways,
                kNtFileShareRead | kNtFileShareWrite | kNtFileShareDelete,
                &guard, 0);
  if (sigs) {
    atomic_store_explicit(sigs, 0, memory_order_release);
    __imp_UnmapViewOfFile(sigs);
  }
  return guard;
}

#endif /* __x86_64__ */
