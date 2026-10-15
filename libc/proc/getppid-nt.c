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
#include "libc/calls/syscall-nt.internal.h"
#include "libc/cosmo.h"
#include "libc/dce.h"
#include "libc/fmt/itoa.h"
#include "libc/nt/enum/status.h"
#include "libc/nt/nt/process.h"
#include "libc/nt/process.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/processbasicinformation.h"
#include "libc/runtime/internal.h"
#include "libc/runtime/runtime.h"
#include "libc/sysv/pib.h"

textwindows static int sys_getppid_nt_ntdll(void) {
  struct NtProcessBasicInformation ProcessInformation;
  uint32_t gotsize = 0;
  if (!NtError(
          NtQueryInformationProcess(GetCurrentProcess(), 0, &ProcessInformation,
                                    sizeof(ProcessInformation), &gotsize)) &&
      gotsize >= sizeof(ProcessInformation) &&
      ProcessInformation.InheritedFromUniqueProcessId) {
    return ProcessInformation.InheritedFromUniqueProcessId;
  }
  return 0;
}

textwindows int sys_getppid_nt(void) {
  if (__get_pib()->ppid_cosmo)
    return __get_pib()->ppid_cosmo;
  return sys_getppid_nt_ntdll();
}

textwindows int sys_getppid_nt_win32(void) {
  if (__get_pib()->ppid_win32)
    return __get_pib()->ppid_win32;
  return sys_getppid_nt_ntdll();
}
