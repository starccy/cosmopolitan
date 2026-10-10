/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2023 Justine Alexandra Roberts Tunney                              │
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
#include "libc/dlopen/dlfcn.h"
#include "libc/intrin/strace.h"

// in a separate file from dlopen(), so that a program which only looks
// symbols up, like Rust's std does for weak ones, doesn't pull the host
// library loader in with it

#define DLOPEN_ERROR "dlopen() wasn't linked into this program"

void *__dlsym_plain(void *, const char *) __attribute__((__weak__));
void *__dlsym_global(const char *, bool) __attribute__((__weak__));

// what dlopen(NULL) returns
char __dlopen_self[1];
char *cosmo_dlerror(void) __attribute__((__weak__));

int dlinfo(void *addr, int req, void *info) {
  return -1;
}

/**
 * Returns string describing last dlopen/dlsym/dlclose error.
 */
char *dlerror(void) {
  if (cosmo_dlerror)
    return cosmo_dlerror();
  return DLOPEN_ERROR;
}

/**
 * Looks up symbol in a library dlopen() returned.
 *
 * A function comes back ready to be called, see cosmo_dltramp().
 *
 * `RTLD_DEFAULT`, and the handle dlopen(NULL) returns, look through the
 * functions cosmo_dlexport() made known and then the libraries opened
 * with `RTLD_GLOBAL`, each for its own symbols only. `RTLD_NEXT` does
 * the same without the first part. The rest of this program can't be
 * found, since it has no dynamic symbol table, and neither can the host
 * libc, whose functions would bypass ours.
 */
void *dlsym(void *handle, const char *name) {
  void *res = 0;
  if (handle == RTLD_DEFAULT || handle == RTLD_NEXT ||
      handle == __dlopen_self) {
    if (__dlsym_global)
      res = __dlsym_global(name, handle == RTLD_NEXT);
  } else if (__dlsym_plain) {
    res = __dlsym_plain(handle, name);
  }
  STRACE("dlsym(%p, %#s) → %p", handle, name, res);
  return res;
}
