// Copyright 2026 Justine Alexandra Roberts Tunney
//
// Permission to use, copy, modify, and/or distribute this software for
// any purpose with or without fee is hereby granted, provided that the
// above copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
// WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
// AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
// DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
// PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
// TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
// PERFORMANCE OF THIS SOFTWARE.

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>

// PTHREAD_MUTEX_ERRORCHECK turns the classic silent-deadlock and
// stray-unlock mistakes into reported errors: relocking a mutex the calling
// thread already holds must return EDEADLK (not hang), and unlocking a mutex
// the thread doesn't hold must return EPERM (not corrupt state). the mutex
// lives in static storage, which cosmo requires for error checking.

static pthread_mutex_t mu;

// exit codes are base + n, so a failure says which mutex it was
static void check(pthread_mutex_t *mu, int base) {
  pthread_mutexattr_t attr;
  if (pthread_mutexattr_init(&attr))
    exit(base + 0);
  if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK))
    exit(base + 1);
  if (pthread_mutex_init(mu, &attr))
    exit(base + 2);
  if (pthread_mutexattr_destroy(&attr))
    exit(base + 3);

  // unlocking a mutex that was never locked => EPERM
  if (pthread_mutex_unlock(mu) != EPERM)
    exit(base + 4);

  if (pthread_mutex_lock(mu))
    exit(base + 5);

  // the owner relocking it => EDEADLK instead of a hang
  if (pthread_mutex_lock(mu) != EDEADLK)
    exit(base + 6);

  if (pthread_mutex_unlock(mu))
    exit(base + 7);

  // unlocking again, now that it's free => EPERM
  if (pthread_mutex_unlock(mu) != EPERM)
    exit(base + 8);

  // waiting on a condition without holding the mutex => EPERM
  pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
  struct timespec ts = {0};
  if (pthread_cond_timedwait(&cv, mu, &ts) != EPERM)
    exit(base + 9);

  pthread_mutex_destroy(mu);
}

int main() {
  check(&mu, 10);

  // not in static memory, where only the error checking type tracks it
  pthread_mutex_t *heap = malloc(sizeof(pthread_mutex_t));
  if (!heap)
    exit(1);
  check(heap, 20);
  free(heap);

  pthread_mutex_t stack;
  check(&stack, 30);
}
