#include "libc/calls/calls.h"
#include "libc/calls/struct/itimerspec.h"
#include "libc/calls/struct/sigevent.h"
#include "libc/calls/struct/timespec.h"
#include "libc/calls/weirdtypes.h"
#include "libc/cosmotime.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/strace.h"
#include "libc/mem/mem.h"
#include "libc/sysv/consts/sig.h"
#include "libc/sysv/consts/timer.h"
#include "libc/sysv/errfuns.h"
#include "libc/thread/thread.h"
#include "libc/thread/thread2.h"

// POSIX interval timers. Linux keeps them in the kernel for the signal
// notifications, which is what the kernel supports. A SIGEV_THREAD timer
// there, and every timer on the other hosts, is a thread of its own that
// sleeps until the deadline and then notifies: the function runs on that
// thread, and a signal goes to the process with the value attached where
// the host can carry one.

int sys_timer_create(int, const struct sigevent *, int *);
int sys_timer_settime(int, int, const struct itimerspec *,
                      struct itimerspec *);
int sys_timer_gettime(int, struct itimerspec *);
int sys_timer_delete(int);
int sys_timer_getoverrun(int);

struct PosixTimer {
  int kid;  // linux kernel timer, or -1
  int clock;
  int overrun;
  bool armed;
  bool dead;
  struct sigevent sev;
  struct itimerspec it;  // it_value is absolute on clock
  pthread_t thread;
  pthread_mutex_t lock;
  pthread_cond_t cond;
};

static void Notify(const struct sigevent *sev) {
  switch (sev->sigev_notify) {
    case SIGEV_SIGNAL:
      if (sigqueue(getpid(), sev->sigev_signo, sev->sigev_value) == -1)
        raise(sev->sigev_signo);
      break;
    case SIGEV_THREAD:
      sev->sigev_notify_function(sev->sigev_value);
      break;
    default:
      break;
  }
}

static void *TimerWorker(void *arg) {
  struct PosixTimer *t = arg;
  pthread_mutex_lock(&t->lock);
  while (!t->dead) {
    if (!t->armed) {
      pthread_cond_wait(&t->cond, &t->lock);
      continue;
    }
    struct timespec now;
    clock_gettime(t->clock, &now);
    if (timespec_cmp(now, t->it.it_value) < 0) {
      pthread_cond_timedwait(&t->cond, &t->lock, &t->it.it_value);
      continue;
    }
    int fires = 0;
    if (timespec_iszero(t->it.it_interval)) {
      t->armed = false;
      fires = 1;
    } else {
      do {
        t->it.it_value = timespec_add(t->it.it_value, t->it.it_interval);
        ++fires;
      } while (timespec_cmp(now, t->it.it_value) >= 0);
    }
    t->overrun = fires - 1;
    struct sigevent sev = t->sev;
    pthread_mutex_unlock(&t->lock);
    Notify(&sev);
    pthread_mutex_lock(&t->lock);
  }
  pthread_mutex_unlock(&t->lock);
  return 0;
}

static struct PosixTimer *TimerNew(int clock, const struct sigevent *sev) {
  struct PosixTimer *t = 0;
  if (!(t = calloc(1, sizeof(*t))))
    return 0;
  t->kid = -1;
  t->clock = clock;
  t->sev = *sev;
  pthread_mutex_init(&t->lock, 0);
  pthread_condattr_t ca;
  pthread_condattr_init(&ca);
  pthread_condattr_setclock(&ca, clock);
  pthread_cond_init(&t->cond, &ca);
  pthread_condattr_destroy(&ca);
  return t;
}

/**
 * Creates interval timer.
 *
 * @param sev says how an expiration is reported, or NULL for SIGALRM
 * @param timerid receives the timer
 * @return 0 on success, or -1 w/ errno
 * @raise EINVAL if clock isn't supported or sev is malformed
 * @raise ENOTSUP if sev asks for SIGEV_THREAD_ID off Linux
 */
int timer_create(int clock, struct sigevent *sev, timer_t *timerid) {
  int rc;
  struct sigevent s;
  struct PosixTimer *t = 0;
  if (sev) {
    s = *sev;
  } else {
    s.sigev_notify = SIGEV_SIGNAL;
    s.sigev_signo = SIGALRM;
    s.sigev_value.sival_int = 0;
  }
  if (s.sigev_notify == SIGEV_THREAD && !s.sigev_notify_function) {
    rc = einval();
  } else if (s.sigev_notify == SIGEV_THREAD_ID && !IsLinux()) {
    rc = enotsup();
  } else if (!(t = TimerNew(clock, &s))) {
    rc = -1;
  } else if (IsLinux() && s.sigev_notify != SIGEV_THREAD) {
    if ((rc = sys_timer_create(clock, &s, &t->kid)) == -1)
      free(t);
  } else {
    struct timespec now;
    if (clock_gettime(clock, &now) == -1) {
      rc = -1;
    } else if ((rc = pthread_create(&t->thread, 0, TimerWorker, t))) {
      errno = rc;
      rc = -1;
    }
    if (rc == -1)
      free(t);
  }
  if (rc != -1)
    *timerid = t;
  STRACE("timer_create(%d, %p, [%p]) → %d% m", clock, sev,
         rc != -1 ? *timerid : 0, rc);
  return rc;
}

/**
 * Arms or disarms interval timer.
 *
 * @param flags can have TIMER_ABSTIME
 * @param neu is the new setting, where a zero it_value disarms
 * @param old receives the setting being replaced, if not null
 * @return 0 on success, or -1 w/ errno
 */
int timer_settime(timer_t timerid, int flags, const struct itimerspec *neu,
                  struct itimerspec *old) {
  int rc;
  struct PosixTimer *t = timerid;
  if (!t || !neu) {
    rc = einval();
  } else if (t->kid != -1) {
    rc = sys_timer_settime(t->kid, flags, neu, old);
  } else if (!timespec_isvalid(neu->it_value) ||
             !timespec_isvalid(neu->it_interval)) {
    rc = einval();
  } else {
    struct timespec now;
    clock_gettime(t->clock, &now);
    pthread_mutex_lock(&t->lock);
    if (old) {
      old->it_interval = t->it.it_interval;
      old->it_value =
          t->armed ? timespec_subz(t->it.it_value, now) : timespec_zero;
    }
    t->it = *neu;
    t->armed = !timespec_iszero(neu->it_value);
    if (t->armed && !(flags & TIMER_ABSTIME))
      t->it.it_value = timespec_add(now, neu->it_value);
    t->overrun = 0;
    pthread_cond_signal(&t->cond);
    pthread_mutex_unlock(&t->lock);
    rc = 0;
  }
  STRACE("timer_settime(%p, %#x, %p, %p) → %d% m", timerid, flags, neu, old,
         rc);
  return rc;
}

/**
 * Returns time until interval timer fires next.
 *
 * @return 0 on success, or -1 w/ errno
 */
int timer_gettime(timer_t timerid, struct itimerspec *cur) {
  int rc;
  struct PosixTimer *t = timerid;
  if (!t || !cur) {
    rc = einval();
  } else if (t->kid != -1) {
    rc = sys_timer_gettime(t->kid, cur);
  } else {
    struct timespec now;
    clock_gettime(t->clock, &now);
    pthread_mutex_lock(&t->lock);
    cur->it_interval = t->it.it_interval;
    cur->it_value =
        t->armed ? timespec_subz(t->it.it_value, now) : timespec_zero;
    pthread_mutex_unlock(&t->lock);
    rc = 0;
  }
  STRACE("timer_gettime(%p, %p) → %d% m", timerid, cur, rc);
  return rc;
}

/**
 * Returns how many expirations the last notification stood for, beyond
 * the first.
 */
int timer_getoverrun(timer_t timerid) {
  int rc;
  struct PosixTimer *t = timerid;
  if (!t) {
    rc = einval();
  } else if (t->kid != -1) {
    rc = sys_timer_getoverrun(t->kid);
  } else {
    pthread_mutex_lock(&t->lock);
    rc = t->overrun;
    pthread_mutex_unlock(&t->lock);
  }
  return rc;
}

/**
 * Deletes interval timer.
 *
 * @return 0 on success, or -1 w/ errno
 */
int timer_delete(timer_t timerid) {
  int rc;
  struct PosixTimer *t = timerid;
  if (!t) {
    rc = einval();
  } else {
    if (t->kid != -1) {
      rc = sys_timer_delete(t->kid);
    } else {
      pthread_mutex_lock(&t->lock);
      t->dead = true;
      pthread_cond_signal(&t->cond);
      pthread_mutex_unlock(&t->lock);
      pthread_join(t->thread, 0);
      rc = 0;
    }
    pthread_cond_destroy(&t->cond);
    pthread_mutex_destroy(&t->lock);
    free(t);
  }
  STRACE("timer_delete(%p) → %d% m", timerid, rc);
  return rc;
}
