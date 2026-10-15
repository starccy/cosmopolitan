#include "libc/calls/calls.h"
#include "libc/calls/struct/aiocb.h"
#include "libc/calls/struct/sigevent.h"
#include "libc/calls/struct/siginfo.h"
#include "libc/calls/struct/sigset.h"
#include "libc/calls/struct/sigval.h"
#include "libc/calls/struct/sigval.internal.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/cosmotime.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/calls/struct/timespec.internal.h"
#include "libc/intrin/strace.h"
#include "libc/mem/mem.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/f.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/sicode.h"
#include "libc/sysv/consts/sig.h"
#include "libc/sysv/errfuns.h"
#include "libc/thread/thread.h"
#include "libc/thread/thread2.h"

// POSIX asynchronous I/O on a pool of threads, the way glibc does it on
// every host. A submitted aiocb sits on one list until it finishes;
// the private fields hold its state: __lock[0] the stage, __lock[1]
// the operation, __td the lio_listio group, __next/__prev the list.
// The result is published through __err with a release store, so
// aio_error() and aio_return() never take the lock and may be called
// from the signal handler that announces completion.
//
// Workers block every signal, so a process-directed signal can't land
// on one; SIGEV_THREAD functions get a thread of their own with the
// mask open. aio_suspend() isn't interrupted by signals (no EINTR).

#define kAioMaxThreads 16
#define kAioIdleMillis 5000

#define NEXT(cb) (*(struct aiocb **)&(cb)->__next)
#define PREV(cb) (*(struct aiocb **)&(cb)->__prev)

enum { kAioIdle, kAioQueued, kAioRunning, kAioDone };
enum { kAioRead = LIO_READ, kAioWrite = LIO_WRITE, kAioFsync = 3, kAioFdsync };

// lio_listio(LIO_NOWAIT) requests that share a notification
struct AioGroup {
  int left;
  struct sigevent sev;
  struct AioGroup *next;
};

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_work = PTHREAD_COND_INITIALIZER;  // request queued
static pthread_cond_t g_done = PTHREAD_COND_INITIALIZER;  // request finished
static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static struct aiocb *g_head, *g_tail;  // submitted and not done, oldest first
static int g_threads;
static int g_idle;

static void AioLink(struct aiocb *cb) {
  NEXT(cb) = 0;
  PREV(cb) = g_tail;
  if (g_tail) {
    NEXT(g_tail) = cb;
  } else {
    g_head = cb;
  }
  g_tail = cb;
}

static void AioUnlink(struct aiocb *cb) {
  struct aiocb *n = NEXT(cb), *p = PREV(cb);
  if (p) {
    NEXT(p) = n;
  } else {
    g_head = n;
  }
  if (n) {
    PREV(n) = p;
  } else {
    g_tail = p;
  }
  NEXT(cb) = PREV(cb) = 0;
}

struct AioCall {
  void (*fn)(union sigval);
  union sigval val;
};

static void *AioCallThread(void *arg) {
  struct AioCall c = *(struct AioCall *)arg;
  sigset_t none;
  free(arg);
  sigemptyset(&none);
  pthread_sigmask(SIG_SETMASK, &none, 0);
  c.fn(c.val);
  return 0;
}

static void AioNotify(const struct sigevent *sev) {
  switch (sev->sigev_notify) {
    case SIGEV_SIGNAL:
      if (__sigqueue(getpid(), sev->sigev_signo, sev->sigev_value,
                     SI_ASYNCIO) == -1)
        kill(getpid(), sev->sigev_signo);
      break;
    case SIGEV_THREAD: {
      pthread_t th;
      pthread_attr_t attr;
      struct AioCall *c = malloc(sizeof(*c));
      if (!c) {
        sev->sigev_notify_function(sev->sigev_value);
        break;
      }
      c->fn = sev->sigev_notify_function;
      c->val = sev->sigev_value;
      pthread_attr_init(&attr);
      pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
      if (pthread_create(&th, &attr, AioCallThread, c)) {
        free(c);
        sev->sigev_notify_function(sev->sigev_value);
      }
      pthread_attr_destroy(&attr);
      break;
    }
    case SIGEV_THREAD_ID: {
      siginfo_t info;
      bzero(&info, sizeof(info));
      info.si_signo = sev->sigev_signo;
      info.si_code = SI_QUEUE;
      info.si_pid = getpid();
      info.si_uid = geteuid();
      info.si_value = sev->sigev_value;
      sys_tgsigqueueinfo(getpid(), sev->sigev_notify_thread_id,
                         sev->sigev_signo, &info);
      break;
    }
    default:
      break;
  }
}

static int AioCheckSigevent(const struct sigevent *sev) {
  if (sev->sigev_notify == SIGEV_THREAD && !sev->sigev_notify_function)
    return einval();
  if (sev->sigev_notify == SIGEV_THREAD_ID && !IsLinux())
    return enotsup();
  return 0;
}

// publishes the outcome and takes the request off the list; returns
// the group when this was its last request, for the caller to notify
// and free once the lock is dropped
static struct AioGroup *AioFinish(struct aiocb *cb, ssize_t ret, int err) {
  struct AioGroup *g = cb->__td;
  AioUnlink(cb);
  cb->__ret = ret;
  cb->__lock[0] = kAioDone;
  __atomic_store_n(&cb->__err, err, __ATOMIC_RELEASE);
  pthread_cond_broadcast(&g_done);
  if (g && --g->left)
    g = 0;
  return g;
}

static ssize_t AioPerform(int fd, int op, void *buf, size_t n, int64_t off) {
  ssize_t rc;
  switch (op) {
    case kAioRead:
      rc = pread(fd, buf, n, off);
      if (rc == -1 && errno == ESPIPE)
        rc = read(fd, buf, n);
      return rc;
    case kAioWrite:
      rc = pwrite(fd, buf, n, off);
      if (rc == -1 && errno == ESPIPE)
        rc = write(fd, buf, n);
      return rc;
    case kAioFsync:
      return fsync(fd);
    case kAioFdsync:
      return fdatasync(fd);
    default:
      return einval();
  }
}

static void *AioWorker(void *arg) {
  struct aiocb *cb;
  pthread_mutex_lock(&g_lock);
  for (;;) {
    for (cb = g_head; cb && cb->__lock[0] != kAioQueued; cb = NEXT(cb)) {
    }
    if (!cb) {
      struct timespec deadline =
          timespec_add(timespec_real(), timespec_frommillis(kAioIdleMillis));
      ++g_idle;
      int rc = pthread_cond_timedwait(&g_work, &g_lock, &deadline);
      --g_idle;
      if (rc == ETIMEDOUT) {
        for (cb = g_head; cb && cb->__lock[0] != kAioQueued; cb = NEXT(cb)) {
        }
        if (!cb) {
          --g_threads;
          break;
        }
      }
      continue;
    }
    cb->__lock[0] = kAioRunning;
    int fd = cb->aio_fildes;
    int op = cb->__lock[1];
    void *buf = (void *)cb->aio_buf;
    size_t n = cb->aio_nbytes;
    int64_t off = cb->aio_offset;
    pthread_mutex_unlock(&g_lock);
    ssize_t ret = AioPerform(fd, op, buf, n, off);
    int err = ret == -1 ? errno : 0;
    pthread_mutex_lock(&g_lock);
    struct sigevent sev = cb->aio_sigevent;
    struct AioGroup *g = AioFinish(cb, ret, err);
    pthread_mutex_unlock(&g_lock);
    AioNotify(&sev);
    if (g) {
      AioNotify(&g->sev);
      free(g);
    }
    pthread_mutex_lock(&g_lock);
  }
  pthread_mutex_unlock(&g_lock);
  return 0;
}

static void AioAtForkChild(void) {
  pthread_mutex_init(&g_lock, 0);
  pthread_cond_init(&g_work, 0);
  pthread_cond_init(&g_done, 0);
  g_head = g_tail = 0;
  g_threads = 0;
  g_idle = 0;
}

static void AioInit(void) {
  pthread_atfork(0, 0, AioAtForkChild);
}

static int AioSubmit(struct aiocb *cb, int op, struct AioGroup *g) {
  int rc = 0;
  if (!cb || cb->aio_reqprio < 0)
    return einval();
  if (fcntl(cb->aio_fildes, F_GETFD) == -1)
    return -1;
  if (AioCheckSigevent(&cb->aio_sigevent) == -1)
    return -1;
  pthread_once(&g_once, AioInit);
  pthread_mutex_lock(&g_lock);
  if (cb->__lock[0] == kAioQueued || cb->__lock[0] == kAioRunning) {
    pthread_mutex_unlock(&g_lock);
    return einval();
  }
  cb->__lock[0] = kAioQueued;
  cb->__lock[1] = op;
  cb->__td = g;
  cb->__ret = 0;
  __atomic_store_n(&cb->__err, EINPROGRESS, __ATOMIC_RELEASE);
  AioLink(cb);
  if (!g_idle && g_threads < kAioMaxThreads) {
    pthread_t th;
    pthread_attr_t attr;
    sigset_t all, old;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, &old);
    int e = pthread_create(&th, &attr, AioWorker, 0);
    pthread_sigmask(SIG_SETMASK, &old, 0);
    pthread_attr_destroy(&attr);
    if (!e) {
      ++g_threads;
    } else if (!g_threads) {
      AioUnlink(cb);
      cb->__lock[0] = kAioIdle;
      __atomic_store_n(&cb->__err, e, __ATOMIC_RELEASE);
      rc = eagain();
    }
  }
  if (!rc)
    pthread_cond_signal(&g_work);
  pthread_mutex_unlock(&g_lock);
  return rc;
}

/**
 * Reads asynchronously.
 *
 * @return 0 if queued, or -1 w/ errno
 * @raise EBADF if `aio_fildes` isn't open
 * @raise EAGAIN if no worker thread could be made
 */
int aio_read(struct aiocb *cb) {
  int rc = AioSubmit(cb, kAioRead, 0);
  STRACE("aio_read(%p) → %d% m", cb, rc);
  return rc;
}

/**
 * Writes asynchronously.
 *
 * @return 0 if queued, or -1 w/ errno
 */
int aio_write(struct aiocb *cb) {
  int rc = AioSubmit(cb, kAioWrite, 0);
  STRACE("aio_write(%p) → %d% m", cb, rc);
  return rc;
}

/**
 * Syncs file asynchronously.
 *
 * @param op is `O_SYNC` or `O_DSYNC`
 * @return 0 if queued, or -1 w/ errno
 */
int aio_fsync(int op, struct aiocb *cb) {
  int rc;
  if (op == O_DSYNC) {
    rc = AioSubmit(cb, kAioFdsync, 0);
  } else if (op == O_SYNC) {
    rc = AioSubmit(cb, kAioFsync, 0);
  } else {
    rc = einval();
  }
  STRACE("aio_fsync(%#x, %p) → %d% m", op, cb, rc);
  return rc;
}

/**
 * Returns state of asynchronous request.
 *
 * @return `EINPROGRESS` while queued or running, 0 when it succeeded,
 *     or the errno it failed with (`ECANCELED` if canceled)
 */
int aio_error(const struct aiocb *cb) {
  return __atomic_load_n(&cb->__err, __ATOMIC_ACQUIRE);
}

/**
 * Returns result of finished asynchronous request.
 *
 * @return what the read, write or sync returned, or -1 w/ errno
 * @raise EINPROGRESS if it hasn't finished
 */
ssize_t aio_return(struct aiocb *cb) {
  int err = __atomic_load_n(&cb->__err, __ATOMIC_ACQUIRE);
  if (err == EINPROGRESS)
    return einprogress();
  if (cb->__ret == -1)
    errno = err;
  return cb->__ret;
}

/**
 * Cancels asynchronous requests that haven't started.
 *
 * @param cb is one request, or NULL for every request on `fd`
 * @return `AIO_CANCELED` if all were canceled, `AIO_NOTCANCELED` if one
 *     was already running, `AIO_ALLDONE` if none was pending, or -1
 *     w/ errno
 * @raise EBADF if `fd` isn't open
 * @raise EINVAL if `cb` is on another descriptor
 */
int aio_cancel(int fd, struct aiocb *cb) {
  int rc = AIO_ALLDONE;
  struct aiocb *c, *next, *canceled = 0;
  struct AioGroup *g, *groups = 0;
  if (fcntl(fd, F_GETFD) == -1)
    return -1;
  if (cb && cb->aio_fildes != fd)
    return einval();
  pthread_once(&g_once, AioInit);
  pthread_mutex_lock(&g_lock);
  for (c = g_head; c; c = next) {
    next = NEXT(c);
    if (cb ? c != cb : c->aio_fildes != fd)
      continue;
    if (c->__lock[0] == kAioRunning) {
      rc = AIO_NOTCANCELED;
      continue;
    }
    if ((g = AioFinish(c, -1, ECANCELED))) {
      g->next = groups;
      groups = g;
    }
    NEXT(c) = canceled;
    canceled = c;
    if (rc != AIO_NOTCANCELED)
      rc = AIO_CANCELED;
  }
  pthread_mutex_unlock(&g_lock);
  for (c = canceled; c; c = next) {
    next = NEXT(c);
    NEXT(c) = 0;
    AioNotify(&c->aio_sigevent);
  }
  while ((g = groups)) {
    groups = g->next;
    AioNotify(&g->sev);
    free(g);
  }
  STRACE("aio_cancel(%d, %p) → %d% m", fd, cb, rc);
  return rc;
}

/**
 * Waits until one of the requests finishes.
 *
 * @param list may hold NULLs, which are skipped
 * @param timeout is relative, or NULL to wait forever
 * @return 0 when one has finished, or -1 w/ errno
 * @raise EAGAIN if `timeout` passed first
 */
int aio_suspend(const struct aiocb *const list[], int n,
                const struct timespec *timeout) {
  int i, rc = 0;
  struct timespec deadline;
  if (n < 0)
    return einval();
  if (timeout) {
    if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 ||
        timeout->tv_nsec >= 1000000000)
      return einval();
    deadline = timespec_add(timespec_real(), *timeout);
  }
  pthread_once(&g_once, AioInit);
  pthread_mutex_lock(&g_lock);
  for (;;) {
    for (i = 0; i < n; ++i) {
      if (list[i] && __atomic_load_n(&list[i]->__err, __ATOMIC_ACQUIRE) !=
                         EINPROGRESS)
        goto Done;
    }
    if (timeout) {
      if (pthread_cond_timedwait(&g_done, &g_lock, &deadline) == ETIMEDOUT) {
        rc = eagain();
        break;
      }
    } else {
      pthread_cond_wait(&g_done, &g_lock);
    }
  }
Done:
  pthread_mutex_unlock(&g_lock);
  STRACE("aio_suspend(%p, %d, %s) → %d% m", list, n,
         DescribeTimespec(0, timeout), rc);
  return rc;
}

/**
 * Submits a list of requests.
 *
 * Each request's `aio_lio_opcode` is `LIO_READ`, `LIO_WRITE` or
 * `LIO_NOP`. With `LIO_WAIT` this returns once they've all finished;
 * with `LIO_NOWAIT` it returns at once and `sev` is notified when the
 * last one finishes.
 *
 * @return 0 on success, or -1 w/ errno
 * @raise EIO if a request couldn't be queued, or failed under `LIO_WAIT`
 */
int lio_listio(int mode, struct aiocb *const list[], int n,
               struct sigevent *sev) {
  int i, rc = 0, failed = 0, skipped = 0;
  struct AioGroup *g = 0;
  if ((mode != LIO_WAIT && mode != LIO_NOWAIT) || n < 0)
    return einval();
  if (mode == LIO_NOWAIT && sev && sev->sigev_notify != SIGEV_NONE) {
    if (AioCheckSigevent(sev) == -1)
      return -1;
    if (!(g = malloc(sizeof(*g))))
      return eagain();
    g->left = n;
    g->sev = *sev;
    g->next = 0;
  }
  for (i = 0; i < n; ++i) {
    struct aiocb *cb = list[i];
    if (!cb || cb->aio_lio_opcode == LIO_NOP) {
      ++skipped;
      continue;
    }
    int op = cb->aio_lio_opcode;
    if (op != LIO_READ && op != LIO_WRITE) {
      cb->__ret = -1;
      __atomic_store_n(&cb->__err, EINVAL, __ATOMIC_RELEASE);
      ++failed;
      ++skipped;
      continue;
    }
    if (AioSubmit(cb, op, g) == -1) {
      cb->__ret = -1;
      __atomic_store_n(&cb->__err, errno, __ATOMIC_RELEASE);
      ++failed;
      ++skipped;
    }
  }
  if (g && skipped) {
    pthread_mutex_lock(&g_lock);
    g->left -= skipped;
    bool last = !g->left;
    pthread_mutex_unlock(&g_lock);
    if (last) {
      AioNotify(&g->sev);
      free(g);
    }
  }
  if (mode == LIO_WAIT) {
    pthread_mutex_lock(&g_lock);
    for (;;) {
      for (i = 0; i < n; ++i) {
        if (list[i] && list[i]->aio_lio_opcode != LIO_NOP &&
            __atomic_load_n(&list[i]->__err, __ATOMIC_ACQUIRE) == EINPROGRESS)
          break;
      }
      if (i == n)
        break;
      pthread_cond_wait(&g_done, &g_lock);
    }
    pthread_mutex_unlock(&g_lock);
    for (i = 0; i < n; ++i) {
      if (list[i] && list[i]->aio_lio_opcode != LIO_NOP &&
          __atomic_load_n(&list[i]->__err, __ATOMIC_ACQUIRE))
        ++failed;
    }
  }
  if (failed)
    rc = eio();
  STRACE("lio_listio(%d, %p, %d, %p) → %d% m", mode, list, n, sev, rc);
  return rc;
}
