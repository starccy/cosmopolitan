#include "libc/atomic.h"
#include "libc/calls/calls.h"
#include "libc/calls/struct/sigaction.h"
#include "libc/calls/struct/siginfo.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/cosmo.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/atomic.h"
#include "libc/intrin/dll.h"
#include "libc/intrin/hostlibc.h"
#include "libc/intrin/kprintf.h"
#include "libc/limits.h"
#include "libc/mem/mem.h"
#include "libc/runtime/runtime.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/futex.h"
#include "libc/sysv/consts/sa.h"
#include "libc/sysv/consts/sig.h"
#include "libc/sysv/errfuns.h"
#include "libc/thread/posixthread.internal.h"
#include "libc/thread/thread.h"
#include "libc/thread/tls.h"

// Threads that are both a host libc thread and a cosmo thread.
//
// Once cosmo_dlopen() has the host glibc up, a thread runs with its tls
// register pointing at a glibc thread control block, and our tib lives
// in that block's unused slot at 0x38, which is where the getters in
// libc/sysv/tlsasm.S look. glibc and cosmo code can then call into each
// other on that thread freely.
//
// - The thread that loaded glibc keeps the block ld.so gave it.
// - Threads cosmo starts after that are started by glibc's
//   pthread_create(), on the stack cosmo allocated.
// - Threads that already existed borrow the block of a host thread that
//   does nothing but wait until the borrower exits. They switch over the
//   first time they call into the host, see __host_enter().
// - Threads the host starts get a tib the first time they run our code,
//   see libc/thread/adopt.c.

#define BUDDY_STARTING 0
#define BUDDY_PARKED   1
#define BUDDY_RELEASED 2

#define ARCH_SET_FS 0x1002

#define HOST_PTHREAD_CREATE_DETACHED 1
#define HOST_IOLBF                   1

struct Buddy {
  atomic_int state;
  void *tcb;
  struct CosmoTib *tib;
};

struct HostCloneArgs {
  int (*func)(void *);
  void *arg;
  void *tls;
  atomic_int *ptid;
  atomic_int *ctid;
};

#if defined(__x86_64__) || defined(__aarch64__)

#ifdef __x86_64__

dontinstrument static long host_syscall(long nr, long a, long b, long c,
                                        long d) {
  long ax;
  register long r10 asm("r10") = d;
  asm volatile("syscall"
               : "=a"(ax)
               : "0"(nr), "D"(a), "S"(b), "d"(c), "r"(r10)
               : "rcx", "r11", "memory");
  return ax;
}

#define NR_futex           202
#define NR_gettid          186
#define NR_arch_prctl      158
#define NR_set_tid_address 218

// our tib pointer lives at %fs:0x38 of a host thread block
#define SLOT 7

dontinstrument static void *host_tcb(void) {
  void *tcb;
  asm volatile("mov\t%%fs:0,%0" : "=r"(tcb));
  return tcb;
}

dontinstrument static void host_set_tp(void *p) {
  host_syscall(NR_arch_prctl, ARCH_SET_FS, (long)p, 0, 0);
}

#else

dontinstrument static long host_syscall(long nr, long a, long b, long c,
                                        long d) {
  register long x0 asm("x0") = a;
  register long x1 asm("x1") = b;
  register long x2 asm("x2") = c;
  register long x3 asm("x3") = d;
  register long x8 asm("x8") = nr;
  asm volatile("svc\t0"
               : "+r"(x0)
               : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
               : "memory");
  return x0;
}

#define NR_futex           98
#define NR_gettid          178
#define NR_set_tid_address 96

// our tib pointer lives in the second word of a host thread block,
// which glibc's aarch64 tcbhead_t leaves unused
#define SLOT 1

dontinstrument static void *host_tcb(void) {
  return __get_tls_raw();
}

dontinstrument static void host_set_tp(void *p) {
  asm volatile("msr\ttpidr_el0,%0" : /* no outputs */ : "r"(p) : "memory");
}

#endif

// the thread register of a cosmo thread points at its tib, at the
// place a host thread block keeps our tib pointer
dontinstrument static void *cosmo_tp(struct CosmoTib *tib) {
#ifdef __x86_64__
  return tib;
#else
  return tib + 1;
#endif
}

dontinstrument static struct CosmoTib *tib_of_tp(void *tp) {
#ifdef __x86_64__
  return tp;
#else
  return (struct CosmoTib *)tp - 1;
#endif
}

dontinstrument static bool host_is_dual(void) {
  void **tp = host_tcb();
  return tp != cosmo_tp(tp[SLOT]);
}

dontinstrument static void host_set_slot(void *tcb, void *tib) {
  ((void **)tcb)[SLOT] = tib;
}

dontinstrument static void host_futex_wait(atomic_int *w, int expect) {
  host_syscall(NR_futex, (long)w, FUTEX_WAIT_PRIVATE, expect, 0);
}

dontinstrument static void host_futex_wake(atomic_int *w) {
  host_syscall(NR_futex, (long)w, FUTEX_WAKE_PRIVATE, INT_MAX, 0);
}

// a host thread whose only job is to own a thread block we borrow
dontinstrument static void *buddy_main(void *arg) {
  struct Buddy *b = arg;
  int state = BUDDY_STARTING;
  b->tcb = host_tcb();
  host_set_slot(b->tcb, b->tib);
  // the owner may have exited and released us before we got here
  atomic_compare_exchange_strong_explicit(&b->state, &state, BUDDY_PARKED,
                                          memory_order_acq_rel,
                                          memory_order_acquire);
  host_futex_wake(&b->state);
  while (atomic_load_explicit(&b->state, memory_order_acquire) !=
         BUDDY_RELEASED)
    host_futex_wait(&b->state, BUDDY_PARKED);
  // glibc frees memory with our allocator as this thread exits, so
  // let it be adopted, which also takes care of `b`
  host_set_slot(b->tcb, 0);
  free(b);
  return 0;
}

// starts a buddy for `pt`, from a thread that is already dual
static int buddy_start(struct PosixThread *pt) {
  int rc;
  unsigned long th;
  struct Buddy *b;
  char attr[128] forcealign(16);
  if (!(b = calloc(1, sizeof(*b))))
    return ENOMEM;
  b->tib = pt->tib;
  __hostlibc.pthread_attr_init(attr);
  __hostlibc.pthread_attr_setstacksize(attr, 65536);
  __hostlibc.pthread_attr_setdetachstate(attr, HOST_PTHREAD_CREATE_DETACHED);
  // published before the thread starts, so an owner that exits
  // meanwhile releases it rather than leaving it parked forever
  pt->pt_buddy = b;
  rc = __hostlibc.pthread_create(&th, attr, buddy_main, b);
  __hostlibc.pthread_attr_destroy(attr);
  if (rc) {
    pt->pt_buddy = 0;
    free(b);
    return rc;
  }
  while (atomic_load_explicit(&b->state, memory_order_acquire) ==
         BUDDY_STARTING)
    host_futex_wait(&b->state, BUDDY_STARTING);
  return 0;
}

/**
 * Makes the calling thread a host thread too, if it isn't already.
 *
 * This is async signal safe, since the thread block it switches to was
 * prepared when the host libc was loaded.
 */
dontinstrument void __host_enter(void) {
  struct Buddy *b;
  struct PosixThread *pt;
  if (!__hostlibc.dual || host_is_dual())
    return;
  pt = _pthread_self();
  if (!(b = pt->pt_buddy)) {
    kprintf("error: cosmo thread %d has no host thread block\n",
            _pthread_tid(pt));
    __builtin_trap();
  }
  host_set_tp(b->tcb);
}

/**
 * Gives back the thread block a cosmo thread borrowed, as it exits.
 */
dontinstrument void __host_leave(struct PosixThread *pt) {
  struct Buddy *b;
  if (!(b = pt->pt_buddy))
    return;
  pt->pt_buddy = 0;
  if (host_tcb() == b->tcb)
    host_set_tp(cosmo_tp(pt->tib));
  atomic_store_explicit(&b->state, BUDDY_RELEASED, memory_order_release);
  host_futex_wake(&b->state);
}

// called on a thread cosmo asked glibc to start
dontinstrument static void *host_thread_main(void *p) {
  struct HostCloneArgs a = *(struct HostCloneArgs *)p;
  int tid = host_syscall(NR_gettid, 0, 0, 0, 0);
  host_set_slot(host_tcb(), tib_of_tp(a.tls));
  // the kernel clears tib_ctid when the thread is really gone, after
  // glibc has finished with the stack we lent it
  host_syscall(NR_set_tid_address, (long)a.ctid, 0, 0, 0);
  atomic_store_explicit(a.ctid, tid, memory_order_release);
  atomic_store_explicit(a.ptid, tid, memory_order_release);
  a.func(a.arg);
  return 0;
}

/**
 * Starts a cosmo thread through the host's pthread_create().
 *
 * This is what clone() does on Linux once the host libc is loaded. The
 * start arguments go at the bottom of the new thread's stack, glibc
 * puts its own thread block at the top.
 */
errno_t __host_clone(int (*func)(void *), char *stk, size_t stksz, void *arg,
                     void *tls, atomic_int *ptid, atomic_int *ctid) {
  int rc;
  unsigned long th;
  char attr[128] forcealign(16);
  struct HostCloneArgs *a = (struct HostCloneArgs *)stk;
  a->func = func;
  a->arg = arg;
  a->tls = tls;
  a->ptid = ptid;
  a->ctid = ctid;
  __host_enter();
  __hostlibc.pthread_attr_init(attr);
  __hostlibc.pthread_attr_setstack(attr, stk, stksz);
  __hostlibc.pthread_attr_setdetachstate(attr, HOST_PTHREAD_CREATE_DETACHED);
  rc = __hostlibc.pthread_create(&th, attr, host_thread_main, a);
  __hostlibc.pthread_attr_destroy(attr);
  return rc;
}

/**
 * Forks through the host's fork(), which also runs our fork handlers,
 * see libc/proc/fork.c.
 */
int __host_fork(void) {
  int rc;
  __host_enter();
  if ((rc = __hostlibc.fork()) == -1)
    errno = *__hostlibc.errno_location();
  return rc;
}

/**
 * Exits through the host's exit(), so its atexit handlers and library
 * destructors run after ours.
 */
wontreturn void __host_exit(int rc) {
  __host_enter();
  __hostlibc.exit(rc);
  __builtin_unreachable();
}

void __host_setenv_glibc(const char *name, const char *value) {
  __host_enter();
  if (value) {
    __hostlibc.setenv(name, value, 1);
  } else {
    __hostlibc.unsetenv(name);
  }
}

void __host_setlocale(int category, const char *locale) {
  __host_enter();
  __hostlibc.setlocale(category, locale);
}

// glibc's struct sigaction, which is the same on x86_64 and aarch64
struct HostSigaction {
  void *handler;
  uint64_t mask[16];
  int flags;
  void (*restorer)(void);
};

#define HOST_SA_RESTORER 0x04000000

static struct {
  void *handler;
  int flags;
} __host_sig[NSIG];

static void host_sig_trampoline(int sig, siginfo_t *si, void *uc) {
  void *h = __host_sig[sig - 1].handler;
  __host_enter();
  ((void (*)(int, siginfo_t *, void *))h)(sig, si, uc);
}

/**
 * sigaction() for host libraries, which the helper routes here so the
 * process keeps one signal table. The kernel's siginfo and ucontext
 * reach the library's handler unchanged, on a thread with its host
 * thread block in place.
 */
int __host_sigaction(int sig, const struct HostSigaction *act,
                     struct HostSigaction *old) {
  void *prevh;
  int prevf;
  struct sigaction sa, prev;
  if (sig < 1 || sig > NSIG) {
    *__hostlibc.errno_location() = EINVAL;
    return -1;
  }
  prevh = __host_sig[sig - 1].handler;
  prevf = __host_sig[sig - 1].flags;
  if (act) {
    bzero(&sa, sizeof(sa));
    sa.sa_mask = act->mask[0];
    sa.sa_flags = act->flags & ~HOST_SA_RESTORER;
    if (act->handler == SIG_DFL || act->handler == SIG_IGN) {
      sa.sa_handler = act->handler;
    } else {
      __host_sig[sig - 1].handler = act->handler;
      __host_sig[sig - 1].flags = act->flags & ~HOST_SA_RESTORER;
      sa.sa_sigaction = host_sig_trampoline;
      sa.sa_flags |= SA_SIGINFO;
    }
  }
  if (sigaction(sig, act ? &sa : 0, &prev) == -1) {
    __host_sig[sig - 1].handler = prevh;
    __host_sig[sig - 1].flags = prevf;
    *__hostlibc.errno_location() = errno;
    return -1;
  }
  if (old) {
    bzero(old, sizeof(*old));
    if (prev.sa_sigaction == host_sig_trampoline) {
      old->handler = prevh;
      old->flags = prevf;
    } else {
      old->handler = prev.sa_handler;
      old->flags = prev.sa_flags;
    }
    old->mask[0] = prev.sa_mask;
  }
  return 0;
}

/**
 * Makes the calling thread, which just loaded the host libc through
 * the helper, and every other cosmo thread, dual.
 */
int __host_threads_init(void) {
  struct Dll *e;
  struct CosmoTib *tib = __get_tls();
  struct PosixThread *me = (struct PosixThread *)tib->tib_pthread;

  // stay on the thread block ld.so gave us. registering our ctid with
  // the kernel again matters when this isn't the main thread, since
  // ld.so pointed it at glibc's tid field
  host_set_slot(__hostlibc.tcb, tib);
  host_set_tp(__hostlibc.tcb);
  host_syscall(NR_set_tid_address, (long)&tib->tib_ctid, 0, 0, 0);
  if (__tls_adopt_init())
    return -1;

  // make stdio of both libcs interleave by line
  __hostlibc.setvbuf(*__hostlibc.stdout_, 0, HOST_IOLBF, 0);

  if (__isthreaded < 2)
    __isthreaded = 2;
  int rc = 0;
  _pthread_lock();
  __hostlibc.dual = true;
  for (e = dll_first(_pthread_list); e; e = dll_next(_pthread_list, e)) {
    struct PosixThread *pt = POSIXTHREAD_CONTAINER(e);
    if (pt == me || (pt->pt_flags & (PT_ADOPTED | PT_EXITING)) ||
        pt->pt_buddy)
      continue;
    if (atomic_load_explicit(&pt->pt_status, memory_order_acquire) >=
        kPosixThreadTerminated)
      continue;
    if ((rc = buddy_start(pt))) {
      kprintf("error: couldn't start a host thread for cosmo thread %d: %s\n",
              _pthread_tid(pt), strerror(rc));
      break;
    }
  }
  if (rc)
    __hostlibc.dual = false;
  _pthread_unlock();
  return rc ? -1 : 0;
}

#else

// TODO(rust-ape): aarch64

void __host_enter(void) {
}

void __host_leave(struct PosixThread *pt) {
}

errno_t __host_clone(int (*func)(void *), char *stk, size_t stksz, void *arg,
                     void *tls, atomic_int *ptid, atomic_int *ctid) {
  return ENOSYS;
}

int __host_fork(void) {
  return enosys();
}

wontreturn void __host_exit(int rc) {
  _Exit(rc);
}

void __host_setenv_glibc(const char *name, const char *value) {
}

void __host_setlocale(int category, const char *locale) {
}

int __host_threads_init(void) {
  return -1;
}

#endif /* __x86_64__ || __aarch64__ */
