#include "libc/calls/struct/rseq.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/atomic.h"
#include "libc/intrin/cxaatexit.h"
#include "libc/intrin/dll.h"
#include "libc/intrin/hostlibc.h"
#include "libc/intrin/kprintf.h"
#include "libc/intrin/maps.h"
#include "libc/intrin/weaken.h"
#include "libc/macros.h"
#include "libc/mem/mem.h"
#include "libc/nt/enum/memflags.h"
#include "libc/nt/enum/pageflags.h"
#include "libc/nt/enum/processaccess.h"
#include "libc/nt/files.h"
#include "libc/nt/memory.h"
#include "libc/nt/runtime.h"
#include "libc/nt/thread.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/runtime/runtime.h"
#include "libc/runtime/syslib.internal.h"
#include "libc/str/locale.internal.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/map.h"
#include "libc/sysv/consts/prot.h"
#include "libc/sysv/consts/sig.h"
#include "libc/sysv/pib.h"
#include "libc/thread/posixthread.internal.h"
#include "libc/thread/thread.h"
#include "libc/thread/tls.h"
#include "third_party/dlmalloc/dlmalloc.h"
#include "third_party/nsync/wait_s.internal.h"

// A thread cosmo didn't create gets a tib the first time it runs code
// that needs one. The getters in libc/sysv/tlsasm.S call __tls_adopt()
// when the thread's tib slot is empty: %fs:0x38 in a host thread block
// on Linux, our tls slot in the TEB on Windows.
//
// One mapping holds the PosixThread, the tls image and the tib. Nothing
// here may touch tls before the slot is written, so the mapping comes
// straight from the kernel and the early system calls are raw.
//
// On Linux the thread gets cleaned up by the destructor of a host
// pthread key. glibc keeps running our free() for a while after its
// key destructors, so the mapping stays until tgkill() says the thread
// is gone. On Windows a fiber local storage callback cleans up.

static struct {
  atomic_uint lock;
  struct Dll *dying;
  struct Dll *spare;
  size_t size;
} __adopt;

#ifdef __x86_64__
#define NR_mmap   9
#define NR_munmap 11
#define NR_gettid 186
#define NR_tgkill 234
#define NR_write  1
#define NR_rseq   334
#define NR_rt_sigprocmask 14
#elif defined(__aarch64__)
#define NR_mmap   222
#define NR_munmap 215
#define NR_gettid 178
#define NR_tgkill 131
#define NR_rt_sigprocmask 135
#define NR_write  64
#define NR_rseq   293
#endif

dontinstrument static long linux_syscall(long nr, long a, long b, long c,
                                         long d, long e, long f) {
#ifdef __x86_64__
  long ax;
  register long r10 asm("r10") = d;
  register long r8 asm("r8") = e;
  register long r9 asm("r9") = f;
  asm volatile("syscall"
               : "=a"(ax)
               : "0"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
               : "rcx", "r11", "memory");
  return ax;
#elif defined(__aarch64__)
  register long x0 asm("x0") = a;
  register long x1 asm("x1") = b;
  register long x2 asm("x2") = c;
  register long x3 asm("x3") = d;
  register long x4 asm("x4") = e;
  register long x5 asm("x5") = f;
  register long x8 asm("x8") = nr;
  asm volatile("svc\t0"
               : "+r"(x0)
               : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
               : "memory");
  return x0;
#endif
}

dontinstrument static void adopt_lock(void) {
  while (atomic_exchange_explicit(&__adopt.lock, 1, memory_order_acquire))
    ;
}

dontinstrument static void adopt_unlock(void) {
  atomic_store_explicit(&__adopt.lock, 0, memory_order_release);
}

dontinstrument static size_t adopt_size(size_t *out_off) {
  size_t align, off, size;
  size = _mktls_size(&align);
  off = ROUNDUP(sizeof(struct PosixThread), MAX(align, 64));
  if (out_off)
    *out_off = off;
  return ROUNDUP(off + size, 65536);
}

dontinstrument static char *adopt_map(size_t size) {
  char *p;
  if (IsWindows()) {
    p = VirtualAlloc(0, size, kNtMemReserve | kNtMemCommit, kNtPageReadwrite);
  } else if (IsXnuSilicon()) {
    long rc = __syslib->__mmap(0, size, PROT_READ | PROT_WRITE,
                               __mmap2host(MAP_PRIVATE | MAP_ANONYMOUS), -1, 0);
    p = rc < 0 && rc > -4096 ? 0 : (char *)rc;
  } else {
    long rc = linux_syscall(NR_mmap, 0, size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    p = rc < 0 && rc > -4096 ? 0 : (char *)rc;
  }
  return p;
}

dontinstrument static void adopt_unmap(char *p, size_t size) {
  if (IsWindows()) {
    VirtualFree(p, 0, kNtMemRelease);
  } else if (IsXnuSilicon()) {
    __syslib->__munmap(p, size);
  } else {
    linux_syscall(NR_munmap, (long)p, size, 0, 0, 0, 0);
  }
}

// releases what the thread's tib picked up while it ran our code
static void adopt_release(struct PosixThread *pt) {
  struct CosmoTib *tib = pt->tib;
  if (tib->tib_nsync)
    nsync_waiter_destroy_(tib->tib_nsync);
  if (tib->tib_malloc)
    tmspace_release(tib->tib_malloc);
  free(tib->tib_keys_dynamic);
}

// frees adopted threads that the kernel says are gone. the mappings are
// kept for the next thread instead of being unmapped
static void adopt_reap(void) {
  struct Dll *e, *e2, *dead = 0;
  int pid = __get_pib()->pid;
  adopt_lock();
  for (e = dll_first(__adopt.dying); e; e = e2) {
    e2 = dll_next(__adopt.dying, e);
    struct PosixThread *pt = DLL_CONTAINER(struct PosixThread, pt_reap, e);
    int tid = atomic_load_explicit(&pt->tib->tib_ptid, memory_order_relaxed);
    if (linux_syscall(NR_tgkill, pid, tid, 0, 0, 0, 0) == -ESRCH) {
      dll_remove(&__adopt.dying, e);
      dll_make_first(&dead, e);
    }
  }
  adopt_unlock();
  while ((e = dll_first(dead))) {
    struct PosixThread *pt = DLL_CONTAINER(struct PosixThread, pt_reap, e);
    dll_remove(&dead, e);
    adopt_release(pt);
    adopt_lock();
    dll_make_first(&__adopt.spare, e);
    adopt_unlock();
  }
}

dontinstrument static char *adopt_alloc(void) {
  struct Dll *e;
  adopt_lock();
  if ((e = dll_first(__adopt.spare)))
    dll_remove(&__adopt.spare, e);
  adopt_unlock();
  if (e)
    return (char *)DLL_CONTAINER(struct PosixThread, pt_reap, e);
  return adopt_map(adopt_size(0));
}

// fills in everything cosmo wants to know about a thread except its
// stack, then publishes the tib in the thread's slot
dontinstrument static struct CosmoTib *adopt_setup(char *mem, int tid) {
  size_t off;
  struct CosmoTib *tib;
  struct PosixThread *pt = (struct PosixThread *)mem;
  // our locks are no-ops until the process has more than one thread
  if (__isthreaded < 2)
    __isthreaded = 2;
  adopt_size(&off);
  bzero(pt, sizeof(*pt));
  _mktls_at(mem + off, &tib);
  dll_init(&pt->list);
  dll_init(&pt->pt_reap);
  pt->pt_flags = PT_ADOPTED;
  pt->pt_locale = &__global_locale;
  pt->pt_tls = mem + off;
  pt->tib = tib;
  atomic_init(&pt->pt_status, kPosixThreadDetached);
  tib->tib_pthread = (intptr_t)pt;
  atomic_init(&tib->tib_ptid, tid);
  atomic_init(&tib->tib_ctid, tid);
  return tib;
}

dontinstrument static void adopt_publish(struct PosixThread *pt) {
  _pthread_lock();
  dll_make_first(&_pthread_list, &pt->list);
  _pthread_unlock();
}

// runs as a host pthread key destructor on the exiting thread
static void adopt_linux_exit(void *arg) {
  struct CosmoTib *tib = __get_tls();
  struct PosixThread *pt = (struct PosixThread *)tib->tib_pthread;
  if (!(pt->pt_flags & PT_ADOPTED))
    return;
  pt->pt_flags |= PT_EXITING | PT_NOCANCEL;
  __cxa_thread_finalize();
  _pthread_lock();
  dll_remove(&_pthread_list, &pt->list);
  _pthread_unlock();
  adopt_lock();
  dll_make_last(&__adopt.dying, &pt->pt_reap);
  adopt_unlock();
}

dontinstrument static struct CosmoTib *adopt_linux(void) {
  char *mem;
  struct CosmoTib *tib;
  struct PosixThread *pt;
  unsigned long all = -1, mask;
  if (!__hostlibc.dual)
    return 0;
  // a signal handler that touches tls before the slot is filled in
  // would adopt this thread a second time
  linux_syscall(NR_rt_sigprocmask, SIG_BLOCK, (long)&all, (long)&mask, 8, 0,
                0);
  if (!(mem = adopt_alloc())) {
    linux_syscall(NR_rt_sigprocmask, SIG_SETMASK, (long)&mask, 0, 8, 0, 0);
    return 0;
  }
  tib = adopt_setup(mem, linux_syscall(NR_gettid, 0, 0, 0, 0, 0, 0));
  pt = (struct PosixThread *)mem;
#ifdef __x86_64__
  asm volatile("mov\t%0,%%fs:0x38" : /* no outputs */ : "r"(tib) : "memory");
#else
  ((struct CosmoTib **)__get_tls_raw())[1] = tib;
#endif

  // malloc's small allocations go through rseq on linux whenever the
  // main thread could register it, so every thread must. a thread the
  // host's libc made has usually registered its own area already (glibc
  // since 2.35), which makes ours fail with EBUSY: the kernel then never
  // writes ours, its critical sections wouldn't restart, and the
  // freelists would be corrupted the first time two such threads met.
  // such a thread is marked and malloc keeps it off the rseq path
  if (linux_syscall(NR_rseq, (long)tib->tib_rseq, 32, 0, RSEQ_SIG, 0, 0)) {
    tib->tib_flags |= TIB_FLAG_NORSEQ;
    ((struct rseq *)tib->tib_rseq)->cpu_id = RSEQ_CPU_ID_UNINITIALIZED;
  }

  // tls works from here on, and malloc once it has a heap
  tib->tib_malloc = tmspace_acquire();
  linux_syscall(NR_rt_sigprocmask, SIG_SETMASK, (long)&mask, 0, 8, 0, 0);
  unsigned long self = __hostlibc.pthread_self();
  // the glibc 2.2.5 version of pthread_getattr_np() leaves the
  // attribute's extension pointer alone, which destroy() frees
  char attr[128] forcealign(16) = {0};
  if (!__hostlibc.pthread_getattr_np(self, attr)) {
    void *addr;
    size_t size;
    if (!__hostlibc.pthread_attr_getstack(attr, &addr, &size)) {
      pt->pt_attr.__stackaddr = addr;
      pt->pt_attr.__stacksize = size;
    }
    __hostlibc.pthread_attr_destroy(attr);
  }
  __hostlibc.pthread_setspecific(__hostlibc.key, tib);
  adopt_publish(pt);
  adopt_reap();
  return tib;
}

#ifdef __aarch64__

/**
 * Cleans up after an adopted thread as libSystem runs its pthread key
 * destructors, see libc/runtime/set_tls.c
 */
void __tls_adopt_xnu_exit(void *arg) {
  struct CosmoTib *tib = arg;
  struct PosixThread *pt = (struct PosixThread *)tib->tib_pthread;
  if (!(pt->pt_flags & PT_ADOPTED))
    return;
  // libSystem cleared our slot before calling us
  __tls_set_xnu(tib);
  pt->pt_flags |= PT_EXITING | PT_NOCANCEL;
  __cxa_thread_finalize();
  _pthread_lock();
  dll_remove(&_pthread_list, &pt->list);
  _pthread_unlock();
  adopt_release(pt);
  __tls_set_xnu(0);
  adopt_unmap((char *)pt, adopt_size(0));
}

dontinstrument static struct CosmoTib *adopt_xnu(void) {
  char *mem;
  struct CosmoTib *tib;
  struct PosixThread *pt;
  static atomic_uint tids;
  if (!(mem = adopt_map(adopt_size(0))))
    return 0;
  // cosmo numbers its threads on this host, see CloneSilicon()
  tib = adopt_setup(mem, 0x7fff0000 - atomic_fetch_add(&tids, 1) % 0x10000);
  pt = (struct PosixThread *)mem;
  atomic_init(&tib->tib_syshand, __syslib->__pthread_self());
  __tls_set_xnu(tib);
  tib->tib_malloc = tmspace_acquire();
  adopt_publish(pt);
  return tib;
}

#endif /* __aarch64__ */

#ifdef __x86_64__

static uint32_t __adopt_fls = -1u;

// runs on the exiting thread, as a fiber local storage callback
__msabi static void adopt_nt_exit(void *arg) {
  struct CosmoTib *tib = __get_tls_win32();
  if (!tib || tib != arg)
    return;
  struct PosixThread *pt = (struct PosixThread *)tib->tib_pthread;
  if (!(pt->pt_flags & PT_ADOPTED))
    return;
  pt->pt_flags |= PT_EXITING | PT_NOCANCEL;
  __cxa_thread_finalize();
  _pthread_lock();
  dll_remove(&_pthread_list, &pt->list);
  _pthread_unlock();
  uint64_t h = atomic_load_explicit(&tib->tib_syshand, memory_order_relaxed);
  if (h)
    CloseHandle(h);
  adopt_release(pt);
  __maps_lock();
  __maps_untrack((char *)pt, adopt_size(0));
  __maps_unlock();
  __set_tls_win32(0);
  adopt_unmap((char *)pt, adopt_size(0));
}

dontinstrument static struct CosmoTib *adopt_nt(void) {
  char *mem;
  intptr_t h;
  struct CosmoTib *tib;
  struct PosixThread *pt;
  if (!(mem = adopt_map(adopt_size(0))))
    return 0;
  tib = adopt_setup(mem, GetCurrentThreadId());
  pt = (struct PosixThread *)mem;
  // cosmo delivers signals to a thread by rewriting its context, which
  // a thread the host owns can't be subjected to, so they all stay
  // blocked here and raise() on this thread runs the handler in place
  atomic_init(&tib->tib_sigmask, -1);
  if (DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                      GetCurrentProcess(), &h, 0, false,
                      kNtDuplicateSameAccess))
    atomic_init(&tib->tib_syshand, h);
  char *base, *lo;
  asm("mov\t%%gs:0x08,%0" : "=r"(base));
  asm("mov\t%%gs:0x1478,%0" : "=r"(lo));
  pt->pt_attr.__stackaddr = lo;
  pt->pt_attr.__stacksize = base - lo;
  __set_tls_win32(tib);

  // tls works from here on, and malloc once it has a heap
  tib->tib_malloc = tmspace_acquire();
  // fork() copies only the memory cosmo knows of, and a child still has
  // this thread in its list of threads to free
  __maps_lock();
  __maps_track(mem, adopt_size(0), PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS);
  __maps_unlock();
  uint32_t fls = atomic_load_explicit(&__adopt_fls, memory_order_acquire);
  if (fls == -1u) {
    uint32_t mine = FlsAlloc(adopt_nt_exit);
    if (atomic_compare_exchange_strong_explicit(&__adopt_fls, &fls, mine,
                                                memory_order_acq_rel,
                                                memory_order_acquire)) {
      fls = mine;
    } else {
      FlsFree(mine);
    }
  }
  if (fls != -1u)
    FlsSetValue(fls, tib);
  adopt_publish(pt);
  return tib;
}

#endif /* __x86_64__ */

/**
 * Gives the calling thread a tib, if it's a host thread that has none.
 *
 * This is called by the tls getters, never directly. It returns null
 * if the thread can't be adopted on this host.
 */
dontinstrument struct CosmoTib *__tls_adopt(void) {
  struct CosmoTib *tib = 0;
  if (IsLinux()) {
    tib = adopt_linux();
#ifdef __x86_64__
  } else if (IsWindows()) {
    tib = adopt_nt();
#elif defined(__aarch64__)
  } else if (IsXnuSilicon()) {
    tib = adopt_xnu();
#endif
  }
  if (!tib) {
    static const char msg[] = "error: a thread cosmo didn't create ran code "
                              "that needs its tls, and it can't be adopted\n";
    if (!IsLinux()) {
      __builtin_trap();
    } else {
      linux_syscall(NR_write, 2, (long)msg, sizeof(msg) - 1, 0,
                    0, 0);
      __builtin_trap();
    }
  }
  return tib;
}

/**
 * Frees an adopted thread whose host thread is known to be gone.
 */
void __tls_adopt_free(struct PosixThread *pt) {
  adopt_release(pt);
  adopt_lock();
  dll_make_first(&__adopt.spare, &pt->pt_reap);
  adopt_unlock();
}

/**
 * Ends the calling adopted thread the way its host would, which runs
 * the host's cleanup and, through it, ours. Called by pthread_exit().
 */
wontreturn void __tls_adopt_exit(void *rc) {
  if (IsLinux() && __hostlibc.pthread_exit) {
    __hostlibc.pthread_exit(rc);
#ifdef __x86_64__
  } else if (IsWindows()) {
    ExitThread(0);
#elif defined(__aarch64__)
  } else if (IsXnuSilicon()) {
    __syslib->__pthread_exit(rc);
#endif
  }
  __builtin_trap();
}

// fork() takes the adoption lock along with the others, so a child
// never inherits it held by a thread that isn't there
void __tls_adopt_onfork_prepare(void) {
  // a host thread calling the host's fork() may not be adopted yet, and
  // adopting it takes this lock, so that happens first
  __asm__ volatile("" : : "r"(__get_tls()) : "memory");
  adopt_lock();
}

void __tls_adopt_onfork_parent(void) {
  adopt_unlock();
}

void __tls_adopt_onfork_child(void) {
  struct Dll *e;
  atomic_store_explicit(&__adopt.lock, 0, memory_order_relaxed);
  // nsync_waiter_wipe_() already took back every waiter, including
  // those of threads that are waiting to be reaped
  for (e = dll_first(__adopt.dying); e; e = dll_next(__adopt.dying, e))
    DLL_CONTAINER(struct PosixThread, pt_reap, e)->tib->tib_nsync = 0;
}

/**
 * Registers the host pthread key whose destructor cleans up after an
 * adopted thread. Called by cosmo_dlopen() once the host libc is up.
 */
int __tls_adopt_init(void) {
  return __hostlibc.pthread_key_create(&__hostlibc.key, adopt_linux_exit);
}
