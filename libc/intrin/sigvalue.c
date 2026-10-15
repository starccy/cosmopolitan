#include "libc/atomic.h"
#include "libc/calls/sig.internal.h"
#include "libc/calls/struct/siginfo.h"
#include "libc/calls/struct/sigval.h"
#include "libc/sysv/consts/sicode.h"

// values that sigqueue() to the calling process carries on hosts whose
// kernel doesn't do that for us (windows signals are delivered by us,
// xnu has no sigqueue at all). A slot holds one queued value; delivery
// takes the oldest one for the signal and fills the siginfo with it.
// Both sides are lock free since the taker runs in signal context.

#define kSigValueSlots 32

enum { kSlotFree, kSlotFilling, kSlotReady, kSlotTaking };

struct SigValue {
  atomic_int state;
  unsigned seq;
  int sig;
  int code;
  int pid;
  int uid;
  union sigval val;
};

static struct SigValue g_slots[kSigValueSlots];
static atomic_uint g_seq;

bool __sig_queue_value(int sig, union sigval val, int code, int pid,
                       int uid) {
  for (int i = 0; i < kSigValueSlots; ++i) {
    struct SigValue *s = g_slots + i;
    int want = kSlotFree;
    if (!atomic_compare_exchange_strong_explicit(&s->state, &want,
                                                 kSlotFilling,
                                                 memory_order_acquire,
                                                 memory_order_relaxed))
      continue;
    s->seq = atomic_fetch_add_explicit(&g_seq, 1, memory_order_relaxed);
    s->sig = sig;
    s->code = code;
    s->pid = pid;
    s->uid = uid;
    s->val = val;
    atomic_store_explicit(&s->state, kSlotReady, memory_order_release);
    return true;
  }
  return false;
}

__privileged void __sig_take_value(int sig, siginfo_t *si) {
  for (;;) {
    struct SigValue *best = 0;
    for (int i = 0; i < kSigValueSlots; ++i) {
      struct SigValue *s = g_slots + i;
      if (atomic_load_explicit(&s->state, memory_order_acquire) ==
              kSlotReady &&
          s->sig == sig && (!best || (int)(s->seq - best->seq) < 0))
        best = s;
    }
    if (!best)
      return;
    int want = kSlotReady;
    if (!atomic_compare_exchange_strong_explicit(&best->state, &want,
                                                 kSlotTaking,
                                                 memory_order_acquire,
                                                 memory_order_relaxed))
      continue;
    si->si_code = best->code;
    si->si_pid = best->pid;
    si->si_uid = best->uid;
    si->si_value = best->val;
    atomic_store_explicit(&best->state, kSlotFree, memory_order_release);
    return;
  }
}
