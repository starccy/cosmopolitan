#include "libc/dce.h"
#include "libc/intrin/fds.h"
#include "libc/nt/errors.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/nt/winsock.h"
#include "libc/sock/internal.h"
#include "libc/sock/syscall_fd.internal.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/thread/thread.h"
#if SupportsWindows()

// Socket options WinSock refused with WSAEINVAL because a nonblocking
// connect was still in flight (TCP_NODELAY, SO_KEEPALIVE and SO_REUSEADDR
// among them). Linux takes those and applies them once the connection is
// up, so they're kept here by handle and tried again on the way into the
// first send, or when connect() sees the handshake complete.

#define PARKED_MAX 32

struct ParkedSockopt {
  int64_t handle;
  int level;
  int optname;
  int optval;
};

__msabi extern typeof(__sys_setsockopt_nt) *const __imp_setsockopt;

static struct ParkedSockopt g_parked[PARKED_MAX] = {
    [0 ... PARKED_MAX - 1] = {.handle = -1}};
static int g_parked_count;
static pthread_mutex_t g_parked_lock = PTHREAD_MUTEX_INITIALIZER;

textwindows bool __sockopt_park(int64_t handle, int level, int optname,
                                int optval) {
  bool ok = false;
  int slot = -1;
  pthread_mutex_lock(&g_parked_lock);
  for (int i = 0; i < PARKED_MAX; ++i) {
    struct ParkedSockopt *p = g_parked + i;
    if (p->handle == handle && p->level == level && p->optname == optname) {
      slot = i;
      break;
    }
    if (slot == -1 && p->handle == -1)
      slot = i;
  }
  if (slot != -1) {
    if (g_parked[slot].handle == -1)
      ++g_parked_count;
    g_parked[slot] = (struct ParkedSockopt){handle, level, optname, optval};
    ok = true;
  }
  pthread_mutex_unlock(&g_parked_lock);
  return ok;
}

textwindows bool __sockopt_lookup(int64_t handle, int level, int optname,
                                  int *out) {
  bool found = false;
  if (!g_parked_count)
    return false;
  pthread_mutex_lock(&g_parked_lock);
  for (int i = 0; i < PARKED_MAX; ++i) {
    struct ParkedSockopt *p = g_parked + i;
    if (p->handle == handle && p->level == level && p->optname == optname) {
      *out = p->optval;
      found = true;
      break;
    }
  }
  pthread_mutex_unlock(&g_parked_lock);
  return found;
}

// an option WinSock still refuses stays parked, since the handshake is
// then still in flight
textwindows void __sockopt_replay(struct Fd *f) {
  if (!g_parked_count)
    return;
  pthread_mutex_lock(&g_parked_lock);
  for (int i = 0; i < PARKED_MAX; ++i) {
    struct ParkedSockopt *p = g_parked + i;
    if (p->handle != f->handle)
      continue;
    int hopt = __sockopt2host(p->level, p->optname);
    if (!hopt ||
        __imp_setsockopt(f->handle, __sol2host(p->level), hopt, &p->optval,
                         sizeof(p->optval)) != -1 ||
        WSAGetLastError() != WSAEINVAL) {
      p->handle = -1;
      --g_parked_count;
    }
  }
  pthread_mutex_unlock(&g_parked_lock);
}

textwindows void __sockopt_forget(int64_t handle) {
  if (!g_parked_count)
    return;
  pthread_mutex_lock(&g_parked_lock);
  for (int i = 0; i < PARKED_MAX; ++i) {
    if (g_parked[i].handle == handle) {
      g_parked[i].handle = -1;
      --g_parked_count;
    }
  }
  pthread_mutex_unlock(&g_parked_lock);
}

#endif /* __x86_64__ */
