#include "libc/procfs/internal.h"

// The lock every generation runs under, and the per-process cache that
// lets one OpenProcess pass serve every file of a process for a throttle
// window, however many readers ask.

pthread_mutex_t pc_lock = PTHREAD_MUTEX_INITIALIZER;

// Set by the thread that holds pc_lock while it generates, so the host
// calls a generator makes are never mistaken for a look at the tree. Per
// thread, since another reader arriving meanwhile must wait for the lock
// and then be answered.
_Thread_local int pc_busy;

void pc_enter(void) {
  pthread_mutex_lock(&pc_lock);
  pc_busy = 1;
}

void pc_leave(void) {
  pc_busy = 0;
  pthread_mutex_unlock(&pc_lock);
}

// One slot per recently seen process. Slots are found by hashed probing
// (NT pids are multiples of 4, so masking their low bits would use a
// quarter of any table) and carry the last generation of the volatile
// files and the process's start time, which tells a recycled pid from the
// process it used to be.
struct pidslot {
  uint32_t pid;
  int64_t ms;  // when vol[] was generated (also the liveness check)
  uint64_t start;
  struct pfs_buf vol[4];    // the last generation of the volatile four
  struct pfs_buf fixed[3];  // cmdline, comm, environ: fixed per incarnation
};
#define NSLOTS 2048

static void slot_reset(struct pidslot *s) {
  for (int i = 0; i < 4; i++)
    pfs_buf_free(&s->vol[i]);
  for (int i = 0; i < 3; i++)
    pfs_buf_free(&s->fixed[i]);
  memset(s, 0, sizeof *s);
}

static struct pidslot *slot_of(uint32_t pid) {
  static struct pidslot slots[NSLOTS];
  uint32_t h = (pid * 2654435761u) >> 16;
  struct pidslot *oldest = 0;
  for (int i = 0; i < 8; i++) {
    struct pidslot *s = &slots[(h + i) & (NSLOTS - 1)];
    if (s->pid == pid)
      return s;
    if (!oldest || s->ms < oldest->ms)
      oldest = s;
  }
  slot_reset(oldest);
  oldest->pid = pid;
  return oldest;
}

static int name_index(const char *const *names, const char *name) {
  for (int i = 0; names[i]; i++)
    if (!strcmp(names[i], name))
      return i;
  return -1;
}

// The slot of a process with its volatile generation no older than
// PID_DIR_MS; 0 for a process that is not there.
static struct pidslot *pid_refresh(uint32_t pid, int64_t t) {
  struct pidslot *s = slot_of(pid);
  if (s->ms && t - s->ms < PID_DIR_MS)
    return s->start ? s : 0;  // start 0: known absent
  for (int i = 0; i < 4; i++) {
    pfs_buf_free(&s->vol[i]);
    memset(&s->vol[i], 0, sizeof s->vol[i]);
  }
  uint64_t start = 0;
  bool alive = pfs_gen_pid_volatile(pid, s->vol, &start);
  s->ms = t;
  if (!alive) {
    s->start = 0;
    return 0;
  }
  if (start != s->start) {  // a recycled pid is a new process
    s->start = start;
    for (int i = 0; i < 3; i++) {
      pfs_buf_free(&s->fixed[i]);
      memset(&s->fixed[i], 0, sizeof s->fixed[i]);
    }
  }
  return s;
}

// The slot generation a volatile pid file's content belongs to: the ms
// stamp of its slot. 0 for anything not served from a slot. Under pc_lock.
int64_t pc_content_gen(const char *vpath) {
  if (strncmp(vpath, "/proc/", 6))
    return 0;
  struct node n;
  pc_parse(vpath + 6, &n);
  if (n.kind != K_PID_SUB)
    return 0;
  const char *file = 0;
  if (!n.rest[0]) {
    file = n.name;
  } else if (!strcmp(n.name, "task")) {
    const char *f = strchr(n.rest, '/');
    if (f && !strchr(f + 1, '/'))
      file = f + 1;
  }
  if (!file || name_index(pfs_pid_volatile, file) < 0)
    return 0;
  struct pidslot *s = slot_of(n.pid);
  if (s->pid != n.pid || !s->start)
    return 0;
  // a slot past its window is due for a refresh, so its content is not
  // the current answer even though nobody has regenerated it yet
  if (pfs_now_ms() - s->ms >= PID_DIR_MS)
    return 0;
  return s->ms;
}

// Content of one /proc/<pid> file, from the slot's cached generation for
// the volatile four, generated on the spot for the rest. False: absent.
// Under pc_lock.
bool pc_pid_content(uint32_t pid, const char *name, struct pfs_buf *out) {
  int vi = name_index(pfs_pid_volatile, name);
  if (vi >= 0) {
    struct pidslot *s = pid_refresh(pid, pfs_now_ms());
    if (!s || s->vol[vi].oom)
      return false;
    pfs_put(out, s->vol[vi].p, s->vol[vi].n);
    return true;
  }
  int si = name_index(pfs_pid_stable, name);
  if (si < 0)
    return false;
  // cmdline, comm, and another process's environ: one host query per
  // incarnation (our own environ changes under setenv, so stays live)
  if (si < 2 || (si == 2 && pid != pfs_self_pid())) {
    struct pidslot *s = pid_refresh(pid, pfs_now_ms());
    if (!s)
      return false;
    struct pfs_buf *c = &s->fixed[si];
    if (!c->p && !c->oom && !pfs_gen_pid_file(c, pid, name))
      return false;
    if (c->oom)
      return false;
    pfs_put(out, c->p, c->n);
    return true;
  }
  if (!pfs_proc_find(pid))
    return false;
  return pfs_gen_pid_file(out, pid, name);
}

// The content of a parsed path, when it is a content file. Under pc_lock.
// A thread's task/<tid>/<file> gets the process-wide answer, since NT
// keeps the per-thread facts Linux would split out behind the same
// handles anyway.
bool pc_gen_node(const struct node *n, struct pfs_buf *b) {
  switch (n->kind) {
    case K_TOP:
      return pfs_gen_top_file(b, n->name);
    case K_NET_FILE:
      return pfs_gen_net_file(b, n->name);
    case K_SYS:
      return pfs_gen_sys_file(b, n->rest);
    case K_PID_SUB:
      if (!n->rest[0])
        return pc_pid_content(n->pid, n->name, b);
      if (!strcmp(n->name, "task")) {
        const char *file = strchr(n->rest, '/');
        if (file && !strchr(file + 1, '/'))
          return pc_pid_content(n->pid, file + 1, b);
      } else if (!strcmp(n->name, "net")) {
        if (!strchr(n->rest, '/') && pfs_proc_find(n->pid))
          return pfs_gen_net_file(b, n->rest);
      }
      return false;
    default:
      return false;
  }
}

// Generates the content of a virtual path into b; false when the path is
// not a content file. Takes pc_lock itself.
bool pc_gen_vpath(const char *vpath, struct pfs_buf *b) {
  bool ok;
  pc_enter();
  if (pc_is_sys(vpath)) {
    ok = pc_sysfs_gen(vpath, b);
  } else {
    struct node n;
    pc_parse(vpath + 5, &n);
    ok = pc_gen_node(&n, b);
  }
  pc_leave();
  if (!ok || b->oom) {
    pfs_buf_free(b);
    return false;
  }
  return true;
}
