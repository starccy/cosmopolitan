#include "libc/procfs/internal.h"

// The text buffer the generators emit into, and the listing the carrier
// collects directory entries in.

static void reserve(struct pfs_buf *b, size_t extra) {
  if (b->oom || b->n + extra <= b->cap)
    return;
  size_t cap = b->cap ? b->cap * 2 : 1024;
  while (cap < b->n + extra)
    cap *= 2;
  char *p = realloc(b->p, cap);
  if (!p) {
    b->oom = 1;
    return;
  }
  b->p = p;
  b->cap = cap;
}

void pfs_put(struct pfs_buf *b, const void *data, size_t n) {
  reserve(b, n);
  if (b->oom)
    return;
  memcpy(b->p + b->n, data, n);
  b->n += n;
}

void pfs_printf(struct pfs_buf *b, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  va_list ap2;
  va_copy(ap2, ap);
  int need = vsnprintf(0, 0, fmt, ap);
  va_end(ap);
  if (need > 0) {
    reserve(b, (size_t)need + 1);
    if (!b->oom) {
      vsnprintf(b->p + b->n, (size_t)need + 1, fmt, ap2);
      b->n += (size_t)need;
    }
  }
  va_end(ap2);
}

void pfs_buf_free(struct pfs_buf *b) {
  free(b->p);
  memset(b, 0, sizeof *b);
}

void pc_list_add(struct pc_list *l, const char *name, unsigned char type) {
  if (l->oom)
    return;
  if (l->n == l->cap) {
    int cap = l->cap ? l->cap * 2 : 64;
    struct pfs_virtent *p = realloc(l->p, (size_t)cap * sizeof *p);
    if (!p) {
      l->oom = true;
      return;
    }
    l->p = p;
    l->cap = cap;
  }
  struct pfs_virtent *e = &l->p[l->n++];
  snprintf(e->name, sizeof e->name, "%s", name);
  e->type = type;
}
