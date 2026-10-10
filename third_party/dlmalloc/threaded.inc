// Cosmopolitan Threaded Memory Allocator
//
// This file provides functions named dlX_threaded() which implement the
// dlmalloc api for multithreaded environments. This implementation goes
// fast for a variety of use cases, and it's fully portable across OSes.
//
// We use two strategies for making multi-threaded malloc() go fast. Our
// first preference is to give each thread its own heap. The thread will
// store a pointer to its mspace in thread-local storage. We recycle the
// heaps we assign. This is very fast because it provides good assurance
// that the mutex on each heap will be uncontended. The only time a lock
// contention should happen, is if a thread shares its malloc'd pointer.
// The downside to assigning each thread its own mspace is if we want to
// have 10,000 threads, it becomes incredibly wasteful. So what we'll do
// is switch to sharding allocations over a fixed number of heaps, based
// on the cpu index, once we have a large number of simultaneous threads

#if !FOOTERS || !MSPACES
#error "threaded dlmalloc needs footers and mspaces"
#endif

static_assert(COSMO_SHARDS == 32);
static_assert(sizeof(unsigned) * 8 == 32);

// bss memory to initialize our heaps which avoids mmapping upon startup
// more critically having this be static ensures pick_heap() never fails
static union {
  alignas(16) char memory[16384];
  struct {
    char foot[16];
    struct malloc_state state;
  };
} g_heaps[COSMO_SHARDS];

static unsigned g_assigned;
static MLOCK_T g_gil;

// tls stores a function pointer to one of these which avoid mispredicts
static void *tmspace_get   (void) { return &g_heaps[cosmo_shard()].state; }
static void *tmspace_get_0 (void) { return &g_heaps[ 0].state; }
static void *tmspace_get_1 (void) { return &g_heaps[ 1].state; }
static void *tmspace_get_2 (void) { return &g_heaps[ 2].state; }
static void *tmspace_get_3 (void) { return &g_heaps[ 3].state; }
static void *tmspace_get_4 (void) { return &g_heaps[ 4].state; }
static void *tmspace_get_5 (void) { return &g_heaps[ 5].state; }
static void *tmspace_get_6 (void) { return &g_heaps[ 6].state; }
static void *tmspace_get_7 (void) { return &g_heaps[ 7].state; }
static void *tmspace_get_8 (void) { return &g_heaps[ 8].state; }
static void *tmspace_get_9 (void) { return &g_heaps[ 9].state; }
static void *tmspace_get_10(void) { return &g_heaps[10].state; }
static void *tmspace_get_11(void) { return &g_heaps[11].state; }
static void *tmspace_get_12(void) { return &g_heaps[12].state; }
static void *tmspace_get_13(void) { return &g_heaps[13].state; }
static void *tmspace_get_14(void) { return &g_heaps[14].state; }
static void *tmspace_get_15(void) { return &g_heaps[15].state; }
static void *tmspace_get_16(void) { return &g_heaps[16].state; }
static void *tmspace_get_17(void) { return &g_heaps[17].state; }
static void *tmspace_get_18(void) { return &g_heaps[18].state; }
static void *tmspace_get_19(void) { return &g_heaps[19].state; }
static void *tmspace_get_20(void) { return &g_heaps[20].state; }
static void *tmspace_get_21(void) { return &g_heaps[21].state; }
static void *tmspace_get_22(void) { return &g_heaps[22].state; }
static void *tmspace_get_23(void) { return &g_heaps[23].state; }
static void *tmspace_get_24(void) { return &g_heaps[24].state; }
static void *tmspace_get_25(void) { return &g_heaps[25].state; }
static void *tmspace_get_26(void) { return &g_heaps[26].state; }
static void *tmspace_get_27(void) { return &g_heaps[27].state; }
static void *tmspace_get_28(void) { return &g_heaps[28].state; }
static void *tmspace_get_29(void) { return &g_heaps[29].state; }
static void *tmspace_get_30(void) { return &g_heaps[30].state; }
static void *tmspace_get_31(void) { return &g_heaps[31].state; }

static const tmspace_get_f kTmspaceGetter[COSMO_SHARDS] = {
    tmspace_get_0,
    tmspace_get_1,
    tmspace_get_2,
    tmspace_get_3,
    tmspace_get_4,
    tmspace_get_5,
    tmspace_get_6,
    tmspace_get_7,
    tmspace_get_8,
    tmspace_get_9,
    tmspace_get_10,
    tmspace_get_11,
    tmspace_get_12,
    tmspace_get_13,
    tmspace_get_14,
    tmspace_get_15,
    tmspace_get_16,
    tmspace_get_17,
    tmspace_get_18,
    tmspace_get_19,
    tmspace_get_20,
    tmspace_get_21,
    tmspace_get_22,
    tmspace_get_23,
    tmspace_get_24,
    tmspace_get_25,
    tmspace_get_26,
    tmspace_get_27,
    tmspace_get_28,
    tmspace_get_29,
    tmspace_get_30,
    tmspace_get_31,
};

tmspace_get_f tmspace_acquire(void) {
  tmspace_get_f res = &tmspace_get;
  if (~g_assigned) {
    bool switch_to_cpu_shard = false;
    ACQUIRE_LOCK(&g_gil);
    if (~g_assigned) {
      unsigned index = bsf(~g_assigned);
      g_assigned |= 1u << index;
      if (!g_heaps[index].state.magic)
        create_mspace_with_base(&g_heaps[index], sizeof(g_heaps[index]), true);
      if (~g_assigned) {
        res = kTmspaceGetter[index];
      } else {
        switch_to_cpu_shard = true;
      }
    }
    RELEASE_LOCK(&g_gil);
    if (switch_to_cpu_shard) {
      // permanently transition malloc runtime to always use cpuid
      // sharding once the process reaches 32 simultaneous threads
      _pthread_lock();
      for (struct Dll *e = dll_first(_pthread_list); e; e = dll_next(_pthread_list, e))
        POSIXTHREAD_CONTAINER(e)->tib->tib_malloc = &tmspace_get;
      _pthread_unlock();
    }
  }
  return res;
}

// Thread Caches
//
// A thread with a heap of its own keeps chunks it frees in a cache that
// belongs to that heap, and hands them out again without taking the
// heap's lock. Small chunks are cached by exact size. Medium ones go by
// size class, eight per power of two: a request is rounded up to its
// class, and a freed chunk is filed under the largest class it holds, so
// anything a class hands out is big enough. A cached chunk stays in use
// as far as dlmalloc is concerned, and its footer still names the heap
// it came from, which is where it goes when the cache lets go of it.
//
// Only the thread owning a heap touches its cache. Once the process has
// so many threads that heaps are shared by cpu, caching stops, and what
// the old caches hold stays with them.

#define TCACHE_SMALL_MAX    1024
#define TCACHE_MEDIUM_MAX   65536
#define TCACHE_SMALL_BINS   (TCACHE_SMALL_MAX / MALLOC_ALIGNMENT + 1)
#define TCACHE_MEDIUM_BINS  49
#define TCACHE_SMALL_COUNT  16
#define TCACHE_MEDIUM_COUNT 8
#define TCACHE_MAX_BYTES    (512 * 1024)

struct TcacheEntry {
  struct TcacheEntry *next;
};

struct Tcache {
  size_t bytes;
  struct TcacheEntry *small[TCACHE_SMALL_BINS];
  struct TcacheEntry *medium[TCACHE_MEDIUM_BINS];
  unsigned char nsmall[TCACHE_SMALL_BINS];
  unsigned char nmedium[TCACHE_MEDIUM_BINS];
};

static struct Tcache g_tcache[COSMO_SHARDS];

static inline struct Tcache *tcache_of(mspace heap) {
  return g_tcache + ((char *)heap - (char *)&g_heaps[0].state) /
                        sizeof(g_heaps[0]);
}

// chunk size of medium class c
static inline size_t tcache_class_size(unsigned c) {
  return (size_t)(8 + (c & 7)) << ((c >> 3) + 7);
}

// smallest class holding a chunk of size s, for s > TCACHE_SMALL_MAX
static inline unsigned tcache_class_ceil(size_t s) {
  unsigned b = bsrl(s - 1);
  return ((b - 10) << 3) + ((s - 1) >> (b - 3)) + 1 - 8;
}

// largest class a chunk of size s holds, for s >= TCACHE_SMALL_MAX
static inline unsigned tcache_class_floor(size_t s) {
  unsigned b = bsrl(s);
  return ((b - 10) << 3) + (s >> (b - 3)) - 8;
}

static void tcache_flush(struct Tcache *tc) {
  struct TcacheEntry *e;
  for (unsigned i = 0; i < TCACHE_SMALL_BINS; ++i) {
    while ((e = tc->small[i])) {
      tc->small[i] = e->next;
      mspace_free(0, e);
    }
    tc->nsmall[i] = 0;
  }
  for (unsigned i = 0; i < TCACHE_MEDIUM_BINS; ++i) {
    while ((e = tc->medium[i])) {
      tc->medium[i] = e->next;
      mspace_free(0, e);
    }
    tc->nmedium[i] = 0;
  }
  tc->bytes = 0;
}

void tmspace_release(tmspace_get_f getter) {
  if (~g_assigned && getter != &tmspace_get) {
    tcache_flush(tcache_of(getter()));
    mspace_trim(getter(), 0);
    ACQUIRE_LOCK(&g_gil);
    if (~g_assigned)
      for (unsigned index = 0; index < COSMO_SHARDS; ++index)
        if (getter == kTmspaceGetter[index])
          g_assigned &= ~(1u << index);
    RELEASE_LOCK(&g_gil);
  }
}

static void dlfree_threaded(void *p) {
  tmspace_get_f getter = __get_tls()->tib_malloc;
  if (p && getter != &tmspace_get) {
    mchunkptr c = mem2chunk(p);
    size_t cs = chunksize(c);
    struct Tcache *tc = tcache_of(getter());
    struct TcacheEntry *e = p;
    // a medium chunk from another thread's heap goes straight back to
    // it. cached here it would count as in use over there for as long
    // as this thread lives. small ones are kept, that's what message
    // passing hands over
    if (!is_mmapped(c) &&
        (cs <= TCACHE_SMALL_MAX || get_mstate_for(c) == (mstate)getter()) &&
        tc->bytes + cs <= TCACHE_MAX_BYTES) {
      if (cs <= TCACHE_SMALL_MAX) {
        unsigned i = cs / MALLOC_ALIGNMENT;
        if (tc->nsmall[i] < TCACHE_SMALL_COUNT) {
          e->next = tc->small[i];
          tc->small[i] = e;
          ++tc->nsmall[i];
          tc->bytes += cs;
          return;
        }
      } else {
        unsigned i = tcache_class_floor(cs);
        if (i && i < TCACHE_MEDIUM_BINS &&
            tc->nmedium[i] < TCACHE_MEDIUM_COUNT) {
          e->next = tc->medium[i];
          tc->medium[i] = e;
          ++tc->nmedium[i];
          tc->bytes += cs;
          return;
        }
      }
    }
  }
  // we configured dlmalloc to store the mpsace pointer in the footer to
  // ensure we free on the old heap if the kernel reschedules our thread
  return mspace_free(0, p);
}

static size_t dlmalloc_usable_size_threaded(void *mem) {
  return mspace_usable_size(mem);
}

static void *dlrealloc_in_place_threaded(void *p, size_t n) {
  return mspace_realloc_in_place(0, p, n);
}

int dlmallopt(int param_number, int value) {
  return mspace_mallopt(param_number, value);
}

static int dlmalloc_trim_threaded(size_t pad) {
  int got_some = 0;
  tmspace_get_f getter = __get_tls()->tib_malloc;
  if (getter != &tmspace_get)
    tcache_flush(tcache_of(getter()));
  for (long i = 0; i < COSMO_SHARDS && g_heaps[i].state.magic; ++i)
    got_some |= mspace_trim(&g_heaps[i].state, pad);
  return got_some;
}

struct ThreadedMallocVisitor {
  mstate heap;
  void (*handler)(void *start, void *end,
                  size_t used_bytes, void *arg);
  void *arg;
};

static void threaded_malloc_visitor(void *start, void *end,
                                    size_t used_bytes, void *arg) {
  struct ThreadedMallocVisitor *tmv = arg;
  if (start == tmv->heap)
    return;
  tmv->handler(start, end, used_bytes, tmv->arg);
}

static void dlmalloc_inspect_all_threaded(void handler(void *start, void *end,
                                                       size_t used_bytes, void *arg),
                                          void *arg) {
  for (long i = 0; i < COSMO_SHARDS && g_heaps[i].state.magic; ++i) {
    struct ThreadedMallocVisitor tmv = {&g_heaps[i].state, handler, arg};
    mspace_inspect_all(&g_heaps[i].state, threaded_malloc_visitor, &tmv);
  }
}

static inline mspace pick_heap(void) {
  tmspace_get_f getter = __get_tls()->tib_malloc;
  return getter();
}

static void *dlmalloc_threaded(size_t n) {
  tmspace_get_f getter = __get_tls()->tib_malloc;
  mspace heap = getter();
  if (getter != &tmspace_get && n < MAX_REQUEST) {
    struct Tcache *tc = tcache_of(heap);
    struct TcacheEntry *e;
    size_t cs = request2size(n);
    if (cs <= TCACHE_SMALL_MAX) {
      unsigned i = cs / MALLOC_ALIGNMENT;
      if ((e = tc->small[i])) {
        tc->small[i] = e->next;
        --tc->nsmall[i];
        tc->bytes -= cs;
        return e;
      }
    } else if (cs <= TCACHE_MEDIUM_MAX) {
      unsigned i = tcache_class_ceil(cs);
      if ((e = tc->medium[i])) {
        tc->medium[i] = e->next;
        --tc->nmedium[i];
        tc->bytes -= chunksize(mem2chunk(e));
        return e;
      }
      n = tcache_class_size(i) - CHUNK_OVERHEAD;
    }
  }
  return mspace_malloc(heap, n);
}

static void *dlcalloc_threaded(size_t n, size_t z) {
  size_t m;
  if (!ckd_mul(&m, n, z) && m <= TCACHE_MEDIUM_MAX &&
      __get_tls()->tib_malloc != &tmspace_get) {
    void *p;
    if ((p = dlmalloc_threaded(m)))
      memset(p, 0, m);
    return p;
  }
  return mspace_calloc(pick_heap(), n, z);
}

static void *dlrealloc_threaded(void *p, size_t n) {
  if (p)
    return mspace_realloc(0, p, n);
  return dlmalloc_threaded(n);
}

static void *dlmemalign_threaded(size_t a, size_t n) {
  return mspace_memalign(pick_heap(), a, n);
}

static struct mallinfo dlmallinfo_threaded(void) {
  struct mallinfo res = {0};
  for (long i = 0; i < COSMO_SHARDS && g_heaps[i].state.magic; ++i) {
    struct mallinfo mi = mspace_mallinfo(&g_heaps[i].state);
    res.arena += mi.arena;
    res.ordblks += mi.ordblks;
    res.hblkhd += mi.hblkhd;
    res.usmblks += mi.usmblks;
    res.uordblks += mi.uordblks;
    res.fordblks += mi.fordblks;
    res.keepcost += mi.keepcost;
  }
  return res;
}

// b/c it's possible for malloc() to return memory inside .bss lool
bool __is_g_heaps(void *ptr) {
  char *p = ptr;
  char *a = (char *)g_heaps;
  char *b = (char *)g_heaps + sizeof(g_heaps);
  return a <= p && p < b;
}

dontinline static void use_threaded_allocator(void) {
  dlmalloc = dlmalloc_threaded;
  dlfree = dlfree_threaded;
  dlcalloc = dlcalloc_threaded;
  dlrealloc = dlrealloc_threaded;
  dlrealloc_in_place = dlrealloc_in_place_threaded;
  dlmemalign = dlmemalign_threaded;
  dlmalloc_usable_size = dlmalloc_usable_size_threaded;
  dlmalloc_inspect_all = dlmalloc_inspect_all_threaded;
  dlmallinfo = dlmallinfo_threaded;
  dlmalloc_trim = dlmalloc_trim_threaded;
}
