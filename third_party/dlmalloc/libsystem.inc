// On Apple Silicon a program that loads host libraries uses libSystem's
// allocator rather than ours, so there's one heap and memory can change
// hands both ways, the way it can between libraries of a native program.
// See libc/dlopen/dlopen.c.

static struct {
  void *(*malloc)(size_t);
  void (*free)(void *);
  void *(*calloc)(size_t, size_t);
  void *(*realloc)(void *, size_t);
  int (*posix_memalign)(void **, size_t, size_t);
  size_t (*malloc_size)(const void *);
} g_sys;

static void *nomem(void *p) {
  if (!p)
    errno = ENOMEM;
  return p;
}

static void *dlmalloc_system(size_t n) {
  return nomem(g_sys.malloc(n));
}

static void dlfree_system(void *p) {
  g_sys.free(p);
}

static void *dlcalloc_system(size_t n, size_t z) {
  return nomem(g_sys.calloc(n, z));
}

static void *dlrealloc_system(void *p, size_t n) {
  return nomem(g_sys.realloc(p, n));
}

static void *dlrealloc_in_place_system(void *p, size_t n) {
  return p && g_sys.malloc_size(p) >= n ? p : 0;
}

static void *dlmemalign_system(size_t a, size_t n) {
  void *p;
  if (a < sizeof(void *))
    a = sizeof(void *);
  if (g_sys.posix_memalign(&p, a, n))
    return nomem(0);
  return p;
}

static size_t dlmalloc_usable_size_system(void *p) {
  return p ? g_sys.malloc_size(p) : 0;
}

static void dlmalloc_inspect_all_system(void handler(void *, void *, size_t,
                                                     void *),
                                        void *arg) {
}

static struct mallinfo dlmallinfo_system(void) {
  struct mallinfo mi = {0};
  return mi;
}

static int dlmalloc_trim_system(size_t pad) {
  return 0;
}

static void use_system_allocator(void) {
#define GET(name) (g_sys.name = __syslib->__dlsym((void *)-2, #name))
  if (!GET(malloc) || !GET(free) || !GET(calloc) || !GET(realloc) ||
      !GET(posix_memalign) || !GET(malloc_size))
    return;
#undef GET
  // our syscalls check pointers against the memory we mapped, and now
  // libSystem maps the heap, see libc/intrin/kisdangerous.c
  __hostlibc.loaded = true;
  dlmalloc = dlmalloc_system;
  dlfree = dlfree_system;
  dlcalloc = dlcalloc_system;
  dlrealloc = dlrealloc_system;
  dlrealloc_in_place = dlrealloc_in_place_system;
  dlmemalign = dlmemalign_system;
  dlmalloc_usable_size = dlmalloc_usable_size_system;
  dlmalloc_inspect_all = dlmalloc_inspect_all_system;
  dlmallinfo = dlmallinfo_system;
  dlmalloc_trim = dlmalloc_trim_system;
}
