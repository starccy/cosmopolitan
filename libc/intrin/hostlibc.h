#ifndef COSMOPOLITAN_LIBC_INTRIN_HOSTLIBC_H_
#define COSMOPOLITAN_LIBC_INTRIN_HOSTLIBC_H_
COSMOPOLITAN_C_START_

#define HOSTLIBC_NONE  0
#define HOSTLIBC_GLIBC 1
#define HOSTLIBC_OTHER 2

// host libc functions handed back by the cosmo_dlopen helper on linux
// and the bsds. everything in here must be called on a thread whose tls
// register points at a host thread block, see __host_enter()
struct HostLibc {
  int kind;
  bool dual;    // host threads carry our tib at tcb+0x38
  bool loaded;  // cosmo_dlopen() loaded something, on any host
  bool envsync;  // the host environment follows ours, see hostenv.c
  unsigned key;
  void *tcb;  // thread block the helper ran on
  int (*pthread_create)(unsigned long *, const void *, void *(*)(void *),
                        void *);
  int (*pthread_attr_init)(void *);
  int (*pthread_attr_setstack)(void *, void *, size_t);
  int (*pthread_attr_setstacksize)(void *, size_t);
  int (*pthread_attr_setdetachstate)(void *, int);
  int (*pthread_attr_destroy)(void *);
  int (*pthread_key_create)(unsigned *, void (*)(void *));
  int (*pthread_setspecific)(unsigned, const void *);
  int (*pthread_getattr_np)(unsigned long, void *);
  int (*pthread_attr_getstack)(const void *, void **, size_t *);
  unsigned long (*pthread_self)(void);
  int (*pthread_atfork)(void (*)(void), void (*)(void), void (*)(void));
  int *(*errno_location)(void);
  int (*fork)(void);
  void (*exit)(int);
  void (*pthread_exit)(void *);
  int (*setenv)(const char *, const char *, int);
  int (*unsetenv)(const char *);
  char *(*setlocale)(int, const char *);
  void (*tzset)(void);
  int (*fflush)(void *);
  int (*setvbuf)(void *, char *, int, size_t);
  void **stdout_;
};

extern struct HostLibc __hostlibc;

void __host_enter(void) libcesque;
int __host_fork(void) libcesque;
wontreturn void __host_exit(int) libcesque;
void __host_setenv(const char *, const char *) libcesque;
void __host_setenv_glibc(const char *, const char *) libcesque;
void __host_env_init(void) libcesque;
void __host_std_closing(int) libcesque;
void __host_std_opened(int) libcesque;
void __host_env_pull(void) libcesque;
void *__host_env_sym(void *) libcesque;
void __host_setlocale(int, const char *) libcesque;
errno_t __host_clone(int (*)(void *), char *, size_t, void *, void *,
                     _Atomic(int) *, _Atomic(int) *) libcesque;
void __fork_prepare_host(void) libcesque;
void __fork_parent_host(void) libcesque;
void __fork_child_host(void) libcesque;

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_INTRIN_HOSTLIBC_H_ */
