#ifndef COSMOPOLITAN_LIBC_DLFCN_H_
#define COSMOPOLITAN_LIBC_DLFCN_H_

#define RTLD_LOCAL    0
#define RTLD_LAZY     1
#define RTLD_NOW      2
#define RTLD_NOLOAD   4
#define RTLD_DEEPBIND 8
#define RTLD_GLOBAL   256
#define RTLD_NODELETE 4096

COSMOPOLITAN_C_START_

#define RTLD_NEXT    ((void *)-1)
#define RTLD_DEFAULT ((void *)0)

typedef struct {
  const char *dli_fname;
  void *dli_fbase;
  const char *dli_sname;
  void *dli_saddr;
} Dl_info;

int dladdr(const void *, Dl_info *) libcesque;
int dlinfo(void *, int, void *) libcesque;

char *dlerror(void) libcesque;
void *dlopen(const char *, int) libcesque;
void *dlsym(void *, const char *) libcesque;
int dlclose(void *) libcesque;

char *cosmo_dlerror(void) libcesque;
void *cosmo_dlopen(const char *, int) libcesque;
void *cosmo_dlsym(void *, const char *) libcesque;
void *cosmo_dltramp(void *) libcesque;
void *cosmo_dlhostcall(void *, int) libcesque;
void *cosmo_dlthunk(void *) libcesque;
void *cosmo_dluntramp(void *) libcesque;
void *cosmo_dldual(void *) libcesque;
int cosmo_dlhost(const void *) libcesque;
int cosmo_dlclose(void *) libcesque;
int *cosmo_dlerrno(void) libcesque;
int cosmo_dlgeterrno(void) libcesque;
void cosmo_dlseterrno(int) libcesque;
void cosmo_envsync(void) libcesque;
char *cosmo_hostpath(const char *, char *, size_t) libcesque;
int cosmo_dlhostfile(const void *) libcesque;
void *cosmo_dladddir(const char *) libcesque;
int cosmo_dlremovedir(void *) libcesque;
size_t cosmo_dlfwrite(const void *, size_t, size_t, void *) libcesque;

#define COSMO_DLEXPORT_FUNC   0  /* a function of this program */
#define COSMO_DLEXPORT_DATA   1  /* a variable, `size` bytes of it */
#define COSMO_DLEXPORT_VARARG 2  /* a variadic function, `va` takes over */
#define COSMO_DLEXPORT_NATIVE 4  /* `addr` already speaks the host's
                                    convention, and is what Windows and
                                    macOS get. `va` is the same function
                                    in ours, which Linux gets. for a
                                    signature the converter can't handle */
#define COSMO_DLEXPORT_COSMO  3  /* a function in this program's own
                                    convention, converted on Windows.
                                    integer and pointer parameters only,
                                    at most six; give a wrapper of your
                                    own as COSMO_DLEXPORT_FUNC when a
                                    parameter is a float or a struct */

struct CosmoDlexport {
  const char *name;
  void *addr;
  size_t size;  /* DATA: bytes. VARARG: how many parameters are fixed */
  int kind;     /* COSMO_DLEXPORT_* */
  void *va;     /* VARARG: the same function taking a va_list */
};

void *cosmo_dlexport(const char *, const struct CosmoDlexport *,
                     size_t) libcesque;
intptr_t cosmo_dlhandle(int) libcesque;
int cosmo_dlfd(intptr_t, int) libcesque;
void *cosmo_hostlink(const char *) libcesque;

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_DLFCN_H_ */
