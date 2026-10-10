#ifndef COSMOPOLITAN_LIBC_DLOPEN_HOSTFILE_INTERNAL_H_
#define COSMOPOLITAN_LIBC_DLOPEN_HOSTFILE_INTERNAL_H_
COSMOPOLITAN_C_START_

// a function every host module's imports of `name` get pointed at
struct HostNtHook {
  const char *name;   // as kernel32 and kernelbase export it
  void *hook;         // ours, taking microsoft's convention
  void *real;         // the host's, where the hook passes the call on
  void *targets[2];   // the host's, as kernelbase and kernel32 export it
};

extern struct HostNtHook __host_nt_file_hooks[];

void __host_file_init(void);
void __host_crt_patch(char *);
void __host_crt_patch_all(void);
void __host_crt_exit(void);
int __host_crt_errno(int);
bool __host_crt_hook(const void *);
bool __host_env_hook(const void *);
int __host_crt_errno_of(int);

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_DLOPEN_HOSTFILE_INTERNAL_H_ */
