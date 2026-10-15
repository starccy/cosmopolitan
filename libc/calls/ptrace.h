#ifndef COSMOPOLITAN_LIBC_CALLS_PTRACE_H_
#define COSMOPOLITAN_LIBC_CALLS_PTRACE_H_
COSMOPOLITAN_C_START_

#define PTRACE_TRACEME                         0
#define PTRACE_PEEKTEXT                        1
#define PTRACE_PEEKDATA                        2
#define PTRACE_PEEKUSER                        3
#define PTRACE_POKETEXT                        4
#define PTRACE_POKEDATA                        5
#define PTRACE_POKEUSER                        6
#define PTRACE_CONT                            7
#define PTRACE_KILL                            8
#define PTRACE_SINGLESTEP                      9
#define PTRACE_GETREGS                         12
#define PTRACE_SETREGS                         13
#define PTRACE_GETFPREGS                       14
#define PTRACE_SETFPREGS                       15
#define PTRACE_ATTACH                          16
#define PTRACE_DETACH                          17
#define PTRACE_GETFPXREGS                      18
#define PTRACE_SETFPXREGS                      19
#define PTRACE_SYSCALL                         24
#define PTRACE_GET_THREAD_AREA                 25
#define PTRACE_SET_THREAD_AREA                 26
#define PTRACE_ARCH_PRCTL                      30
#define PTRACE_SYSEMU                          31
#define PTRACE_SYSEMU_SINGLESTEP               32
#define PTRACE_SINGLEBLOCK                     33
#define PTRACE_SETOPTIONS                      0x4200
#define PTRACE_GETEVENTMSG                     0x4201
#define PTRACE_GETSIGINFO                      0x4202
#define PTRACE_SETSIGINFO                      0x4203
#define PTRACE_GETREGSET                       0x4204
#define PTRACE_SETREGSET                       0x4205
#define PTRACE_SEIZE                           0x4206
#define PTRACE_INTERRUPT                       0x4207
#define PTRACE_LISTEN                          0x4208
#define PTRACE_PEEKSIGINFO                     0x4209
#define PTRACE_GETSIGMASK                      0x420a
#define PTRACE_SETSIGMASK                      0x420b
#define PTRACE_SECCOMP_GET_FILTER              0x420c
#define PTRACE_SECCOMP_GET_METADATA            0x420d
#define PTRACE_GET_SYSCALL_INFO                0x420e
#define PTRACE_GET_RSEQ_CONFIGURATION          0x420f
#define PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG 0x4210
#define PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG 0x4211

#define PTRACE_O_TRACESYSGOOD    0x00000001
#define PTRACE_O_TRACEFORK       0x00000002
#define PTRACE_O_TRACEVFORK      0x00000004
#define PTRACE_O_TRACECLONE      0x00000008
#define PTRACE_O_TRACEEXEC       0x00000010
#define PTRACE_O_TRACEVFORKDONE  0x00000020
#define PTRACE_O_TRACEEXIT       0x00000040
#define PTRACE_O_TRACESECCOMP    0x00000080
#define PTRACE_O_EXITKILL        0x00100000
#define PTRACE_O_SUSPEND_SECCOMP 0x00200000
#define PTRACE_O_MASK            0x003000ff

#define PTRACE_EVENT_FORK       1
#define PTRACE_EVENT_VFORK      2
#define PTRACE_EVENT_CLONE      3
#define PTRACE_EVENT_EXEC       4
#define PTRACE_EVENT_VFORK_DONE 5
#define PTRACE_EVENT_EXIT       6
#define PTRACE_EVENT_SECCOMP    7
#define PTRACE_EVENT_STOP       128

#define PTRACE_PEEKSIGINFO_SHARED 1

#define PTRACE_SYSCALL_INFO_NONE    0
#define PTRACE_SYSCALL_INFO_ENTRY   1
#define PTRACE_SYSCALL_INFO_EXIT    2
#define PTRACE_SYSCALL_INFO_SECCOMP 3

struct ptrace_peeksiginfo_args {
  uint64_t off;
  uint32_t flags;
  int32_t nr;
};

struct ptrace_syscall_info {
  uint8_t op;
  uint8_t pad[3];
  uint32_t arch;
  uint64_t instruction_pointer;
  uint64_t stack_pointer;
  union {
    struct {
      uint64_t nr;
      uint64_t args[6];
    } entry;
    struct {
      int64_t rval;
      uint8_t is_error;
    } exit;
    struct {
      uint64_t nr;
      uint64_t args[6];
      uint32_t ret_data;
    } seccomp;
  };
};

long ptrace(int, ...);

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_CALLS_PTRACE_H_ */
