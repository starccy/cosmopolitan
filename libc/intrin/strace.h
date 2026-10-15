#ifndef COSMOPOLITAN_LIBC_CALLS_STRACE_INTERNAL_H_
#define COSMOPOLITAN_LIBC_CALLS_STRACE_INTERNAL_H_

#ifndef SYSDEBUG
#define SYSDEBUG 0
#endif

#ifdef MODE_DBG
#define _STRACE_VERBOSE 1
#else
#define _STRACE_VERBOSE 0
#endif

#define _NTTRACE    _STRACE_VERBOSE /* not configurable w/ flag yet */
#define _KERNTRACE  _STRACE_VERBOSE /* not configurable w/ flag yet */
#define _POLLTRACE  _STRACE_VERBOSE /* not configurable w/ flag yet */
#define _LOCKTRACE  _STRACE_VERBOSE /* not configurable w/ flag yet */
#define _DATATRACE  1               /* not configurable w/ flag yet */
#define _STDIOTRACE 0               /* not configurable w/ flag yet */
#define _TIMETRACE  0               /* not configurable w/ flag yet */

#define STRACE_PROLOGUE "%rSYS %7P %7H %'18T "

#if !(__ASSEMBLER__ + __LINKER__ + 0)
COSMOPOLITAN_C_START_

// the process-wide flag is checked first: it's set whenever any thread
// turns tracing on, so a zero spares the thread block lookup
extern int __strace;

#define STRACE(FMT, ...)                       \
  ((void)(SYSDEBUG && __strace > 0 && strace_enabled(0) > 0 && \
          (__stracef(STRACE_PROLOGUE FMT "\n", ##__VA_ARGS__), 0)))

#define DATATRACE(FMT, ...)                                  \
  ((void)(SYSDEBUG && _DATATRACE && __strace > 0 && strace_enabled(0) > 0 && \
          (__stracef(STRACE_PROLOGUE FMT "\n", ##__VA_ARGS__), 0)))

#define POLLTRACE(FMT, ...)                                  \
  ((void)(SYSDEBUG && _POLLTRACE && __strace > 0 && strace_enabled(0) > 0 && \
          (__stracef(STRACE_PROLOGUE FMT "\n", ##__VA_ARGS__), 0)))

#define KERNTRACE(FMT, ...)                                                 \
  ((void)(SYSDEBUG && _KERNTRACE && __strace > 0 && strace_enabled(0) > 0 &&                \
          (__stracef(STRACE_PROLOGUE "\e[2m" FMT "\e[0m\n", ##__VA_ARGS__), \
           0)))

#define STDIOTRACE(FMT, ...)                                  \
  ((void)(SYSDEBUG && _STDIOTRACE && __strace > 0 && strace_enabled(0) > 0 && \
          (__stracef(STRACE_PROLOGUE FMT "\n", ##__VA_ARGS__), 0)))

#define NTTRACE(FMT, ...)                                                   \
  ((void)(SYSDEBUG && _NTTRACE && __strace > 0 && strace_enabled(0) > 0 &&                  \
          (__stracef(STRACE_PROLOGUE "\e[2m" FMT "\e[0m\n", ##__VA_ARGS__), \
           0)))

#define LOCKTRACE(FMT, ...)                                  \
  ((void)(SYSDEBUG && _LOCKTRACE && __strace > 0 && strace_enabled(0) > 0 && \
          (__stracef(STRACE_PROLOGUE FMT "\n", ##__VA_ARGS__), 0)))

#define TIMETRACE(FMT, ...)                                  \
  ((void)(SYSDEBUG && _TIMETRACE && __strace > 0 && strace_enabled(0) > 0 && \
          (__stracef(STRACE_PROLOGUE FMT "\n", ##__VA_ARGS__), 0)))

int strace_enabled(int);
void __stracef(const char *, ...);

COSMOPOLITAN_C_END_
#endif /* !(__ASSEMBLER__ + __LINKER__ + 0) */
#endif /* COSMOPOLITAN_LIBC_CALLS_STRACE_INTERNAL_H_ */
