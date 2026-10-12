// log() built with fma, picked at run time by log() on x86 that has it
#ifdef __x86_64__
#define log                  __log_fma
#define TINYMATH_FMA_VARIANT 1
#include "libc/tinymath/log.c"
#endif
