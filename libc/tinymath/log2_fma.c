// log2() built with fma, picked at run time by log2() on x86 that has it
#ifdef __x86_64__
#define log2                  __log2_fma
#define TINYMATH_FMA_VARIANT 1
#include "libc/tinymath/log2.c"
#endif
