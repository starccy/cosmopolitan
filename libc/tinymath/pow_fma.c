// pow() built with fma, picked at run time by pow() on x86 that has it
#ifdef __x86_64__
#define pow                  __pow_fma
#define TINYMATH_FMA_VARIANT 1
#include "libc/tinymath/pow.c"
#endif
