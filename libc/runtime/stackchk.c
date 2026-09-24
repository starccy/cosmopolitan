#include "libc/intrin/kprintf.h"
#include "libc/runtime/runtime.h"
#include "libc/stdio/rand.h"

// Code built with -fstack-protector needs libc to define these symbols.
// cosmocc's compilers use the global guard, since the TLS slot GCC would
// otherwise pick, %fs:0x28, is tib_pthread here. The low byte is zero so
// a string overflow can't run past the canary.

uintptr_t __stack_chk_guard = 0xa9ea9ea9ea9ea900;

__attribute__((__constructor__(101))) static void __stack_chk_init(void) {
  __stack_chk_guard = _rand64() & ~0xfful;
}

__attribute__((__weak__)) wontreturn void __stack_chk_fail(void) {
  kprintf("error: stack smashing detected\n");
  __builtin_trap();
}
