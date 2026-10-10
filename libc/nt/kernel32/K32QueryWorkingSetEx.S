#include "libc/nt/codegen.h"
.imp	kernel32,__imp_K32QueryWorkingSetEx,K32QueryWorkingSetEx

	.text.windows
	.ftrace1
K32QueryWorkingSetEx:
	.ftrace2
#ifdef __x86_64__
	push	%rbp
	mov	%rsp,%rbp
	mov	__imp_K32QueryWorkingSetEx(%rip),%rax
	jmp	__sysv2nt
#elif defined(__aarch64__)
	mov	x0,#0
	ret
#endif
	.endfn	K32QueryWorkingSetEx,globl
	.previous
