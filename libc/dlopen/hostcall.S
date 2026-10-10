#include "libc/macros.h"

//	a call into a host function made from outside this program, for
//	callers that use the host's convention themselves. the stub that
//	jumps here (see cosmo_dlhostcall) pushed %rbp and made it the
//	frame, so the caller's home space is at 16(%rbp) and its stack
//	arguments start at 48(%rbp). %r11 is the function. entered at the
//	label for the number of stack slots to copy, an even one, at most
//	16. dlopen.c copies this whole thing out of the program; nothing
//	in it may be relative to where it was linked

#ifdef __x86_64__

	.section .text.hostlink,"ax",@progbits
	.balign	16
__hostcall_nt16:
	pushq	168(%rbp)
	pushq	160(%rbp)
__hostcall_nt14:
	pushq	152(%rbp)
	pushq	144(%rbp)
__hostcall_nt12:
	pushq	136(%rbp)
	pushq	128(%rbp)
__hostcall_nt10:
	pushq	120(%rbp)
	pushq	112(%rbp)
__hostcall_nt8:
	pushq	104(%rbp)
	pushq	96(%rbp)
__hostcall_nt6:
	pushq	88(%rbp)
	pushq	80(%rbp)
__hostcall_nt4:
	pushq	72(%rbp)
	pushq	64(%rbp)
__hostcall_nt2:
	pushq	56(%rbp)
	pushq	48(%rbp)
__hostcall_nt0:
	sub	$32,%rsp
	call	*%r11
	leave
	ret
__hostcall_nt_end:

//	what __hostlink_callregs_nt calls, which lays the arguments out
//	itself, to make the frame the code above wants. %r10 is where to
//	enter it
__hostcall_frame:
	push	%rbp
	mov	%rsp,%rbp
	jmp	*%r10
__hostcall_frame_end:

	.globl	__hostcall_nt16,__hostcall_nt14,__hostcall_nt12,__hostcall_nt10
	.globl	__hostcall_nt8,__hostcall_nt6,__hostcall_nt4,__hostcall_nt2
	.globl	__hostcall_nt0,__hostcall_nt_end
	.hidden	__hostcall_nt16,__hostcall_nt14,__hostcall_nt12,__hostcall_nt10
	.hidden	__hostcall_nt8,__hostcall_nt6,__hostcall_nt4,__hostcall_nt2
	.hidden	__hostcall_nt0,__hostcall_nt_end
	.globl	__hostcall_frame,__hostcall_frame_end
	.hidden	__hostcall_frame,__hostcall_frame_end
	.type	__hostcall_nt16,@function
	.size	__hostcall_nt16,__hostcall_nt_end-__hostcall_nt16

#endif
