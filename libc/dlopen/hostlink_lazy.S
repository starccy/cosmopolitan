#include "libc/macros.h"

//  for the Rust side:
//	where a function stub made by `cargo xtask build` goes the first
//	time it's called. the stub points %r11 (x17 on arm64) at the
//	function's HostLinkSym. the arguments are kept for the function
//	and __hostlink_bind() says where it is

	.section .text.hostlink,"ax",@progbits
__hostlink_lazy:

#ifdef __x86_64__

	push	%rbp
	mov	%rsp,%rbp
	sub	$0xc0,%rsp
	movdqu	%xmm0,0x00(%rsp)
	movdqu	%xmm1,0x10(%rsp)
	movdqu	%xmm2,0x20(%rsp)
	movdqu	%xmm3,0x30(%rsp)
	movdqu	%xmm4,0x40(%rsp)
	movdqu	%xmm5,0x50(%rsp)
	movdqu	%xmm6,0x60(%rsp)
	movdqu	%xmm7,0x70(%rsp)
	mov	%rdi,0x80(%rsp)
	mov	%rsi,0x88(%rsp)
	mov	%rdx,0x90(%rsp)
	mov	%rcx,0x98(%rsp)
	mov	%r8,0xa0(%rsp)
	mov	%r9,0xa8(%rsp)
	mov	%rax,0xb0(%rsp)
	mov	%r10,0xb8(%rsp)
	mov	%r11,%rdi
	call	__hostlink_bind
	mov	%rax,%r11
	movdqu	0x00(%rsp),%xmm0
	movdqu	0x10(%rsp),%xmm1
	movdqu	0x20(%rsp),%xmm2
	movdqu	0x30(%rsp),%xmm3
	movdqu	0x40(%rsp),%xmm4
	movdqu	0x50(%rsp),%xmm5
	movdqu	0x60(%rsp),%xmm6
	movdqu	0x70(%rsp),%xmm7
	mov	0x80(%rsp),%rdi
	mov	0x88(%rsp),%rsi
	mov	0x90(%rsp),%rdx
	mov	0x98(%rsp),%rcx
	mov	0xa0(%rsp),%r8
	mov	0xa8(%rsp),%r9
	mov	0xb0(%rsp),%rax
	mov	0xb8(%rsp),%r10
	leave
	jmp	*%r11

#elif defined(__aarch64__)

	stp	x29,x30,[sp,#-0xe0]!
	mov	x29,sp
	stp	q0,q1,[sp,#0x10]
	stp	q2,q3,[sp,#0x30]
	stp	q4,q5,[sp,#0x50]
	stp	q6,q7,[sp,#0x70]
	stp	x0,x1,[sp,#0x90]
	stp	x2,x3,[sp,#0xa0]
	stp	x4,x5,[sp,#0xb0]
	stp	x6,x7,[sp,#0xc0]
	str	x8,[sp,#0xd0]
	mov	x0,x17
	bl	__hostlink_bind
	mov	x16,x0
	ldp	q0,q1,[sp,#0x10]
	ldp	q2,q3,[sp,#0x30]
	ldp	q4,q5,[sp,#0x50]
	ldp	q6,q7,[sp,#0x70]
	ldp	x0,x1,[sp,#0x90]
	ldp	x2,x3,[sp,#0xa0]
	ldp	x4,x5,[sp,#0xb0]
	ldp	x6,x7,[sp,#0xc0]
	ldr	x8,[sp,#0xd0]
	ldp	x29,x30,[sp],#0xe0
	br	x16

#endif

	.endfn	__hostlink_lazy,globl

#ifdef __x86_64__

//	a Windows DLL calling one of our functions back, through the thunk
//	__hostlink_callback() made, which put the signature in %r10 and the
//	function in %r11. microsoft's convention wants rsi, rdi and xmm6-15
//	kept, which ours doesn't

	.section .text.hostlink,"ax",@progbits
__hostlink_nt2sysv:
	.cfi_startproc
	push	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp,-16
	mov	%rsp,%rbp
	.cfi_def_cfa_register %rbp
	push	%rbx
	.cfi_offset %rbx,-24
	push	%rsi
	.cfi_offset %rsi,-32
	push	%rdi
	.cfi_offset %rdi,-40
	push	%r12
	.cfi_offset %r12,-48
	sub	$0xa0+0x1a0,%rsp
	movdqu	%xmm6,-0x30(%rbp)
	.cfi_offset %xmm6,-0x40
	movdqu	%xmm7,-0x40(%rbp)
	.cfi_offset %xmm7,-0x50
	movdqu	%xmm8,-0x50(%rbp)
	.cfi_offset %xmm8,-0x60
	movdqu	%xmm9,-0x60(%rbp)
	.cfi_offset %xmm9,-0x70
	movdqu	%xmm10,-0x70(%rbp)
	.cfi_offset %xmm10,-0x80
	movdqu	%xmm11,-0x80(%rbp)
	.cfi_offset %xmm11,-0x90
	movdqu	%xmm12,-0x90(%rbp)
	.cfi_offset %xmm12,-0xa0
	movdqu	%xmm13,-0xa0(%rbp)
	.cfi_offset %xmm13,-0xb0
	movdqu	%xmm14,-0xb0(%rbp)
	.cfi_offset %xmm14,-0xc0
	movdqu	%xmm15,-0xc0(%rbp)
	.cfi_offset %xmm15,-0xd0
	mov	%r11,%r12
	mov	%rsp,%rbx
//	all arguments to the home area and above it, xmm0-3 to the side
	mov	%rcx,16(%rbp)
	mov	%rdx,24(%rbp)
	mov	%r8,32(%rbp)
	mov	%r9,40(%rbp)
	movq	%xmm0,0x00(%rbx)
	movq	%xmm1,0x08(%rbx)
	movq	%xmm2,0x10(%rbx)
	movq	%xmm3,0x18(%rbx)
	lea	16(%rbp),%rdi
	mov	%r10,%rsi
	mov	%rbx,%rdx
	call	__hostlink_nt2sysv_layout
//	stack arguments
	mov	0x90(%rbx),%rcx
	lea	15(,%rcx,8),%rax
	and	$-16,%rax
	sub	%rax,%rsp
	xor	%edx,%edx
1:	cmp	%rcx,%rdx
	jae	2f
	mov	0xa0(%rbx,%rdx,8),%rax
	mov	%rax,(%rsp,%rdx,8)
	inc	%rdx
	jmp	1b
2:	movq	0x50(%rbx),%xmm0
	movq	0x58(%rbx),%xmm1
	movq	0x60(%rbx),%xmm2
	movq	0x68(%rbx),%xmm3
	movq	0x70(%rbx),%xmm4
	movq	0x78(%rbx),%xmm5
	movq	0x80(%rbx),%xmm6
	movq	0x88(%rbx),%xmm7
	mov	0x20(%rbx),%rdi
	mov	0x28(%rbx),%rsi
	mov	0x30(%rbx),%rdx
	mov	0x38(%rbx),%rcx
	mov	0x40(%rbx),%r8
	mov	0x48(%rbx),%r9
	mov	0x98(%rbx),%rax
	call	*%r12
	movdqu	-0x30(%rbp),%xmm6
	movdqu	-0x40(%rbp),%xmm7
	movdqu	-0x50(%rbp),%xmm8
	movdqu	-0x60(%rbp),%xmm9
	movdqu	-0x70(%rbp),%xmm10
	movdqu	-0x80(%rbp),%xmm11
	movdqu	-0x90(%rbp),%xmm12
	movdqu	-0xa0(%rbp),%xmm13
	movdqu	-0xb0(%rbp),%xmm14
	movdqu	-0xc0(%rbp),%xmm15
	lea	-0x20(%rbp),%rsp
	pop	%r12
	pop	%rdi
	pop	%rsi
	pop	%rbx
	pop	%rbp
	.cfi_def_cfa %rsp,8
	ret
	.cfi_endproc
	.endfn	__hostlink_nt2sysv,globl

#endif

//	calls function %rdi (x0) with the HostLinkRegs at %rsi (x1), and
//	returns the first integer register in %rax and the first floating
//	point one in %rdx (x0 and x1)

	.section .text.hostlink,"ax",@progbits
__hostlink_callregs:

#ifdef __x86_64__

	.cfi_startproc
	push	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp,-16
	mov	%rsp,%rbp
	.cfi_def_cfa_register %rbp
	push	%rbx
	.cfi_offset %rbx,-24
	push	%r12
	.cfi_offset %r12,-32
	mov	%rdi,%r12
	mov	%rsi,%rbx
	mov	0x80(%rbx),%rcx
	lea	15(,%rcx,8),%rax
	and	$-16,%rax
	sub	%rax,%rsp
	xor	%edx,%edx
1:	cmp	%rcx,%rdx
	jae	2f
	mov	0x90(%rbx,%rdx,8),%rax
	mov	%rax,(%rsp,%rdx,8)
	inc	%rdx
	jmp	1b
2:	movq	0x40(%rbx),%xmm0
	movq	0x48(%rbx),%xmm1
	movq	0x50(%rbx),%xmm2
	movq	0x58(%rbx),%xmm3
	movq	0x60(%rbx),%xmm4
	movq	0x68(%rbx),%xmm5
	movq	0x70(%rbx),%xmm6
	movq	0x78(%rbx),%xmm7
	mov	0x00(%rbx),%rdi
	mov	0x08(%rbx),%rsi
	mov	0x10(%rbx),%rdx
	mov	0x18(%rbx),%rcx
	mov	0x20(%rbx),%r8
	mov	0x28(%rbx),%r9
	mov	0x88(%rbx),%rax
	call	*%r12
	movq	%xmm0,%rdx
	lea	-16(%rbp),%rsp
	pop	%r12
	pop	%rbx
	pop	%rbp
	.cfi_def_cfa %rsp,8
	ret
	.cfi_endproc

#elif defined(__aarch64__)

	stp	x29,x30,[sp,#-32]!
	mov	x29,sp
	stp	x19,x20,[sp,#16]
	mov	x19,x0
	mov	x20,x1
	ldr	x9,[x20,#0x80]
	lsl	x10,x9,#3
	add	x10,x10,#15
	and	x10,x10,#-16
	sub	sp,sp,x10
	mov	x11,#0
1:	cmp	x11,x9
	b.hs	2f
	add	x12,x20,#0x90
	ldr	x13,[x12,x11,lsl #3]
	str	x13,[sp,x11,lsl #3]
	add	x11,x11,#1
	b	1b
2:	ldp	d0,d1,[x20,#0x40]
	ldp	d2,d3,[x20,#0x50]
	ldp	d4,d5,[x20,#0x60]
	ldp	d6,d7,[x20,#0x70]
	ldp	x0,x1,[x20,#0x00]
	ldp	x2,x3,[x20,#0x10]
	ldp	x4,x5,[x20,#0x20]
	ldp	x6,x7,[x20,#0x30]
	mov	x16,x19
	blr	x16
	fmov	x1,d0
	mov	sp,x29
	ldp	x19,x20,[sp,#16]
	ldp	x29,x30,[sp],#32
	ret

#endif

	.endfn	__hostlink_callregs,globl

#ifdef __x86_64__

//	the same with microsoft's convention: four register slots, xmm0-3
//	for the floating point ones, and 32 bytes of home space below the
//	stack arguments

__hostlink_callregs_nt:
	.cfi_startproc
	push	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp,-16
	mov	%rsp,%rbp
	.cfi_def_cfa_register %rbp
	push	%rbx
	.cfi_offset %rbx,-24
	push	%r12
	.cfi_offset %r12,-32
	push	%r13
	.cfi_offset %r13,-40
	push	%r14
	.cfi_offset %r14,-48
	mov	%rdi,%r12
	mov	%rsi,%rbx
//	the call is made from outside this program when it can be, see
//	cosmo_dlhostcall(): %r13 is where to enter the copy of hostcall.S
//	for this many stack arguments and %r14 the stub that makes its frame
	mov	0x80(%rbx),%rdi
	call	__hostcall_entry
	mov	%rax,%r13
	mov	%rdx,%r14
	mov	0x80(%rbx),%rcx
	lea	15+32(,%rcx,8),%rax
	and	$-16,%rax
	sub	%rax,%rsp
	xor	%edx,%edx
1:	cmp	%rcx,%rdx
	jae	2f
	mov	0x90(%rbx,%rdx,8),%rax
	mov	%rax,32(%rsp,%rdx,8)
	inc	%rdx
	jmp	1b
2:	movq	0x40(%rbx),%xmm0
	movq	0x48(%rbx),%xmm1
	movq	0x50(%rbx),%xmm2
	movq	0x58(%rbx),%xmm3
	mov	0x00(%rbx),%rcx
	mov	0x08(%rbx),%rdx
	mov	0x10(%rbx),%r8
	mov	0x18(%rbx),%r9
	test	%r14,%r14
	jz	3f
	mov	%r12,%r11
	mov	%r13,%r10
	call	*%r14
	jmp	4f
3:	call	*%r12
4:	movq	%xmm0,%rdx
	lea	-32(%rbp),%rsp
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbx
	pop	%rbp
	.cfi_def_cfa %rsp,8
	ret
	.cfi_endproc
	.endfn	__hostlink_callregs_nt,globl

//	one of our callers calling a host function through the thunk
//	__hostlink_thunk() made, which put the signature in %r10 and the
//	function in %r11. a caller anywhere else is host code, which calls
//	in microsoft's convention already, so it goes straight through

	.section .text.hostlink,"ax",@progbits
__hostlink_sysv2nt:
	.cfi_startproc
	push	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp,-16
	mov	%rsp,%rbp
	.cfi_def_cfa_register %rbp
	push	%rdx
	mov	8(%rbp),%rax
	lea	__hostlink_bounds(%rip),%rdx
	cmp	(%rdx),%rax
	jb	1f
	cmp	8(%rdx),%rax
	jb	2f
1:	pop	%rdx
	pop	%rbp
	.cfi_remember_state
	.cfi_def_cfa %rsp,8
	jmp	*%r11
	.cfi_restore_state
2:	pop	%rdx
	push	%rbx
	.cfi_offset %rbx,-24
	push	%r12
	.cfi_offset %r12,-32
	sub	$0x310,%rsp
	mov	%rsp,%rbx
	mov	%r10,0x300(%rbx)
	mov	%rdi,0x00(%rbx)
	mov	%rsi,0x08(%rbx)
	mov	%rdx,0x10(%rbx)
	mov	%rcx,0x18(%rbx)
	mov	%r8,0x20(%rbx)
	mov	%r9,0x28(%rbx)
	movq	%xmm0,0x30(%rbx)
	movq	%xmm1,0x38(%rbx)
	movq	%xmm2,0x40(%rbx)
	movq	%xmm3,0x48(%rbx)
	movq	%xmm4,0x50(%rbx)
	movq	%xmm5,0x58(%rbx)
	movq	%xmm6,0x60(%rbx)
	movq	%xmm7,0x68(%rbx)
	mov	%r11,%r12
//	__hostlink_sysv2nt_layout(gp, fp, stack, desc, regs)
	mov	%rbx,%rdi
	lea	0x30(%rbx),%rsi
	lea	16(%rbp),%rdx
	mov	%r10,%rcx
	lea	0x70(%rbx),%r8
	call	__hostlink_sysv2nt_layout
	mov	%r12,%rdi
	lea	0x70(%rbx),%rsi
	call	__hostlink_callregs_nt
	mov	%rax,%rdi
	mov	0x300(%rbx),%rsi
	mov	%rdx,%r12
	call	__hostlink_widen_ret
	movq	%r12,%xmm0
	lea	-16(%rbp),%rsp
	pop	%r12
	pop	%rbx
	pop	%rbp
	.cfi_def_cfa %rsp,8
	ret
	.cfi_endproc
	.endfn	__hostlink_sysv2nt,globl

#endif

//	the table cosmo_hostlink() looks through. each archive of stubs puts
//	a pointer to its HostLinkLib in .sort.rodata.hostlink.2

	.section .sort.rodata.hostlink.1,"a",@progbits
	.balign	8
__hostlink_libs:
	.previous
	.section .sort.rodata.hostlink.3,"a",@progbits
	.balign	8
__hostlink_libs_end:
	.previous
	.type	__hostlink_libs,@object
	.type	__hostlink_libs_end,@object
	.globl	__hostlink_libs
	.globl	__hostlink_libs_end
