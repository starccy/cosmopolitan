#include "libc/macros.h"

//	code that libc/dlopen makes at runtime is copied from here, into
//	executable memory of its own or into the host libraries that
//	cosmo_dlexport() builds. nothing here runs in place. each template
//	ends in eight byte slots that a copy gets its values written into,
//	and reads them relative to its own position. templates.internal.h
//	has the C side, and the comment above each template names its
//	slots in order

	.section .rodata.dltemplates,"a",@progbits

//	pads to the slots of the template starting at `start`. arm64 reads
//	them with ldr literal, so they're eight byte aligned in a copy too,
//	which the copy's place and the template's start both are. x86 reads
//	them as they fall
	.macro	slots start
#ifdef __aarch64__
	.if	(-(.-\start))&7
	.skip	(-(.-\start))&7
	.endif
#endif
	.endm

#ifdef __x86_64__

//	the conversion from microsoft's convention to ours around a call
//	to the function in slot `func`. microsoft passes the first four
//	integer arguments in rcx, rdx, r8 and r9 and the next two above its
//	shadow space, and wants rsi, rdi and xmm6 through xmm15 back
//	unchanged, which we don't promise. the arguments past the sixth are
//	copied down to where we want them, sixteen of them since the count
//	isn't known. MS2SYSV_FRAME in templates.internal.h describes it
	MS2SYSV_COPY = 16
	MS2SYSV_ARGS = MS2SYSV_COPY * 8
	MS2SYSV_FRAME = MS2SYSV_ARGS + 160
	.macro	ms2sysv func
	push	%rbp
	mov	%rsp,%rbp
	push	%rsi
	push	%rdi
	sub	$MS2SYSV_FRAME,%rsp
	i = 0
	.rept	MS2SYSV_COPY
	mov	64+i*8(%rbp),%rax
	mov	%rax,i*8(%rsp)
	i = i + 1
	.endr
	.irp	r,6,7,8,9,10,11,12,13,14,15
	movaps	%xmm\r,MS2SYSV_ARGS+(\r-6)*16(%rsp)
	.endr
	mov	%rcx,%rdi
	mov	%rdx,%rsi
	mov	%r8,%rdx
	mov	%r9,%rcx
	mov	48(%rbp),%r8
	mov	56(%rbp),%r9
	call	*\func(%rip)
	.irp	r,6,7,8,9,10,11,12,13,14,15
	movaps	MS2SYSV_ARGS+(\r-6)*16(%rsp),%xmm\r
	.endr
	add	$MS2SYSV_FRAME,%rsp
	pop	%rdi
	pop	%rsi
	leave
	ret
	.endm

//	jumps to the target. slots: target
	.balign	8
__tmpl_jump:
	jmp	*1f(%rip)
	slots	__tmpl_jump
1:	.quad	0
__tmpl_jump_end:

//	a function of ours for a microsoft caller. slots: func
	.balign	8
__tmpl_ms2sysv:
	ms2sysv	1f
	slots	__tmpl_ms2sysv
1:	.quad	0
__tmpl_ms2sysv_end:

//	a host function for callers in our convention, see foreign_tramp.S,
//	which takes the function in %r11. %rax is left alone since it holds
//	%al for a variadic callee. slots: func, foreign_tramp
	.balign	8
__tmpl_sysv_thunk:
	mov	1f(%rip),%r11
	mov	2f(%rip),%r10
	jmp	*%r10
	slots	__tmpl_sysv_thunk
1:	.quad	0
2:	.quad	0
__tmpl_sysv_thunk_end:

//	a host function on windows. a caller inside this program uses our
//	convention and goes through the sysv2nt copy, which takes the
//	function in %rax and wants a frame made. a caller anywhere else is
//	host code, which got the thunk handed back to it as a callback, so
//	it goes straight to the function. slots: __executable_start, _end,
//	func, sysv2nt
	.balign	8
__tmpl_nt_thunk:
	mov	(%rsp),%r10
	cmp	.Lnt_lo(%rip),%r10
	jb	1f
	cmp	.Lnt_hi(%rip),%r10
	jae	1f
	push	%rbp
	mov	%rsp,%rbp
	mov	.Lnt_func(%rip),%rax
	mov	.Lnt_sysv2nt(%rip),%r10
	jmp	*%r10
1:	mov	.Lnt_func(%rip),%rax
	jmp	*%rax
	slots	__tmpl_nt_thunk
.Lnt_lo:
	.quad	0
.Lnt_hi:
	.quad	0
.Lnt_func:
	.quad	0
.Lnt_sysv2nt:
	.quad	0
__tmpl_nt_thunk_end:

//	a function of ours that host code may call too. a caller inside
//	this program goes straight to it, any other gets the conversion.
//	slots: __executable_start, _end, func
	.balign	8
__tmpl_dual_thunk:
	mov	(%rsp),%r10
	cmp	.Ldual_lo(%rip),%r10
	jb	1f
	cmp	.Ldual_hi(%rip),%r10
	jae	1f
	mov	.Ldual_func(%rip),%r11
	jmp	*%r11
1:	ms2sysv	.Ldual_func
	slots	__tmpl_dual_thunk
.Ldual_lo:
	.quad	0
.Ldual_hi:
	.quad	0
.Ldual_func:
	.quad	0
__tmpl_dual_thunk_end:

//	makes the frame hostcall.S wants and enters its copy, with the
//	function in %r11. slots: func, entry
	.balign	8
__tmpl_hostcall_stub:
	push	%rbp
	mov	%rsp,%rbp
	mov	1f(%rip),%r11
	mov	2f(%rip),%r10
	jmp	*%r10
	slots	__tmpl_hostcall_stub
1:	.quad	0
2:	.quad	0
__tmpl_hostcall_stub_end:

//	enters a hostlink converter with the descriptor in %r10 and the
//	function in %r11. slots: desc, func, converter
	.balign	8
__tmpl_hostlink_thunk:
	mov	1f(%rip),%r10
	mov	2f(%rip),%r11
	mov	3f(%rip),%rax
	jmp	*%rax
	slots	__tmpl_hostlink_thunk
1:	.quad	0
2:	.quad	0
3:	.quad	0
__tmpl_hostlink_thunk_end:

//	a variadic function of ours for a microsoft caller, with `n` fixed
//	parameters. microsoft puts every variadic argument in the shadow
//	space or on the stack above it, and duplicates a float in its
//	integer register, so spilling rcx..r9 leaves the whole list in
//	memory in order. the va_list at -48(%rbp) says both register save
//	areas are spent, so every va_arg() reads the caller's list. the
//	callee is the function's va_list form; it takes six parameters in
//	registers, and fixed ones past those and the va_list pointer once
//	they're spent go on its stack. xmm6-15 are saved below the va_list
//	at -224(%rbp) up. kVtrampFrame in dlexport.c describes this frame.
//	slots: the va_list form
	.macro	vtramp n
	.balign	8
.Lvtramp\n:
	mov	%rcx,8(%rsp)
	mov	%rdx,16(%rsp)
	mov	%r8,24(%rsp)
	mov	%r9,32(%rsp)
	push	%rbp
	mov	%rsp,%rbp
	push	%rsi
	push	%rdi
	sub	$48+160,%rsp
	.irp	r,6,7,8,9,10,11,12,13,14,15
	movaps	%xmm\r,-224+(\r-6)*16(%rbp)
	.endr
	movl	$48,-48(%rbp)			// gp_offset
	movl	$176,-44(%rbp)			// fp_offset
	lea	16+\n*8(%rbp),%rax
	mov	%rax,-40(%rbp)			// overflow_arg_area
	movq	$0,-32(%rbp)			// reg_save_area
	i = 0
	.irp	r,rdi,rsi,rdx,rcx,r8,r9
	.if	i < \n
	mov	16+i*8(%rbp),%\r
	.elseif	i == \n
	lea	-48(%rbp),%\r
	.endif
	i = i + 1
	.endr
	.if	\n >= 6
	sub	$((\n-6+1)*8+15)&~15,%rsp
	i = 0
	.rept	\n-6
	mov	16+(6+i)*8(%rbp),%rax
	mov	%rax,i*8(%rsp)
	i = i + 1
	.endr
	lea	-48(%rbp),%rax
	mov	%rax,(\n-6)*8(%rsp)
	.endif
	call	*1f(%rip)
	.irp	r,6,7,8,9,10,11,12,13,14,15
	movaps	-224+(\r-6)*16(%rbp),%xmm\r
	.endr
	lea	-16(%rbp),%rsp
	pop	%rdi
	pop	%rsi
	leave
	ret
	slots	.Lvtramp\n
1:	.quad	0
.Lvtramp\n\()_end:
	.endm

#define VTRAMPS 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16

#elif defined(__aarch64__)

//	jumps to the target. slots: target
	.balign	8
__tmpl_jump:
	ldr	x16,1f
	br	x16
	slots	__tmpl_jump
1:	.quad	0
__tmpl_jump_end:

//	a host function for callers in our convention, see foreign_tramp.S,
//	which takes the function in x16. x8 is left alone since it holds
//	where a returned struct goes. slots: func, foreign_tramp
	.balign	8
__tmpl_sysv_thunk:
	ldr	x16,1f
	ldr	x10,2f
	br	x10
	slots	__tmpl_sysv_thunk
1:	.quad	0
2:	.quad	0
__tmpl_sysv_thunk_end:

//	a variadic function of ours for an apple caller, with `n` fixed
//	parameters. apple puts every variadic argument on the stack in
//	eight byte slots, which is what a va_list with no registers left
//	reads. with all eight registers taken by fixed parameters the
//	va_list pointer goes on the callee's stack; fixed parameters past
//	that are on the caller's stack at their natural sizes, which can't
//	be relaid without their types. slots: the va_list form
	.macro	vtramp n
	.balign	8
.Lvtramp\n:
	sub	sp,sp,#64
	stp	x29,x30,[sp,#48]
	add	x29,sp,#48
	add	x9,x29,#16
	str	x9,[sp,#16]			// __stack
	str	xzr,[sp,#24]			// __gr_top
	str	xzr,[sp,#32]			// __vr_top
	str	wzr,[sp,#40]			// __gr_offs
	str	wzr,[sp,#44]			// __vr_offs
	.if	\n < 8
	add	x\n,sp,#16
	.else
	add	x9,sp,#16
	str	x9,[sp]
	.endif
	ldr	x9,1f
	blr	x9
	ldp	x29,x30,[sp,#48]
	add	sp,sp,#64
	ret
	slots	.Lvtramp\n
1:	.quad	0
.Lvtramp\n\()_end:
	.endm

#define VTRAMPS 0,1,2,3,4,5,6,7,8

#endif

	.irp	n,VTRAMPS
	vtramp	\n
	.endr

//	{offset from the table, size} of the vtramp for each count of fixed
//	parameters, from zero up to __tmpl_vtramp_count - 1
	.balign	4
__tmpl_vtramps:
	.irp	n,VTRAMPS
	.long	.Lvtramp\n-__tmpl_vtramps
	.long	.Lvtramp\n\()_end-.Lvtramp\n
	.endr
__tmpl_vtramps_end:
__tmpl_vtramp_count:
	.long	(__tmpl_vtramps_end-__tmpl_vtramps)/8

//	what dlexport.c copies has to fit the space it gives each one
	.if	__tmpl_jump_end-__tmpl_jump > 16
	.error	"__tmpl_jump is bigger than TRAMP"
	.endif
#ifdef __x86_64__
	.if	__tmpl_ms2sysv_end-__tmpl_ms2sysv > 512
	.error	"__tmpl_ms2sysv is bigger than CTRAMP"
	.endif
#endif
	.irp	n,VTRAMPS
	.if	.Lvtramp\n\()_end-.Lvtramp\n > 512
	.error	"a vtramp is bigger than VTRAMP"
	.endif
	.endr

	.globl	__tmpl_jump,__tmpl_jump_end
	.globl	__tmpl_sysv_thunk,__tmpl_sysv_thunk_end
	.globl	__tmpl_vtramps,__tmpl_vtramp_count
	.hidden	__tmpl_jump,__tmpl_jump_end
	.hidden	__tmpl_sysv_thunk,__tmpl_sysv_thunk_end
	.hidden	__tmpl_vtramps,__tmpl_vtramp_count
#ifdef __x86_64__
	.globl	__tmpl_ms2sysv,__tmpl_ms2sysv_end
	.globl	__tmpl_nt_thunk,__tmpl_nt_thunk_end
	.globl	__tmpl_dual_thunk,__tmpl_dual_thunk_end
	.globl	__tmpl_hostcall_stub,__tmpl_hostcall_stub_end
	.globl	__tmpl_hostlink_thunk,__tmpl_hostlink_thunk_end
	.hidden	__tmpl_ms2sysv,__tmpl_ms2sysv_end
	.hidden	__tmpl_nt_thunk,__tmpl_nt_thunk_end
	.hidden	__tmpl_dual_thunk,__tmpl_dual_thunk_end
	.hidden	__tmpl_hostcall_stub,__tmpl_hostcall_stub_end
	.hidden	__tmpl_hostlink_thunk,__tmpl_hostlink_thunk_end
#endif
