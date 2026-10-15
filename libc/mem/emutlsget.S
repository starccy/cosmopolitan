#include "libc/dce.h"
#include "libc/macros.h"

//	fast path of llvm's emulated tls, see libc/mem/emutls.c
//
//	fetches the tib the way the getters in libc/sysv/tlsasm.S do,
//	reads the variable's slot from the control block and the object
//	from the thread's array, and leaves everything else to the slow
//	path. the slot is read without an acquire, since a thread only
//	ever indexes its own array with it
//
//	@param	rdi/x0 is the control block (__emutls_v.<name>)
//	@return	rax/x0 is the thread's object

#ifdef __x86_64__

	.section .text.tpidr_raw.emutls,"ax",@progbits
	.balign	16
__emutls_get_address:
	mov	16(%rdi),%rax		// EmutlsControl::index
	test	%rax,%rax
	jz	9f
	mov	__hostos(%rip),%ecx
	test	$_HOSTWINDOWS|_HOSTXNU,%ecx
	jnz	3f
	mov	%fs:0x38,%rcx		// CosmoTib::tib_self2
1:	test	%rcx,%rcx
	jz	9f
	mov	0x1d0(%rcx),%rcx	// CosmoTib::tib_emutls
	test	%rcx,%rcx
	jz	9f
	cmp	(%rcx),%rax		// EmutlsArray::n
	ja	9f
	mov	(%rcx,%rax,8),%rax	// EmutlsArray::p[index-1]
	test	%rax,%rax
	jz	9f
	ret
3:	test	$_HOSTXNU,%ecx
	jz	4f
	mov	%gs:0x30,%rcx
	jmp	1b
4:	mov	__tls_index(%rip),%ecx
	mov	%gs:0x1480(,%rcx,8),%rcx
	jmp	1b
9:	jmp	__emutls_get_address_slow
	.endfn	__emutls_get_address,globl

#elif defined(__aarch64__)

	.section .text.tpidr_raw.emutls,"ax",@progbits
	.balign	16
__emutls_get_address:
	ldr	x1,[x0,#16]		// EmutlsControl::index
	cbz	x1,9f
	adrp	x2,__hostos
	ldr	w2,[x2,#:lo12:__hostos]
	tbnz	w2,#3,3f		// _HOSTXNU
	mrs	x2,tpidr_el0
	ldr	x2,[x2,#8]		// the tib, see libc/sysv/tlsasm.S
1:	cbz	x2,9f
	ldr	x2,[x2,#0x1d0]		// CosmoTib::tib_emutls
	cbz	x2,9f
	ldr	x3,[x2]			// EmutlsArray::n
	cmp	x1,x3
	b.hi	9f
	ldr	x2,[x2,x1,lsl #3]	// EmutlsArray::p[index-1]
	cbz	x2,9f
	mov	x0,x2
	ret
3:	adrp	x3,__tls_slot_offset
	ldr	x3,[x3,#:lo12:__tls_slot_offset]
	mrs	x2,tpidrro_el0
	and	x2,x2,#-8
	ldr	x2,[x2,x3]
	b	1b
9:	b	__emutls_get_address_slow
	.endfn	__emutls_get_address,globl

#endif
