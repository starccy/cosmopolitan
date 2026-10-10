#-*-mode:makefile-gmake;indent-tabs-mode:t;tab-width:8;coding:utf-8-*-┐
#── vi: set noet ft=make ts=8 sw=8 fenc=utf-8 :vi ────────────────────┘

PKGS += THIRD_PARTY_LIBFFI

THIRD_PARTY_LIBFFI_ARTIFACTS += THIRD_PARTY_LIBFFI_A
THIRD_PARTY_LIBFFI = $(THIRD_PARTY_LIBFFI_A_DEPS) $(THIRD_PARTY_LIBFFI_A)
THIRD_PARTY_LIBFFI_A = o/$(MODE)/third_party/libffi/libffi.a
THIRD_PARTY_LIBFFI_A_FILES :=					\
	$(wildcard third_party/libffi/*)			\
	$(wildcard third_party/libffi/x86/*)			\
	$(wildcard third_party/libffi/aarch64/*)
THIRD_PARTY_LIBFFI_A_HDRS = $(filter %.h,$(THIRD_PARTY_LIBFFI_A_FILES))
THIRD_PARTY_LIBFFI_A_SRCS_C = $(filter %.c,$(THIRD_PARTY_LIBFFI_A_FILES))
THIRD_PARTY_LIBFFI_A_SRCS_S = $(filter %.S,$(THIRD_PARTY_LIBFFI_A_FILES))
THIRD_PARTY_LIBFFI_A_SRCS =					\
	$(THIRD_PARTY_LIBFFI_A_SRCS_C)				\
	$(THIRD_PARTY_LIBFFI_A_SRCS_S)

# the c sources are guarded by the architecture they're for, while an
# assembly file for the other one would make an object with nothing in
# it, which the package check can't read
ifeq ($(ARCH), x86_64)
THIRD_PARTY_LIBFFI_A_ASM = $(filter third_party/libffi/x86/%,$(THIRD_PARTY_LIBFFI_A_SRCS_S))
else
THIRD_PARTY_LIBFFI_A_ASM = $(filter third_party/libffi/aarch64/%,$(THIRD_PARTY_LIBFFI_A_SRCS_S))
endif

THIRD_PARTY_LIBFFI_A_OBJS =					\
	$(THIRD_PARTY_LIBFFI_A_SRCS_C:%.c=o/$(MODE)/%.o)	\
	$(THIRD_PARTY_LIBFFI_A_ASM:%.S=o/$(MODE)/%.o)

THIRD_PARTY_LIBFFI_A_CHECKS =					\
	$(THIRD_PARTY_LIBFFI_A).pkg

THIRD_PARTY_LIBFFI_A_DIRECTDEPS =				\
	LIBC_CALLS						\
	LIBC_INTRIN						\
	LIBC_MEM						\
	LIBC_NEXGEN32E						\
	LIBC_RUNTIME						\
	LIBC_STDIO						\
	LIBC_STR						\
	LIBC_SYSV						\
	LIBC_THREAD						\
	THIRD_PARTY_COMPILER_RT

THIRD_PARTY_LIBFFI_A_DEPS :=					\
	$(call uniq,$(foreach x,$(THIRD_PARTY_LIBFFI_A_DIRECTDEPS),$($(x))))

$(THIRD_PARTY_LIBFFI_A):					\
		third_party/libffi/				\
		$(THIRD_PARTY_LIBFFI_A).pkg			\
		$(THIRD_PARTY_LIBFFI_A_OBJS)

$(THIRD_PARTY_LIBFFI_A).pkg:					\
		$(THIRD_PARTY_LIBFFI_A_OBJS)			\
		$(foreach x,$(THIRD_PARTY_LIBFFI_A_DIRECTDEPS),$($(x)_A).pkg)

$(THIRD_PARTY_LIBFFI_A_OBJS): private				\
		CFLAGS +=					\
			-ffunction-sections			\
			-fdata-sections

# rules.mk assembles .S files as empty ones on aarch64, except these
o/$(MODE)/third_party/libffi/aarch64/sysv.o: third_party/libffi/aarch64/sysv.S
	@$(COMPILE) -AOBJECTIFY.S $(OBJECTIFY.S) $(OUTPUT_OPTION) -c $<

THIRD_PARTY_LIBFFI_LIBS = $(foreach x,$(THIRD_PARTY_LIBFFI_ARTIFACTS),$($(x)))
THIRD_PARTY_LIBFFI_SRCS = $(foreach x,$(THIRD_PARTY_LIBFFI_ARTIFACTS),$($(x)_SRCS))
THIRD_PARTY_LIBFFI_HDRS = $(foreach x,$(THIRD_PARTY_LIBFFI_ARTIFACTS),$($(x)_HDRS))
THIRD_PARTY_LIBFFI_CHECKS = $(foreach x,$(THIRD_PARTY_LIBFFI_ARTIFACTS),$($(x)_CHECKS))
THIRD_PARTY_LIBFFI_OBJS = $(foreach x,$(THIRD_PARTY_LIBFFI_ARTIFACTS),$($(x)_OBJS))
$(THIRD_PARTY_LIBFFI_OBJS): $(BUILD_FILES) third_party/libffi/BUILD.mk

.PHONY: o/$(MODE)/third_party/libffi
o/$(MODE)/third_party/libffi:					\
		$(THIRD_PARTY_LIBFFI_CHECKS)			\
		$(THIRD_PARTY_LIBFFI_A)
