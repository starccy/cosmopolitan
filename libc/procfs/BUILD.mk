#-*-mode:makefile-gmake;indent-tabs-mode:t;tab-width:8;coding:utf-8-*-┐
#── vi: set noet ft=make ts=8 sw=8 fenc=utf-8 :vi ────────────────────┘

PKGS += LIBC_PROCFS

LIBC_PROCFS_ARTIFACTS += LIBC_PROCFS_A
LIBC_PROCFS = $(LIBC_PROCFS_A_DEPS) $(LIBC_PROCFS_A)
LIBC_PROCFS_A = o/$(MODE)/libc/procfs/procfs.a
LIBC_PROCFS_A_FILES := $(wildcard libc/procfs/*)
LIBC_PROCFS_A_HDRS = $(filter %.h,$(LIBC_PROCFS_A_FILES))
LIBC_PROCFS_A_SRCS_S = $(filter %.S,$(LIBC_PROCFS_A_FILES))
LIBC_PROCFS_A_SRCS_C = $(filter %.c,$(LIBC_PROCFS_A_FILES))

LIBC_PROCFS_A_SRCS =					\
	$(LIBC_PROCFS_A_SRCS_S)				\
	$(LIBC_PROCFS_A_SRCS_C)

LIBC_PROCFS_A_OBJS =					\
	$(LIBC_PROCFS_A_SRCS_S:%.S=o/$(MODE)/%.o)	\
	$(LIBC_PROCFS_A_SRCS_C:%.c=o/$(MODE)/%.o)

LIBC_PROCFS_A_CHECKS =					\
	$(LIBC_PROCFS_A).pkg				\
	$(LIBC_PROCFS_A_HDRS:%=o/$(MODE)/%.ok)

LIBC_PROCFS_A_DIRECTDEPS =				\
	LIBC_CALLS					\
	LIBC_FMT					\
	LIBC_INTRIN					\
	LIBC_MEM					\
	LIBC_NEXGEN32E					\
	LIBC_NT_ADVAPI32				\
	LIBC_NT_IPHLPAPI				\
	LIBC_NT_KERNEL32				\
	LIBC_NT_NTDLL					\
	LIBC_NT_PSAPI					\
	LIBC_PROC					\
	LIBC_RUNTIME					\
	LIBC_SOCK					\
	LIBC_STDIO					\
	LIBC_STR					\
	LIBC_SYSV					\
	LIBC_SYSV_CALLS					\
	LIBC_THREAD					\
	THIRD_PARTY_COMPILER_RT				\
	THIRD_PARTY_DLMALLOC				\
	THIRD_PARTY_GDTOA				\
	THIRD_PARTY_NSYNC				\

LIBC_PROCFS_A_DEPS :=					\
	$(call uniq,$(foreach x,$(LIBC_PROCFS_A_DIRECTDEPS),$($(x))))

$(LIBC_PROCFS_A):libc/procfs/				\
		$(LIBC_PROCFS_A).pkg			\
		$(LIBC_PROCFS_A_OBJS)

$(LIBC_PROCFS_A).pkg:					\
		$(LIBC_PROCFS_A_OBJS)			\
		$(foreach x,$(LIBC_PROCFS_A_DIRECTDEPS),$($(x)_A).pkg)

# aarch64 friendly assembly code
o/$(MODE)/libc/procfs/procfs.o: libc/procfs/procfs.S
	@$(COMPILE) -AOBJECTIFY.S $(OBJECTIFY.S) $(OUTPUT_OPTION) -c $<

LIBC_PROCFS_LIBS = $(foreach x,$(LIBC_PROCFS_ARTIFACTS),$($(x)))
LIBC_PROCFS_SRCS = $(foreach x,$(LIBC_PROCFS_ARTIFACTS),$($(x)_SRCS))
LIBC_PROCFS_HDRS = $(foreach x,$(LIBC_PROCFS_ARTIFACTS),$($(x)_HDRS))
LIBC_PROCFS_CHECKS = $(foreach x,$(LIBC_PROCFS_ARTIFACTS),$($(x)_CHECKS))
LIBC_PROCFS_OBJS = $(foreach x,$(LIBC_PROCFS_ARTIFACTS),$($(x)_OBJS))
$(LIBC_PROCFS_OBJS): $(BUILD_FILES) libc/procfs/BUILD.mk

.PHONY: o/$(MODE)/libc/procfs
o/$(MODE)/libc/procfs: $(LIBC_PROCFS_CHECKS)
