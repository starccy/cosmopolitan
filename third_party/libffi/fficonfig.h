#ifndef COSMOPOLITAN_THIRD_PARTY_LIBFFI_FFICONFIG_H_
#define COSMOPOLITAN_THIRD_PARTY_LIBFFI_FFICONFIG_H_

#define EH_FRAME_FLAGS "a"
#define HAVE_ALLOCA_H 1
#define HAVE_AS_CFI_PSEUDO_OP 1
#define HAVE_HIDDEN_VISIBILITY_ATTRIBUTE 1
#define HAVE_LONG_DOUBLE 1
#define HAVE_MEMCPY 1
#define HAVE_INTTYPES_H 1
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_STRINGS_H 1
#define HAVE_UNISTD_H 1
#define STDC_HEADERS 1
#define HAVE_RO_EH_FRAME 1
#define SIZEOF_DOUBLE 8
#define SIZEOF_LONG_DOUBLE 16
#define SIZEOF_SIZE_T 8
#define VERSION "3.8.0"
#ifdef __x86_64__
#define HAVE_AS_X86_PCREL 1
#define HAVE_AS_X86_64_UNWIND_SECTION_TYPE 1
#endif

#ifdef LIBFFI_ASM
#define FFI_HIDDEN(name) .hidden name
#else
#define FFI_HIDDEN __attribute__((visibility("hidden")))
#endif

#endif
