#ifndef COSMOPOLITAN_THIRD_PARTY_LIBFFI_FFITARGET_H_
#define COSMOPOLITAN_THIRD_PARTY_LIBFFI_FFITARGET_H_
#if defined(__x86_64__)
#include "third_party/libffi/x86/ffitarget.h"
#elif defined(__aarch64__)
#include "third_party/libffi/aarch64/ffitarget.h"
#else
#error "unsupported architecture"
#endif
#endif
