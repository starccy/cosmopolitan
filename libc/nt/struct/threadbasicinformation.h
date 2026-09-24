#ifndef COSMOPOLITAN_LIBC_NT_STRUCT_THREADBASICINFORMATION_H_
#define COSMOPOLITAN_LIBC_NT_STRUCT_THREADBASICINFORMATION_H_
#include "libc/nt/struct/clientid.h"

struct NtThreadBasicInformation {
  int32_t ExitStatus;
  void *TebBaseAddress;
  struct NtClientId ClientId;
  uintptr_t AffinityMask;
  int32_t Priority;
  int32_t BasePriority;
};

#endif /* COSMOPOLITAN_LIBC_NT_STRUCT_THREADBASICINFORMATION_H_ */
