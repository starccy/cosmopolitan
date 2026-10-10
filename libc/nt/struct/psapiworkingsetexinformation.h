#ifndef COSMOPOLITAN_LIBC_NT_STRUCT_PSAPIWORKINGSETEXINFORMATION_H_
#define COSMOPOLITAN_LIBC_NT_STRUCT_PSAPIWORKINGSETEXINFORMATION_H_
COSMOPOLITAN_C_START_

// VirtualAttributes: bit 0 Valid. when it's clear, bits 22-23 say where
// the page is (0 nowhere, 1 in memory off the working set, 2 pagefile)
struct NtPsapiWorkingSetExInformation {
  void *VirtualAddress;
  uint64_t VirtualAttributes;
};

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_NT_STRUCT_PSAPIWORKINGSETEXINFORMATION_H_ */
