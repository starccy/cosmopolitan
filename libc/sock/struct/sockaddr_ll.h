#ifndef COSMOPOLITAN_LIBC_SOCK_STRUCT_SOCKADDR_LL_H_
#define COSMOPOLITAN_LIBC_SOCK_STRUCT_SOCKADDR_LL_H_
COSMOPOLITAN_C_START_

/* the address of an AF_PACKET socket, in linux's layout */
struct sockaddr_ll {
  uint16_t sll_family;
  uint16_t sll_protocol; /* ETH_P_xxx, network byte order */
  int32_t sll_ifindex;
  uint16_t sll_hatype;
  uint8_t sll_pkttype;
  uint8_t sll_halen;
  uint8_t sll_addr[8];
};

struct packet_mreq {
  int32_t mr_ifindex;
  uint16_t mr_type;
  uint16_t mr_alen;
  uint8_t mr_address[8];
};

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_SOCK_STRUCT_SOCKADDR_LL_H_ */
