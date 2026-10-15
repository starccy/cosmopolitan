#ifndef COSMOPOLITAN_LIBC_SOCK_STRUCT_IP_MREQ_H_
#define COSMOPOLITAN_LIBC_SOCK_STRUCT_IP_MREQ_H_
#include "libc/sock/struct/sockaddr.h"
COSMOPOLITAN_C_START_

struct ip_mreq {
  struct in_addr imr_multiaddr; /* IP multicast address of group */
  struct in_addr imr_interface; /* local IP address of interface */
};

/* linux's field order; the bsds and windows put the source second */
struct ip_mreq_source {
  struct in_addr imr_multiaddr;
  struct in_addr imr_interface;
  struct in_addr imr_sourceaddr;
};

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_SOCK_STRUCT_IP_MREQ_H_ */
