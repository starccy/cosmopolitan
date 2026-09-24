#ifndef COSMOPOLITAN_LIBC_SYSV_CONSTS_PACKET_H_
#define COSMOPOLITAN_LIBC_SYSV_CONSTS_PACKET_H_

/* sll_pkttype */
#define PACKET_HOST      0
#define PACKET_BROADCAST 1
#define PACKET_MULTICAST 2
#define PACKET_OTHERHOST 3
#define PACKET_OUTGOING  4

/* SOL_PACKET options */
#define PACKET_ADD_MEMBERSHIP  1
#define PACKET_DROP_MEMBERSHIP 2
#define PACKET_RECV_OUTPUT     3
#define PACKET_RX_RING         5
#define PACKET_STATISTICS      6

/* packet_mreq.mr_type */
#define PACKET_MR_MULTICAST 0
#define PACKET_MR_PROMISC   1
#define PACKET_MR_ALLMULTI  2

/* protocols, host byte order; sll_protocol takes them htons()'d */
#define ETH_P_LOOP 0x0060
#define ETH_P_IP   0x0800
#define ETH_P_ARP  0x0806
#define ETH_P_IPV6 0x86dd
#define ETH_P_ALL  0x0003

#endif /* COSMOPOLITAN_LIBC_SYSV_CONSTS_PACKET_H_ */
