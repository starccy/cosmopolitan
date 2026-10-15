#ifndef COSMOPOLITAN_LIBC_SYSV_CONSTS_IP_H_
#define COSMOPOLITAN_LIBC_SYSV_CONSTS_IP_H_

#define IP_TOS             1
#define IP_TTL             2
#define IP_HDRINCL         3
#define IP_OPTIONS         4
#define IP_PKTINFO         8
#define IP_MTU_DISCOVER    10
#define IP_RECVTTL         12
#define IP_RECVTOS         13
#define IP_MTU             14
#define IP_UNICAST_IF      50
#define IP_MULTICAST_IF    32
#define IP_MULTICAST_TTL   33
#define IP_MULTICAST_LOOP  34
#define IP_ADD_MEMBERSHIP  35
#define IP_DROP_MEMBERSHIP 36
#define IP_UNBLOCK_SOURCE  37
#define IP_BLOCK_SOURCE    38
#define IP_ADD_SOURCE_MEMBERSHIP  39
#define IP_DROP_SOURCE_MEMBERSHIP 40

#define IP_DEFAULT_MULTICAST_TTL  1
#define IP_DEFAULT_MULTICAST_LOOP 1

#define IP_PMTUDISC_DONT      0
#define IP_PMTUDISC_WANT      1
#define IP_PMTUDISC_DO        2
#define IP_PMTUDISC_PROBE     3
#define IP_PMTUDISC_INTERFACE 4
#define IP_PMTUDISC_OMIT      5

#endif /* COSMOPOLITAN_LIBC_SYSV_CONSTS_IP_H_ */
