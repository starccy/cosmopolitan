#ifndef COSMOPOLITAN_LIBC_SYSV_CONSTS_SO_H_
#define COSMOPOLITAN_LIBC_SYSV_CONSTS_SO_H_

#define SO_DEBUG       1
#define SO_REUSEADDR   2
#define SO_TYPE        3
#define SO_ERROR       4
#define SO_DONTROUTE   5
#define SO_BROADCAST   6
#define SO_SNDBUF      7
#define SO_RCVBUF      8
#define SO_KEEPALIVE   9
#define SO_OOBINLINE   10
#define SO_LINGER      13
#define SO_REUSEPORT   15
#define SO_PASSCRED    16
#define SO_PEERCRED    17
#define SO_RCVLOWAT    18
#define SO_SNDLOWAT    19
#define SO_RCVTIMEO    20
#define SO_SNDTIMEO    21
#define SO_BINDTODEVICE 25
#define SO_TIMESTAMP   29
#define SO_SNDBUFFORCE 32
#define SO_RCVBUFFORCE 33
#define SO_BINDTOIFINDEX 62
#define SO_ACCEPTCONN  30
#define SO_PROTOCOL    38
#define SO_DOMAIN      39

/* bsd only; sits above linux's numbers */
#define SO_USELOOPBACK 0x1000

#endif /* COSMOPOLITAN_LIBC_SYSV_CONSTS_SO_H_ */
