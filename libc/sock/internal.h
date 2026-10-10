#ifndef COSMOPOLITAN_LIBC_SOCK_INTERNAL_H_
#define COSMOPOLITAN_LIBC_SOCK_INTERNAL_H_
#include "libc/calls/struct/iovec.h"
#include "libc/calls/struct/sigset.h"
#include "libc/calls/struct/timespec.h"
#include "libc/intrin/fds.h"
#include "libc/nt/struct/overlapped.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/nt/winsock.h"
#include "libc/sock/select.h"
#include "libc/sock/sock.h"
#include "libc/sock/struct/msghdr.h"
#include "libc/sock/struct/sockaddr.h"
#include "libc/sysv/consts/af.h"
#include "libc/sysv/consts/msg.h"
COSMOPOLITAN_C_START_

// the MSG_* bits with a name here; on the hosts other than linux any
// other bit (MSG_MORE, MSG_ZEROCOPY, MSG_CMSG_CLOEXEC, ...) is dropped
// by the send/recv wrappers the way linux drops bits it doesn't know
#define __MSG_NAMED                                                    \
  (MSG_OOB | MSG_PEEK | MSG_DONTROUTE | MSG_CTRUNC | MSG_TRUNC |        \
   MSG_DONTWAIT | MSG_WAITALL | MSG_NOSIGNAL | MSG_FASTOPEN)

#define kNtFdRead                   1
#define kNtFdWrite                  2
#define kNtFdOob                    4
#define kNtFdAccept                 8
#define kNtFdConnect                16
#define kNtFdClose                  32
#define kNtFdQos                    64
#define kNtFdGroupQos               128
#define kNtFdRoutingInterfaceChange 256
#define kNtFdAddressListChange      512

/* ------------------------------------------------------------------------------------*/

#define SOCKFD_OVERLAP_BUFSIZ 128

int32_t __sys_accept(int32_t, void *, uint32_t *, int) __wur;
int32_t __sys_accept4(int32_t, void *, uint32_t *, int) __wur;
int32_t __sys_bind(int32_t, const void *, uint32_t);
int32_t __sys_connect(int32_t, const void *, uint32_t);
int32_t __sys_getpeername(int32_t, void *, uint32_t *);
int32_t __sys_getsockname(int32_t, void *, uint32_t *);
int32_t __sys_socket(int32_t, int32_t, int32_t);
int32_t __sys_socketpair(int32_t, int32_t, int32_t, int32_t[2]);

int32_t sys_accept4(int32_t, struct sockaddr_storage *, uint32_t *,
                    int) __wur;
int32_t sys_bind(int32_t, const void *, uint32_t);
int32_t sys_connect(int32_t, const void *, uint32_t);
int32_t sys_getsockopt(int32_t, int32_t, int32_t, void *, uint32_t *);
int32_t sys_listen(int32_t, int32_t);
int32_t sys_getsockname(int32_t, void *, uint32_t *);
int32_t sys_getpeername(int32_t, void *, uint32_t *);
int32_t sys_shutdown(int32_t, int32_t);
int32_t sys_socket(int32_t, int32_t, int32_t);
int32_t sys_socketpair(int32_t, int32_t, int32_t, int32_t[2]);
ssize_t sys_recvfrom(int, void *, size_t, int, void *, uint32_t *);
int sys_recvmmsg(int, struct mmsghdr *, unsigned, int, struct timespec *);
struct Fd;
bool __is_pmtudisc(int, int);
ssize_t __cmsg2nt(const void *, size_t, void *, size_t);
size_t __cmsg2linux_nt(const void *, size_t, void *, size_t, bool *);
ssize_t sys_sendmsg_nt(int, const struct msghdr *, uint32_t);
ssize_t sys_recvmsg_nt(int, struct msghdr *, uint32_t);
ssize_t __winsock_dgram_rc(struct Fd *, ssize_t, const struct iovec *, size_t,
                           bool *);
void __winsock_udp_connreset(int64_t, bool);
int __pmtudisc2nt(int);
int __pmtudisc2linux_nt(int);
int sys_sendmmsg(int, struct mmsghdr *, unsigned, int);
ssize_t sys_sendto(int, const void *, size_t, int, const void *, uint32_t);
int32_t sys_select(int32_t, fd_set *, fd_set *, fd_set *, struct timeval *);
int sys_pselect(int, fd_set *, fd_set *, fd_set *, struct timespec *,
                const void *);
int sys_setsockopt(int, int, int, const void *, uint32_t);

int sys_socket_nt(int, int, int);
int sys_socket_packet_nt(int, int);
int sys_bind_packet_nt(struct Fd *, const void *, uint32_t);
ssize_t sys_recv_packet_nt(struct Fd *, const struct iovec *, size_t, uint32_t,
                           void *, uint32_t *);

/*
int sys_socketpair_nt_stream(int, int, int, int[2]) ;
int sys_socketpair_nt_dgram(int, int, int, int[2]) ;
*/
int sys_socketpair_nt(int, int, int, int[2]);
int sys_select_nt(int, fd_set *, fd_set *, fd_set *, const struct timespec *,
                  const sigset_t *);

size_t __iovec2nt(struct NtIovec[hasatleast 16], const struct iovec *, size_t);

bool __winsock_recv_ready(int64_t, uint32_t);
bool __winsock_send_ready(int64_t);
int __winsock_fionbio(struct Fd *);
ssize_t __winsock_recv_nonblock(struct Fd *, const struct iovec *, size_t,
                                uint32_t, void *, uint32_t *);
ssize_t __winsock_send_nonblock(struct Fd *, const struct iovec *, size_t,
                                uint32_t, const void *, uint32_t);
size_t __winsock_clamp_send(struct iovec[hasatleast 16], const struct iovec *,
                            size_t);
struct Fd;
bool __sockopt_park(int64_t, int, int, int);
bool __sockopt_lookup(int64_t, int, int, int *);
void __sockopt_replay(struct Fd *);
void __sockopt_forget(int64_t);
ssize_t __winsock_block(int64_t, uint32_t, bool, uint32_t, uint64_t,
                        int (*)(int64_t, struct NtOverlapped *, uint32_t *,
                                void *),
                        void *);

struct msghdr;
bool __scm_stream_nt(struct Fd *);
bool __scm_msgpipe_nt(struct Fd *);

// an SCM_RIGHTS frame built for a datagram, unixdgram-nt.c's use of
// what scmrights-nt.c does for streams and socketpairs
struct ScmFrame {
  unsigned char *p;  // head, then `room` bytes for the caller
  size_t hlen;
  size_t made;
  int64_t proc;  // where the handles went
};
ssize_t __scm_frame_build_nt(struct ScmFrame *, const struct msghdr *,
                             uint32_t, size_t);
void __scm_frame_done_nt(struct ScmFrame *, bool);
ssize_t __scm_frame_take_nt(struct Fd *, const unsigned char *, size_t, bool);

// AF_UNIX SOCK_DGRAM on windows, unixdgram-nt.c
bool __udg_nt(const struct Fd *);
int __udg_socket_nt(int, int, int);
int __udg_bind_nt(struct Fd *, const void *, uint32_t);
int __udg_connect_nt(struct Fd *, const void *, uint32_t);
ssize_t __udg_sendto_nt(int, const struct iovec *, size_t, int, const void *,
                        uint32_t, const struct msghdr *);
ssize_t __udg_recv_nt(int, const struct iovec *, size_t, int, void *,
                      uint32_t *, bool *);
ssize_t __udg_recvmsg_nt(int, struct msghdr *, int, bool);
int __udg_getname_nt(struct Fd *, bool, struct sockaddr_storage *, uint32_t *);
void __udg_ref_nt(struct Fd *);
void __udg_close_nt(struct Fd *);

// the winsock sends and receives after the address was translated
ssize_t __winsock_sendto_nt(int, const struct iovec *, size_t, uint32_t,
                            const void *, uint32_t, void *, uint32_t);
ssize_t __winsock_recvfrom_nt(int, const struct iovec *, size_t, uint32_t,
                              void *, uint32_t *, struct NtMsgHdr *);
ssize_t __scm_msgpipe_send_nt(int, const struct msghdr *);
ssize_t __scm_send_nt(int, const struct msghdr *, int);
ssize_t __scm_recv_nt(struct Fd *, const struct iovec *, size_t, uint32_t,
                      bool, uint64_t);
void __scm_take_nt(struct Fd *, struct msghdr *, bool);
void __scm_forget_nt(struct Fd *);

void WinSockInit(void);
int64_t __winsockerr(void);
int __fixupnewsockfd(int, int);
int64_t GetNtBaseSocket(int64_t);

int __fixsunpath(struct sockaddr_un *, const void **, uint32_t *);
void __unfixsunpath(void *, uint32_t *, uint32_t);

// socketpair() on windows: message pairs are a named pipe, whose ends
// are kFdFile with a socket mode, and stream pairs are two sockets we
// connected through a temporary path, marked by this mode. either way
// linux reports both ends as unnamed, and so do we
#define kSockPairStreamMode 0140600
forceinline bool __sockpair_nt(const struct Fd *f) {
  return (f->kind == kFdFile && (f->mode & 0170000) == 0140000) ||
         (f->kind == kFdSocket && f->mode == kSockPairStreamMode);
}

// whether an address is too short to be one. an AF_UNIX address is the
// family plus as much of the path as there is, so "\0name" (linux's
// abstract namespace) or a short path is under sizeof(struct sockaddr)
forceinline bool __sockaddr_too_short(const struct sockaddr *addr,
                                      uint32_t size) {
  if (size < sizeof(addr->sa_family))
    return true;
  if (size >= sizeof(struct sockaddr))
    return false;
  return addr->sa_family != AF_UNIX;
}

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_SOCK_INTERNAL_H_ */
