#include "libc/calls/internal.h"
#include "libc/calls/state.internal.h"
#include "libc/dce.h"
#include "libc/intrin/fds.h"
#include "libc/macros.h"
#include "libc/sock/internal.h"
#include "libc/sock/tcpinfo.internal.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/ipproto.h"
#include "libc/sysv/consts/sol.h"
#include "libc/sysv/consts/tcp.h"
#include "libc/sysv/errfuns.h"

// TCP_INFO off linux: xnu's struct tcp_info and windows' TCP_INFO_v0
// put into linux's struct tcp_info. states are renumbered, xnu's
// millisecond times become microseconds, windows of bytes become
// segments, and what a host doesn't report stays zero

#define TCP_INFO_XNU 0x200

// xnu's TCPS_* order
static const uint8_t kXnuStates[] = {
    TCPI_CLOSE,      TCPI_LISTEN,  TCPI_SYN_SENT, TCPI_SYN_RECV,
    TCPI_ESTABLISHED, TCPI_CLOSE_WAIT, TCPI_FIN_WAIT1, TCPI_CLOSING,
    TCPI_LAST_ACK,   TCPI_FIN_WAIT2, TCPI_TIME_WAIT,
};

// bsd/netinet/tcp_private.h, under its pragma pack(4); the times are
// milliseconds, the windows bytes
struct tcp_info_xnu {
  uint8_t state;
  uint8_t options;
  uint8_t snd_wscale;
  uint8_t rcv_wscale;
  uint32_t flags;
  uint32_t rto;  // zero unless the retransmit timer is running
  uint32_t snd_mss;
  uint32_t rcv_mss;
  uint32_t rttcur;
  uint32_t srtt;
  uint32_t rttvar;
  uint32_t rttbest;
  uint32_t snd_ssthresh;
  uint32_t snd_cwnd;
  uint32_t rcv_space;
  uint32_t snd_wnd;
  uint32_t snd_nxt;
  uint32_t rcv_nxt;
  int32_t last_outif;
  uint32_t snd_sbbytes;
  uint64_t txpackets;
  uint64_t txbytes;
  uint64_t txretransmitbytes;
  uint64_t txunacked;
  uint64_t rxpackets;
  uint64_t rxbytes;
  uint64_t rxduplicatebytes;
  uint64_t rxoutoforderbytes;
  uint64_t snd_bw;
  uint8_t synrexmits;
  uint8_t unused1;
  uint16_t unused2;
  uint64_t cell_rxpackets;
  uint64_t cell_rxbytes;
  uint64_t cell_txpackets;
  uint64_t cell_txbytes;
  uint64_t wifi_rxpackets;
  uint64_t wifi_rxbytes;
  uint64_t wifi_txpackets;
  uint64_t wifi_txbytes;
  uint64_t wired_rxpackets;
  uint64_t wired_rxbytes;
  uint64_t wired_txpackets;
  uint64_t wired_txbytes;
  uint32_t connstatus;
  uint16_t tfo;
  uint16_t ecn;
  uint32_t ecn_recv_ce;
  uint32_t ecn_recv_cwr;
  uint32_t rcvoopack;
  uint32_t pawsdrop;
  uint32_t sack_recovery_episode;
  uint32_t reordered_pkts;
  uint32_t dsack_sent;
  uint32_t dsack_recvd;
  uint32_t flowhash;
  uint64_t txretransmitpackets;
  uint32_t rcv_srtt;
  uint8_t more[128];  // ecn and pacing counters, grows with the release
} __attribute__((__packed__, __aligned__(4)));

static_assert(offsetof(struct tcp_info_xnu, txpackets) == 68);
static_assert(offsetof(struct tcp_info_xnu, synrexmits) == 140);
static_assert(offsetof(struct tcp_info_xnu, cell_rxpackets) == 144);
static_assert(offsetof(struct tcp_info_xnu, connstatus) == 240);
static_assert(offsetof(struct tcp_info_xnu, txretransmitpackets) == 284);
static_assert(offsetof(struct tcp_info_xnu, rcv_srtt) == 292);

bool __tcpinfo(int level, int optname) {
  return !IsLinux() && level == SOL_TCP && optname == TCP_INFO;
}

static uint32_t Segs(uint64_t bytes, uint32_t mss) {
  return mss ? bytes / mss : 0;
}

static int GetXnu(int fd, struct tcp_info_linux *li) {
  struct tcp_info_xnu xi = {0};
  uint32_t len = sizeof(xi);
  if (sys_getsockopt(fd, IPPROTO_TCP, TCP_INFO_XNU, &xi, &len) == -1)
    return -1;
  li->tcpi_state = xi.state < ARRAYLEN(kXnuStates) ? kXnuStates[xi.state] : 0;
  li->tcpi_options = xi.options & 15;
  li->tcpi_wscale = (xi.snd_wscale & 15) | (xi.rcv_wscale << 4);
  li->tcpi_rto = xi.rto * 1000;
  li->tcpi_snd_mss = xi.snd_mss;
  li->tcpi_rcv_mss = xi.rcv_mss;
  li->tcpi_rtt = xi.srtt * 1000;
  li->tcpi_rttvar = xi.rttvar * 1000;
  li->tcpi_min_rtt = xi.rttbest * 1000;
  li->tcpi_snd_ssthresh = Segs(xi.snd_ssthresh, xi.snd_mss);
  li->tcpi_snd_cwnd = Segs(xi.snd_cwnd, xi.snd_mss);
  li->tcpi_rcv_space = xi.rcv_space;
  li->tcpi_snd_wnd = xi.snd_wnd;
  li->tcpi_unacked = Segs(xi.txunacked, xi.snd_mss);
  li->tcpi_bytes_sent = xi.txbytes;
  li->tcpi_bytes_acked = xi.txbytes - MIN(xi.txunacked, xi.txbytes);
  li->tcpi_bytes_received = xi.rxbytes;
  li->tcpi_bytes_retrans = xi.txretransmitbytes;
  li->tcpi_segs_out = xi.txpackets;
  li->tcpi_segs_in = xi.rxpackets;
  li->tcpi_notsent_bytes = xi.snd_sbbytes - MIN(xi.txunacked, xi.snd_sbbytes);
  li->tcpi_retransmits = xi.synrexmits;
  li->tcpi_rcv_rtt = xi.rcv_srtt * 1000;
  li->tcpi_total_retrans = xi.txretransmitpackets;
  li->tcpi_rcv_ooopack = xi.rcvoopack;
  li->tcpi_reord_seen = xi.reordered_pkts;
  li->tcpi_dsack_dups = xi.dsack_recvd;
  return 0;
}

int __tcpinfo_get(int fd, void *optval, uint32_t *optlen) {
  if (!optval || !optlen)
    return efault();
  if (__tcphint_check(fd) == -1)
    return -1;
  struct tcp_info_linux li = {0};
  if (IsWindows()) {
    if (__tcpinfo_nt(__get_pib()->fds.p + fd, &li) == -1)
      return -1;
  } else if (IsXnu()) {
    if (GetXnu(fd, &li) == -1)
      return -1;
  } else {
    return enoprotoopt();
  }
  uint32_t n = MIN(*optlen, sizeof(li));
  memcpy(optval, &li, n);
  *optlen = n;
  return 0;
}
