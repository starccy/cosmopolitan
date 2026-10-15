#include "libc/dce.h"
#include "libc/intrin/fds.h"
#include "libc/macros.h"
#include "libc/nt/errors.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/nt/winsock.h"
#include "libc/sock/internal.h"
#include "libc/sock/tcpinfo.internal.h"
#if SupportsWindows()

#define SIO_TCP_INFO 0xD8000027u

__msabi extern typeof(WSAIoctl) *const __imp_WSAIoctl;

// winsock's TCPSTATE order
static const uint8_t kNtStates[] = {
    TCPI_CLOSE,     TCPI_LISTEN,    TCPI_SYN_SENT,   TCPI_SYN_RECV,
    TCPI_ESTABLISHED, TCPI_FIN_WAIT1, TCPI_FIN_WAIT2, TCPI_CLOSE_WAIT,
    TCPI_CLOSING,   TCPI_LAST_ACK,  TCPI_TIME_WAIT,
};

struct TcpInfoV0 {
  uint32_t State;
  uint32_t Mss;
  uint64_t ConnectionTimeMs;
  uint8_t TimestampsEnabled;
  uint32_t RttUs;
  uint32_t MinRttUs;
  uint32_t BytesInFlight;
  uint32_t Cwnd;  // bytes
  uint32_t SndWnd;
  uint32_t RcvWnd;
  uint32_t RcvBuf;
  uint64_t BytesOut;
  uint64_t BytesIn;
  uint32_t BytesReordered;
  uint32_t BytesRetrans;
  uint32_t FastRetrans;
  uint32_t DupAcksIn;
  uint32_t TimeoutEpisodes;
  uint8_t SynRetrans;
};

static uint32_t Segs(uint64_t bytes, uint32_t mss) {
  return mss ? bytes / mss : 0;
}

textwindows int __tcpinfo_nt(struct Fd *fd, struct tcp_info_linux *li) {
  struct TcpInfoV0 ti = {0};
  uint32_t version = 0, got = 0;
  if (__imp_WSAIoctl(fd->handle, SIO_TCP_INFO, &version, sizeof(version), &ti,
                     sizeof(ti), &got, 0, 0) == -1) {
    // a listener or a socket that never connected has no tcp
    // connection to ask about
    int err = WSAGetLastError();
    if (err != WSAEOPNOTSUPP && err != WSAENOTCONN && err != WSAEINVAL)
      return __winsockerr();
    li->tcpi_state = fd->listening ? TCPI_LISTEN : TCPI_CLOSE;
    return 0;
  }
  li->tcpi_state = ti.State < ARRAYLEN(kNtStates) ? kNtStates[ti.State] : 0;
  li->tcpi_options = ti.TimestampsEnabled ? 1 : 0;
  li->tcpi_snd_mss = ti.Mss;
  li->tcpi_rcv_mss = ti.Mss;
  li->tcpi_rtt = ti.RttUs;
  li->tcpi_min_rtt = ti.MinRttUs;
  li->tcpi_unacked = Segs(ti.BytesInFlight, ti.Mss);
  li->tcpi_snd_cwnd = Segs(ti.Cwnd, ti.Mss);
  li->tcpi_snd_wnd = ti.SndWnd;
  li->tcpi_rcv_wnd = ti.RcvWnd;
  li->tcpi_rcv_space = ti.RcvBuf;
  li->tcpi_bytes_sent = ti.BytesOut;
  li->tcpi_bytes_acked = ti.BytesOut - MIN(ti.BytesInFlight, ti.BytesOut);
  li->tcpi_bytes_received = ti.BytesIn;
  li->tcpi_bytes_retrans = ti.BytesRetrans;
  li->tcpi_dsack_dups = ti.DupAcksIn;
  li->tcpi_retransmits = ti.SynRetrans;
  return 0;
}

#endif /* SupportsWindows() */
