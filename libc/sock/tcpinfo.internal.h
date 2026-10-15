#ifndef COSMOPOLITAN_LIBC_SOCK_TCPINFO_INTERNAL_H_
#define COSMOPOLITAN_LIBC_SOCK_TCPINFO_INTERNAL_H_
#include "libc/intrin/fds.h"
COSMOPOLITAN_C_START_

// linux's tcp states
#define TCPI_ESTABLISHED 1
#define TCPI_SYN_SENT    2
#define TCPI_SYN_RECV    3
#define TCPI_FIN_WAIT1   4
#define TCPI_FIN_WAIT2   5
#define TCPI_TIME_WAIT   6
#define TCPI_CLOSE       7
#define TCPI_CLOSE_WAIT  8
#define TCPI_LAST_ACK    9
#define TCPI_LISTEN      10
#define TCPI_CLOSING     11

// linux's struct tcp_info, 280 bytes as of 6.x
struct tcp_info_linux {
  uint8_t tcpi_state;
  uint8_t tcpi_ca_state;
  uint8_t tcpi_retransmits;
  uint8_t tcpi_probes;
  uint8_t tcpi_backoff;
  uint8_t tcpi_options;
  uint8_t tcpi_wscale;  // snd_wscale:4, rcv_wscale:4
  uint8_t tcpi_bits;    // delivery_rate_app_limited:1, fastopen_client_fail:2
  uint32_t tcpi_rto;    // microseconds
  uint32_t tcpi_ato;
  uint32_t tcpi_snd_mss;
  uint32_t tcpi_rcv_mss;
  uint32_t tcpi_unacked;  // segments
  uint32_t tcpi_sacked;
  uint32_t tcpi_lost;
  uint32_t tcpi_retrans;
  uint32_t tcpi_fackets;
  uint32_t tcpi_last_data_sent;
  uint32_t tcpi_last_ack_sent;
  uint32_t tcpi_last_data_recv;
  uint32_t tcpi_last_ack_recv;
  uint32_t tcpi_pmtu;
  uint32_t tcpi_rcv_ssthresh;
  uint32_t tcpi_rtt;  // microseconds
  uint32_t tcpi_rttvar;
  uint32_t tcpi_snd_ssthresh;  // segments
  uint32_t tcpi_snd_cwnd;      // segments
  uint32_t tcpi_advmss;
  uint32_t tcpi_reordering;
  uint32_t tcpi_rcv_rtt;
  uint32_t tcpi_rcv_space;
  uint32_t tcpi_total_retrans;
  uint64_t tcpi_pacing_rate;
  uint64_t tcpi_max_pacing_rate;
  uint64_t tcpi_bytes_acked;
  uint64_t tcpi_bytes_received;
  uint32_t tcpi_segs_out;
  uint32_t tcpi_segs_in;
  uint32_t tcpi_notsent_bytes;
  uint32_t tcpi_min_rtt;
  uint32_t tcpi_data_segs_in;
  uint32_t tcpi_data_segs_out;
  uint64_t tcpi_delivery_rate;
  uint64_t tcpi_busy_time;
  uint64_t tcpi_rwnd_limited;
  uint64_t tcpi_sndbuf_limited;
  uint32_t tcpi_delivered;
  uint32_t tcpi_delivered_ce;
  uint64_t tcpi_bytes_sent;
  uint64_t tcpi_bytes_retrans;
  uint32_t tcpi_dsack_dups;
  uint32_t tcpi_reord_seen;
  uint32_t tcpi_rcv_ooopack;
  uint32_t tcpi_snd_wnd;
  uint32_t tcpi_rcv_wnd;
  uint32_t tcpi_rehash;
  uint16_t tcpi_total_rto;
  uint16_t tcpi_total_rto_recoveries;
  uint32_t tcpi_total_rto_time;
  uint32_t tcpi_received_ce;
  uint32_t tcpi_delivered_e1_bytes;
  uint32_t tcpi_delivered_e0_bytes;
  uint32_t tcpi_delivered_ce_bytes;
  uint32_t tcpi_received_e1_bytes;
  uint32_t tcpi_received_e0_bytes;
  uint32_t tcpi_received_ce_bytes;
  uint32_t tcpi_ecn_bits;  // ecn_mode:2, accecn_opt_seen:2, accecn_fail_mode:4, options2:24
};

bool __tcpinfo(int, int);
int __tcpinfo_get(int, void *, uint32_t *);
int __tcpinfo_nt(struct Fd *, struct tcp_info_linux *);

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_SOCK_TCPINFO_INTERNAL_H_ */
