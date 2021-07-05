#ifndef _TCPIP_H_
#define _TCPIP_H_

#include "net.h"
#include "ipsec_t.h"

#include <sys/types.h>

#define SINGLE_FLOW

#ifndef SINGLE_FLOW

#include "cuckoo_hash.h"

#endif

#define INIT_FRAGM_NUM_SIZE(img_len, frg_num, last_size) \
    do                                                   \
    {                                                    \
        frg_num = img_len / MAX_PAYLOAD_SIZE;            \
        last_size = img_len % MAX_PAYLOAD_SIZE;          \
    } while (0) // each fragment has size MAX_PAYLOAD_SIZE except the last one (last_size)

#define IPH_NO_FRAGM 0x4000

typedef struct __attribute__((packed)) tcp_dgram {
    tcp_hdr_t hdr;
    void *data;
} tcp_dgram_t;

typedef struct __attribute__((packed)) ip_dgram {
    ip_hdr_t hdr;
    tcp_dgram_t tcp_pkt;
} ip_dgram_t;

// some data structures for TCP Reassembly
typedef struct __attribute__((packed)) tcp_flow_id {
    uint16_t src_port;
    uint16_t dst_port;
    struct in_addr src_ip;
    struct in_addr dst_ip;
} tcp_fid_t;

typedef struct __attribute__((packed)) tcp_segment {
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t len;
    char data[TUN_MSS]; // max size = TUN_MSS 1448
} tcp_seg_t;            // max size = 4 + 4 + 2 + 1448 = 1458

typedef struct __attribute__((packed)) tcp_reasm_buf {
    tcp_fid_t fid;
    uint8_t count;
    fifo_t *fifo;
} tcp_rbuf_t;

typedef struct tcpip {
    uint32_t id;
    struct in_addr src_ip;
    struct in_addr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    fifo_t *rbuf; // reassemble buffer
    struct ipsec *ips;
#ifndef SINGLE_FLOW
    uint32_t last_seq;
    uint32_t ack;
#endif

    void (*on_recv)(struct tcpip *tcpip, uint32_t seq, void *data, uint16_t len);

} tcpip_t;

#define GET_TCP_FID(ip_pkt)                       \
    {                                             \
        .src_ip = ip_pkt->hdr.src_ip,             \
        .dst_ip = ip_pkt->hdr.dst_ip,             \
        .src_port = ip_pkt->tcp_pkt.hdr.src_port, \
        .dst_port = ip_pkt->tcp_pkt.hdr.dst_port  \
    }

#define PAYLOAD_LEN(ip_pkt) (ip_pkt->hdr.total_len - (ip_pkt->hdr.hdr_len << 2) - (ip_pkt->tcp_pkt.hdr.doff << 2))


tcpip_t *tcpip(in_addr_t addr, uint16_t port);

int connect(tcpip_t *tcpip);

int read(tcpip_t *tcpip, void *buf, int len);

int write(tcpip_t *tcpip, const void *buf, int len);

int close(tcpip_t *tcpip);

static void tcpip_on_recv(tcpip_t *tcpip, uint32_t seq, void *data, uint16_t len);

#endif