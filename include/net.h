#ifndef _NET_H_
#define _NET_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>

#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <pthread.h>
#include <endian.h>

#include <sgx_tcrypto.h>


#define SYS_MTU 1500
#define TUN_HDR 52   // IPH(20) - TCPH(32)
#define TUN_MSS 1448 // MTU(1500) - (IPH(20) + TCPH(32))
#define TUN_SEG_NUM(n) (n / TUN_MSS + 1)
#define MAX_SEG_NUM 80

//#define likely(x) __builtin_expect(!!(x), 1)
//#define unlikely(x) __builtin_expect(!!(x), 0)

#ifndef _NETINET_IN_H
/* Internet address.  */
typedef uint32_t in_addr_t;
typedef struct in_addr {
    in_addr_t s_addr;
} in_addr;
#endif

typedef struct __attribute__((packed)) ip_hdr // 20 bytes, without Options
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int hdr_len: 4; /* header length */
    unsigned int ver: 4;     /* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int hdr_len : 4; /* version */
    unsigned int ver : 4;     /* header length */
#endif                        // 4 bits version and 4 bits internet header length
    uint8_t tos;              // 8 bits type of service
    uint16_t total_len;       // 8 bits length of the packet
    uint16_t id;              // identification
    uint16_t flags_fo;        // 3 bits flags and 13 bits fragment offset
    uint8_t ttl;              // 8 bits time to live
    uint8_t protocol;
    uint16_t checksum; // 16 bits one's complement checksum of the IP header and IP options
    struct in_addr src_ip;
    struct in_addr dst_ip;
} ip_hdr_t;

typedef struct __attribute__((packed)) tcp_hdr // 32 bytes, with Options
{
    uint16_t src_port;              // 16 bits, 2 bytes
    uint16_t dst_port;              // 16 bits, 2 bytes
    uint32_t seq_num;               // 32 bits, 4 bytes
    uint32_t ack_num;               // 32 bits, 4 bytes
#if __BYTE_ORDER == __LITTLE_ENDIAN // 16 bits, 2 bytes
    uint16_t res1: 4;
    uint16_t doff: 4;
    uint16_t fin: 1;
    uint16_t syn: 1;
    uint16_t rst: 1;
    uint16_t psh: 1;
    uint16_t ack: 1;
    uint16_t urg: 1;
    uint16_t res2: 2;
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint16_t doff : 4;
    uint16_t res1 : 4;
    uint16_t res2 : 2;
    uint16_t urg : 1;
    uint16_t ack : 1;
    uint16_t psh : 1;
    uint16_t rst : 1;
    uint16_t syn : 1;
    uint16_t fin : 1;
#endif
    uint16_t window;  // 16 bits, 2 bytes
    uint16_t chksum;  // 16 bits, 2 bytes
    uint16_t urg_ptr; // 16 bits, 2 bytes
    // // options
    // uint8_t opt_nop1;
    // uint8_t opt_nop2;
    // struct __attribute__((packed))
    // {
    //     uint8_t opt_ts_kind;
    //     uint8_t opt_ts_len;
    //     uint32_t opt_ts_val;
    //     uint32_t opt_ts_ecr;
    // };
} tcp_hdr_t;

#define isascii(c) (((c) & ~0x7f) == 0) /* If C is a 7 bit value.  */
#define isspace(c) (c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r' || c == ' ')
#define isdigit(c) (c >= '0' && c <= '9')
in_addr_t inet_addr(const char *cp);

#endif