#ifndef _IPSEC_T_H_
#define _IPSEC_T_H_

/*
    The top-level interface that supplies secure end-to-end communication
    in which an endpoint is the enclave. Generally, it should implement 
    common POSIX-style I/O APIs: ipsec(), read(). write(). 
*/
#include "fifo.h"
#include "tcpip.h"
#include "net.h"
#include "ring_buf_t.h"
#include "config.h"

#define PROTO_TCP 1
#define IPPROTO_TCP 6


#define IP_MTU_SIZE 1500
#define IPH_SIZE sizeof(ip_hdr_t)
#define TCPH_SIZE sizeof(tcp_hdr_t)
#define MAC_SIZE SGX_AESGCM_MAC_SIZE
#define MAX_PAYLOAD_SIZE (IP_MTU_SIZE - 2 * (IPH_SIZE + TCPH_SIZE) - MAC_SIZE)
#define ENCRYPTED_SIZE (IPH_SIZE + TCPH_SIZE + MAX_PAYLOAD_SIZE)

struct __attribute__((packed)) ipsec_payload
{
    ip_hdr_t iph;
    tcp_hdr_t tcph;
    uint8_t raw[MAX_PAYLOAD_SIZE];
    uint8_t mac[MAC_SIZE];
};

typedef struct __attribute__((packed)) ipsec
{
    uint32_t id; // unique identifier to distinguish an enclave-started IPSec connection
    uint8_t protocol; // TCP/UDP, only TCP supported now 
    struct ring_buf *cbuf; // exchange ciphertext from/to the untrusted area
    struct tcpip *tcpip;
} ips_t;

// initialize the ips_t structure, allocate cbuf and pbuf
ips_t *ipsec(int protocol);

// read()
static int read_ips(ips_t *ips, struct ipsec_payload *pld);

// write()
static int write_ips(ips_t *ips, struct ipsec_payload *pld);

// close()
int close_ips(ips_t *ips);

#endif