#include "tcpip.h"
#include "utils_t.h"


static uint32_t tcpip_id;

tcpip_t *tcpip(in_addr_t addr, uint16_t port) {
    tcpip_t *tcpip = (tcpip_t *) malloc(sizeof(tcpip_t));
    if (tcpip == NULL) {
        eprintf("tcpip_t malloc failed\n");
        abort();
    }

    tcpip->id = tcpip_id++;

    tcpip->src_ip.s_addr = inet_addr(IPSEC_SRC_ADDR);
    tcpip->dst_ip.s_addr = addr;

    tcpip->src_port = IPSEC_SRC_PORT;
    tcpip->dst_port = port;

    tcpip->ips = ipsec(PROTO_TCP);
    tcpip->ips->tcpip = tcpip;

    tcpip->rbuf = (fifo_t *) malloc(sizeof(fifo_t));
    fifo_alloc(tcpip->rbuf, 16 * PKT_SIZE_PADDING);

    tcpip->on_recv = tcpip_on_recv;

    return tcpip;
}

int connect(tcpip_t *tcpip) {
    eprintf("stub!");
    return -1;
}

// blocked-IO
int read(tcpip_t *tcpip, void *buf, int len) {
    // read len bytes from the tcpip->rbuf into buf
    assert(tcpip != NULL && buf != NULL);
    // eprintf("%s: tcpip: %p, buf: %p, len: %d\n", __func__, tcpip, buf, len);
    fifo_read(tcpip->rbuf, buf, len);
}

int write(tcpip_t *tcpip, const void *buf, int len) {
    eprintf("stub!");
    return -1;
}

int close(tcpip_t *tcpip) {
    fifo_free(tcpip->rbuf);
    free(tcpip);

    return 0;
}

/*
TCP Reassembly workflow:
1. Upon receiving a TCP packet, extract its flow id (4 tuples)
2. For each flow, maintain a queue storing the incoming packet in order.
   The head pointers of queues are saved in a hashtable, whose keys are flow ids.
3. Insert the incoming segment into the corresponding position of the queue (how to search?)
4. TODO: fix logic error
    Plan A. Set up the queue as a array buffer and regard it as the read buffer of the TCP stack; (No OOO consideration)
    Plan B. Set up the queue as a linked-list and copy the in-order segments to a read buffer; (Can recover OOO packets)
    * Plan C. Use some flags to check the OOO and copy the buffer directly to the read buffer (mitigate the number of copy, can only mark the appearance of OOO)
5. Enclave app read the queue/buffer via a wrapped read() function (has same signature as system read())

Myth:
Should each flow being handled by a thread? It seems to be ridiculous when the num. of flows blooms
greatly.
But what if maintaining a thread pool? What about the performance influenced by the lock introduced by the synchronization requirement?
*/


#ifdef SINGLE_FLOW

static void tcpip_on_recv(tcpip_t *tcpip, uint32_t seq, void *data,
                          uint16_t len) {
  static uint32_t last_seq = 0;
  assert(data != NULL && tcpip != NULL);

  if (unlikely(last_seq >= seq)) {
    eprintf("TCP Retransmission detected at seq %d\n", seq);
    abort();
  }
  last_seq = seq;

  fifo_write(tcpip->rbuf, data, len);
}

#else

cuckoo_hash htable; // save the fid->tcpip hash mapping

static void tcpip_on_recv(ip_dgram_t *ip_pkt) {
    assert(ip_pkt != NULL);

    tcp_fid_t fid = GET_TCP_FID(ip_pkt);
    cuckoo_item_t *item = cuckoo_hash_lookup(&htable, fid);

    int payload_len;

    if (unlikely(item == NULL)) {
        // new flow, create a new rbuf
        tcp_rbuf_t *rbuf = (tcp_rbuf_t *) malloc(sizeof(tcp_rbuf_t));
        rbuf->fid = fid;
        fifo_alloc(rbuf->fifo, sizeof(tcp_seg_t) * 1000);

        tcp_seg_t *seg = (tcp_seg_t *) malloc(sizeof(tcp_seg_t));

        seg->ack_num = ip_pkt->tcp_pkt.hdr.ack_num;
        seg->seq_num = ip_pkt->tcp_pkt.hdr.seq_num;
        seg->len = PAYLOAD_LEN(ip_pkt);
        seg->data = (char *) malloc(seg->len);

        cuckoo_hash_insert(&htable, fid, seg); // TODO: completely free seg after use
    }
}

#endif