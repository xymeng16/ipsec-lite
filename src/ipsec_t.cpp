#include "ipsec_t.h"
#include <cstring>
#include <cstdlib>
#include <pthread.h>
#include <cstdint>

#include "checksum_asm.h"


static uint32_t ips_id;
static pthread_t ips_thrd;
extern double ips_recv_time;
long ssec, snsec, esec, ensec;
// this routine continuously read the cbuf and try to fetch
// a IPSec packet to decrypt and send to TCP stack to reassemble
static void *ipsec_driver(void *p)
{
    assert(p != NULL);

    ips_t *ips = (ips_t *)p;
    struct ipsec_payload ips_pld;
    int ret, count = 0;
    while (1)
    {
        ring_buf_read(ips->cbuf, &ips_pld);
        aes128gcm_decrypt(&ips_pld, ENCRYPTED_SIZE, &ips_pld, ips_pld.mac);

        if (unlikely(__builtin_bswap16(ips_pld.iph.total_len) == IPH_SIZE + TCPH_SIZE))
        {
            // no payload
            eprintf(MAG("strange no payload\n"));
            continue;
        }
        
        // eprintf("this ips_pld seq num is %d, mac is ", __builtin_bswap32(ips_pld.tcph.seq_num));
        // for (int j = 0; j < 16; j++)
        // {
        //     eprintf("%x", ips_pld.mac[j]);
        // }
        // eprintf("\n");

        // ip checksum
        ips_pld.iph.checksum = __builtin_bswap16(ips_pld.iph.checksum);
        if (unlikely(fast_csum(&ips_pld.iph, 5, 0)))
        {
            eprintf("#%d packet IP Checksum is 0x%x!", count++, fast_csum(&ips_pld.iph, 5, 0));
            abort();
        }

        // tcp checksum
        ips_pld.tcph.chksum = __builtin_bswap16(ips_pld.tcph.chksum);
        if (unlikely(fast_csum((void *)&ips_pld.tcph,
                               (TCPH_SIZE + MAX_PAYLOAD_SIZE) / 4,
                               csum_tcpudp_nofold(
                                   ips_pld.iph.src_ip.s_addr,
                                   ips_pld.iph.dst_ip.s_addr,
                                   TCPH_SIZE + MAX_PAYLOAD_SIZE,
                                   IPPROTO_TCP,
                                   0))))
        {
            eprintf("#%d packet TCP Checksum is 0x%x!", count,
                    fast_csum((void *)&ips_pld.tcph,
                              (TCPH_SIZE + MAX_PAYLOAD_SIZE) / 4,
                              csum_tcpudp_nofold(
                                  ips_pld.iph.src_ip.s_addr,
                                  ips_pld.iph.dst_ip.s_addr,
                                  TCPH_SIZE + MAX_PAYLOAD_SIZE,
                                  IPPROTO_TCP,
                                  0)));
            abort();
        }


//        ocall_get_time(&ssec, &snsec);
        // send to tcp...
        ips->tcpip->on_recv(ips->tcpip, __builtin_bswap32(ips_pld.tcph.seq_num) + 1, ips_pld.raw, MAX_PAYLOAD_SIZE);
//        ocall_get_time(&esec, &ensec);
//        ips_recv_time += TIME_ELAPSED_IN_MS(ssec, snsec, esec, ensec);
    }
}

// initialize the ips_t structure, allocate cbuf
// and run the ipsec driver thread
ips_t *ipsec(int protocol)
{
    ips_t *ips = (ips_t *)malloc(sizeof(ips_t));
    if (unlikely(ips == NULL))
    {
        eprintf(RED("ips_t malloc failed\n"));
        abort();
    }

    ips->protocol = protocol;

    // ips->cbuf = (ring_buf_t *)malloc(sizeof(ring_buf_t));

    // if (unlikely(ips->cbuf == NULL))
    // {
    //     eprintf(RED("ips_t->cbuf malloc failed\n"));
    //     abort();
    // }

    ocall_rbuf_init((void **)&ips->cbuf);

    pthread_create(&ips_thrd, NULL, ipsec_driver, ips);

    return ips;
}

// read()
static int read_ips(ips_t *ips, struct ipsec_payload *pld)
{
    // read one ipsec_payload from the cbuf
    assert(ips != NULL && pld != NULL);

    ring_buf_read(ips->cbuf, pld);
}

// write()
static int write_ips(ips_t *ips, struct ipsec_payload *pld)
{
    eprintf("stub!\n");
    return -1;
}

// close()
int close_ips(ips_t *ips)
{
    if (ips == NULL)
    {
        return 0;
    }
    if (ips->tcpip == NULL)
    {
        eprintf(RED("tcpip strangely closed before ipsec close\n"));
        return -1;
    }
    ring_buf_deinit(ips->cbuf);
    close(ips->tcpip);
    free(ips);
    return 0;
}
