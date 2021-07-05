#include "fifo.h"
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <cstdio>

#define min(a, b) ((a) < (b) ? (a) : (b))

static inline unsigned int fifo_unused(fifo_t *fifo)
{
    return (fifo->mask + 1) - (fifo->in - fifo->out);
}

void fifo_alloc(fifo_t *fifo, unsigned int size)
{
    assert(fifo != nullptr);
    // round up size to the next power of 2 for the bitwise optimization
    size = roundup_pow_of_two(size);

    fifo->in = fifo->out = 0;
    assert((fifo->data = malloc(size)));
    fifo->mask = size - 1;
    fifo->ttl_rx_byte = fifo->ttl_tx_byte = 0;
}

void fifo_free(fifo_t *fifo)
{
    assert(fifo != nullptr && fifo->data != nullptr);
    free(fifo->data);
    fifo->in = 0;
    fifo->out = 0;
    fifo->data = nullptr;
    fifo->mask = 0;
}

static void fifo_copy_in(fifo_t *fifo, const void *src, unsigned int len, unsigned int off)
{
    assert(fifo != nullptr && src != nullptr);

    unsigned int size = fifo->mask + 1;
    unsigned int l;

    off &= fifo->mask;
    l = min(len, size - off);
#ifdef _DEBUG
    if (l != len)
    {
        printf("write rollback\n");
    }
#endif
    memcpy(fifo->data + off, src, l);     // handle the common part
    memcpy(fifo->data, src + l, len - l); // handle the uncommon part if need
    /*
	 * make sure that the data in the fifo is up to date before
	 * incrementing the fifo->in index counter
	 */
    asm volatile(""
                 :
                 :
                 : "memory");
}

unsigned int fifo_write(fifo_t *fifo, const void *buf, unsigned int len)
{
    assert(fifo != nullptr && buf != nullptr);

    unsigned int l;

    while (len > fifo_unused(fifo))
        ; // busy-waiting until space is available

    fifo_copy_in(fifo, buf, len, fifo->in);
    // above function contains a memory barrier make sure that fifo->in
    // is updated after the copy of data is over

    fifo->in += len;
    fifo->ttl_rx_byte += len;
    return len;
}

static void fifo_copy_out(fifo_t *fifo, void *dst, unsigned int len, unsigned int off)
{
    assert(fifo != nullptr && dst != nullptr);

    unsigned int size = fifo->mask + 1;
    unsigned int l;

    off &= fifo->mask;
    l = min(len, size - off);
#ifdef _DEBUG
    if (l != len)
    {
        printf("read rollback\n");
    }
#endif
    memcpy(dst, fifo->data + off, l);     // handle the common part
    memcpy(dst + l, fifo->data, len - l); // handle the uncommon part if need
    // above part breaks the cache line, should be optimized if possible

    asm volatile(""
                 :
                 :
                 : "memory");
}

/* TODO:***NEED TO BE CORRECTED***
follow the POSIX read() style (given the expected N bytes to read, n is the buf size):
    unsigned int len = 0, nbytes = 0;
    while((nbytes = read(fd, buf, n)) > 0)
    {
        len += nbytes;
        buf += nbytes;
        // do something using the buf or wait for the full data stream...
        if (len >= N)
            break;
    }
*/
unsigned int fifo_read(fifo_t *fifo, void *buf, unsigned int len)
{
    assert(fifo != nullptr && buf != nullptr);

    unsigned int l;

    while (len > (fifo->in - fifo->out))
        ;
    // printf("busy waitting...\n"); // busy-waiting until data is available
    // should we hand over this to the user-side?

    fifo_copy_out(fifo, buf, len, fifo->out);
    fifo->out += len;
    fifo->ttl_tx_byte += len;
    return len;
}
