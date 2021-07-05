/*
    A FIFO ring buffer that support unbounded byte stream 
    communication between single producer and single consumer.

    Part of code copied from Linux kernel.
*/

#ifndef _FIFO_H_
#define _FIFO_H_

#include <sys/types.h>
#include <unistd.h>

#define __inline inline
#define __always_inline __inline __attribute__((__always_inline__))

typedef struct __fifo
{
    unsigned int in;
    unsigned int out;
    unsigned int mask;
    unsigned long long ttl_rx_byte;
    unsigned long long ttl_tx_byte;
    void *data;
} fifo_t;

/**
 * fls - find last set bit in word
 * @x: the word to search
 *
 * This is defined in a similar way as the libc and compiler builtin
 * ffs, but returns the position of the most significant set bit.
 *
 * fls(value) returns 0 if value is 0 or the position of the last
 * set bit if value is nonzero. The last (most significant) bit is
 * at position 32.
 */
static __always_inline int fls(unsigned int x)
{
    int r;

    asm("bsrl %1,%0\n\t"
        "jnz 1f\n\t"
        "movl $-1,%0\n"
        "1:"
        : "=r"(r)
        : "rm"(x));

    return r + 1;
}

static __always_inline int fls64(unsigned long long x)
{
    int bitpos = -1;
    /*
	 * AMD64 says BSRQ won't clobber the dest reg if x==0; Intel64 says the
	 * dest reg is undefined if x==0, but their CPU architect says its
	 * value is written to set it to the same as before.
	 */
    asm("bsrq %1,%q0"
        : "+r"(bitpos)
        : "rm"(x));

    return bitpos + 1;
}

static inline __attribute__((const)) int __ilog2_u32(unsigned int n)
{
    return fls(n) - 1;
}

static inline __attribute__((const)) int __ilog2_u64(unsigned long long n)
{
    return fls64(n) - 1;
}

static inline unsigned fls_long(unsigned long l)
{
    if (sizeof(l) == 4)
        return fls(l);
    return fls64(l);
}

/**
 * ilog2 - log base 2 of 32-bit or a 64-bit unsigned value
 * @n: parameter
 *
 * constant-capable log of base 2 calculation
 * - this can be used to initialise global variables from constant data, hence
 * the massive ternary operator construction
 *
 * selects the appropriately-sized optimised version depending on sizeof(n)
 */
#define ilog2(n)                                                                                              \
    (                                                                                                         \
        __builtin_constant_p(n) ? ((n) < 2 ? 0 : 63 - __builtin_clzll(n)) : (sizeof(n) <= 4) ? __ilog2_u32(n) \
                                                                                             : __ilog2_u64(n))

/*
 * round up to nearest power of two
 */
static inline __attribute__((const)) unsigned long __roundup_pow_of_two(unsigned long n)
{
    return 1UL << fls_long(n - 1);
}

#define roundup_pow_of_two(n)                                                     \
    (                                                                             \
        __builtin_constant_p(n) ? (                                               \
                                      (n == 1) ? 1 : (1UL << (ilog2((n)-1) + 1))) \
                                : __roundup_pow_of_two(n))

void fifo_alloc(fifo_t *fifo, unsigned int size);
void fifo_free(fifo_t *fifo);
unsigned int fifo_write(fifo_t *fifo, const void *buf, unsigned int len);
unsigned int fifo_read(fifo_t *fifo, void *buf, unsigned int len);

#endif