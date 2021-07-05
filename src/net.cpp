#include "net.h"
#include "limits.h"

#define ntohl(x) __builtin_bswap32(x)
#define ntohs(x) __builtin_bswap16(x)
#define htonl(x) __builtin_bswap32(x)
#define htons(x) __builtin_bswap16(x)

/* Check whether "cp" is a valid ASCII representation of an IPv4
   Internet address and convert it to a binary address.  Returns 1 if
   the address is valid, 0 if not.  This replaces inet_addr, the
   return value from which cannot distinguish between failure and a
   local broadcast address.  Write a pointer to the first
   non-converted character to *endp.  */
static int inet_aton_end(const char *cp, struct in_addr *addr, const char **endp)
{
    static const in_addr_t max[4] = {0xffffffff, 0xffffff, 0xffff, 0xff};
    in_addr_t val;
    char c;
    union iaddr
    {
        uint8_t bytes[4];
        uint32_t word;
    } res;
    uint8_t *pp = res.bytes;
    int digit;

    res.word = 0;
    c = *cp;
    for (;;)
    {
        /* Collect number up to ``.''.  Values are specified as for C:
         0x=hex, 0=octal, isdigit=decimal.  */
        if (!isdigit(c))
            goto ret_0;
        {
            char *endp;
            unsigned long ul = strtoul(cp, &endp, 0);
            if (ul == ULONG_MAX && errno == ERANGE)
                goto ret_0;
            if (ul > 0xfffffffful)
                goto ret_0;
            val = ul;
            digit = cp != endp;
            cp = endp;
        }
        c = *cp;
        if (c == '.')
        {
            /* Internet format:
             a.b.c.d
             a.b.c        (with c treated as 16 bits)
             a.b        (with b treated as 24 bits).  */
            if (pp > res.bytes + 2 || val > 0xff)
                goto ret_0;
            *pp++ = val;
            c = *++cp;
        }
        else
            break;
    }
    /* Check for trailing characters.  */
    if (c != '\0' && (!isascii(c) || !isspace(c)))
        goto ret_0;
    /*  Did we get a valid digit?  */
    if (!digit)
        goto ret_0;
    /* Check whether the last part is in its limits depending on the
     number of parts in total.  */
    if (val > max[pp - res.bytes])
        goto ret_0;
    if (addr != NULL)
        addr->s_addr = res.word | htonl(val);
    *endp = cp;

    return 1;
ret_0:
    return 0;
}

/* ASCII IPv4 Internet address interpretation routine.  The value
   returned is in network order.  */
in_addr_t inet_addr(const char *cp)
{
    struct in_addr val;
    const char *endp;
    if (inet_aton_end(cp, &val, &endp))
        return val.s_addr;
    return ((in_addr_t) 0xffffffff);
}