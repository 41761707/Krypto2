/*
 * MBEDTLS MD_5 with changed IV values for university purposes 
 * http://www.apache.org/licenses/LICENSE-2.0
 *
*/

#ifndef MD5_H
#define MD5_H

#include <cstring>
#include <cstdint>

inline void mbedtls_put_unaligned_uint32(void *p, uint32_t x);
inline uint32_t mbedtls_get_unaligned_uint32(const void *p);
#define MBEDTLS_BSWAP32 __builtin_bswap32
#define MBEDTLS_IS_BIG_ENDIAN ((__BYTE_ORDER__) == (__ORDER_BIG_ENDIAN__))
#define MBEDTLS_PUT_UINT32_LE(n, data, offset)                                   \
    {                                                                            \
        if (MBEDTLS_IS_BIG_ENDIAN)                                               \
        {                                                                        \
            mbedtls_put_unaligned_uint32((data) + (offset), MBEDTLS_BSWAP32((uint32_t) (n))); \
        }                                                                        \
        else                                                                     \
        {                                                                        \
            mbedtls_put_unaligned_uint32((data) + (offset), ((uint32_t) (n)));   \
        }                                                                        \
    }
#define MBEDTLS_GET_UINT32_LE(data, offset)                                \
    ((MBEDTLS_IS_BIG_ENDIAN)                                               \
        ? MBEDTLS_BSWAP32(mbedtls_get_unaligned_uint32((data) + (offset))) \
        : mbedtls_get_unaligned_uint32((data) + (offset))                  \
    )


inline void mbedtls_put_unaligned_uint32(void *p, uint32_t x)
{
    memcpy(p, &x, sizeof(x));
}


inline uint32_t mbedtls_get_unaligned_uint32(const void *p)
{
    uint32_t r;
    memcpy(&r, p, sizeof(r));
    return r;
}

struct Context{
    uint32_t total[2];
    uint32_t state[4];
    unsigned char buffer[64];
};
int mbedtls_md5_procedure(Context *ctx,
                       const unsigned char *input,
                       size_t ilen, unsigned char output[16]);
int mbedtls_internal_md5_process(Context *ctx,
                                 const unsigned char data[64]);
int mbedtls_modified_md5_procedure(Context *ctx,
                       unsigned char *input,
                       size_t ilen, unsigned char output[16],
                       bool modify);
int mbedtls_2nd_iter_md5(Context *ctx,
                                 unsigned char data[64],
                                 bool modify,
                                 bool mode);




#endif