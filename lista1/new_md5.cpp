/*
 * MBEDTLS MD_5 with changed IV values for university purposes 
 * http://www.apache.org/licenses/LICENSE-2.0
 *
*/

#include "md5.hpp"


int mbedtls_modified_md5_procedure(Context *ctx,
                       unsigned char *input,
                       size_t ilen,
                       unsigned char output[16],
                       bool modify)
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    if (modify){
        ctx->state[0] = 0x52589324;
        ctx->state[1] = 0x3093d7ca;
        ctx->state[2] = 0x2a06dc54;
        ctx->state[3] = 0x20c5be06;
    }
    else {
        ctx->state[0] = 0xd2589324;
        ctx->state[1] = 0xb293d7ca;
        ctx->state[2] = 0xac06dc54;
        ctx->state[3] = 0xa2c5be06;
    }

    int ret = -1;
    size_t fill;
    uint32_t left;

    if (ilen == 0) {
        return 0;
    }

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += (uint32_t) ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if (ctx->total[0] < (uint32_t) ilen) {
        ctx->total[1]++;
    }

    if (left && ilen >= fill) {
        memcpy((void *) (ctx->buffer + left), input, fill);
        if ((ret = mbedtls_2nd_iter_md5(ctx, ctx->buffer, modify,1)) != 0) {
            return ret;
        }

        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while (ilen >= 64) {
        if ((ret = mbedtls_2nd_iter_md5(ctx, input, modify,1)) != 0) {
            return ret;
        }

        input += 64;
        ilen  -= 64;
    }

    if (ilen > 0) {
        memcpy((void *) (ctx->buffer + left), input, ilen);
    }

    MBEDTLS_PUT_UINT32_LE(ctx->state[0], output,  0);
    MBEDTLS_PUT_UINT32_LE(ctx->state[1], output,  4);
    MBEDTLS_PUT_UINT32_LE(ctx->state[2], output,  8);
    MBEDTLS_PUT_UINT32_LE(ctx->state[3], output, 12);

    return 0;
}
int mbedtls_2nd_iter_md5(Context *ctx,
                                 unsigned char data[64],
                                 bool modify,
                                 bool mode)
{
    uint32_t M[16];
    uint32_t A; 
    uint32_t B; 
    uint32_t C; 
    uint32_t D;
    M[0] = MBEDTLS_GET_UINT32_LE(data,  0);
    M[1] = MBEDTLS_GET_UINT32_LE(data,  4);
    M[2] = MBEDTLS_GET_UINT32_LE(data,  8);
    M[3] = MBEDTLS_GET_UINT32_LE(data, 12);
    M[4] = MBEDTLS_GET_UINT32_LE(data, 16);
    M[5] = MBEDTLS_GET_UINT32_LE(data, 20);
    M[6] = MBEDTLS_GET_UINT32_LE(data, 24);
    M[7] = MBEDTLS_GET_UINT32_LE(data, 28);
    M[8] = MBEDTLS_GET_UINT32_LE(data, 32);
    M[9] = MBEDTLS_GET_UINT32_LE(data, 36);
    M[10] = MBEDTLS_GET_UINT32_LE(data, 40);
    M[11] = MBEDTLS_GET_UINT32_LE(data, 44);
    M[12] = MBEDTLS_GET_UINT32_LE(data, 48);
    M[13] = MBEDTLS_GET_UINT32_LE(data, 52);
    M[14] = MBEDTLS_GET_UINT32_LE(data, 56);
    M[15] = MBEDTLS_GET_UINT32_LE(data, 60);

#define S(x, n)                                                          \
    (((x) << (n)) | (((x) & 0xFFFFFFFF) >> (32 - (n))))

#define P(a, b, c, d, k, s, t)                                                \
    do                                                                  \
    {                                                                   \
        (a) += F((b), (c), (d)) + M[(k)] + (t);                     \
        (a) = S((a), (s)) + (b);                                         \
    } while (0)

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];

#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
    if (modify){
        uint32_t tmp;

        P(A, B, C, D,  0,  7, 0xD76AA478);
        //M1
        /*tmp = calc_new(A, 0xa000820, 0x84200000, 0x0, ~B);
        M[0] += S((tmp - A), 7);
        A = tmp;*/
        if(mode)
        {
            tmp = A & ~0xa000820 & 0xFFFFFFFF;
            tmp = tmp | 0x84200000;
            tmp = (tmp & ~0x0) | B & 0x0;
            M[0] += S((tmp - A), 7);
            A = tmp;
        }
        //M0
        //tu nic


        P(D, A, B, C,  1, 12, 0xE8C7B756);
        //M1
        /*tmp = calc_new(D, 0x2208026, 0x8c000800, 0x701f10c0, A);
        M[1] += S((tmp-D),12);
        D = tmp;*/
        if(mode)
        {
            tmp = D & ~0x2208026 & 0xFFFFFFFF;
            tmp = tmp | 0x8c000800;
            tmp = (tmp & ~0x701f10c0) | A & 0x701f10c0;
            M[1] += S((tmp-D),12);
            D = tmp;
        }
        //M0
        //tu nic
        P(C, D, A, B,  2, 17, 0x242070DB);
        //M1
        /*tmp = calc_new(C, 0x40201080, 0x3e1f0966, 0x80000018, D);
        M[2] += S((tmp - C), 17);
        C = tmp;*/
        if(mode)
        {
            tmp = C & ~0x40201080 & 0xFFFFFFFF;
            tmp = tmp | 0x3e1f0966;
            tmp = (tmp & ~0x80000018) | D & 0x80000018;
            M[2] += S((tmp - C), 17);
            C = tmp;
        }
        //M0
        //tmp = calc_new(C, 0x80840, 0x0, 0x0, D);

        P(B, C, D, A,  3, 22, 0xC1BDCEEE);
        //M1
        /*tmp = calc_new(B, 0x443b19ee, 0x3a040010, 0x80000601, C);
        M[3] += S((tmp - B), 22);
        B = tmp;*/
        if(mode)
        {
            tmp = B & ~0x443b19ee & 0xFFFFFFFF;
            tmp = tmp | 0x3a040010;
            tmp = (tmp & ~0x80000601) | C & 0x80000601;
            M[3] += S((tmp - B), 22);
            B = tmp;
        }
        //M0
        //tmp = calc_new(B, 0x800040, 0x80080800, 0x77f780, C);

        P(A, B, C, D,  4,  7, 0xF57C0FAF);
        //M1
        //tmp = calc_new(A, 0xb41011af, 0x482f0e50, 0x80000000, ~B);
        if(mode)
        {
            tmp = A & ~0xb41011af & 0xFFFFFFFF;
            tmp = tmp | 0x482f0e50;
            tmp = (tmp & ~0x80000000) | ~B & 0x80000000;
            M[4] += S((tmp - A), 7);
            A = tmp;
        }
        //M0
        //tmp = calc_new(A,  0x88400025, 0x88400025, 0x0, ~B);

        P(D, A, B, C,  5, 12, 0x4787C62A);
        //M1
        /*tmp = calc_new(D, 0x9a1113a9, 0x4220c56, 0x80000000, A);
        M[5] += S((tmp - D), 12);
        D = tmp;*/
        if(mode)
        {
            tmp = D & ~0x9a1113a9 & 0xFFFFFFFF;
            tmp = tmp | 0x4220c56;
            tmp = (tmp & ~0x80000000) | A & 0x80000000;
            M[5] += S((tmp - D), 12);
            D = tmp;
        }
        //M0
        //tmp = calc_new(D, 0x888043a4, 0x27fbc41, 0x7500001a, A);
        P(C, D, A, B,  6, 17, 0xA8304613);
        //M1
        /*tmp = calc_new(C, 0x83201c0, 0x16011e01, 0x81808000, D ^ 0x80000000);
        M[6] += S((tmp - C), 17);
        C = tmp;*/
        if(mode)
        {
            tmp = C & ~0x83201c0 & 0xFFFFFFFF;
            tmp = tmp | 0x16011e01;
            tmp = (tmp & ~0x81808000) | (D ^ 0x80000000) & 0x81808000;
            M[6] += S((tmp - C), 17);
            C = tmp;
        }
        //M0
        //tmp = calc_new(C, 0xfc0107df, 0x3fef820, 0x0,D);
        P(B, C, D, A,  7, 22, 0xFD469501);
        //M1
        /*tmp = calc_new(B, 0x1b810001, 0x043283c0, 0x80000002, C);
        M[7] += S((tmp - B), 22);
        B = tmp;*/
        if(mode)
        {
            tmp = B & ~0x1b810001 & 0xFFFFFFFF;
            tmp = tmp | 0x043283c0;
            tmp = (tmp & ~0x80000002) | C & 0x80000002;
            M[7] += S((tmp - B), 22);
            B = tmp;
        }
        //M0
        //tmp = calc_new(B, 0xfe0eaabf, 0x1910540, 0x0, C);

        P(A, B, C, D,  8,  7, 0x698098D8);
        //M1
        /*tmp = calc_new(A, 0x3828202, 0x1c0101c1, 0x80001000, B);
        M[8] += S((tmp - A), 7);
        A = tmp;*/
        if(mode)
        {
            tmp = A & ~0x3828202 & 0xFFFFFFFF;
            tmp = tmp | 0x1c0101c1;
            tmp = (tmp & ~0x80001000) | B & 0x80001000;
            M[8] += S((tmp - A), 7);
            A = tmp;
        }
        //M0
        //tmp = calc_new(A, 0x40f80c2, 0xfb102f3d, 0x1000, B);

        P(D, A, B, C,  9, 12, 0x8B44F7AF);
        //M1
        /*tmp = calc_new(D, 0x41003, 0x078383c0, 0x80000000, A);
        M[9] += S((tmp - D), 12);
        D = tmp;*/
        if(mode)
        {
            tmp = D & ~0x41003 & 0xFFFFFFFF;
            tmp = tmp | 0x078383c0;
            tmp = (tmp & ~0x80000000) | A & 0x80000000;
            M[9] += S((tmp - D), 12);
            D = tmp;
        }
        //M0
        //tmp = calc_new(D, 0x80802183, 0x401f9040, 0x0, A);

        P(C, D, A, B, 10, 17, 0xFFFF5BB1);
        //M1
        /*tmp = calc_new(C, 0x21000, 0x000583c3, 0x80086000, D);
        M[10] += S((tmp - C), 17);
        C = tmp;*/
        if(mode)
        {
            tmp = C & ~0x21000 & 0xFFFFFFFF;
            tmp = tmp | 0x000583c3;
            tmp = (tmp & ~0x80086000) | D & 0x80086000;
            M[10] += S((tmp - C), 17);
            C = tmp;
        }
        //M0
        //tmp = calc_new(C, 0xc00e3101, 0x180c2, 0x4000, D);

        P(B, C, D, A, 11, 22, 0x895CD7BE);
        //M1
        /*tmp = calc_new(B, 0x7e000, 0x00081080, 0xff000000, C);
        M[11] += S((tmp - B), 22);
        B = tmp;*/
        if(mode)
        {
            tmp = B & ~0x7e000 & 0xFFFFFFFF;
            tmp = tmp | 0x00081080;
            tmp = (tmp & ~0xff000000) | C & 0xff000000;
            M[11] += S((tmp - B), 22);
            B = tmp;
        }
        //M0
        //tmp = calc_new(B, 0xc007e080, 0x81100, 0x3000000, C);

        P(A, B, C, D, 12,  7, 0x6B901122);
        //M1
        //tmp = calc_new(A, 0x40000080, 0x3f0fe008, 0x80000000, ~B);
        //M[12] += S((tmp - A), 7);
        //A = tmp;
        if(mode)
        {
            tmp = A & ~0x40000080 & 0xFFFFFFFF;
            tmp = tmp |  0x3f0fe008;
            tmp = (tmp & ~0x80000000) | ~B & 0x80000000;
            M[12] += S((tmp - A), 7);
            A = tmp;
        }
        //M0
        //tmp = calc_new(A,0x82000180, 0x410fe008, 0x0, ~B);
        P(D, A, B, C, 13, 12, 0xFD987193);
        //M1
        /*tmp = calc_new(D, 0x3f040000, 0x400be088, 0x80000000, A);
        M[13] += S((tmp - D), 12);
        D = tmp;*/
        if(mode)
        {
            tmp = D & ~0x3f040000 & 0xFFFFFFFF;
            tmp = tmp |  0x400be088;
            tmp = (tmp & ~0x80000000) | A & 0x80000000;
            M[13] += S((tmp - D), 12);
            D = tmp;
        }
        //M0
        //tmp = calc_new(D, 0xa3040000, 0xbe188, 0x0, A);

        P(C, D, A, B, 14, 17, 0xA679438E);
        //M1
        /*tmp = calc_new(C, 0x02008008, 0x7d000000, 0x80000000, D);
        M[14] += S((tmp - C), 17);
        C = tmp;*/
        if(mode)
        {
            tmp = C & ~0x02008008 & 0xFFFFFFFF;
            tmp = tmp |  0x7d000000;
            tmp = (tmp & ~0x80000000) | D & 0x80000000;
            M[14] += S((tmp - C), 17);
            C = tmp;
        }
        //M0
        //tmp = calc_new(C, 0x82000008, 0x21008000, 0x0, D);

        P(B, C, D, A, 15, 22, 0x49B40821);
        //M1
        /*tmp = calc_new(B, 0x00000000, 0x20000000, 0x80000000, C);
        M[15] += S((tmp - B), 22);
        B = tmp;*/
        if(mode)
        {
            tmp = B & ~0x00000000 & 0xFFFFFFFF;
            tmp = tmp |  0x20000000;
            tmp = (tmp & ~0x80000000) | C & 0x80000000;
            M[15] += S((tmp - B), 22);
            B = tmp;
        }
        //M0
        //tmp = calc_new(B, 0x80000000, 0x20000000, 0x0, C);
    }
    else {
        P(A, B, C, D,  0,  7, 0xD76AA478);
        P(D, A, B, C,  1, 12, 0xE8C7B756);
        P(C, D, A, B,  2, 17, 0x242070DB);
        P(B, C, D, A,  3, 22, 0xC1BDCEEE);
        P(A, B, C, D,  4,  7, 0xF57C0FAF);
        P(D, A, B, C,  5, 12, 0x4787C62A);
        P(C, D, A, B,  6, 17, 0xA8304613);
        P(B, C, D, A,  7, 22, 0xFD469501);
        P(A, B, C, D,  8,  7, 0x698098D8);
        P(D, A, B, C,  9, 12, 0x8B44F7AF);
        P(C, D, A, B, 10, 17, 0xFFFF5BB1);
        P(B, C, D, A, 11, 22, 0x895CD7BE);
        P(A, B, C, D, 12,  7, 0x6B901122);
        P(D, A, B, C, 13, 12, 0xFD987193);
        P(C, D, A, B, 14, 17, 0xA679438E);
        P(B, C, D, A, 15, 22, 0x49B40821);
    }

#undef F

#define F(x, y, z) ((y) ^ ((z) & ((x) ^ (y))))

    P(A, B, C, D,  1,  5, 0xF61E2562);
    P(D, A, B, C,  6,  9, 0xC040B340);
    P(C, D, A, B, 11, 14, 0x265E5A51);
    P(B, C, D, A,  0, 20, 0xE9B6C7AA);
    P(A, B, C, D,  5,  5, 0xD62F105D);
    P(D, A, B, C, 10,  9, 0x02441453);
    P(C, D, A, B, 15, 14, 0xD8A1E681);
    P(B, C, D, A,  4, 20, 0xE7D3FBC8);
    P(A, B, C, D,  9,  5, 0x21E1CDE6);
    P(D, A, B, C, 14,  9, 0xC33707D6);
    P(C, D, A, B,  3, 14, 0xF4D50D87);
    P(B, C, D, A,  8, 20, 0x455A14ED);
    P(A, B, C, D, 13,  5, 0xA9E3E905);
    P(D, A, B, C,  2,  9, 0xFCEFA3F8);
    P(C, D, A, B,  7, 14, 0x676F02D9);
    P(B, C, D, A, 12, 20, 0x8D2A4C8A);

#undef F

#define F(x, y, z) ((x) ^ (y) ^ (z))

    P(A, B, C, D,  5,  4, 0xFFFA3942);
    P(D, A, B, C,  8, 11, 0x8771F681);
    P(C, D, A, B, 11, 16, 0x6D9D6122);
    P(B, C, D, A, 14, 23, 0xFDE5380C);
    P(A, B, C, D,  1,  4, 0xA4BEEA44);
    P(D, A, B, C,  4, 11, 0x4BDECFA9);
    P(C, D, A, B,  7, 16, 0xF6BB4B60);
    P(B, C, D, A, 10, 23, 0xBEBFBC70);
    P(A, B, C, D, 13,  4, 0x289B7EC6);
    P(D, A, B, C,  0, 11, 0xEAA127FA);
    P(C, D, A, B,  3, 16, 0xD4EF3085);
    P(B, C, D, A,  6, 23, 0x04881D05);
    P(A, B, C, D,  9,  4, 0xD9D4D039);
    P(D, A, B, C, 12, 11, 0xE6DB99E5);
    P(C, D, A, B, 15, 16, 0x1FA27CF8);
    P(B, C, D, A,  2, 23, 0xC4AC5665);

#undef F

#define F(x, y, z) ((y) ^ ((x) | ~(z)))

    P(A, B, C, D,  0,  6, 0xF4292244);
    P(D, A, B, C,  7, 10, 0x432AFF97);
    P(C, D, A, B, 14, 15, 0xAB9423A7);
    P(B, C, D, A,  5, 21, 0xFC93A039);
    P(A, B, C, D, 12,  6, 0x655B59C3);
    P(D, A, B, C,  3, 10, 0x8F0CCC92);
    P(C, D, A, B, 10, 15, 0xFFEFF47D);
    P(B, C, D, A,  1, 21, 0x85845DD1);
    P(A, B, C, D,  8,  6, 0x6FA87E4F);
    P(D, A, B, C, 15, 10, 0xFE2CE6E0);
    P(C, D, A, B,  6, 15, 0xA3014314);
    P(B, C, D, A, 13, 21, 0x4E0811A1);
    P(A, B, C, D,  4,  6, 0xF7537E82);
    P(D, A, B, C, 11, 10, 0xBD3AF235);
    P(C, D, A, B,  2, 15, 0x2AD7D2BB);
    P(B, C, D, A,  9, 21, 0xEB86D391);

#undef F

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;

    MBEDTLS_PUT_UINT32_LE(M[0], data, 0);
    MBEDTLS_PUT_UINT32_LE(M[1], data, 4);
    MBEDTLS_PUT_UINT32_LE(M[2], data, 8);
    MBEDTLS_PUT_UINT32_LE(M[3], data, 12);
    MBEDTLS_PUT_UINT32_LE(M[4], data, 16);
    MBEDTLS_PUT_UINT32_LE(M[5], data, 20);
    MBEDTLS_PUT_UINT32_LE(M[6], data, 24);
    MBEDTLS_PUT_UINT32_LE(M[7], data, 28);
    MBEDTLS_PUT_UINT32_LE(M[8], data, 32);
    MBEDTLS_PUT_UINT32_LE(M[9], data, 36);
    MBEDTLS_PUT_UINT32_LE(M[10], data, 40);
    MBEDTLS_PUT_UINT32_LE(M[11], data, 44);
    MBEDTLS_PUT_UINT32_LE(M[12], data, 48);
    MBEDTLS_PUT_UINT32_LE(M[13], data, 52);
    MBEDTLS_PUT_UINT32_LE(M[14], data, 56);
    MBEDTLS_PUT_UINT32_LE(M[15], data, 60);

    return 0;
}

