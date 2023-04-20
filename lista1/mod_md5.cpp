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
        if ((ret = mbedtls_modified_internal_md5_process(ctx, ctx->buffer, modify)) != 0) {
            return ret;
        }

        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while (ilen >= 64) {
        if ((ret = mbedtls_modified_internal_md5_process(ctx, input, modify)) != 0) {
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

// new_z = (local.Z & (~zero_bits)) | one_bits
// new_z = ((local.Z & (local.y | (~y_bits))) | (local.y & (y_bits))) 
uint32_t calc_new(uint32_t old_val, uint32_t zero_bits, uint32_t one_bits, uint32_t another_bits, uint32_t another_val){
    uint32_t ones = 0xffffffff;
    uint32_t new_val = (old_val & (zero_bits ^ ones)) | one_bits;
    if (another_bits != 0)
        new_val = ((new_val & (another_val | (~another_bits))) | (another_val & (another_bits)));
    return new_val;
}


int mbedtls_modified_internal_md5_process(Context *ctx,
                                 unsigned char data[64],
                                 bool modify)
{
    struct {
        uint32_t X[16], A, B, C, D;
    } local;

    local.X[0] = MBEDTLS_GET_UINT32_LE(data,  0);
    local.X[1] = MBEDTLS_GET_UINT32_LE(data,  4);
    local.X[2] = MBEDTLS_GET_UINT32_LE(data,  8);
    local.X[3] = MBEDTLS_GET_UINT32_LE(data, 12);
    local.X[4] = MBEDTLS_GET_UINT32_LE(data, 16);
    local.X[5] = MBEDTLS_GET_UINT32_LE(data, 20);
    local.X[6] = MBEDTLS_GET_UINT32_LE(data, 24);
    local.X[7] = MBEDTLS_GET_UINT32_LE(data, 28);
    local.X[8] = MBEDTLS_GET_UINT32_LE(data, 32);
    local.X[9] = MBEDTLS_GET_UINT32_LE(data, 36);
    local.X[10] = MBEDTLS_GET_UINT32_LE(data, 40);
    local.X[11] = MBEDTLS_GET_UINT32_LE(data, 44);
    local.X[12] = MBEDTLS_GET_UINT32_LE(data, 48);
    local.X[13] = MBEDTLS_GET_UINT32_LE(data, 52);
    local.X[14] = MBEDTLS_GET_UINT32_LE(data, 56);
    local.X[15] = MBEDTLS_GET_UINT32_LE(data, 60);

#define S(x, n)                                                          \
    (((x) << (n)) | (((x) & 0xFFFFFFFF) >> (32 - (n))))

#define P(a, b, c, d, k, s, t)                                                \
    do                                                                  \
    {                                                                   \
        (a) += F((b), (c), (d)) + local.X[(k)] + (t);                     \
        (a) = S((a), (s)) + (b);                                         \
    } while (0)

    local.A = ctx->state[0];
    local.B = ctx->state[1];
    local.C = ctx->state[2];
    local.D = ctx->state[3];

#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
    if (modify){
        uint32_t new_a, new_b, new_c, new_d;

        P(local.A, local.B, local.C, local.D,  0,  7, 0xD76AA478);
        new_a = calc_new(local.A, 0xa000820, 0x84200000, 0x80000000, ~local.B);
        local.X[0] += S((new_a - local.A), 7);
        local.A = new_a;

        P(local.D, local.A, local.B, local.C,  1, 12, 0xE8C7B756);
        new_d = calc_new(local.D, 0x2208026, 0x0c000800, 0xf01f10c0, local.A);
        local.X[1] += S((new_d - local.D), 12);
        local.D = new_d;
        
        P(local.C, local.D, local.A, local.B,  2, 17, 0x242070DB);
        new_c = calc_new(local.C, 0x40201080, 0x3e1f0966, 0x80000018, local.D);
        local.X[2] += S((new_c - local.C), 17);
        local.C = new_c;

        P(local.B, local.C, local.D, local.A,  3, 22, 0xC1BDCEEE);
        new_b = calc_new(local.B, 0x443b19ee, 0x3a040010, 0x80000601, local.C);
        local.X[3] += S((new_b - local.B), 22);
        local.B = new_b;

        P(local.A, local.B, local.C, local.D,  4,  7, 0xF57C0FAF);
        new_a = calc_new(local.A, 0xb41011af, 0x482f0e50, 0x80000000, ~local.B);
        local.X[4] += S((new_a - local.A), 7);
        local.A = new_a;

        P(local.D, local.A, local.B, local.C,  5, 12, 0x4787C62A);
        new_d = calc_new(local.D, 0x9a1113a9, 0x4220c56, 0x80000000, local.A);
        local.X[5] += S((new_d - local.D), 12);
        local.D = new_d;

        P(local.C, local.D, local.A, local.B,  6, 17, 0xA8304613);
        new_c = calc_new(local.C, 0x83201c0, 0x16011e01, 0x81808000, local.D ^ 0x80000000);
        local.X[6] += S((new_c - local.C), 17);
        local.C = new_c;

        P(local.B, local.C, local.D, local.A,  7, 22, 0xFD469501);
        new_b = calc_new(local.B, 0x1b810001, 0x043283c0, 0x80000002, local.C);
        local.X[7] += S((new_b - local.B), 22);
        local.B = new_b;

        P(local.A, local.B, local.C, local.D,  8,  7, 0x698098D8);
        new_a = calc_new(local.A, 0x3828202, 0x1c0101c1, 0x80001000, local.B);
        local.X[8] += S((new_a - local.A), 7);
        local.A = new_a;

        P(local.D, local.A, local.B, local.C,  9, 12, 0x8B44F7AF);
        new_d = calc_new(local.D, 0x41003, 0x078383c0, 0x80000000, local.A);
        local.X[9] += S((new_d - local.D), 12);
        local.D = new_d;

        P(local.C, local.D, local.A, local.B, 10, 17, 0xFFFF5BB1);
        new_c = calc_new(local.C, 0x21000, 0x000583c3, 0x80086000, local.D);
        local.X[10] += S((new_c - local.C), 17);
        local.C = new_c;

        P(local.B, local.C, local.D, local.A, 11, 22, 0x895CD7BE);
        new_b = calc_new(local.B, 0x7e000, 0x00081080, 0xff000000, local.C);
        local.X[11] += S((new_b - local.B), 22);
        local.B = new_b;

        P(local.A, local.B, local.C, local.D, 12,  7, 0x6B901122);
        new_a = calc_new(local.A, 0x40000080, 0x3f0fe008, 0x80000000, ~local.B);
        local.X[12] += S((new_a - local.A), 7);
        local.A = new_a;

        P(local.D, local.A, local.B, local.C, 13, 12, 0xFD987193);
        new_d = calc_new(local.D, 0x3f040000, 0x400be088, 0x80000000, local.A);
        local.X[13] += S((new_d - local.D), 12);
        local.D = new_d;

        P(local.C, local.D, local.A, local.B, 14, 17, 0xA679438E);
        new_c = calc_new(local.C, 0x02008008, 0x7d000000, 0x80000000, local.D);
        local.X[14] += S((new_c - local.C), 17);
        local.C = new_c;

        P(local.B, local.C, local.D, local.A, 15, 22, 0x49B40821);
        new_b = calc_new(local.B, 0x00000000, 0x20000000, 0x80000000, local.C);
        local.X[15] += S((new_b - local.B), 22);
        local.B = new_b;
    }
    else {
        P(local.A, local.B, local.C, local.D,  0,  7, 0xD76AA478);
        P(local.D, local.A, local.B, local.C,  1, 12, 0xE8C7B756);
        P(local.C, local.D, local.A, local.B,  2, 17, 0x242070DB);
        P(local.B, local.C, local.D, local.A,  3, 22, 0xC1BDCEEE);
        P(local.A, local.B, local.C, local.D,  4,  7, 0xF57C0FAF);
        P(local.D, local.A, local.B, local.C,  5, 12, 0x4787C62A);
        P(local.C, local.D, local.A, local.B,  6, 17, 0xA8304613);
        P(local.B, local.C, local.D, local.A,  7, 22, 0xFD469501);
        P(local.A, local.B, local.C, local.D,  8,  7, 0x698098D8);
        P(local.D, local.A, local.B, local.C,  9, 12, 0x8B44F7AF);
        P(local.C, local.D, local.A, local.B, 10, 17, 0xFFFF5BB1);
        P(local.B, local.C, local.D, local.A, 11, 22, 0x895CD7BE);
        P(local.A, local.B, local.C, local.D, 12,  7, 0x6B901122);
        P(local.D, local.A, local.B, local.C, 13, 12, 0xFD987193);
        P(local.C, local.D, local.A, local.B, 14, 17, 0xA679438E);
        P(local.B, local.C, local.D, local.A, 15, 22, 0x49B40821);
    }

#undef F

#define F(x, y, z) ((y) ^ ((z) & ((x) ^ (y))))

    P(local.A, local.B, local.C, local.D,  1,  5, 0xF61E2562);
    P(local.D, local.A, local.B, local.C,  6,  9, 0xC040B340);
    P(local.C, local.D, local.A, local.B, 11, 14, 0x265E5A51);
    P(local.B, local.C, local.D, local.A,  0, 20, 0xE9B6C7AA);
    P(local.A, local.B, local.C, local.D,  5,  5, 0xD62F105D);
    P(local.D, local.A, local.B, local.C, 10,  9, 0x02441453);
    P(local.C, local.D, local.A, local.B, 15, 14, 0xD8A1E681);
    P(local.B, local.C, local.D, local.A,  4, 20, 0xE7D3FBC8);
    P(local.A, local.B, local.C, local.D,  9,  5, 0x21E1CDE6);
    P(local.D, local.A, local.B, local.C, 14,  9, 0xC33707D6);
    P(local.C, local.D, local.A, local.B,  3, 14, 0xF4D50D87);
    P(local.B, local.C, local.D, local.A,  8, 20, 0x455A14ED);
    P(local.A, local.B, local.C, local.D, 13,  5, 0xA9E3E905);
    P(local.D, local.A, local.B, local.C,  2,  9, 0xFCEFA3F8);
    P(local.C, local.D, local.A, local.B,  7, 14, 0x676F02D9);
    P(local.B, local.C, local.D, local.A, 12, 20, 0x8D2A4C8A);

#undef F

#define F(x, y, z) ((x) ^ (y) ^ (z))

    P(local.A, local.B, local.C, local.D,  5,  4, 0xFFFA3942);
    P(local.D, local.A, local.B, local.C,  8, 11, 0x8771F681);
    P(local.C, local.D, local.A, local.B, 11, 16, 0x6D9D6122);
    P(local.B, local.C, local.D, local.A, 14, 23, 0xFDE5380C);
    P(local.A, local.B, local.C, local.D,  1,  4, 0xA4BEEA44);
    P(local.D, local.A, local.B, local.C,  4, 11, 0x4BDECFA9);
    P(local.C, local.D, local.A, local.B,  7, 16, 0xF6BB4B60);
    P(local.B, local.C, local.D, local.A, 10, 23, 0xBEBFBC70);
    P(local.A, local.B, local.C, local.D, 13,  4, 0x289B7EC6);
    P(local.D, local.A, local.B, local.C,  0, 11, 0xEAA127FA);
    P(local.C, local.D, local.A, local.B,  3, 16, 0xD4EF3085);
    P(local.B, local.C, local.D, local.A,  6, 23, 0x04881D05);
    P(local.A, local.B, local.C, local.D,  9,  4, 0xD9D4D039);
    P(local.D, local.A, local.B, local.C, 12, 11, 0xE6DB99E5);
    P(local.C, local.D, local.A, local.B, 15, 16, 0x1FA27CF8);
    P(local.B, local.C, local.D, local.A,  2, 23, 0xC4AC5665);

#undef F

#define F(x, y, z) ((y) ^ ((x) | ~(z)))

    P(local.A, local.B, local.C, local.D,  0,  6, 0xF4292244);
    P(local.D, local.A, local.B, local.C,  7, 10, 0x432AFF97);
    P(local.C, local.D, local.A, local.B, 14, 15, 0xAB9423A7);
    P(local.B, local.C, local.D, local.A,  5, 21, 0xFC93A039);
    P(local.A, local.B, local.C, local.D, 12,  6, 0x655B59C3);
    P(local.D, local.A, local.B, local.C,  3, 10, 0x8F0CCC92);
    P(local.C, local.D, local.A, local.B, 10, 15, 0xFFEFF47D);
    P(local.B, local.C, local.D, local.A,  1, 21, 0x85845DD1);
    P(local.A, local.B, local.C, local.D,  8,  6, 0x6FA87E4F);
    P(local.D, local.A, local.B, local.C, 15, 10, 0xFE2CE6E0);
    P(local.C, local.D, local.A, local.B,  6, 15, 0xA3014314);
    P(local.B, local.C, local.D, local.A, 13, 21, 0x4E0811A1);
    P(local.A, local.B, local.C, local.D,  4,  6, 0xF7537E82);
    P(local.D, local.A, local.B, local.C, 11, 10, 0xBD3AF235);
    P(local.C, local.D, local.A, local.B,  2, 15, 0x2AD7D2BB);
    P(local.B, local.C, local.D, local.A,  9, 21, 0xEB86D391);

#undef F

    ctx->state[0] += local.A;
    ctx->state[1] += local.B;
    ctx->state[2] += local.C;
    ctx->state[3] += local.D;

    MBEDTLS_PUT_UINT32_LE(local.X[0], data, 0);
    MBEDTLS_PUT_UINT32_LE(local.X[1], data, 4);
    MBEDTLS_PUT_UINT32_LE(local.X[2], data, 8);
    MBEDTLS_PUT_UINT32_LE(local.X[3], data, 12);
    MBEDTLS_PUT_UINT32_LE(local.X[4], data, 16);
    MBEDTLS_PUT_UINT32_LE(local.X[5], data, 20);
    MBEDTLS_PUT_UINT32_LE(local.X[6], data, 24);
    MBEDTLS_PUT_UINT32_LE(local.X[7], data, 28);
    MBEDTLS_PUT_UINT32_LE(local.X[8], data, 32);
    MBEDTLS_PUT_UINT32_LE(local.X[9], data, 36);
    MBEDTLS_PUT_UINT32_LE(local.X[10], data, 40);
    MBEDTLS_PUT_UINT32_LE(local.X[11], data, 44);
    MBEDTLS_PUT_UINT32_LE(local.X[12], data, 48);
    MBEDTLS_PUT_UINT32_LE(local.X[13], data, 52);
    MBEDTLS_PUT_UINT32_LE(local.X[14], data, 56);
    MBEDTLS_PUT_UINT32_LE(local.X[15], data, 60);

    return 0;
}