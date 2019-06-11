/*
 * Copyright 2004-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>

#include "sha.h"

int SHA512_Init(SHA512_CTX *c)
{
    c->h[0] = U64(0x6a09e667f3bcc908);
    c->h[1] = U64(0xbb67ae8584caa73b);
    c->h[2] = U64(0x3c6ef372fe94f82b);
    c->h[3] = U64(0xa54ff53a5f1d36f1);
    c->h[4] = U64(0x510e527fade682d1);
    c->h[5] = U64(0x9b05688c2b3e6c1f);
    c->h[6] = U64(0x1f83d9abfb41bd6b);
    c->h[7] = U64(0x5be0cd19137e2179);

    c->Nl = 0;
    c->Nh = 0;
    c->num = 0;
    c->md_len = SHA512_DIGEST_LENGTH;
    return 1;
}

static void sha512_block_data_order(SHA512_CTX *ctx, const void *in, size_t num);

int SHA512_Final(unsigned char *md, SHA512_CTX *c)
{
    unsigned char *p = (unsigned char *)c->u.p;
    size_t n = c->num;

    p[n] = 0x80;                /* There always is a room for one */
    n++;
    if (n > (sizeof(c->u) - 16)) {
        memset(p + n, 0, sizeof(c->u) - n);
        n = 0;
        sha512_block_data_order(c, p, 1);
    }

    memset(p + n, 0, sizeof(c->u) - 16 - n);
    p[sizeof(c->u) - 1] = (unsigned char)(c->Nl);
    p[sizeof(c->u) - 2] = (unsigned char)(c->Nl >> 8);
    p[sizeof(c->u) - 3] = (unsigned char)(c->Nl >> 16);
    p[sizeof(c->u) - 4] = (unsigned char)(c->Nl >> 24);
    p[sizeof(c->u) - 5] = (unsigned char)(c->Nl >> 32);
    p[sizeof(c->u) - 6] = (unsigned char)(c->Nl >> 40);
    p[sizeof(c->u) - 7] = (unsigned char)(c->Nl >> 48);
    p[sizeof(c->u) - 8] = (unsigned char)(c->Nl >> 56);
    p[sizeof(c->u) - 9] = (unsigned char)(c->Nh);
    p[sizeof(c->u) - 10] = (unsigned char)(c->Nh >> 8);
    p[sizeof(c->u) - 11] = (unsigned char)(c->Nh >> 16);
    p[sizeof(c->u) - 12] = (unsigned char)(c->Nh >> 24);
    p[sizeof(c->u) - 13] = (unsigned char)(c->Nh >> 32);
    p[sizeof(c->u) - 14] = (unsigned char)(c->Nh >> 40);
    p[sizeof(c->u) - 15] = (unsigned char)(c->Nh >> 48);
    p[sizeof(c->u) - 16] = (unsigned char)(c->Nh >> 56);

    sha512_block_data_order(c, p, 1);

    if (md == 0)
        return 0;

    switch (c->md_len) {
    /* Let compiler decide if it's appropriate to unroll... */
    case SHA224_DIGEST_LENGTH:
        for (n = 0; n < SHA224_DIGEST_LENGTH / 8; n++) {
            SHA_LONG64 t = c->h[n];

            *(md++) = (unsigned char)(t >> 56);
            *(md++) = (unsigned char)(t >> 48);
            *(md++) = (unsigned char)(t >> 40);
            *(md++) = (unsigned char)(t >> 32);
            *(md++) = (unsigned char)(t >> 24);
            *(md++) = (unsigned char)(t >> 16);
            *(md++) = (unsigned char)(t >> 8);
            *(md++) = (unsigned char)(t);
        }
        /*
         * For 224 bits, there are four bytes left over that have to be
         * processed separately.
         */
        {
            SHA_LONG64 t = c->h[SHA224_DIGEST_LENGTH / 8];

            *(md++) = (unsigned char)(t >> 56);
            *(md++) = (unsigned char)(t >> 48);
            *(md++) = (unsigned char)(t >> 40);
            *(md++) = (unsigned char)(t >> 32);
        }
        break;
    case SHA256_DIGEST_LENGTH:
        for (n = 0; n < SHA256_DIGEST_LENGTH / 8; n++) {
            SHA_LONG64 t = c->h[n];

            *(md++) = (unsigned char)(t >> 56);
            *(md++) = (unsigned char)(t >> 48);
            *(md++) = (unsigned char)(t >> 40);
            *(md++) = (unsigned char)(t >> 32);
            *(md++) = (unsigned char)(t >> 24);
            *(md++) = (unsigned char)(t >> 16);
            *(md++) = (unsigned char)(t >> 8);
            *(md++) = (unsigned char)(t);
        }
        break;
    case SHA384_DIGEST_LENGTH:
        for (n = 0; n < SHA384_DIGEST_LENGTH / 8; n++) {
            SHA_LONG64 t = c->h[n];

            *(md++) = (unsigned char)(t >> 56);
            *(md++) = (unsigned char)(t >> 48);
            *(md++) = (unsigned char)(t >> 40);
            *(md++) = (unsigned char)(t >> 32);
            *(md++) = (unsigned char)(t >> 24);
            *(md++) = (unsigned char)(t >> 16);
            *(md++) = (unsigned char)(t >> 8);
            *(md++) = (unsigned char)(t);
        }
        break;
    case SHA512_DIGEST_LENGTH:
        for (n = 0; n < SHA512_DIGEST_LENGTH / 8; n++) {
            SHA_LONG64 t = c->h[n];

            *(md++) = (unsigned char)(t >> 56);
            *(md++) = (unsigned char)(t >> 48);
            *(md++) = (unsigned char)(t >> 40);
            *(md++) = (unsigned char)(t >> 32);
            *(md++) = (unsigned char)(t >> 24);
            *(md++) = (unsigned char)(t >> 16);
            *(md++) = (unsigned char)(t >> 8);
            *(md++) = (unsigned char)(t);
        }
        break;
    /* ... as well as make sure md_len is not abused. */
    default:
        return 0;
    }

    return 1;
}

int SHA512_Update(SHA512_CTX *c, const void *_data, size_t len)
{
    SHA_LONG64 l;
    unsigned char *p = c->u.p;
    const unsigned char *data = (const unsigned char *)_data;

    if (len == 0)
        return 1;

    l = (c->Nl + (((SHA_LONG64) len) << 3)) & U64(0xffffffffffffffff);
    if (l < c->Nl)
        c->Nh++;
    if (sizeof(len) >= 8)
        c->Nh += (((SHA_LONG64) len) >> 61);
    c->Nl = l;

    if (c->num != 0) {
        size_t n = sizeof(c->u) - c->num;

        if (len < n) {
            memcpy(p + c->num, data, len), c->num += (unsigned int)len;
            return 1;
        } else {
            memcpy(p + c->num, data, n), c->num = 0;
            len -= n, data += n;
            sha512_block_data_order(c, p, 1);
        }
    }

    if (len >= sizeof(c->u)) {
        if ((size_t)data % sizeof(c->u.d[0]) != 0)
            while (len >= sizeof(c->u))
                memcpy(p, data, sizeof(c->u)),
                sha512_block_data_order(c, p, 1),
                len -= sizeof(c->u), data += sizeof(c->u);
        else
            sha512_block_data_order(c, data, len / sizeof(c->u)),
            data += len, len %= sizeof(c->u), data -= len;
    }

    if (len != 0)
        memcpy(p, data, len), c->num = (int)len;

    return 1;
}

void SHA512_Transform(SHA512_CTX *c, const unsigned char *data)
{
    if ((size_t)data % sizeof(c->u.d[0]) != 0)
        memcpy(c->u.p, data, sizeof(c->u.p)), data = c->u.p;
    sha512_block_data_order(c, data, 1);
}

typedef void *(*memset_t)(void *, int, size_t);

static volatile memset_t memset_func = memset;

void OPENSSL_cleanse(void *ptr, size_t len)
{
    memset_func(ptr, 0, len);
}

unsigned char *SHA512(const unsigned char *d, size_t n, unsigned char *md)
{
    SHA512_CTX c;
    static unsigned char m[SHA512_DIGEST_LENGTH];

    if (md == NULL)
        md = m;
    SHA512_Init(&c);
    SHA512_Update(&c, d, n);
    SHA512_Final(md, &c);
    OPENSSL_cleanse(&c, sizeof(c));
    return md;
}

static const SHA_LONG64 K512[80] = {
    U64(0x428a2f98d728ae22), U64(0x7137449123ef65cd),
    U64(0xb5c0fbcfec4d3b2f), U64(0xe9b5dba58189dbbc),
    U64(0x3956c25bf348b538), U64(0x59f111f1b605d019),
    U64(0x923f82a4af194f9b), U64(0xab1c5ed5da6d8118),
    U64(0xd807aa98a3030242), U64(0x12835b0145706fbe),
    U64(0x243185be4ee4b28c), U64(0x550c7dc3d5ffb4e2),
    U64(0x72be5d74f27b896f), U64(0x80deb1fe3b1696b1),
    U64(0x9bdc06a725c71235), U64(0xc19bf174cf692694),
    U64(0xe49b69c19ef14ad2), U64(0xefbe4786384f25e3),
    U64(0x0fc19dc68b8cd5b5), U64(0x240ca1cc77ac9c65),
    U64(0x2de92c6f592b0275), U64(0x4a7484aa6ea6e483),
    U64(0x5cb0a9dcbd41fbd4), U64(0x76f988da831153b5),
    U64(0x983e5152ee66dfab), U64(0xa831c66d2db43210),
    U64(0xb00327c898fb213f), U64(0xbf597fc7beef0ee4),
    U64(0xc6e00bf33da88fc2), U64(0xd5a79147930aa725),
    U64(0x06ca6351e003826f), U64(0x142929670a0e6e70),
    U64(0x27b70a8546d22ffc), U64(0x2e1b21385c26c926),
    U64(0x4d2c6dfc5ac42aed), U64(0x53380d139d95b3df),
    U64(0x650a73548baf63de), U64(0x766a0abb3c77b2a8),
    U64(0x81c2c92e47edaee6), U64(0x92722c851482353b),
    U64(0xa2bfe8a14cf10364), U64(0xa81a664bbc423001),
    U64(0xc24b8b70d0f89791), U64(0xc76c51a30654be30),
    U64(0xd192e819d6ef5218), U64(0xd69906245565a910),
    U64(0xf40e35855771202a), U64(0x106aa07032bbd1b8),
    U64(0x19a4c116b8d2d0c8), U64(0x1e376c085141ab53),
    U64(0x2748774cdf8eeb99), U64(0x34b0bcb5e19b48a8),
    U64(0x391c0cb3c5c95a63), U64(0x4ed8aa4ae3418acb),
    U64(0x5b9cca4f7763e373), U64(0x682e6ff3d6b2b8a3),
    U64(0x748f82ee5defb2fc), U64(0x78a5636f43172f60),
    U64(0x84c87814a1f0ab72), U64(0x8cc702081a6439ec),
    U64(0x90befffa23631e28), U64(0xa4506cebde82bde9),
    U64(0xbef9a3f7b2c67915), U64(0xc67178f2e372532b),
    U64(0xca273eceea26619c), U64(0xd186b8c721c0c207),
    U64(0xeada7dd6cde0eb1e), U64(0xf57d4f7fee6ed178),
    U64(0x06f067aa72176fba), U64(0x0a637dc5a2c898a6),
    U64(0x113f9804bef90dae), U64(0x1b710b35131c471b),
    U64(0x28db77f523047d84), U64(0x32caab7b40c72493),
    U64(0x3c9ebe0a15c9bebc), U64(0x431d67c49c100d4c),
    U64(0x4cc5d4becb3e42b6), U64(0x597f299cfc657e2a),
    U64(0x5fcb6fab3ad6faec), U64(0x6c44198c4a475817)
};

# ifndef PULL64
#  define B(x,j)    (((SHA_LONG64)(*(((const unsigned char *)(&x))+j)))<<((7-j)*8))
#  define PULL64(x) (B(x,0)|B(x,1)|B(x,2)|B(x,3)|B(x,4)|B(x,5)|B(x,6)|B(x,7))
# endif
# ifndef ROTR
#  define ROTR(x,s)       (((x)>>s) | (x)<<(64-s))
# endif
# define Sigma0(x)       (ROTR((x),28) ^ ROTR((x),34) ^ ROTR((x),39))
# define Sigma1(x)       (ROTR((x),14) ^ ROTR((x),18) ^ ROTR((x),41))
# define sigma0(x)       (ROTR((x),1)  ^ ROTR((x),8)  ^ ((x)>>7))
# define sigma1(x)       (ROTR((x),19) ^ ROTR((x),61) ^ ((x)>>6))
# define Ch(x,y,z)       (((x) & (y)) ^ ((~(x)) & (z)))
# define Maj(x,y,z)      (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#  define ROUND_00_15(i,a,b,c,d,e,f,g,h)        do {    \
        T1 += h + Sigma1(e) + Ch(e,f,g) + K512[i];      \
        h = Sigma0(a) + Maj(a,b,c);                     \
        d += T1;        h += T1;                        } while (0)

#  define ROUND_16_80(i,j,a,b,c,d,e,f,g,h,X)    do {    \
        s0 = X[(j+1)&0x0f];     s0 = sigma0(s0);        \
        s1 = X[(j+14)&0x0f];    s1 = sigma1(s1);        \
        T1 = X[(j)&0x0f] += s0 + s1 + X[(j+9)&0x0f];    \
        ROUND_00_15(i+j,a,b,c,d,e,f,g,h);               } while (0)

static void sha512_block_data_order(SHA512_CTX *ctx, const void *in,
                                    size_t num)
{
    const SHA_LONG64 *W = in;
    SHA_LONG64 a, b, c, d, e, f, g, h, s0, s1, T1;
    SHA_LONG64 X[16];
    int i;

    while (num--) {

        a = ctx->h[0];
        b = ctx->h[1];
        c = ctx->h[2];
        d = ctx->h[3];
        e = ctx->h[4];
        f = ctx->h[5];
        g = ctx->h[6];
        h = ctx->h[7];

        T1 = X[0] = PULL64(W[0]);
        ROUND_00_15(0, a, b, c, d, e, f, g, h);
        T1 = X[1] = PULL64(W[1]);
        ROUND_00_15(1, h, a, b, c, d, e, f, g);
        T1 = X[2] = PULL64(W[2]);
        ROUND_00_15(2, g, h, a, b, c, d, e, f);
        T1 = X[3] = PULL64(W[3]);
        ROUND_00_15(3, f, g, h, a, b, c, d, e);
        T1 = X[4] = PULL64(W[4]);
        ROUND_00_15(4, e, f, g, h, a, b, c, d);
        T1 = X[5] = PULL64(W[5]);
        ROUND_00_15(5, d, e, f, g, h, a, b, c);
        T1 = X[6] = PULL64(W[6]);
        ROUND_00_15(6, c, d, e, f, g, h, a, b);
        T1 = X[7] = PULL64(W[7]);
        ROUND_00_15(7, b, c, d, e, f, g, h, a);
        T1 = X[8] = PULL64(W[8]);
        ROUND_00_15(8, a, b, c, d, e, f, g, h);
        T1 = X[9] = PULL64(W[9]);
        ROUND_00_15(9, h, a, b, c, d, e, f, g);
        T1 = X[10] = PULL64(W[10]);
        ROUND_00_15(10, g, h, a, b, c, d, e, f);
        T1 = X[11] = PULL64(W[11]);
        ROUND_00_15(11, f, g, h, a, b, c, d, e);
        T1 = X[12] = PULL64(W[12]);
        ROUND_00_15(12, e, f, g, h, a, b, c, d);
        T1 = X[13] = PULL64(W[13]);
        ROUND_00_15(13, d, e, f, g, h, a, b, c);
        T1 = X[14] = PULL64(W[14]);
        ROUND_00_15(14, c, d, e, f, g, h, a, b);
        T1 = X[15] = PULL64(W[15]);
        ROUND_00_15(15, b, c, d, e, f, g, h, a);

        for (i = 16; i < 80; i += 16) {
            ROUND_16_80(i, 0, a, b, c, d, e, f, g, h, X);
            ROUND_16_80(i, 1, h, a, b, c, d, e, f, g, X);
            ROUND_16_80(i, 2, g, h, a, b, c, d, e, f, X);
            ROUND_16_80(i, 3, f, g, h, a, b, c, d, e, X);
            ROUND_16_80(i, 4, e, f, g, h, a, b, c, d, X);
            ROUND_16_80(i, 5, d, e, f, g, h, a, b, c, X);
            ROUND_16_80(i, 6, c, d, e, f, g, h, a, b, X);
            ROUND_16_80(i, 7, b, c, d, e, f, g, h, a, X);
            ROUND_16_80(i, 8, a, b, c, d, e, f, g, h, X);
            ROUND_16_80(i, 9, h, a, b, c, d, e, f, g, X);
            ROUND_16_80(i, 10, g, h, a, b, c, d, e, f, X);
            ROUND_16_80(i, 11, f, g, h, a, b, c, d, e, X);
            ROUND_16_80(i, 12, e, f, g, h, a, b, c, d, X);
            ROUND_16_80(i, 13, d, e, f, g, h, a, b, c, X);
            ROUND_16_80(i, 14, c, d, e, f, g, h, a, b, X);
            ROUND_16_80(i, 15, b, c, d, e, f, g, h, a, X);
        }

        ctx->h[0] += a;
        ctx->h[1] += b;
        ctx->h[2] += c;
        ctx->h[3] += d;
        ctx->h[4] += e;
        ctx->h[5] += f;
        ctx->h[6] += g;
        ctx->h[7] += h;

        W += SHA_LBLOCK;
    }
}

