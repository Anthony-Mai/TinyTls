/******************************************************************************
*
* Copyright © 2018-2019 Anthony Mai Mai_Anthony@hotmail.com. All Rights Reserved.
*
* This file is a part of the software package TinyTls, originally known as TinySsl.
* This software is written by Anthony Mai and is provided under the terms and
* conditions of the GNU General Public License Version 3.0 (GPL V3.0). For the
* specific GPL V3.0 license terms please refer to:
*         https://www.gnu.org/licenses/gpl.html.
*
* This Copyright Notices contained in this code. are NOT to be removed or modified.
* If this package is used in a product, Anthony Mai should be given attribution as
* the author of the parts of the library used. This can be in the form of a textual
* message at program startup or in documentation provided with the package.
*
* This library is free for commercial and non-commercial use as long as the
* following conditions are aheared to. The following conditions apply to
* all code found in this distribution:
*
* 1. Redistributions of source code must retain the copyright notice, this
*    list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
*
* 3. All advertising materials mentioning features or use of this software
*    must display the following acknowledgement:
*
*    "This product contains software written by Anthony Mai (Mai_Anthony@hotmail.com)
*     The original source code can obtained from such and such internet sites or by
*     contacting the author directly."
*
* 4. This software may or may not contain patented technology owned by a third party.
*    Obtaining a copy of this software, with or without explicit authorization from
*    the author, does NOT imply that applicable patents have been licensed. It is up
*    to you to make sure that utilization of this software package does not infringe
*    on any third party's patents or other intellectual proerty rights.
*
* THIS SOFTWARE IS PROVIDED BY ANTHONY MAI "AS IS". ANY EXPRESS OR IMPLIED WARRANTIES,
* INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
* FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
* BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
* IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* The license and distribution terms for any publically available version or derivative
* of this code cannot be changed.  i.e. this code cannot simply be copied and put under
* another distribution license [including the GNU Public License.]
*
******************************************************************************/

#include <stdint.h>
#include <string.h>

#define RIPCTX  CTX
#define DSIZE   RIP_SIZE

#include "ripemd.h"

typedef union u32 {
    unsigned char b[4];
    uint32_t v;
} u32;

typedef union u64 {
    unsigned char b[8];
    uint64_t v;
} u64;

static void WriteLE32(unsigned char* ptr, uint32_t x)
{
    ((u32*)ptr)->v = x;
}

static void WriteLE64(unsigned char* ptr, uint64_t x)
{
    ((u64*)ptr)->v = x;
}

/// Internal RIPEMD-160 implementation.
#define f1(x, y, z)     (x ^ y ^ z)
#define f2(x, y, z)     ((x & y) | (~x & z))
#define f3(x, y, z)     ((x | ~y) ^ z)
#define f4(x, y, z)     ((x & z) | (y & ~z))
#define f5(x, y, z)     ( x ^ (y | ~z))

/** Initialize RIPEMD-160 state. */
void inline Initialize(uint32_t* s)
{
    s[0] = 0x67452301ul;
    s[1] = 0xEFCDAB89ul;
    s[2] = 0x98BADCFEul;
    s[3] = 0x10325476ul;
    s[4] = 0xC3D2E1F0ul;
}

#define rol(x, i)   ((x << i) | (x >> (32 - i)))

#define Round(a, b, c, d, e, f, x, k, r)    a = rol((a + f + x + k), r) + e; c = rol(c, 10)


#define R11(a, b, c, d, e, x, r)    Round(a, b, c, d, e, f1(b, c, d), x, 0, r)

#define R21(a, b, c, d, e, x, r)    Round(a, b, c, d, e, f2(b, c, d), x, 0x5A827999, r)

#define R31(a, b, c, d, e, x, r)    Round(a, b, c, d, e, f3(b, c, d), x, 0x6ED9EBA1, r)

#define R41(a, b, c, d, e, x, r)    Round(a, b, c, d, e, f4(b, c, d), x, 0x8F1BBCDC, r)

#define R51(a, b, c, d, e, x, r)    Round(a, b, c, d, e, f5(b, c, d), x, 0xA953FD4E, r)

#define R12(a, b, c, d, e, x, r)    Round(a, b, c, d, e, f5(b, c, d), x, 0x50A28BE6, r)

#define R22(a, b, c, d, e, x, r)    Round(a, b, c, d, e, f4(b, c, d), x, 0x5C4DD124, r)

#define R32(a, b, c, d, e, x, r)    Round(a, b, c, d, e, f3(b, c, d), x, 0x6D703EF3, r)

#define R42(a, b, c, d, e, x, r)    Round(a, b, c, d, e, f2(b, c, d), x, 0x7A6D76E9, r)

#define R52(a, b, c, d, e, x, r)    Round(a, b, c, d, e, f1(b, c, d), x, 0, r)

uint32_t static inline ReadLE32(const uchar* ptr)
{
    union {
        uchar b[4];
        uint32_t v;
    } x;
    x.b[0] = ptr[0]; x.b[1] = ptr[1]; x.b[2] = ptr[2]; x.b[3] = ptr[3]; // Little endian
    return x.v;
}


/** Perform a RIPEMD-160 transformation, processing a 64-byte chunk. */
static void Transform(uint32_t* s, const unsigned char* chunk)
{
    uint32_t a1 = s[0], b1 = s[1], c1 = s[2], d1 = s[3], e1 = s[4];
    uint32_t a2 = a1, b2 = b1, c2 = c1, d2 = d1, e2 = e1;
    uint32_t w0 = ReadLE32(chunk + 0), w1 = ReadLE32(chunk + 4), w2 = ReadLE32(chunk + 8), w3 = ReadLE32(chunk + 12);
    uint32_t w4 = ReadLE32(chunk + 16), w5 = ReadLE32(chunk + 20), w6 = ReadLE32(chunk + 24), w7 = ReadLE32(chunk + 28);
    uint32_t w8 = ReadLE32(chunk + 32), w9 = ReadLE32(chunk + 36), w10 = ReadLE32(chunk + 40), w11 = ReadLE32(chunk + 44);
    uint32_t w12 = ReadLE32(chunk + 48), w13 = ReadLE32(chunk + 52), w14 = ReadLE32(chunk + 56), w15 = ReadLE32(chunk + 60);

    R11(a1, b1, c1, d1, e1, w0, 11);
    R12(a2, b2, c2, d2, e2, w5, 8);
    R11(e1, a1, b1, c1, d1, w1, 14);
    R12(e2, a2, b2, c2, d2, w14, 9);
    R11(d1, e1, a1, b1, c1, w2, 15);
    R12(d2, e2, a2, b2, c2, w7, 9);
    R11(c1, d1, e1, a1, b1, w3, 12);
    R12(c2, d2, e2, a2, b2, w0, 11);
    R11(b1, c1, d1, e1, a1, w4, 5);
    R12(b2, c2, d2, e2, a2, w9, 13);
    R11(a1, b1, c1, d1, e1, w5, 8);
    R12(a2, b2, c2, d2, e2, w2, 15);
    R11(e1, a1, b1, c1, d1, w6, 7);
    R12(e2, a2, b2, c2, d2, w11, 15);
    R11(d1, e1, a1, b1, c1, w7, 9);
    R12(d2, e2, a2, b2, c2, w4, 5);
    R11(c1, d1, e1, a1, b1, w8, 11);
    R12(c2, d2, e2, a2, b2, w13, 7);
    R11(b1, c1, d1, e1, a1, w9, 13);
    R12(b2, c2, d2, e2, a2, w6, 7);
    R11(a1, b1, c1, d1, e1, w10, 14);
    R12(a2, b2, c2, d2, e2, w15, 8);
    R11(e1, a1, b1, c1, d1, w11, 15);
    R12(e2, a2, b2, c2, d2, w8, 11);
    R11(d1, e1, a1, b1, c1, w12, 6);
    R12(d2, e2, a2, b2, c2, w1, 14);
    R11(c1, d1, e1, a1, b1, w13, 7);
    R12(c2, d2, e2, a2, b2, w10, 14);
    R11(b1, c1, d1, e1, a1, w14, 9);
    R12(b2, c2, d2, e2, a2, w3, 12);
    R11(a1, b1, c1, d1, e1, w15, 8);
    R12(a2, b2, c2, d2, e2, w12, 6);

    R21(e1, a1, b1, c1, d1, w7, 7);
    R22(e2, a2, b2, c2, d2, w6, 9);
    R21(d1, e1, a1, b1, c1, w4, 6);
    R22(d2, e2, a2, b2, c2, w11, 13);
    R21(c1, d1, e1, a1, b1, w13, 8);
    R22(c2, d2, e2, a2, b2, w3, 15);
    R21(b1, c1, d1, e1, a1, w1, 13);
    R22(b2, c2, d2, e2, a2, w7, 7);
    R21(a1, b1, c1, d1, e1, w10, 11);
    R22(a2, b2, c2, d2, e2, w0, 12);
    R21(e1, a1, b1, c1, d1, w6, 9);
    R22(e2, a2, b2, c2, d2, w13, 8);
    R21(d1, e1, a1, b1, c1, w15, 7);
    R22(d2, e2, a2, b2, c2, w5, 9);
    R21(c1, d1, e1, a1, b1, w3, 15);
    R22(c2, d2, e2, a2, b2, w10, 11);
    R21(b1, c1, d1, e1, a1, w12, 7);
    R22(b2, c2, d2, e2, a2, w14, 7);
    R21(a1, b1, c1, d1, e1, w0, 12);
    R22(a2, b2, c2, d2, e2, w15, 7);
    R21(e1, a1, b1, c1, d1, w9, 15);
    R22(e2, a2, b2, c2, d2, w8, 12);
    R21(d1, e1, a1, b1, c1, w5, 9);
    R22(d2, e2, a2, b2, c2, w12, 7);
    R21(c1, d1, e1, a1, b1, w2, 11);
    R22(c2, d2, e2, a2, b2, w4, 6);
    R21(b1, c1, d1, e1, a1, w14, 7);
    R22(b2, c2, d2, e2, a2, w9, 15);
    R21(a1, b1, c1, d1, e1, w11, 13);
    R22(a2, b2, c2, d2, e2, w1, 13);
    R21(e1, a1, b1, c1, d1, w8, 12);
    R22(e2, a2, b2, c2, d2, w2, 11);

    R31(d1, e1, a1, b1, c1, w3, 11);
    R32(d2, e2, a2, b2, c2, w15, 9);
    R31(c1, d1, e1, a1, b1, w10, 13);
    R32(c2, d2, e2, a2, b2, w5, 7);
    R31(b1, c1, d1, e1, a1, w14, 6);
    R32(b2, c2, d2, e2, a2, w1, 15);
    R31(a1, b1, c1, d1, e1, w4, 7);
    R32(a2, b2, c2, d2, e2, w3, 11);
    R31(e1, a1, b1, c1, d1, w9, 14);
    R32(e2, a2, b2, c2, d2, w7, 8);
    R31(d1, e1, a1, b1, c1, w15, 9);
    R32(d2, e2, a2, b2, c2, w14, 6);
    R31(c1, d1, e1, a1, b1, w8, 13);
    R32(c2, d2, e2, a2, b2, w6, 6);
    R31(b1, c1, d1, e1, a1, w1, 15);
    R32(b2, c2, d2, e2, a2, w9, 14);
    R31(a1, b1, c1, d1, e1, w2, 14);
    R32(a2, b2, c2, d2, e2, w11, 12);
    R31(e1, a1, b1, c1, d1, w7, 8);
    R32(e2, a2, b2, c2, d2, w8, 13);
    R31(d1, e1, a1, b1, c1, w0, 13);
    R32(d2, e2, a2, b2, c2, w12, 5);
    R31(c1, d1, e1, a1, b1, w6, 6);
    R32(c2, d2, e2, a2, b2, w2, 14);
    R31(b1, c1, d1, e1, a1, w13, 5);
    R32(b2, c2, d2, e2, a2, w10, 13);
    R31(a1, b1, c1, d1, e1, w11, 12);
    R32(a2, b2, c2, d2, e2, w0, 13);
    R31(e1, a1, b1, c1, d1, w5, 7);
    R32(e2, a2, b2, c2, d2, w4, 7);
    R31(d1, e1, a1, b1, c1, w12, 5);
    R32(d2, e2, a2, b2, c2, w13, 5);

    R41(c1, d1, e1, a1, b1, w1, 11);
    R42(c2, d2, e2, a2, b2, w8, 15);
    R41(b1, c1, d1, e1, a1, w9, 12);
    R42(b2, c2, d2, e2, a2, w6, 5);
    R41(a1, b1, c1, d1, e1, w11, 14);
    R42(a2, b2, c2, d2, e2, w4, 8);
    R41(e1, a1, b1, c1, d1, w10, 15);
    R42(e2, a2, b2, c2, d2, w1, 11);
    R41(d1, e1, a1, b1, c1, w0, 14);
    R42(d2, e2, a2, b2, c2, w3, 14);
    R41(c1, d1, e1, a1, b1, w8, 15);
    R42(c2, d2, e2, a2, b2, w11, 14);
    R41(b1, c1, d1, e1, a1, w12, 9);
    R42(b2, c2, d2, e2, a2, w15, 6);
    R41(a1, b1, c1, d1, e1, w4, 8);
    R42(a2, b2, c2, d2, e2, w0, 14);
    R41(e1, a1, b1, c1, d1, w13, 9);
    R42(e2, a2, b2, c2, d2, w5, 6);
    R41(d1, e1, a1, b1, c1, w3, 14);
    R42(d2, e2, a2, b2, c2, w12, 9);
    R41(c1, d1, e1, a1, b1, w7, 5);
    R42(c2, d2, e2, a2, b2, w2, 12);
    R41(b1, c1, d1, e1, a1, w15, 6);
    R42(b2, c2, d2, e2, a2, w13, 9);
    R41(a1, b1, c1, d1, e1, w14, 8);
    R42(a2, b2, c2, d2, e2, w9, 12);
    R41(e1, a1, b1, c1, d1, w5, 6);
    R42(e2, a2, b2, c2, d2, w7, 5);
    R41(d1, e1, a1, b1, c1, w6, 5);
    R42(d2, e2, a2, b2, c2, w10, 15);
    R41(c1, d1, e1, a1, b1, w2, 12);
    R42(c2, d2, e2, a2, b2, w14, 8);

    R51(b1, c1, d1, e1, a1, w4, 9);
    R52(b2, c2, d2, e2, a2, w12, 8);
    R51(a1, b1, c1, d1, e1, w0, 15);
    R52(a2, b2, c2, d2, e2, w15, 5);
    R51(e1, a1, b1, c1, d1, w5, 5);
    R52(e2, a2, b2, c2, d2, w10, 12);
    R51(d1, e1, a1, b1, c1, w9, 11);
    R52(d2, e2, a2, b2, c2, w4, 9);
    R51(c1, d1, e1, a1, b1, w7, 6);
    R52(c2, d2, e2, a2, b2, w1, 12);
    R51(b1, c1, d1, e1, a1, w12, 8);
    R52(b2, c2, d2, e2, a2, w5, 5);
    R51(a1, b1, c1, d1, e1, w2, 13);
    R52(a2, b2, c2, d2, e2, w8, 14);
    R51(e1, a1, b1, c1, d1, w10, 12);
    R52(e2, a2, b2, c2, d2, w7, 6);
    R51(d1, e1, a1, b1, c1, w14, 5);
    R52(d2, e2, a2, b2, c2, w6, 8);
    R51(c1, d1, e1, a1, b1, w1, 12);
    R52(c2, d2, e2, a2, b2, w2, 13);
    R51(b1, c1, d1, e1, a1, w3, 13);
    R52(b2, c2, d2, e2, a2, w13, 6);
    R51(a1, b1, c1, d1, e1, w8, 14);
    R52(a2, b2, c2, d2, e2, w14, 5);
    R51(e1, a1, b1, c1, d1, w11, 11);
    R52(e2, a2, b2, c2, d2, w0, 15);
    R51(d1, e1, a1, b1, c1, w6, 8);
    R52(d2, e2, a2, b2, c2, w3, 13);
    R51(c1, d1, e1, a1, b1, w15, 5);
    R52(c2, d2, e2, a2, b2, w9, 11);
    R51(b1, c1, d1, e1, a1, w13, 6);
    R52(b2, c2, d2, e2, a2, w11, 11);

    uint32_t t = s[0];
    s[0] = s[1] + c1 + d2;
    s[1] = s[2] + d1 + e2;
    s[2] = s[3] + e1 + a2;
    s[3] = s[4] + a1 + b2;
    s[4] = t + b1 + c2;
}


////// RIPEMD160

struct CDAT
{
    uint    state[5];
    uint    Lo, Hi;
};


const CDAT* ripCd()
{
    static const CDAT  r160Cd = {
        { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 },
        0, 0
    };
    return &r160Cd;
}

/******************************************************************************
* Function:     SetRip
*
* Description:  Set the SHA256 cipher
*
* Returns:      None.
******************************************************************************/
void SetRip(CIPHER* pCipher)
{
    pCipher->eCipher = CIPHER_SHA256;
    pCipher->cSize = sizeof(CTX);
    pCipher->dSize = DSIZE;
    pCipher->pIData = ripCd();

    pCipher->Init = ripInit;
    pCipher->Input = ripInput;
    pCipher->Digest = ripDigest;
    pCipher->Hash = ripHash;
}

/******************************************************************************
* Function:     ripInit
*
* Description:  Initialize the RIPEMD160 hash context
*
* Returns:      None
******************************************************************************/
void ripInit
(
    RIPCTX*     pCtx,
    const CDAT* pIData
)
{
    if (pIData == NULL) pIData = ripCd();

    memcpy(pCtx->s, pIData->state, sizeof(pCtx->s));
    pCtx->bytes = pIData->Lo;
}

//CRIPEMD160& CRIPEMD160::Write(const unsigned char* data, size_t len)
void ripInput(RIPCTX* pCtx, const uchar* pBuffer, uint nCount)
{
    const uchar* end = pBuffer + nCount;
    size_t bufsize = pCtx->bytes & 63;
    if (bufsize && bufsize + nCount >= 64) {
        // Fill the buffer, and process it.
        memcpy(pCtx->buf + bufsize, pBuffer, 64 - bufsize);
        pCtx->bytes += 64 - bufsize;
        pBuffer += 64 - bufsize;
        Transform(pCtx->s, pCtx->buf);
        bufsize = 0;
    }
    while (end >= pBuffer + 64) {
        // Process full chunks directly from the source.
        Transform(pCtx->s, pBuffer);
        pCtx->bytes += 64;
        pBuffer += 64;
    }
    if (end > pBuffer) {
        // Fill the buffer with what remains.
        memcpy(pCtx->buf + bufsize, pBuffer, end - pBuffer);
        pCtx->bytes += end - pBuffer;
    }
    //return *this;
}


/******************************************************************************
* Function:     ripDigest
*
* Description:  Calculate the RIPEMD160 message digest result. The RIPEMD160
*               Context can continue to take input afterwards.
*
* Returns:      None
******************************************************************************/
void ripDigest(const RIPCTX* pCtx, uchar pDigest[RIP_SIZE])
{
    static const uchar pad[64] = {0x80};
    uchar sizedesc[8];
    RIPCTX rip = *pCtx;
    WriteLE64(sizedesc, rip.bytes << 3);
    ripInput(&rip, pad, 1 + ((119 - (pCtx->bytes & 63)) & 63));
    ripInput(&rip, sizedesc, 8);
    WriteLE32(pDigest, rip.s[0]);
    WriteLE32(pDigest + 4, rip.s[1]);
    WriteLE32(pDigest + 8, rip.s[2]);
    WriteLE32(pDigest + 12, rip.s[3]);
    WriteLE32(pDigest + 16, rip.s[4]);
}


/******************************************************************************
* Function:     ripHash
*
* Description:  Calculate the SHA256 hash of a block of message
*
* Returns:      None
******************************************************************************/
void ripHash
(
    const uchar*    pData,
    uint            nSize,
    uchar           pDigest[RIP_SIZE]
)
{
    RIPCTX  rip;

    ripInit(&rip, ripCd());
    ripInput(&rip, pData, nSize);
    ripDigest(&rip, pDigest);
}
