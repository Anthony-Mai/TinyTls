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
#include <memory.h>

#include "cipher.h"

//#define SHA512_SIZE     64
#define SHA512_CBLOCK   128
/* SHA-512 treats input data as a
 * contiguous array of 64 bit
 * wide big-endian values. */
#define SHA_LONG64 U64

#define SHA512  CTX
#define DSIZE   SHA512_SIZE

#include "sha512.h"

#include "base_type.h"


struct CDAT
{
    uint64  state[8];
    uint    Lo, Hi;
};

static void Sha512Transform(SHA512* pCtx, const void* in);

const CDAT* Sha384Cd()
{
    static const CDAT  cSha384Cd = {
        { 0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
          0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL},
        0, 0
    };

    return &cSha384Cd;
}

const CDAT* Sha512Cd()
{
    static const CDAT  cSha512Cd = {
        { 0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
          0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL},
        0, 0
    };

    return &cSha512Cd;
}

/******************************************************************************
* Function:     SetSha384
*
* Description:  Set the SHA256 cipher
*
* Returns:      None.
******************************************************************************/
void SetSha384(CIPHER* pCipher)
{
    pCipher->eCipher = CIPHER_SHA384;
    pCipher->cSize = sizeof(CTX);
    pCipher->dSize = SHA384_SIZE;
    pCipher->pIData = Sha384Cd();

    pCipher->Init = Sha384Init;
    pCipher->Input = Sha512Input;
    pCipher->Digest = Sha384Digest;
    pCipher->Hash = Sha384Hash;
}

/******************************************************************************
* Function:     SetSha256
*
* Description:  Set the SHA256 cipher
*
* Returns:      None.
******************************************************************************/
void SetSha512(CIPHER* pCipher)
{
    pCipher->eCipher = CIPHER_SHA512;
    pCipher->cSize = sizeof(CTX);
    pCipher->dSize = DSIZE;
    pCipher->pIData = Sha512Cd();

    pCipher->Init = Sha512Init;
    pCipher->Input = Sha512Input;
    pCipher->Digest = Sha512Digest;
    pCipher->Hash = Sha512Hash;
}

void Sha384Init(SHA512* p, const CDAT* pIData)
{
    if (pIData == NULL) pIData = Sha384Cd();

    p->Nl = 0;
    p->Nh = 0;
    p->num = 0;
    p->md_len = SHA384_SIZE;

    memcpy(p->h_, pIData->state, sizeof(p->h_));
}

void Sha512Init(SHA512* p, const CDAT* pIData)
{
    if (pIData == NULL) pIData = Sha512Cd();

    p->Nl = 0;
    p->Nh = 0; 
    p->num = 0;
    p->md_len = SHA512_SIZE;

    memcpy(p->h_, pIData->state, sizeof(p->h_));
}

static void shaDigest(SHA512* sha/*, uint8_t md[DSIZE]*/)
{
    uchar* p = (uchar*)sha->u.p;
    size_t n = sha->num;

    p[n++] = 0x80;  // There always is a room for one
    if (n > (SHA512_CBLOCK - 16)) {
        memset(p + n, 0, SHA512_CBLOCK - n);
        n = 0;
        Sha512Transform(sha, p);
    }

    memset(p + n, 0, SHA512_CBLOCK - 16 - n);

#ifdef  CONFIG_BIG_ENDIAN
    sha.u.d[SHA_LBLOCK - 2] = sha.Nh;
    sha.u.d[SHA_LBLOCK - 1] = sha.Nl;
#else
    p[SHA512_CBLOCK - 1] = (uchar)(sha->Nl);
    p[SHA512_CBLOCK - 2] = (uchar)(sha->Nl >> 8);
    p[SHA512_CBLOCK - 3] = (uchar)(sha->Nl >> 16);
    p[SHA512_CBLOCK - 4] = (uchar)(sha->Nl >> 24);
    p[SHA512_CBLOCK - 5] = (uchar)(sha->Nl >> 32);
    p[SHA512_CBLOCK - 6] = (uchar)(sha->Nl >> 40);
    p[SHA512_CBLOCK - 7] = (uchar)(sha->Nl >> 48);
    p[SHA512_CBLOCK - 8] = (uchar)(sha->Nl >> 56);
    p[SHA512_CBLOCK - 9] = (uchar)(sha->Nh);
    p[SHA512_CBLOCK - 10] = (uchar)(sha->Nh >> 8);
    p[SHA512_CBLOCK - 11] = (uchar)(sha->Nh >> 16);
    p[SHA512_CBLOCK - 12] = (uchar)(sha->Nh >> 24);
    p[SHA512_CBLOCK - 13] = (uchar)(sha->Nh >> 32);
    p[SHA512_CBLOCK - 14] = (uchar)(sha->Nh >> 40);
    p[SHA512_CBLOCK - 15] = (uchar)(sha->Nh >> 48);
    p[SHA512_CBLOCK - 16] = (uchar)(sha->Nh >> 56);
#endif

    Sha512Transform(sha, p);
}

void Sha384Digest(const SHA512* pSha, uint8_t md[SHA384_SIZE])
{
    SHA512  sha = *pSha;

    shaDigest(&sha);

    if (md) for (size_t n = 0; n < SHA384_SIZE / 8; n++)
    {
        M64 m;
        m.u64 = sha.h_[n];
        *(md++) = m.u8.b7;
        *(md++) = m.u8.b6;
        *(md++) = m.u8.b5;
        *(md++) = m.u8.b4;
        *(md++) = m.u8.b3;
        *(md++) = m.u8.b2;
        *(md++) = m.u8.b1;
        *(md++) = m.u8.b0;
    }
}

void Sha512Digest(const SHA512* pSha, uint8_t md[DSIZE])
{
    SHA512  sha = *pSha;

    shaDigest(&sha);

    if (md) for (size_t n=0; n < SHA512_SIZE/8; n++) {
        M64 m;
        m.u64 = sha.h_[n];
        *(md++) = m.u8.b7;
        *(md++) = m.u8.b6;
        *(md++) = m.u8.b5;
        *(md++) = m.u8.b4;
        *(md++) = m.u8.b3;
        *(md++) = m.u8.b2;
        *(md++) = m.u8.b1;
        *(md++) = m.u8.b0;
    }
}

/******************************************************************************
* Function:     Sha384Hash
*
* Description:  Calculate the SHA384 hash of a block of message
*
* Returns:      None
******************************************************************************/
void Sha384Hash
(
    const uchar*    pData,
    uint            nSize,
    uchar           pDigest[SHA384_SIZE]
)
{
    SHA512  sha;

    Sha384Init(&sha, Sha384Cd());
    Sha512Input(&sha, pData, nSize);
    Sha384Digest(&sha, pDigest);
}

/******************************************************************************
* Function:     Sha512Hash
*
* Description:  Calculate the SHA512 hash of a block of message
*
* Returns:      None
******************************************************************************/
void Sha512Hash
(
    const uchar*    pData,
    uint            nSize,
    uchar           pDigest[SHA512_SIZE]
)
{
    SHA512  sha;

    Sha512Init(&sha, Sha512Cd());
    Sha512Input(&sha, pData, nSize);
    Sha512Digest(&sha, pDigest);
}

void Sha512Input(SHA512* pCtx, const uint8_t* pData, uint32_t len)
{
    uint64_t l;
    uint8_t* p = pCtx->u.p;
    const uint8_t* data = pData;

    if (len==0) return;

    l = (pCtx->Nl+(((uint64_t)len)<<3))&0xffffffffffffffffULL;
    if (l < pCtx->Nl) pCtx->Nh++;
    if (sizeof(len)>=8) pCtx->Nh+=(((uint64_t)len)>>61);
    pCtx->Nl=l;

    if (pCtx->num != 0)
    {
        size_t n = SHA512_CBLOCK - pCtx->num;

        if (len < n)
        {
            memcpy(p + pCtx->num, data, len);
            pCtx->num += (unsigned int)len;
            return;
        }
        else    
        {
            memcpy(p + pCtx->num, data, n);
            pCtx->num = 0;
            len-=n, data+=n;
            Sha512Transform (pCtx, p);
        }
    }

    while (len >= SHA512_CBLOCK)
    {
        Sha512Transform(pCtx, data);//,len/SHA512_CBLOCK),
        data += SHA512_CBLOCK;
        len  -= SHA512_CBLOCK;
    }

    if (len != 0) { memcpy(p, data, len); pCtx->num = (int)len; }
}

static const uint64_t K512[80] = 
{
    UINT64(0x428a2f98d728ae22),UINT64(0x7137449123ef65cd),
    UINT64(0xb5c0fbcfec4d3b2f),UINT64(0xe9b5dba58189dbbc),
    UINT64(0x3956c25bf348b538),UINT64(0x59f111f1b605d019),
    UINT64(0x923f82a4af194f9b),UINT64(0xab1c5ed5da6d8118),
    UINT64(0xd807aa98a3030242),UINT64(0x12835b0145706fbe),
    UINT64(0x243185be4ee4b28c),UINT64(0x550c7dc3d5ffb4e2),
    UINT64(0x72be5d74f27b896f),UINT64(0x80deb1fe3b1696b1),
    UINT64(0x9bdc06a725c71235),UINT64(0xc19bf174cf692694),
    UINT64(0xe49b69c19ef14ad2),UINT64(0xefbe4786384f25e3),
    UINT64(0x0fc19dc68b8cd5b5),UINT64(0x240ca1cc77ac9c65),
    UINT64(0x2de92c6f592b0275),UINT64(0x4a7484aa6ea6e483),
    UINT64(0x5cb0a9dcbd41fbd4),UINT64(0x76f988da831153b5),
    UINT64(0x983e5152ee66dfab),UINT64(0xa831c66d2db43210),
    UINT64(0xb00327c898fb213f),UINT64(0xbf597fc7beef0ee4),
    UINT64(0xc6e00bf33da88fc2),UINT64(0xd5a79147930aa725),
    UINT64(0x06ca6351e003826f),UINT64(0x142929670a0e6e70),
    UINT64(0x27b70a8546d22ffc),UINT64(0x2e1b21385c26c926),
    UINT64(0x4d2c6dfc5ac42aed),UINT64(0x53380d139d95b3df),
    UINT64(0x650a73548baf63de),UINT64(0x766a0abb3c77b2a8),
    UINT64(0x81c2c92e47edaee6),UINT64(0x92722c851482353b),
    UINT64(0xa2bfe8a14cf10364),UINT64(0xa81a664bbc423001),
    UINT64(0xc24b8b70d0f89791),UINT64(0xc76c51a30654be30),
    UINT64(0xd192e819d6ef5218),UINT64(0xd69906245565a910),
    UINT64(0xf40e35855771202a),UINT64(0x106aa07032bbd1b8),
    UINT64(0x19a4c116b8d2d0c8),UINT64(0x1e376c085141ab53),
    UINT64(0x2748774cdf8eeb99),UINT64(0x34b0bcb5e19b48a8),
    UINT64(0x391c0cb3c5c95a63),UINT64(0x4ed8aa4ae3418acb),
    UINT64(0x5b9cca4f7763e373),UINT64(0x682e6ff3d6b2b8a3),
    UINT64(0x748f82ee5defb2fc),UINT64(0x78a5636f43172f60),
    UINT64(0x84c87814a1f0ab72),UINT64(0x8cc702081a6439ec),
    UINT64(0x90befffa23631e28),UINT64(0xa4506cebde82bde9),
    UINT64(0xbef9a3f7b2c67915),UINT64(0xc67178f2e372532b),
    UINT64(0xca273eceea26619c),UINT64(0xd186b8c721c0c207),
    UINT64(0xeada7dd6cde0eb1e),UINT64(0xf57d4f7fee6ed178),
    UINT64(0x06f067aa72176fba),UINT64(0x0a637dc5a2c898a6),
    UINT64(0x113f9804bef90dae),UINT64(0x1b710b35131c471b),
    UINT64(0x28db77f523047d84),UINT64(0x32caab7b40c72493),
    UINT64(0x3c9ebe0a15c9bebc),UINT64(0x431d67c49c100d4c),
    UINT64(0x4cc5d4becb3e42b6),UINT64(0x597f299cfc657e2a),
    UINT64(0x5fcb6fab3ad6faec),UINT64(0x6c44198c4a475817) 
};

#define B(x,j)    (((uint64_t)(*(((const uint8_t*)(&x))+j)))<<((7-j)*8))
#define PULL64(x) (B(x,0)|B(x,1)|B(x,2)|B(x,3)|B(x,4)|B(x,5)|B(x,6)|B(x,7))
#define ROTR(x,s)   (((x)>>s) | (x)<<(64-s))

#define Sigma0(x)   (ROTR((x),28) ^ ROTR((x),34) ^ ROTR((x),39))
#define Sigma1(x)   (ROTR((x),14) ^ ROTR((x),18) ^ ROTR((x),41))
#define sigma0(x)   (ROTR((x),1)  ^ ROTR((x),8)  ^ ((x)>>7))
#define sigma1(x)   (ROTR((x),19) ^ ROTR((x),61) ^ ((x)>>6))

#define Ch(x,y,z)   (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define ROUND_00_15(i,a,b,c,d,e,f,g,h) do { \
    T1 += h + Sigma1(e) + Ch(e,f,g) + K512[i]; \
    h = Sigma0(a) + Maj(a,b,c); \
    d += T1; h += T1; } while (0)

#define ROUND_16_80(i,j,a,b,c,d,e,f,g,h,X) do { \
    s0 = X[(j+1)&0x0f]; s0 = sigma0(s0); \
    s1 = X[(j+14)&0x0f]; s1 = sigma1(s1); \
    T1 = X[(j)&0x0f] += s0 + s1 + X[(j+9)&0x0f]; \
    ROUND_00_15(i+j,a,b,c,d,e,f,g,h); } while (0)

void Sha512Transform(SHA512* pCtx, const void* in)
{
    const uint64_t* W = (const uint64_t*)in;
    uint64_t  a,b,c,d,e,f,g,h,s0,s1,T1;
    uint64_t  X[16];
    int i;

    a = pCtx->h_[0];  b = pCtx->h_[1];  c = pCtx->h_[2];  d = pCtx->h_[3];
    e = pCtx->h_[4];  f = pCtx->h_[5];  g = pCtx->h_[6];  h = pCtx->h_[7];

#ifdef ECP_CONFIG_BIG_ENDIAN
    T1 = X[0] = W[0];   ROUND_00_15(0,a,b,c,d,e,f,g,h);
    T1 = X[1] = W[1];   ROUND_00_15(1,h,a,b,c,d,e,f,g);
    T1 = X[2] = W[2];   ROUND_00_15(2,g,h,a,b,c,d,e,f);
    T1 = X[3] = W[3];   ROUND_00_15(3,f,g,h,a,b,c,d,e);
    T1 = X[4] = W[4];   ROUND_00_15(4,e,f,g,h,a,b,c,d);
    T1 = X[5] = W[5];   ROUND_00_15(5,d,e,f,g,h,a,b,c);
    T1 = X[6] = W[6];   ROUND_00_15(6,c,d,e,f,g,h,a,b);
    T1 = X[7] = W[7];   ROUND_00_15(7,b,c,d,e,f,g,h,a);
    T1 = X[8] = W[8];   ROUND_00_15(8,a,b,c,d,e,f,g,h);
    T1 = X[9] = W[9];   ROUND_00_15(9,h,a,b,c,d,e,f,g);
    T1 = X[10] = W[10]; ROUND_00_15(10,g,h,a,b,c,d,e,f);
    T1 = X[11] = W[11]; ROUND_00_15(11,f,g,h,a,b,c,d,e);
    T1 = X[12] = W[12]; ROUND_00_15(12,e,f,g,h,a,b,c,d);
    T1 = X[13] = W[13]; ROUND_00_15(13,d,e,f,g,h,a,b,c);
    T1 = X[14] = W[14]; ROUND_00_15(14,c,d,e,f,g,h,a,b);
    T1 = X[15] = W[15]; ROUND_00_15(15,b,c,d,e,f,g,h,a);
#else
    T1 = X[0]  = PULL64(W[0]);  ROUND_00_15(0,a,b,c,d,e,f,g,h);
    T1 = X[1]  = PULL64(W[1]);  ROUND_00_15(1,h,a,b,c,d,e,f,g);
    T1 = X[2]  = PULL64(W[2]);  ROUND_00_15(2,g,h,a,b,c,d,e,f);
    T1 = X[3]  = PULL64(W[3]);  ROUND_00_15(3,f,g,h,a,b,c,d,e);
    T1 = X[4]  = PULL64(W[4]);  ROUND_00_15(4,e,f,g,h,a,b,c,d);
    T1 = X[5]  = PULL64(W[5]);  ROUND_00_15(5,d,e,f,g,h,a,b,c);
    T1 = X[6]  = PULL64(W[6]);  ROUND_00_15(6,c,d,e,f,g,h,a,b);
    T1 = X[7]  = PULL64(W[7]);  ROUND_00_15(7,b,c,d,e,f,g,h,a);
    T1 = X[8]  = PULL64(W[8]);  ROUND_00_15(8,a,b,c,d,e,f,g,h);
    T1 = X[9]  = PULL64(W[9]);  ROUND_00_15(9,h,a,b,c,d,e,f,g);
    T1 = X[10] = PULL64(W[10]); ROUND_00_15(10,g,h,a,b,c,d,e,f);
    T1 = X[11] = PULL64(W[11]); ROUND_00_15(11,f,g,h,a,b,c,d,e);
    T1 = X[12] = PULL64(W[12]); ROUND_00_15(12,e,f,g,h,a,b,c,d);
    T1 = X[13] = PULL64(W[13]); ROUND_00_15(13,d,e,f,g,h,a,b,c);
    T1 = X[14] = PULL64(W[14]); ROUND_00_15(14,c,d,e,f,g,h,a,b);
    T1 = X[15] = PULL64(W[15]); ROUND_00_15(15,b,c,d,e,f,g,h,a);
#endif

    for (i=16;i<80;i+=16)
    {
        ROUND_16_80(i, 0,a,b,c,d,e,f,g,h,X);
        ROUND_16_80(i, 1,h,a,b,c,d,e,f,g,X);
        ROUND_16_80(i, 2,g,h,a,b,c,d,e,f,X);
        ROUND_16_80(i, 3,f,g,h,a,b,c,d,e,X);
        ROUND_16_80(i, 4,e,f,g,h,a,b,c,d,X);
        ROUND_16_80(i, 5,d,e,f,g,h,a,b,c,X);
        ROUND_16_80(i, 6,c,d,e,f,g,h,a,b,X);
        ROUND_16_80(i, 7,b,c,d,e,f,g,h,a,X);
        ROUND_16_80(i, 8,a,b,c,d,e,f,g,h,X);
        ROUND_16_80(i, 9,h,a,b,c,d,e,f,g,X);
        ROUND_16_80(i,10,g,h,a,b,c,d,e,f,X);
        ROUND_16_80(i,11,f,g,h,a,b,c,d,e,X);
        ROUND_16_80(i,12,e,f,g,h,a,b,c,d,X);
        ROUND_16_80(i,13,d,e,f,g,h,a,b,c,X);
        ROUND_16_80(i,14,c,d,e,f,g,h,a,b,X);
        ROUND_16_80(i,15,b,c,d,e,f,g,h,a,X);
    }

    pCtx->h_[0] += a; pCtx->h_[1] += b; pCtx->h_[2] += c; pCtx->h_[3] += d;
    pCtx->h_[4] += e; pCtx->h_[5] += f; pCtx->h_[6] += g; pCtx->h_[7] += h;
}

int signTest3()
{
    uint8_t clientRandom[32] = {
        0x6a, 0x68, 0x75, 0x71, 0x1a, 0xbe, 0x09, 0x85, 0x88, 0xd8, 0x40, 0xc0, 0xab, 0xbe, 0x20, 0x78,
        0xba, 0x37, 0x08, 0x02, 0x4d, 0x23, 0x4a, 0x77, 0xb8, 0xb5, 0x3f, 0x7d, 0x9f, 0x15, 0x97, 0x8f };

    uint8_t serverRandom[32] = {
        0xF3, 0xCB, 0xBA, 0xDA, 0xF0, 0x51, 0x8C, 0x2C, 0x03, 0x2E, 0x39, 0xA0, 0x12, 0x9C, 0xC1, 0x6E,
        0x96, 0x00, 0x0A, 0x49, 0x54, 0x6D, 0xCF, 0x48, 0xEA, 0x64, 0x3E, 0xEE, 0x12, 0xE7, 0x2F, 0x8B };

    uint8_t eccParams[] = {
        0x03, 0x00, 0x1d, 0x20,
        0x03, 0x12, 0x1a, 0xac, 0x49, 0xa7, 0xbf, 0x29, 0xfe, 0x58, 0x20, 0x17, 0xb4, 0x15, 0x30, 0x6d,
        0x5c, 0xae, 0x4b, 0xdb, 0x36, 0xfc, 0x6c, 0xd8, 0x05, 0x1e, 0x2f, 0x0f, 0x89, 0x99, 0x35, 0x27 };

    const uint8_t c_exp[] = {
        0x0f, 0x88, 0xb7, 0xa5, 0x57, 0x96, 0x33, 0x7b, 0xbb, 0xa4, 0x0a, 0x0b, 0x4e, 0x99, 0xf0, 0xa3,
        0xb8, 0xda, 0x2d, 0xa4, 0x25, 0xf8, 0x3f, 0x0f, 0x95, 0xa5, 0x8e, 0x17, 0xae, 0x90, 0x51, 0xa6,
        0xdd, 0xb1, 0x34, 0x1a, 0x0c, 0x49, 0xc2, 0x0e, 0x7c, 0x13, 0xe2, 0x04, 0x7c, 0x0b, 0xe4, 0x84,
        0xb4, 0x16, 0x08, 0x28, 0x3f, 0x02, 0x99, 0x6b, 0x78, 0xef, 0xd0, 0x6a, 0x4a, 0xd0, 0x41, 0x92 };

    SHA512 ctx;
    uint8_t eccHash[64];

    Sha512Init(&ctx, Sha512Cd());
    Sha512Input(&ctx, clientRandom, 32);
    Sha512Input(&ctx, serverRandom, 32);
    Sha512Input(&ctx, eccParams, 36);
    Sha512Digest(&ctx, eccHash);

    int ret = 0;
    ret |= memcmp(c_exp, eccHash, 64);
    return ret;
}
