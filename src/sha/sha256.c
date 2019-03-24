/******************************************************************************
*
* Copyright © 2014-2019 Anthony Mai Mai_Anthony@hotmail.com. All Rights Reserved.
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

/******************************************************************************
*
*  File Name:       sha256.c
*
*  Description:     SHA-256 message digest algorithm implementation.
*
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         6/28/2014 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <string.h>
//#include <stdlib.h>
#include <stdint.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif //(_MSC_VER)

#include "cipher.h"

#define SHA256  CTX
#define DSIZE   SHA256_SIZE

#include "sha256.h"
#include "endian.h"


/* this Microsft VC++ intrinsic rotate makes a big difference to the speed of this code */

#if defined(_MSC_VER)
#define rotr32(x,n)   _lrotr(x,n)
#else
#define rotr32(x,n)   (((x) >> n) | ((x) << (32 - n)))
#endif

#if !defined(bswap_32)
#define bswap_32(x) (rotr32((x), 24) & 0x00ff00ff | rotr32((x), 8) & 0xff00ff00)
#endif

/* SHA256 mixing function definitions   */

#define ch(x,y,z)   (((x) & (y)) ^ (~(x) & (z)))
#define maj(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define s256_0(x) (rotr32((x),  2) ^ rotr32((x), 13) ^ rotr32((x), 22)) 
#define s256_1(x) (rotr32((x),  6) ^ rotr32((x), 11) ^ rotr32((x), 25)) 
#define g256_0(x) (rotr32((x),  7) ^ rotr32((x), 18) ^ ((x) >>  3)) 
#define g256_1(x) (rotr32((x), 17) ^ rotr32((x), 19) ^ ((x) >> 10)) 

/* rotated SHA256 round definition. Rather than swapping variables as in    */
/* FIPS-180, different variables are 'rotated' on each round, returning     */
/* to their starting positions every eight rounds                           */

#define h2(i) ctx->wdat[i & 15] += \
    g256_1(ctx->wdat[(i + 14) & 15]) + ctx->wdat[(i + 9) & 15] + g256_0(ctx->wdat[(i + 1) & 15])

#define h2_cycle(i,j)  \
    v[(7 - i) & 7] += (j ? h2(i) : ctx->wdat[i & 15]) + k256[i + j] \
        + s256_1(v[(4 - i) & 7]) + ch(v[(4 - i) & 7], v[(5 - i) & 7], v[(6 - i) & 7]); \
    v[(3 - i) & 7] += v[(7 - i) & 7]; \
    v[(7 - i) & 7] += s256_0(v[(0 - i) & 7]) + maj(v[(0 - i) & 7], v[(1 - i) & 7], v[(2 - i) & 7])

// SHA256 mixing data
static const uint k256[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};


static void sha256Round(SHA256* ctx);


static const uint i256[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};


struct CDAT
{
    uint    state[8];
    uint    Lo,Hi;
};


const CDAT* Sha256Cd()
{
    static const CDAT  cSha256Cd = {
        {0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A,0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19},
        0, 0
    };

    return &cSha256Cd;
}


/******************************************************************************
* Function:     SetSha256
*
* Description:  Set the SHA256 cipher
*
* Returns:      None.
******************************************************************************/
void SetSha256(CIPHER* pCipher)
{
    pCipher->eCipher = CIPHER_SHA256;
    pCipher->cSize  = sizeof(CTX);
    pCipher->dSize  = DSIZE;
    pCipher->pIData = Sha256Cd();

    pCipher->Init  = Sha256Init;
    pCipher->Input = Sha256Input;
    pCipher->Digest= Sha256Digest;
    pCipher->Hash  = Sha256Hash;
}


void sha256Round(SHA256* ctx)
{
    uint    v[8], j;

    memcpy(v, ctx->hash, 32);

    for(j = 0; j < 64; j += 16)
    {
        h2_cycle( 0, j); h2_cycle( 1, j); h2_cycle( 2, j); h2_cycle( 3, j);
        h2_cycle( 4, j); h2_cycle( 5, j); h2_cycle( 6, j); h2_cycle( 7, j);
        h2_cycle( 8, j); h2_cycle( 9, j); h2_cycle(10, j); h2_cycle(11, j);
        h2_cycle(12, j); h2_cycle(13, j); h2_cycle(14, j); h2_cycle(15, j);
    }

    ctx->hash[0] += v[0]; ctx->hash[1] += v[1]; ctx->hash[2] += v[2]; ctx->hash[3] += v[3];
    ctx->hash[4] += v[4]; ctx->hash[5] += v[5]; ctx->hash[6] += v[6]; ctx->hash[7] += v[7];
}


/******************************************************************************
* Function:     Sha256Init
*
* Description:  Initialize the SHA-256 hash
*
* Returns:      None
******************************************************************************/
void Sha256Init
(
    SHA256*     pShaCtx,
    const CDAT* pIData
)
{
    if (pIData == NULL) pIData = Sha256Cd();

    memcpy(pShaCtx->hash, pIData->state, sizeof(pShaCtx->hash));
    pShaCtx->count[0] = pIData->Lo;
    pShaCtx->count[1] = pIData->Hi;
}


/******************************************************************************
* Function:     Sha256Input
*
* Description:  Do SHA-256 hash on input data. The has is done by first calling
*               Sha256Init, then do multiple Sha256Input as necessary, and
*               finally call Sha256Digest to get result.
*
* Returns:      None
******************************************************************************/
void Sha256Input
(
    SHA256*     pSha,
    const uchar*    pBuffer,
    uint            nCount
)
{
    uint   dataCount, chunk;

    // Get count of bytes already in data
    dataCount = pSha->count[0] & 0x3F;

    // Update byte count
    pSha->count[0] += nCount;
    pSha->count[1] += (pSha->count[0] < nCount)&1;

    // Handle any leading odd-sized chunks
    for ( ; (dataCount&3) && nCount; dataCount++, nCount--)
    {
        pSha->wdat[(dataCount)>>2] = (pSha->wdat[(dataCount)>>2]<<8) + (*pBuffer++);
    }

    if (dataCount >= SHA256_DATA)
    {
        sha256Round(pSha); dataCount &= 0x3F;
    }

    for ( ; nCount > 3; )
    {
        chunk = SHA256_DATA - dataCount;
        if (chunk > nCount)
        {
            chunk = nCount & (-4);
            Byte2Int(pBuffer, &(pSha->wdat[(dataCount>>2)&0x3F]), chunk>>2);
            dataCount += chunk; pBuffer += chunk; nCount -= chunk;
            break;
        }
        else if (chunk)
        {
            Byte2Int(pBuffer, &(pSha->wdat[(dataCount>>2)&0x3F]), chunk>>2);
            dataCount += chunk; pBuffer += chunk; nCount -= chunk;
        }
        sha256Round(pSha); dataCount &= 0x3F;
    }

    for ( ; nCount; dataCount++, nCount--)
    {
        pSha->wdat[(dataCount>>2)&0x3F] = (pSha->wdat[(dataCount>>2)&0x3F]<<8) + (*pBuffer++);
    }
}


/******************************************************************************
* Function:     Sha256Digest
*
* Description:  Calculate the SHA-256 message digest result. The SHA256 Context
*               can continue to take input afterwards.
*
* Returns:      None
******************************************************************************/
void Sha256Digest
(
    const SHA256*   pSha,                   //Context for SHA-256 hash
    uchar           pDigest[SHA256_SIZE]    //A 32 bytes buffer to contain the hash result
)
{
    uint        count;
    SHA256  sha = *pSha;

    // Compute number of bytes mod 64
    count = sha.count[0] & 0x3F;

    // Set the first char of padding to 0x80.  This is safe since there is
    // always at least one byte free
    sha.wdat[(count)>>2] = (sha.wdat[(count)>>2]<<8) + (0x80); count++;

    for ( ; (count&3); count++)
    {
        sha.wdat[(count)>>2] = (sha.wdat[(count)>>2]<<8);
    }

    // Pad out to 56 mod 64
    memset(&(sha.wdat[count>>2]), 0, SHA256_DATA - count);
    if (SHA256_DATA - count < 8)
    {
        // Two lots of padding:  Pad the first block to 64 bytes
        sha256Round(&sha);

        // Now fill the next block with 56 bytes
        memset(sha.wdat, 0, SHA256_DATA);
    }

    // Append length in bits and transform
    sha.wdat[14] = (sha.count[1] << 3) + (sha.count[0] >> 29);
    sha.wdat[15] = (sha.count[0] << 3);
    sha256Round(&sha);

    Int2Byte(sha.hash, pDigest, SHA256_SIZE>>2); 
}


/******************************************************************************
* Function:     Sha256Hash
*
* Description:  Calculate the SHA256 hash of a block of message
*
* Returns:      None
******************************************************************************/
void Sha256Hash
(
    const uchar*    pData,
    uint            nSize,
    uchar           pDigest[SHA256_SIZE]
)
{
    SHA256  sha;

    Sha256Init(&sha, Sha256Cd());
    Sha256Input(&sha, pData, nSize);
    Sha256Digest(&sha, pDigest);
}


#ifdef TEST_SHA256

#include <stdio.h>
#include <string.h>

typedef struct SHA256TEST
{
    const char* pTestString;
    char        result[64];
} SHA256TEST;

//Do NOT modify this. This is the official SHA256 test suite. It is found at:
//    https://www.dlitz.net/crypto/shad256-test-vectors/
static SHA256TEST gSHA256Tests[] = {
    {"",    "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"},
    {"abc", "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"},
    {"Þ\030‰A£7]:Š\006\036gWn’m", //DE188941A3375D3A8A061E67576E926D
            "067C531269735CA7F541FDACA8F0DC76305D3CADA140F89372A410FE5EFF6E4D"},
    {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"},
    {0, ""}
};


uint sha256Test()
{
    uint        i, j=0;
    SHA256      sha256;
    SHA256TEST* pTest = gSHA256Tests;
    uchar       digest[SHA256_SIZE];
    uchar       digestMsg[SHA256_SIZE*2+2];

    while (pTest->pTestString && (j == 0))
    {
        Sha256Init(&sha256, Sha256Cd());
        Sha256Input(&sha256, pTest->pTestString, strlen(pTest->pTestString));
        Sha256Digest(&sha256, digest);

        for (i=0; i<SHA256_SIZE; i++)
        {
            sprintf((char*)&(digestMsg[i+i]), "%02X", digest[i]);
        }
        j |= memcmp(digestMsg, pTest->result, sizeof(pTest->result));

        pTest++;
    }

    return j;
}

#endif //TEST_SHA256
