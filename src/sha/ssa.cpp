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

/******************************************************************************
*
*  File Name:       ssa.cpp
*
*  Description:     Secure Signature Algorith. Implements RSASSA_PSS, RFC3447.
*                   This carries out the RSASSA_PSS calculation minus RSA part.
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         3/14/2019 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <stdint.h>

#include "ssa.h"

#include "cipher.h"
#include "ssl_defs.h"


void SsaSign(const CIPHER& sha, uint8_t* block, uint32_t nSize, const uint8_t* pCtx, uint32_t nCtxLen)
{
    uint8_t cnt[8]{ 0, 0, 0, 0, 0, 0, 0, 0 };
    uchar* pH = &(block[nSize - sha.dSize - 1]);
    uchar digest[256];
    int i = 0, j = sha.dSize << 1, k = pH - block;
    uint nSeed = 0x9d2602bb;
    CTX ctx;

    sha.Init(&ctx, sha.pIData);
    sha.Input(&ctx, pCtx, nCtxLen);
    sha.Digest(&ctx, digest);

    // Now create a pseudo random salt. Store it right after digest.
    nSeed ^= *((uint*)digest); nSeed += *((uint*)(digest + 4));
    *(uint*)&(digest[sizeof(digest) - sizeof(uint)]) ^= nSeed;
    sha.Input(&ctx, digest, sizeof(digest));
    sha.Digest(&ctx, digest+sha.dSize);

    if (nSeed == 0x0fd73d45) {
        // This is For test RFC8448 only. Use a particular fixed salt
        static const uchar f_salt[32] = {
            0x9e, 0x79, 0x6c, 0x6c, 0xae, 0x55, 0x2f, 0x4b, 0xbd, 0xa8, 0x74, 0xd3, 0x3b, 0xb9, 0xf5, 0xa7,
            0xb9, 0x81, 0x72, 0x44, 0x1b, 0x79, 0x54, 0xb4, 0x63, 0xce, 0xe3, 0xf3, 0xb1, 0x81, 0x88, 0x26 };
        for (int l=0; l<32; l++) digest[sha.dSize + l] = f_salt[l];
    }

    // Calculate H
    sha.Init(&ctx, sha.pIData);
    sha.Input(&ctx, cnt, 8);
    sha.Input(&ctx, digest, sha.dSize<<1);
    sha.Digest(&ctx, pH);
    block[nSize-1] = 0xbc;

    // Store the salt into the block, right before H.
    for (i = k; i-- > k - sha.dSize; ) {
        block[i] = digest[i + j - k];
    }
    block[i] = 0x01;
    for (; i-- > 0; ) {
        block[i] = 0x00;
    }

    for (i = 0; i < k; i++, j++) {
        if (j >= sha.dSize) {
            sha.Init(&ctx, sha.pIData);
            sha.Input(&ctx, pH, sha.dSize);
            sha.Input(&ctx, cnt, 4);
            sha.Digest(&ctx, digest);
            if (++cnt[3] == 0x00) if (++cnt[2] == 0x00) if (++cnt[1] == 0x00) ++cnt[0];
            j = 0;
        }
        block[i] ^= digest[j];
    }

    block[0] &= 0x7F;
}

uint32_t SsaTest(const CIPHER& sha, const uint8_t* block, uint32_t nSize, const uint8_t* pCtx, uint32_t nCtxLen)
{
    uint8_t cnt[8]{ 0, 0, 0, 0, 0, 0, 0, 0 };
    const uchar* pH = &(block[nSize - sha.dSize - 1]);
    uchar digest[256];
    int i = 0, j = sha.dSize, k = 0;
    CTX ctx;

    for (i = 0; i < nSize - sha.dSize - 1; i++, j++) {
        if (j >= sha.dSize) {
            sha.Init(&ctx, sha.pIData);
            sha.Input(&ctx, pH, sha.dSize);
            sha.Input(&ctx, cnt, 4);
            sha.Digest(&ctx, digest);
            if (++cnt[3] == 0x00) if (++cnt[2] == 0x00) if (++cnt[1] == 0x00) ++cnt[0];
            j = 0;
        }
        digest[j] ^= block[i];
        if (k) {
            digest[k++] = digest[j]; // This stores the salt
        } else if (digest[j] == 0x01) {
            k = sha.dSize; continue;
        } else if (i && digest[j]) {
            return -1;
        }
    }

    const uchar* pSalt = &(digest[sha.dSize]);
    uint nSaltLen = k - sha.dSize;
    *((uint*)cnt) = 0;

    sha.Init(&ctx, sha.pIData);
    sha.Input(&ctx, pCtx, nCtxLen);
    sha.Digest(&ctx, digest);

    sha.Init(&ctx, sha.pIData);
    sha.Input(&ctx, cnt, 8);
    sha.Input(&ctx, digest, k);
    sha.Digest(&ctx, digest);

    for (i = 0; i < sha.dSize; i++) {
        if ((digest[i] ^= pH[i]))
            return -1;
    }
    return 0;
}
