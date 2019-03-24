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

#include <stdlib.h>
#include <stdint.h>

#include "hmac.h"

#include "cipher.h"

uint HMac::size() const
{
    return c_.dSize;
}

HMac::HMac(const CIPHER& c, const uchar* key, size_t cbKeySize) :
    c_(c)
{
    size_t i = 0;
    uchar ipad[64], opad[64];
    for (i = 0; i < cbKeySize; i++) {
        ipad[i] = key[i] ^ 0x36;
        opad[i] = key[i] ^ 0x5C;
    }
    for (; i < 64; i++) {
        ipad[i] = 0x36;
        opad[i] = 0x5C;
    }
    c_.Init(&ctx1_, c_.pIData);
    c_.Init(&ctx2_, c_.pIData);
    c_.Input(&ctx1_, ipad, sizeof(ipad));
    c_.Input(&ctx2_, opad, sizeof(opad));
}

HMac& HMac::hash(HMac& src, const uchar* text, size_t cbSize)
{
    CTX ctx1(ctx1_);
    CTX ctx2(ctx2_);
    uchar d[32];
    c_.Input(&ctx1, src, c_.dSize);
    c_.Input(&ctx1, text, cbSize);
    c_.Digest(&ctx1, d);
    c_.Input(&ctx2, d, c_.dSize);
    c_.Digest(&ctx2, digest_);

    return *this;
}

HMac& HMac::hash(const uchar* text, size_t cbSize)
{
    CTX ctx1(ctx1_);
    CTX ctx2(ctx2_);
    uchar d[32];
    c_.Input(&ctx1, text, cbSize);
    c_.Digest(&ctx1, d);
    c_.Input(&ctx2, d, c_.dSize);
    c_.Digest(&ctx2, digest_);

    return *this;
}


PrfHash::PrfHash(
    const CIPHER& c,
    const uchar* key,
    size_t cbKeySize,
    const uchar* seed,
    size_t cbSeedSize
) :
    seed_(seed),
    nSeedSize_(cbSeedSize),
    nGenSize_(0),
    nUseSize_(0),
    mac_(c, key, cbKeySize),
    a_(c, key, cbKeySize)
{
    a_.hash(seed_, nSeedSize_);
}

void PrfHash::Output(uchar* pOut, size_t cbBufSize)
{
    while (cbBufSize > 0) {
        int nAvail(nGenSize_ - nUseSize_);
        if (nAvail <= 0) {
            // Generate one round of 32 bytes.
            mac_.hash(a_, seed_, nSeedSize_);
            // Generate A[i+1] = HMAC_hash(key, A[i])
            a_.hash(a_, a_.size());
            nGenSize_ += mac_.size();
            continue;
        }
        // Then take any bytes that are available.
        if (nAvail > int(cbBufSize)) nAvail = int(cbBufSize);
        int i, off = nUseSize_ & 31;
        for (i = 0; i < nAvail; i++) pOut[i] = mac_[i+off];
        nUseSize_ += nAvail; pOut += nAvail; cbBufSize -= nAvail;
    }
}
