/******************************************************************************
*
* Copyright © 2019 Anthony Mai Mai_Anthony@hotmail.com. All Rights Reserved.
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
*  File Name:       hkdf.cpp
*
*  Description:     Hmac Key Derivation Function. 
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         2/14/2019 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <stdint.h>
#include <string.h>
#include <new>
#include "hkdf.h"

#include "cipher.h"

const uchar Hkdf::null_[32]{0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};

// Based on https://tools.ietf.org/html/rfc5869
Hkdf::Hkdf(
    const CIPHER& c,
    const uchar* key,
    size_t cbKeySize,
    const uchar* ikm,
    size_t cbIkmSize
  ) :
    HMac(c, (key && cbKeySize)? key: null_, (key && cbKeySize)? cbKeySize: c.dSize),
    info_(nullptr),
    nsize_(0),
    bsize_(0),
    cnt_(0)
{
    if (!ikm) {
        memcpy(this->digest_, key, cbKeySize);
        return;
    }
    hash(ikm, cbIkmSize);
    new(this) HMac(c, *this, c.dSize);
}

Hkdf::Hkdf(const Hkdf& src, const uchar* ikm, size_t cbIkmSize
  ) :
    HMac(src.c_, src, src.c_.dSize),
    info_(nullptr),
    nsize_(0),
    bsize_(0),
    cnt_(0)
{
    if (!ikm) return;
    hash(ikm, cbIkmSize);
    new(this) HMac(this->c_, *this, this->c_.dSize);
}

void Hkdf::ExpandLabel(const char* label, const uchar* pInfo, size_t cbInfoSize, size_t L)
{
    uint i = 0, j = 0;
    uchar labelMsg[64];
    const char* pL = label;

    // If L is 0, pInfo is hashed first and L is assumed to be digest size, else pInfo used directly.
    if (L == 0) L = j = c_.dSize;
    labelMsg[0] = uchar(L>>8); labelMsg[1] = uchar(L); labelMsg[2] = 0x00;
    labelMsg[3] = 't'; labelMsg[4] = 'l'; labelMsg[5] = 's';
    labelMsg[6] = '1'; labelMsg[7] = '3'; labelMsg[8] = ' ';
    for (i = 9; (*label); ) {
        labelMsg[i++] = *label++;
    }
    labelMsg[2] = (i - 3);
    if (j) {
        labelMsg[i++] = c_.dSize;
        c_.Hash(pInfo, cbInfoSize, &(labelMsg[i]));
        i += c_.dSize;
    } else {
        labelMsg[i++] = uchar(cbInfoSize);
        memcpy(&(labelMsg[i]), pInfo, cbInfoSize);
        i += cbInfoSize;
    }
    Expand (labelMsg, i);
}


void Hkdf::Expand(const uchar* pInfo, size_t cbInfoSize)
{
    info_ = pInfo; nsize_ = cbInfoSize;
    CTX ctx1(ctx1_);
    CTX ctx2(ctx2_);
    uchar c[4];
    cnt_ = 0;
    c[0] = uchar(++cnt_);
    c_.Input(&ctx1, pInfo, cbInfoSize);
    c_.Input(&ctx1, c, 1);
    c_.Digest(&ctx1, digest_);
    c_.Input(&ctx2, digest_, c_.dSize);
    c_.Digest(&ctx2, digest_);
    bsize_ = c_.dSize;
}

void Hkdf::Output(uchar* pOut, size_t cbBufSize)
{
    while (cbBufSize > 0) {
        while (bsize_ > 0) {
            *pOut++ = digest_[c_.dSize - (bsize_--)];
            if (--cbBufSize == 0) return;
        }
        CTX ctx1(ctx1_), ctx2(ctx2_);
        uchar c[4];
        c[0] = uchar(++cnt_);
        c_.Input(&ctx1, digest_, c_.dSize);
        c_.Input(&ctx1, info_, nsize_);
        c_.Input(&ctx1, c, 1);
        c_.Digest(&ctx1, digest_);
        c_.Input(&ctx2, digest_, c_.dSize);
        c_.Digest(&ctx2, digest_);
        bsize_ += c_.dSize;
    }
}
