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
*  File Name:       base58.cpp
*
*  Description:     Base58 encoding and decoding.
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         10/18/2018 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <stdint.h>
#include <memory.h>
#include "base58.h"
#include "ecc.h"

struct N58 : NN {
    uint32_t reduce58();
    void madd58(uint8_t v);
};

uint32_t N58::reduce58()
{
    uint32_t r = 0, q = 0;
    for (uint32_t i = N; i-- > 0; ) {
        q = n_[i] / 58; n_[i] -= q * 58;
        q += r * 74051160;
        r <<= 4; r += n_[i];
        n_[i] = q; q = r / 58;
        n_[i] += q; r -= q * 58;
    }
    return r;
}

void N58::madd58(uint8_t a)
{
    uint32_t r = 0, q = 0, v(a);
    NN n(*this);
    *this <<= 6;
    n <<= 1; *this -= n;
    n <<= 1; *this -= n;
    for (uint32_t i = 0; i < N; i++) {
        n_[i] += a;
        if (n_[i] >= a) break;
        a = 1;
    }
}


uint32_t base58Encode(const uint8_t* pIn, uint32_t cbSize, char* pOut)
{
    // https://en.bitcoin.it/wiki/Base58Check_encoding
    static const uint8_t sCode[]{ "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" };
    uint8_t bData[32];
    uint8_t bOut[48];
    uint8_t* p = bOut;
    char* p0 = pOut;
    while (*pIn == 0x00) {
        pIn++; cbSize--; *pOut++ = '1';
    }
    memset(bData, 0, sizeof(bData));
    memcpy(bData + 32 - cbSize, pIn, cbSize);
    N58 n; n.netIn(bData);
    do {
        *p++ = n.reduce58();
    } while (!n.is0());
    while (p-- > bOut) {
        *pOut++ = sCode[*p];
    }    
    *pOut = 0x00;
    return pOut - p0;
}

uint32_t base58Decode(const char* pIn, uint32_t cbSize, uint8_t* pOut)
{
    uint8_t* p0 = pOut;
    while (*pIn == '1') {
        pIn++; cbSize--; *pOut++ = 0x00;
    }

    N58 n;
    while (cbSize--) {
        uint8_t v(*pIn++);
        if (v > 'k') v--;
        if (v > 'Z') v -= 0x06;
        if (v > 'N') v --;
        if (v > 'H') v--;
        if (v > '9') v -= 0x07;
        v -= '1';
        n.madd58(v);
    }
    uint8_t* p = ((uint8_t*)n.n_) + (n.N<<2);
    while (*--p == 0x00) {}
    while (p >= ((uint8_t*)n.n_)) {
        *pOut++ = *p--;
    }
    return pOut - p0;
}

