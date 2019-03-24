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
#include <new>

#include "aes128.h"

static uint8_t gSBox[256] = {
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

//union u128 {
//    uint64_t d[2];
//    uint32_t w[4];
//    uint8_t b[16];

void u128::netIn(const uint8_t s[16])
{
    for (int i = 0; i < sizeof(d); i++) {
        b[i] = s[sizeof(d) - 1 - i];
        //b[i] = s[i];
    }
}

void u128::netOut(uint8_t s[16])
{
    for (int i = 0; i < sizeof(d); i++) {
        s[sizeof(d) - 1 - i] = b[i];
        //s[i] = b[i];
    }
}

//u128& u128::shiftR()
//{
//    uint8_t c(0xE1 & (0x00 - (b[0] & 0x01)));
//    d[0] = (d[1] << 63) | (d[0] >> 1);
//    d[1] >>= 1; b[15] ^= c;
//    return *this;
//}

//u128& u128::operator ^= (const u128& s)
//{
//    d[0] ^= s.d[0];
//    d[1] ^= s.d[1];
//    return *this;
//}

void u128::pmult(AesText& x) const
{
    u128 z{ 0llu, 0llu };
    u128 v(*this); //; v.netIn(h.text[0].b);
    for (int j = 0; j < sizeof(x); j++) {
        //uint8_t b = x.text[0].b[j];
        int8_t b(x.text[0].b[j]);
        for (int i = 8; i-- > 0; b <<= 1) {
            int64_t d = int64_t(b) >> 7;
            z.d[1] ^= d & v.d[1];
            z.d[0] ^= d & v.d[0];
            v.shiftR();
        }
    }
    z.netOut(x.text[0].b);
}

AesCtr::AesCtr(const uint8_t iv[12])
{
    for (uint32_t i = 0; i < 12; i++) text[0].b[i] = iv[i];
    text[3].b[3] = 1;  text[3].b[2] = text[3].b[1] = text[3].b[0] = 0;
}

void AesCtr::incIV()
{
    for (uint32_t i = 12; i-- > 4; ) if (++text[0].b[i]) break;
    text[3].b[3] = 1;  text[3].b[2] = text[3].b[1] = text[3].b[0] = 0;
}

HKey::HKey(const AesText& key)
{
    static const uint8_t br[16]{0x00, 0x08, 0x04, 0x0c, 0x02, 0x0a, 0x06, 0x0e, 0x01, 0x09, 0x05, 0x0d, 0x03, 0x0b, 0x07, 0x0f};
    int i, j;
    u128* p = h[0];
    p[br[0]] = {0, 0}; p[br[1]].netIn(key.text[0].b);
    for (j = 1; j < 16; j+=j) {
        for (i = 1; i < j; i++) {
            (p[br[j + i]] = p[br[j]]) ^= p[br[i]];
        }
        (p[br[j + j]] = p[br[j]]).shiftR();
    }
    for ( ; j < 512; j++) {
        for (i = 0; i < 16; i++) {
            (p[j] = p[j - 16]).shiftR().shiftR().shiftR().shiftR();
        }
    }
}

HKey::HKey(const AesCtx& ctx)
{
    AesText hk{ 0,0,0,0 };
    ctx(hk);
    new(this) HKey(hk);
}

void HKey::pmult(AesText& x)
{
    u128 z{ 0llu, 0llu };
    for (uint32_t i = 0; i < sizeof(x); i++) {
        uint8_t c = x.text[0].b[i];
        z ^= h[i + i + 1][c & 0x0F];
        z ^= h[i + i][c >>4];
    }
    z.netOut(x.text[0].b);
}

AesKey& AesKey::set(const uint8_t b[16])
{
    for (int i = 0; i < sizeof(data); i++) data[0].b[i] = b[i];
    return *this;
}

bool AesText::operator == (const AesText& s)
{
    return ((s.text[0].v == text[0].v) && (s.text[1].v == text[1].v)
        && (s.text[2].v == text[2].v) && (s.text[3].v == text[3].v));
}

AesText& AesText::set(const uint8_t b[16])
{
    for (int i = 0; i < sizeof(text); i++) text[0].b[i] = b[i];
    return *this;
}

void AesText::out(uint8_t b[16])
{
    for (int i = 0; i < sizeof(text); i++) b[i] = text[0].b[i];
}

void AesText::AddRound(const AesKey& roundKey)
{
    text[0].v ^= roundKey.data[0].v;
    text[1].v ^= roundKey.data[1].v;
    text[2].v ^= roundKey.data[2].v;
    text[3].v ^= roundKey.data[3].v;
}

void AesText::SubBytes()
{
    for (int i = 0; i < 16; i++) {
        text[0].b[i] = gSBox[text[0].b[i]];
    }
}

void AesText::ShiftRows()
{
    uint8_t t;
    t = text[0].b[1];
    text[0].b[1] = text[1].b[1];
    text[1].b[1] = text[2].b[1];
    text[2].b[1] = text[3].b[1];
    text[3].b[1] = t;
    t = text[0].b[2]; text[0].b[2] = text[2].b[2]; text[2].b[2] = t;
    t = text[1].b[2]; text[1].b[2] = text[3].b[2]; text[3].b[2] = t;
    t = text[3].b[3];
    text[3].b[3] = text[2].b[3];
    text[2].b[3] = text[1].b[3];
    text[1].b[3] = text[0].b[3];
    text[0].b[3] = t;
}

static uint8_t xtime(uint8_t x)
{
    return ((x << 1) ^ (((int8_t)x >> 7) & 0x1b));
}

void AesText::MixColumns()
{
    uint32_t i;
    uint8_t Tmp, Tm, t;
    for (i = 0; i < 4; ++i)
    {
        u32& txt = text[i];
        t = txt.b[0];
        Tmp = txt.b[0] ^ txt.b[1] ^ txt.b[2] ^ txt.b[3];
        Tm = txt.b[0] ^ txt.b[1]; Tm = xtime(Tm);  txt.b[0] ^= Tm ^ Tmp;
        Tm = txt.b[1] ^ txt.b[2]; Tm = xtime(Tm);  txt.b[1] ^= Tm ^ Tmp;
        Tm = txt.b[2] ^ txt.b[3]; Tm = xtime(Tm);  txt.b[2] ^= Tm ^ Tmp;
        Tm = txt.b[3] ^ t;  Tm = xtime(Tm);  txt.b[3] ^= Tm ^ Tmp;
    }
}

AesText& AesText::inc()
{
    if (!++text[3].b[3])
        if (!++text[3].b[2])
            if (!++text[3].b[1])
                ++text[3].b[0];
    return *this;
}

void AesText::Enc(AesText& x) const
{
    x.text[0].v ^= text[0].v;
    x.text[1].v ^= text[1].v;
    x.text[2].v ^= text[2].v;
    x.text[3].v ^= text[3].v;
}

// https://www.youtube.com/watch?v=evjFwDRTmV0
void aes_NewRound(AesKey& key, uint32_t it)
{
    static const uint8_t sCon[16] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a };
    u32 data = key.data[3];
    // Rotate and substitute byte
    data.b[0] = gSBox[data.b[1]] ^ sCon[it];
    data.b[1] = gSBox[data.b[2]];
    data.b[2] = gSBox[data.b[3]];
    data.b[3] = gSBox[key.data[3].b[0]];

    // Write back column 0
    data.v ^= key.data[0].v;
    key.data[0].v = data.v;

    // Write back column 1
    data.v ^= key.data[1].v;
    key.data[1].v = data.v;

    // Write back column 2
    data.v ^= key.data[2].v;
    key.data[2].v = data.v;

    // Write back column 3
    data.v ^= key.data[3].v;
    key.data[3].v = data.v;
}

AesKey& AesKey::operator () (uint32_t n)
{
    static const uint8_t sCon[16] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a };
    u32 d = data[3];
    // Rotate and substitute byte
    d.b[0] = gSBox[d.b[1]] ^ sCon[n];
    d.b[1] = gSBox[d.b[2]];
    d.b[2] = gSBox[d.b[3]];
    d.b[3] = gSBox[data[3].b[0]];

    // Write back column 0
    d.v ^= data[0].v;
    data[0].v = d.v;

    // Write back column 1
    d.v ^= data[1].v;
    data[1].v = d.v;

    // Write back column 2
    d.v ^= data[2].v;
    data[2].v = d.v;

    // Write back column 3
    d.v ^= data[3].v;
    data[3].v = d.v;

    return *this;
}

// https://www.youtube.com/watch?v=evjFwDRTmV0

#ifndef WIN32

AesCtx::AesCtx(const AesKey& key) :
    r0(key),
    r1(r0),
    r2(r1(1)),
    r3(r2(2)),
    r4(r3(3)),
    r5(r4(4)),
    r6(r5(5)),
    r7(r6(6)),
    r8(r7(7)),
    r9(r8(8)),
    rf(r9(9))
{
    rf(10);
}

#else //WIN32

AesCtx::AesCtx(const AesKey& key) :
    r0(key)
{
    _asm {
        push ecx
        mov ecx, dword ptr [this]

        // Take r0, which is the raw 128 bits key
        movups xmm1, mmword ptr [ecx]

        // Generate round key r1.
        aeskeygenassist xmm0, xmm1, 0x01
        psrldq xmm0, 12
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        add ecx, 16
        shufps xmm1, xmm1, 0x39
        // Save round key r1
        movups mmword ptr[ecx], xmm1

        // Generate round key r2.
        aeskeygenassist xmm0, xmm1, 0x02
        psrldq xmm0, 12
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        add ecx, 16
        shufps xmm1, xmm1, 0x39
        // Save round key r2
        movups mmword ptr[ecx], xmm1

        // Generate round key r3.
        aeskeygenassist xmm0, xmm1, 0x04
        psrldq xmm0, 12
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        add ecx, 16
        shufps xmm1, xmm1, 0x39
        // Save round key r3
        movups mmword ptr[ecx], xmm1

        // Generate round key r4.
        aeskeygenassist xmm0, xmm1, 0x08
        psrldq xmm0, 12
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        add ecx, 16
        shufps xmm1, xmm1, 0x39
        // Save round key r4
        movups mmword ptr[ecx], xmm1

        // Generate round key r5.
        aeskeygenassist xmm0, xmm1, 0x10
        psrldq xmm0, 12
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        add ecx, 16
        shufps xmm1, xmm1, 0x39
        // Save round key r5
        movups mmword ptr[ecx], xmm1

        // Generate round key r6.
        aeskeygenassist xmm0, xmm1, 0x20
        psrldq xmm0, 12
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        add ecx, 16
        shufps xmm1, xmm1, 0x39
        // Save round key r6
        movups mmword ptr[ecx], xmm1

        // Generate round key r7.
        aeskeygenassist xmm0, xmm1, 0x40
        psrldq xmm0, 12
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        add ecx, 16
        shufps xmm1, xmm1, 0x39
        // Save round key r7
        movups mmword ptr[ecx], xmm1

        // Generate round key r8.
        aeskeygenassist xmm0, xmm1, 0x80
        psrldq xmm0, 12
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        add ecx, 16
        shufps xmm1, xmm1, 0x39
        // Save round key r8
        movups mmword ptr[ecx], xmm1

        // Generate round key r9.
        aeskeygenassist xmm0, xmm1, 0x1b
        psrldq xmm0, 12
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        add ecx, 16
        shufps xmm1, xmm1, 0x39
        // Save round key r9
        movups mmword ptr[ecx], xmm1

        // Generate round key rf.
        aeskeygenassist xmm0, xmm1, 0x36
        psrldq xmm0, 12
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        movd eax, xmm1
        shufps xmm1, xmm1, 0x39

        movd xmm0, eax
        pxor xmm1, xmm0
        add ecx, 16
        shufps xmm1, xmm1, 0x39
        // Save round key rf
        movups mmword ptr[ecx], xmm1

        // Finish up.
        emms
        pop ecx
    }
}

#endif //WIN32

const AesCtx& AesCtx::operator () (AesText& t) const
{
#ifdef WIN32
    _asm {
        push ebx
        mov ebx, t
        movups xmm0, mmword ptr [ecx]
        movups xmm1, mmword ptr [ebx]
        pxor   xmm1, xmm0 // Round 0
        movups xmm0, mmword ptr[ecx+16]
        aesenc xmm1, xmm0 // Round 1
        movups xmm0, mmword ptr[ecx + 32]
        aesenc xmm1, xmm0 // Round 2
        movups xmm0, mmword ptr[ecx + 48]
        aesenc xmm1, xmm0 // Round 3
        movups xmm0, mmword ptr[ecx + 64]
        aesenc xmm1, xmm0 // Round 4
        movups xmm0, mmword ptr[ecx + 80]
        aesenc xmm1, xmm0 // Round 5
        movups xmm0, mmword ptr[ecx + 96]
        aesenc xmm1, xmm0 // Round 6
        movups xmm0, mmword ptr[ecx + 112]
        aesenc xmm1, xmm0 // Round 7
        movups xmm0, mmword ptr[ecx + 128]
        aesenc xmm1, xmm0 // Round 8
        movups xmm0, mmword ptr[ecx + 144]
        aesenc xmm1, xmm0 // Round 9
        movups xmm0, mmword ptr[ecx + 160]
        aesenclast xmm1, xmm0 // Round final
        movups  mmword ptr [ebx], xmm1
        emms
        pop ebx
    }

#else //WIN32

    t.AddRound(r0); // Initial round.

    // 9 main rounds
    for (uint32_t i = 0; i++ < 9;) {
        t.SubBytes();
        t.ShiftRows();
        t.MixColumns();
        t.AddRound(rnd[i]);
    }

    // Final round. No MixColumns.
    t.SubBytes();
    t.ShiftRows();
    t.AddRound(rf);

#endif //WIN32

    return *this;
}

Aes128Gcm::Aes128Gcm(const uint8_t key[16], const uint8_t iv[12]) :
    aes_(AesKey().set(key)),
    ctr_(iv),
    hkey_(aes_)
{
}

Aes128Gcm::~Aes128Gcm()
{
}

int Aes128Gcm::Encrypt(
    uint8_t* pText,     // plain text to be encrypted in place.
    size_t cbLen,       // Bytes of plain text to be encrypted.
    uint8_t ivExp[8],   // Explicit portion of IV to set, 8 bytes.
    uint8_t sTag[16],   // Security tag output, 16 bytes.
    const uint8_t* aadText, // AAD data input. Should be 13 bytes.
    size_t cbAad        // Bytes of AAD data. Should be 13 bytes.
    )
{
    size_t i, j, k;
    AesCtr icb(ctr_);
    AesCtr cb(icb);

    aes_(icb); // This block will be used to encrypt final authentication tag.

    AesText tag{0, 0, 0, 0};

    if (aadText)
    for (i = 0; i < cbAad; i += sizeof(AesText)) {
        AesText txt;
        uint8_t* p = txt.text[0].b;
        k = (cbAad - i);
        if (k > sizeof(AesText)) k = sizeof(AesText);
        if (k >= sizeof(AesText)) txt.set(aadText + i);
        else {
            for (j = 0; j < k; j++) p[j] = aadText[i + j];
            for ( ; j < sizeof(AesText); j++) p[j] = 0;
        }
        txt.Enc(tag);
        hkey_.pmult(tag);
    }

    if (pText)
    for (i = 0; i < cbLen; i += sizeof(AesText)) {
        AesText txt;
        uint8_t* p = txt.text[0].b;
        k = (cbLen - i);
        if (k > sizeof(AesText)) k = sizeof(AesText);
        if (k >= sizeof(AesText)) txt.set(pText + i);
        else {
            for (j = 0; j < k; j++) p[j] = pText[i + j];
            for (; j < sizeof(AesText); j++) p[j] = 0;
        }
        ctr_.inc();
        aes_(cb = ctr_);
        cb.Enc(txt);
        for (j = k; j < sizeof(AesText); j++) p[j] = 0;
        if (k >= sizeof(AesText)) {
            txt.out(pText + i);
        } else {
            for (j = 0; j < cbLen - i; j++) pText[i+j] = p[j];
        }

        txt.Enc(tag);
        hkey_.pmult(tag);
    }

    // Finally calculate the authentication tag
    for (j=cbAad<<3, k=cbLen<<3, i = 8; i-- > 0; j >>= 8, k>>= 8) {
        cb.text[0].b[i] = uint8_t(j);
        cb.text[2].b[i] = uint8_t(k);
    }
    cb.Enc(tag);
    hkey_.pmult(tag);

    icb.Enc(tag);
    tag.out(sTag);

    for (i = 0; i < 8; i++) ivExp[i] = ctr_.text[1].b[i];
    ctr_.incIV();

    return 0;
}

int Aes128Gcm::Decrypt(
    uint8_t* pText,
    size_t cbLen,
    const uint8_t cTag[16],
    const uint8_t* aadText,
    size_t cbAad)
{
    size_t i, j, k;
    uint8_t sTag[16];
    AesCtr icb(ctr_);
    AesCtr cb(icb);

    aes_(icb); // This block will be used to encrypt final authentication tag.

    AesText tag{ 0, 0, 0, 0 };

    if (aadText)
        for (i = 0; i < cbAad; i += sizeof(AesText)) {
            AesText txt;
            uint8_t* p = txt.text[0].b;
            k = (cbAad - i);
            if (k > sizeof(AesText)) k = sizeof(AesText);
            if (k >= sizeof(AesText)) txt.set(aadText + i);
            else {
                for (j = 0; j < k; j++) p[j] = aadText[i + j];
                for (; j < sizeof(AesText); j++) p[j] = 0;
            }
            txt.Enc(tag);
            hkey_.pmult(tag);
        }

    if (pText)
        for (i = 0; i < cbLen; i += sizeof(AesText)) {
            AesText txt;
            uint8_t* p = txt.text[0].b;
            k = (cbLen - i);
            if (k > sizeof(AesText)) k = sizeof(AesText);
            if (k >= sizeof(AesText)) txt.set(pText + i);
            else {
                for (j = 0; j < k; j++) p[j] = pText[i + j];
                for (; j < sizeof(AesText); j++) p[j] = 0;
            }
            ctr_.inc();
            aes_(cb = ctr_);

            txt.Enc(tag);
            cb.Enc(txt);

            for (j = k; j < sizeof(AesText); j++) p[j] = 0;
            if (k >= sizeof(AesText)) {
                txt.out(pText + i);
            }
            else {
                for (j = 0; j < cbLen - i; j++) pText[i + j] = p[j];
            }

            //txt.Enc(tag);
            hkey_.pmult(tag);
        }

    // Finally calculate the authentication tag
    for (j = cbAad << 3, k = cbLen << 3, i = 8; i-- > 0; j >>= 8, k >>= 8) {
        cb.text[0].b[i] = uint8_t(j);
        cb.text[2].b[i] = uint8_t(k);
    }
    cb.Enc(tag);
    hkey_.pmult(tag);

    icb.Enc(tag);
    tag.out(sTag);

    ctr_.incIV();

    return memcmp(sTag, cTag, sizeof(sTag));
}

// ==== Extra stuff which is normally not needed ====
// S-Box generation
static uint8_t pm(uint8_t a, uint8_t b)
{
    static const uint32_t gS = 0x11B;
    uint32_t i, x = a, y = 0;
    while (b) {
        if (b & 1) y ^= x;
        x <<= 1; b >>= 1;
    }
    for (i = 32; i-- > 8; ) {
        if (y & (1 << i)) {
            y ^= gS << (i - 8);
        }
    }
    return uint8_t(y);
}

void aes_sgen()
{
    uint32_t i, x, y;
    uint8_t S[256];
    uint8_t a = 0x03, b = 0, c = 1, r;
    gSBox[0] = 0x00;
    S[0] = 0x00;
    S[1] = 0x01;

    for (i = 1; i < 256; i++) {
        S[i] = c = pm(a, c);
    }

    for (i = 1; i < 256; i++) {
        if (i == 255) {
            i = i;
        }
        b = S[i];
        x = i * 254;
        y = x % 255;
        c = S[y];
        r = c;
        c = (c << 1) | (c >> 7); r ^= c;
        c = (c << 1) | (c >> 7); r ^= c;
        c = (c << 1) | (c >> 7); r ^= c;
        c = (c << 1) | (c >> 7); r ^= c;
        r ^= 0x63;
        gSBox[b] = r;
    }

    gSBox[0] = 0x63; gSBox[1] = 0x7c;
}
