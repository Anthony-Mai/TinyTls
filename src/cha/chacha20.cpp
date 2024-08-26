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
#include "chacha20.h"

// https://tools.ietf.org/html/rfc7539


bool ChachaBlock::operator == (const ChachaBlock& r)
{
    int i;
    for (i = 0; i < 16; i++) if (data_[i] != r.data_[i]) break;
    return (i == 16);
}

void Chacha20::Init(const ChachaKey& k, const ChachaNounce& nc)
{
    state_[0] = 0x61707865; state_[1] = 0x3320646e; state_[2] = 0x79622d32, state_[3] = 0x6b206574;
    state_[4] = k.data_[0]; state_[5] = k.data_[1]; state_[6] = k.data_[2]; state_[7] = k.data_[3];
    state_[8] = k.data_[4]; state_[9] = k.data_[5]; state_[10] = k.data_[6]; state_[11] = k.data_[7];
    state_[12] = 0/*count*/; state_[13] = nc.n_[0]; state_[14] = nc.n_[1]; state_[15] = nc.n_[2];
}

int Chacha20::Encrypt(
    uint8_t* pText,     // plain text to be encrypted in place.
    size_t cbLen,       // Bytes of plain text to be encrypted.
    uint8_t sTag[16],   // Security tag output, 16 bytes.
    const uint8_t* aadText, // AAD data input. Should be 13 bytes.
    size_t cbAad        // Bytes of AAD data. Should be 13 bytes.
    )
{
    Poly1305 ply(*this);
    ++(*this);
    Block(*(ChachaBlock*)pText);
    return 0;
}

bool Chacha20::operator == (const Chacha20& r)
{
    int i;
    for (i = 0; i < 16; i++) if (state_[i] != r.state_[i]) break;
    return (i == 16);
}

Chacha20& Chacha20::operator ++ ()
{
    state_[12]++;
    return *this;
}

Chacha20& Chacha20::operator += (const Chacha20& r)
{
    for (int i = 0; i < sizeof(state_) / sizeof(state_[0]); i++) {
        state_[i] += r.state_[i];
    }
    return *this;
}

void Chacha20::operator ()(ChachaBlock& b) const
{
    b.data_[0] ^= state_[0]; b.data_[1] ^= state_[1]; b.data_[2] ^= state_[2]; b.data_[3] ^= state_[3];
    b.data_[4] ^= state_[4]; b.data_[5] ^= state_[5]; b.data_[6] ^= state_[6]; b.data_[7] ^= state_[7];
    b.data_[8] ^= state_[8]; b.data_[9] ^= state_[9]; b.data_[10] ^= state_[10]; b.data_[11] ^= state_[11];
    b.data_[12] ^= state_[12]; b.data_[13] ^= state_[13]; b.data_[14] ^= state_[14]; b.data_[15] ^= state_[15];
}

void Chacha20::QRound(int ia, int ib, int ic, int id)
{
    uint32_t A(state_[ia]), B(state_[ib]), C(state_[ic]), D(state_[id]);

    A += B; D ^= A; D = ((D<<16)|(D>>16));
    C += D; B ^= C; B = ((B<<12)|(B>>20));
    state_[ia] = A += B; D ^= A; state_[id] = D = ((D<<8)|(D>>24));
    state_[ic] = C += D; B ^= C; state_[ib] = ((B<<7)|(B>>25));
}

void Chacha20::InnerRound()
{
    QRound(0, 4, 8, 12);
    QRound(1, 5, 9, 13);
    QRound(2, 6, 10, 14);
    QRound(3, 7, 11, 15);
    QRound(0, 5, 10, 15);
    QRound(1, 6, 11, 12);
    QRound(2, 7, 8, 13);
    QRound(3, 4, 9, 14);
}

int Chacha20::Encode(uint8_t* pText, size_t cbLen, int off)
{
    while (cbLen) {
        Chacha20 cc(*this);
        for (int i = 0; i < 10; i++) cc.InnerRound();
        cc += *this;

        for (const uint8_t* p = (const uint8_t*)cc.state_; off < 64; ) {
            *pText++ ^= p[off++]; if (--cbLen <= 0) break;
        }
        if (off >= 64) {
            state_[12] ++; off -= 64;
        }
    }
    return off;
}

void Chacha20::Block(ChachaBlock& b)
{
    Chacha20 cc(*this);
    for (int i = 0; i < 10; i++) cc.InnerRound();
    cc += *this; cc(b);
    state_[12] ++;
}

Poly1305::Poly1305(
    const Chacha20& cha
) : cc_{0,0,0,0,0},
    ac_{0,0,0,0,0},
    off_(0), cnt_(0)
{
    Chacha20 cc(cha);
    for (int i = 0; i < 10; i++) cc.InnerRound();
    cc += cha;

    // https://tools.ietf.org/html/rfc7539#section-2.5.1
    r_[0] = cc.state_[0] & 0x0FFFFFFF;
    r_[1] = cc.state_[1] & 0x0FFFFFFC;
    r_[2] = cc.state_[2] & 0x0FFFFFFC;
    r_[3] = cc.state_[3] & 0x0FFFFFFC;

    s_[0] = cc.state_[4];
    s_[1] = cc.state_[5];
    s_[2] = cc.state_[6];
    s_[3] = cc.state_[7];
}

union u64 {
	uint64_t v;
	uint32_t u[2];
};

// If needed, message is padded with 0 bytes to make exact 16 byte blocks
void Poly1305::add(const uint8_t* pMsg, size_t cbBytes) {
    size_t i, j;
    while (cbBytes) {
        for ( ; off_ < 16; ) {
            ((uint8_t*)ac_)[off_++] = *pMsg++;
            if (--cbBytes <= 0) {
                break;
            }
        }
        if (off_ >= 16) mreduce();
    }
}

void Poly1305::mreduce() {
    uint32_t i, j;
    uint32_t mm[8];

    // Pad 1 then 0 bytes to a full block
    ((uint8_t*)ac_)[off_++] = 0x01;
    while (off_ < 20) ((uint8_t*)ac_)[off_++] = 0x00;
    cnt_++; off_ = 0;
    mm[7] = mm[6] = mm[5] = mm[4] = 0; mm[3] = mm[2] = mm[1] = mm[0] = 0;
    for (i = 0; (j = i) <= 4; i++) {
        if ((cc_[i] += ac_[i]) < ac_[i]) {
            if (++cc_[i + 1] == 0) if (++cc_[i + 2] == 0) if (++cc_[i + 3] == 0) ++cc_[i + 4];
        }
        for (j = 0; j < 4; j++) {
            u64 u{ uint64_t(cc_[i]) * r_[j] };
            u.u[1] += ((mm[i + j] += u.u[0]) < u.u[0]);
            if ((mm[i + j + 1] += u.u[1]) < u.u[1]) ++mm[i + j + 2];
        }
    }
    // Reduction by modulo (2^130 - 5)
    ac_[0] = mm[4] & 0xFFFFFFFC; mm[4] &= 3;
    ac_[1] = mm[5]; mm[5] = 0;
    ac_[2] = mm[6]; mm[6] = 0;
    ac_[3] = mm[7]; mm[7] = 0;
    ac_[4] = 0;
    if ((mm[0] += ac_[0]) < ac_[0]) if (++mm[1] == 0) if (++mm[2] == 0) if (++mm[3] == 0) ++mm[4];
    ac_[0] = (ac_[0] >> 2) | (ac_[1] << 30);
    if ((mm[0] += ac_[0]) < ac_[0]) if (++mm[1] == 0) if (++mm[2] == 0) if (++mm[3] == 0) ++mm[4];
    if ((mm[1] += ac_[1]) < ac_[1]) if (++mm[2] == 0) if (++mm[3] == 0) ++mm[4];
    ac_[1] = (ac_[1] >> 2) | (ac_[2] << 30);
    if ((mm[1] += ac_[1]) < ac_[1]) if (++mm[2] == 0) if (++mm[3] == 0) ++mm[4];
    if ((mm[2] += ac_[2]) < ac_[2]) if (++mm[3] == 0) ++mm[4];
    ac_[2] = (ac_[2] >> 2) | (ac_[3] << 30);
    if ((mm[2] += ac_[2]) < ac_[2]) if (++mm[3] == 0) ++mm[4];
    if ((mm[3] += ac_[3]) < ac_[3]) ++mm[4];
    ac_[3] = (ac_[3] >> 2);
    if ((mm[3] += ac_[3]) < ac_[3]) ++mm[4];
    // One more reduction if needed
    if (mm[4] >= 4) {
        mm[4] -= 4;
        if ((mm[0] += 5) < 5) if (++mm[1] == 0) if (++mm[2] == 0) if (++mm[3] == 0) ++mm[4];
    }
    // Copy back to accumulator cc;
    cc_[0] = mm[0]; cc_[1] = mm[1]; cc_[2] = mm[2]; cc_[3] = mm[3]; cc_[4] = mm[4];
}

void Poly1305::final(uint8_t tag[16])
{
    if (off_ > 0u) mreduce();
    // Add s to the result
    if ((cc_[0] += s_[0]) < s_[0]) if (++cc_[1] == 0) if (++cc_[2] == 0) if (++cc_[3] == 0) ++cc_[4];
    if ((cc_[1] += s_[1]) < s_[1]) if (++cc_[2] == 0) if (++cc_[3] == 0) ++cc_[4];
    if ((cc_[2] += s_[2]) < s_[2]) if (++cc_[3] == 0) ++cc_[4];
    if ((cc_[3] += s_[3]) < s_[3]) ++cc_[4];
    // Finally output the tag
    for (size_t i = 0; i < 16; i += 4) {
        tag[i] = ((uint8_t*)cc_)[i]; tag[i + 1] = ((uint8_t*)cc_)[i + 1];
        tag[i + 2] = ((uint8_t*)cc_)[i + 2]; tag[i + 3] = ((uint8_t*)cc_)[i + 3];
    }
}

// The final partial block is paded with 0 bytes after appending 0x01 first.
void Poly1305::hash(uint8_t tag[16], const uint8_t* pMsg, size_t cbBytes)
{
	size_t i,j;
	uint32_t cc[5]{ 0,0,0,0,0 };
	uint32_t acc[5];
	uint32_t mm[8];
	while (cbBytes) {
		for (i = 0; i < 16;  ) {
			((uint8_t*)acc)[i++] = *pMsg++;
			if (--cbBytes <= 0) break;
		}
		((uint8_t*)acc)[i++] = 0x01;
		while (i < 20) ((uint8_t*)acc)[i++] = 0x00;
		mm[7] = mm[6] = mm[5] = mm[4] = 0; mm[3] = mm[2] = mm[1] = mm[0] = 0;
		for (i = 0; (j = i) <= 4; i++) {
			if ((cc[i] += acc[i]) < acc[i]) {
				if (++cc[i + 1] == 0) if (++cc[i + 2] == 0) if (++cc[i + 3] == 0) ++cc[i + 4];
			}
			for (j = 0; j < 4; j++) {
				u64 u{uint64_t(cc[i]) * r_[j]};
				u.u[1] += ((mm[i + j] += u.u[0]) < u.u[0]);
				if ((mm[i + j + 1] += u.u[1]) < u.u[1]) ++mm[i+j+2];
			}
		}
		// Reduction by modulo (2^130 - 5)
		acc[0] = mm[4] & 0xFFFFFFFC; mm[4] &= 3;
		acc[1] = mm[5]; mm[5] = 0;
		acc[2] = mm[6]; mm[6] = 0;
		acc[3] = mm[7]; mm[7] = 0;
		acc[4] = 0;
		if ((mm[0] += acc[0]) < acc[0]) if (++mm[1] == 0) if (++mm[2] == 0) if (++mm[3] == 0) ++mm[4];
		acc[0] = (acc[0]>>2)|(acc[1] << 30);
		if ((mm[0] += acc[0]) < acc[0]) if (++mm[1] == 0) if (++mm[2] == 0) if (++mm[3] == 0) ++mm[4];
		if ((mm[1] += acc[1]) < acc[1]) if (++mm[2] == 0) if (++mm[3] == 0) ++mm[4];
		acc[1] = (acc[1] >> 2) | (acc[2] << 30);
		if ((mm[1] += acc[1]) < acc[1]) if (++mm[2] == 0) if (++mm[3] == 0) ++mm[4];
		if ((mm[2] += acc[2]) < acc[2]) if (++mm[3] == 0) ++mm[4];
		acc[2] = (acc[2] >> 2) | (acc[3] << 30);
		if ((mm[2] += acc[2]) < acc[2]) if (++mm[3] == 0) ++mm[4];
		if ((mm[3] += acc[3]) < acc[3]) ++mm[4];
		acc[3] = (acc[3] >> 2);
		if ((mm[3] += acc[3]) < acc[3]) ++mm[4];
		// One more reduction if needed
		if (mm[4] >= 4) {
			mm[4] -= 4;
			if ((mm[0] += 5) < 5) if (++mm[1] == 0) if (++mm[2] == 0) if (++mm[3] == 0) ++mm[4];
		}
		// Copy back to accumulator cc;
		cc[0] = mm[0]; cc[1] = mm[1]; cc[2] = mm[2]; cc[3] = mm[3]; cc[4] = mm[4];
	}
	// Add s to the result
	if ((cc[0] += s_[0]) < s_[0]) if (++cc[1] == 0) if (++cc[2] == 0) if (++cc[3] == 0) ++cc[4];
	if ((cc[1] += s_[1]) < s_[1]) if (++cc[2] == 0) if (++cc[3] == 0) ++cc[4];
	if ((cc[2] += s_[2]) < s_[2]) if (++cc[3] == 0) ++cc[4];
	if ((cc[3] += s_[3]) < s_[3]) ++cc[4];
	// Finally output the tag
	for (i = 0; i < 16; i += 4) {
		tag[i] = ((uint8_t*)cc)[i]; tag[i+1] = ((uint8_t*)cc)[i+1];
		tag[i+2] = ((uint8_t*)cc)[i+2]; tag[i+3] = ((uint8_t*)cc)[i+3];
	}
}
