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

#include "ecc.h"

#define LITTLE_ENDIAN 1

typedef union U8
{
    uint64_t    u8;
    struct {
#ifdef BIG_ENDIAN
    uint32_t    high;
    uint32_t    low;
#elif LITTLE_ENDIAN
    uint32_t    low;
    uint32_t    high;
#else
    ERROR   Need to define endianness
    uint    low;
    uint    high;
#endif //BIG_ENDIAN
    }           u4;
} U8;


uint32_t NN::lead0_ = 1;
NN NN::P_{ uint32_t(-19),uint32_t(-1),uint32_t(-1),uint32_t(-1),uint32_t(-1),uint32_t(-1),uint32_t(-1),0x7FFFFFFF };

NN N2::P_(uint32_t(-38), uint32_t(-1), uint32_t(-1), uint32_t(-1), uint32_t(-1), uint32_t(-1), uint32_t(-1), uint32_t(-1));
NN N2::R_(38, 0, 0, 0, 0, 0, 0, 0);

NN::NN()
    : n0(0),n1(0),n2(0),n3(0),n4(0),n5(0),n6(0),n7(0)
{
}

NN::NN(uint32_t d0)
    : n0(d0), n1(0), n2(0), n3(0), n4(0), n5(0), n6(0), n7(0)
{
}

NN::NN(uint32_t d0, uint32_t d1, uint32_t d2, uint32_t d3, uint32_t d4, uint32_t d5, uint32_t d6, uint32_t d7)
    : n0(d0), n1(d1), n2(d2), n3(d3), n4(d4), n5(d5), n6(d6), n7(d7)
{
}

NN::NN(const NN& s)
    : n0(s.n0),n1(s.n1),n2(s.n2),n3(s.n3),n4(s.n4),n5(s.n5),n6(s.n6),n7(s.n7)
{
}

// Initialize x25519 parameter. This is no longer needed.
void NN::init(const NN& P)
{
    P_ = P;
    lead0_ = P_.lead0();
}

// Number of leading 0 bits.
uint32_t NN::lead0() const
{
    for (uint32_t i = N; i-- > 0; ) {
        for (uint32_t j = 32; j-- > 0; ) {
            if ((1 << j)&n_[i]) {
                return ((N - i) << 5) - j - 1;
            }
        }
    }
    return N << 5;
}

// Input bytes in native endianness.
NN& NN::bytesIn(const uint8_t* pBytes)
{
    for (uint32_t i = 0; i < N; i++) {
        n_[i] = reinterpret_cast<const uint32_t*>(pBytes)[i];
    }
    return *this;
}

// Output bytes in native endianness.
void NN::bytesOut(uint8_t* pBytes) const
{
    for (uint32_t i = 0; i < N; i++) {
        reinterpret_cast<uint32_t*>(pBytes)[i] = n_[i];
    }
}

// Input from network order, or big endian.
NN& NN::netIn(const uint8_t* pBytes)
{
    uint32_t d = 0;
    for (uint32_t i = N; i-- > 0; ) {
        d = *pBytes++;
        d <<= 8; d |= *pBytes++;
        d <<= 8; d |= *pBytes++;
        d <<= 8; d |= *pBytes++;
        n_[i] = d;
    }
    return *this;
}

// Output to network order, or big endian.
void NN::netOut(uint8_t* pBytes) const
{
    for (uint32_t i = N; i-- > 0; ) {
        uint32_t d = n_[i];
        *pBytes++ = uint8_t(d>>24);
        *pBytes++ = uint8_t(d>>16);
        *pBytes++ = uint8_t(d>>8);
        *pBytes++ = uint8_t(d);
    }
}

// Modulo reduction by X25519 prime.
NN& NN::reduce()
{
    while (*this >= NN::P_) {
        n_[N - 1] -= 0x80000000;
        if ((n_[0] += 19) >= 19) continue;
        for (uint32_t i = 1; ++n_[i] == 0; ) if (++i >= N) break;
    }
    return *this;
}

const NN ecc_BPO{ 0x5CF5D3ED, 0x5812631A, 0xA2F79CD6, 0x14DEF9DE, 0 , 0, 0, 0x10000000 }; // X25519 BPO

// Modulo reduce by x25519 base point order
NN& NN::reduceb()
{
    NN r(ecc_BPO * (n_[N - 1] >> 28));
    if (r > *this) *this += ecc_BPO;
    *this -= r;
    return *this;
}

// Generic modulo reduction.
NN& NN::reduce(const NN& p)
{
    while (*this >= p) *this -= p;
    return *this;
}

NN NN::operator + (const NN& m) const
{
    NN r(*this);
    for (uint32_t i = 0; i < N; i++) {
        if ((r.n_[i] += m.n_[i]) >= m.n_[i]) continue;
        for (uint32_t j = i + 1; j < N; j++) { if (++r.n_[j]) break; }
    }

    return r;
}

NN NN::operator - (const NN& m) const
{
    NN r(*this);
    for (uint32_t i = 0; i < N; i++) {
        if (r.n_[i] >= m.n_[i]) { r.n_[i] -= m.n_[i]; continue; }
        r.n_[i] -= m.n_[i];
        for (uint32_t j = i + 1; j < N; j++) { if (r.n_[j]--) break; }
    }

    return r;
}

NN NN::operator << (uint32_t w) const
{
    int32_t i = N, j = i - (w >> 5), d1 = w & 31, d2 = 32 - d1;
    NN r;
    if (d1 == 0) {
        while (j-- > 0) r.n_[--i] = n_[j];
        while (i-- > 0) r.n_[i] = 0;
        return r;
    }
    j--;
    while (j > 0) {
        r.n_[--i] = n_[j--] << d1;
        r.n_[i] |= n_[j] >> d2;
    }
    r.n_[--i] = n_[j] << d1;
    while (i > 0) r.n_[--i] = 0;

    return r;
}

NN NN::operator >> (uint32_t w) const
{
    int32_t i = 0, j = i + (w >> 5), d1 = w & 31, d2 = 32 - d1;
    NN r;
    if (d1 == 0) {
        while (j < N) r.n_[i++] = n_[j++];
        while (i < N) r.n_[i++] = 0;
        return r;
    }
    while (j < N - 1) {
        r.n_[i] = n_[j] >> d1;
        r.n_[i++] |= n_[++j] << d2;
    }
    r.n_[i++] = n_[j] >> d1;
    while (i < N) r.n_[i++] = 0;

    return r;
}

NN& NN::operator += (const NN& m)
{
    for (uint32_t i = 0; i < N; i++) {
        if ((n_[i] += m.n_[i]) >= m.n_[i]) continue;
        for (uint32_t j = i + 1; j < N; j++) { if (++n_[j]) break; }
    }

    return *this;
}

NN& NN::operator -= (const NN& m)
{
    for (uint32_t i = 0; i < N; i++) {
        if (n_[i] >= m.n_[i]) { n_[i] -= m.n_[i]; continue; }
        n_[i] -= m.n_[i];
        for (uint32_t j = i + 1; j < N; j++) { if (n_[j]--) break; }
    }

    return *this;
}

NN& NN::operator += (uint32_t w)
{
    if ((n_[0] += w) >= w) return *this;
    for (uint32_t j = 1; j < N; j++) { if (++n_[j]) break; }

    return *this;
}

NN& NN::operator -= (uint32_t w)
{
    if (n_[0] < w) {
        for (uint32_t j = 1; j < N; j++) { if (n_[j]--) break; }
    }
    n_[0] -= w;
    return *this;
}

NN& NN::operator <<= (uint32_t w)
{
    int32_t i=N, j=i-(w>>5),d1=w&31,d2=32-d1;
    if (d1 == 0) {
        while (j-- > 0) n_[--i] = n_[j];
        while (i-- > 0) n_[i] = 0;
        return *this;
    }
    j--;
    while (j > 0) {
        n_[--i] = n_[j--]<<d1;
        n_[i] |= n_[j] >> d2;
    }
    n_[--i] = n_[j] << d1;
    while (i > 0) n_[--i] = 0;

    return *this;
}

NN& NN::operator >>= (uint32_t w)
{
    int32_t i = 0, j = i + (w >> 5), d1 = w & 31, d2 = 32 - d1;
    if (d1 == 0) {
        while (j < N) n_[i++] = n_[j++];
        while (i < N) n_[i++] = 0;
        return *this;
    }
    while (j < N - 1) {
        n_[i] = n_[j] >> d1;
        n_[i++] |= n_[++j] << d2;
    }
    n_[i++] = n_[j] >> d1;
    while (i < N) n_[i++] = 0;

    return *this;
}

NN::operator bool() const
{
    for (uint32_t i = 0; i < N; i++) {
        if (n_[i]) return true;
    }
    return false;
}

bool NN::is0() const
{
    for (int32_t i = N; i-- > 0; ) {
        if (n_[i]) return false;
    }
    return true;
}

bool NN::is1() const
{
    for (int32_t i = N; i-- > 0; ) {
        if (n_[i]) {
            return ((i == 0) && n_[i] == 1);
        }
    }
    return false;
}

bool NN::operator >= (const NN& t) const
{
    for (uint32_t i = N; i-- > 0; ) {
        if (n_[i] > t.n_[i]) return true;
        if (n_[i] < t.n_[i]) return false;
    }
    return true;
}

bool NN::operator <= (const NN& t) const
{
    for (uint32_t i = N; i-- > 0; ) {
        if (n_[i] > t.n_[i]) return false;
        if (n_[i] < t.n_[i]) return true;
    }
    return true;
}

bool NN::operator == (const NN& t) const
{
    for (uint32_t i = 0; i < N; i++) {
        if (n_[i] != t.n_[i]) return false;
    }
    return true;
}

bool NN::operator != (const NN& t) const
{
    for (uint32_t i = 0; i < N; i++) {
        if (n_[i] != t.n_[i]) return true;
    }
    return false;
}

bool NN::operator > (const NN& t) const
{
    for (uint32_t i = N; i-- > 0; ) {
        if (n_[i] > t.n_[i]) return true;
        if (n_[i] < t.n_[i]) return false;
    }
    return false;
}

bool NN::operator < (const NN& t) const
{
    for (uint32_t i = N; i-- > 0; ) {
        if (n_[i] > t.n_[i]) return false;
        if (n_[i] < t.n_[i]) return true;
    }
    return false;
}

bool NN::operator < (uint32_t t) const
{
    for (uint32_t i = N; i-- > 1; ) {
        if (n_[i]) return false;
    }
    return (n0 < t);
}

NN& NN::operator = (uint32_t m)
{
    for (uint32_t i = N; i-- > 1; ) n_[i] = 0;
    n0 = m;
    return *this;
}

// Simple multiplication, with multiplicant just a uint32
N2 NN::operator * (uint32_t m) const
{
    uint32_t    i;
    U8			oneData{ 0 };
    N2          ret;

    for (i = 0; i<N; i++) {
        if ((ret.n_[i] += oneData.u4.high) < oneData.u4.high) {
            uint32_t k = i + 1;
            while (++ret.n_[k] == 0 && k<N2::N-1) k++;
        }
        oneData.u8 = (uint64_t)n_[i] * m;
        if ((ret.n_[i] += oneData.u4.low) < oneData.u4.low) oneData.u4.high++;
    }
    ret.n_[i] += oneData.u4.high;

    return ret;
}

// Simple multiplication only. No modulo reduction.
N2 NN::operator * (const NN& m) const
{
    uint32_t    i, j;
    U8			oneData;
    N2          ret;

    for (i = 0; i<N; i++) {
        for (j = 0; j<N; j++) {
            oneData.u8 = (uint64_t)n_[i] * m.n_[j];
            if ((ret.n_[i + j] += oneData.u4.low) < oneData.u4.low) oneData.u4.high++;
            if ((ret.n_[i + j + 1] += oneData.u4.high) < oneData.u4.high) {
                uint32_t k = i+j+2;
                while (++ret.n_[k] == 0) k++;
            }
        }
    }

    return ret;
}

// Multiply and modulo by x25519 prime.
NN NN::operator ^ (const NN& m) const
{
    uint32_t    i, j;
    U8			oneData;
    N2          R;

    // R = this * m
    for (i = 0; i<N; i++) {
        for (j = 0; j<N; ) {
            oneData.u8 = (uint64_t)n_[i] * m.n_[j];
            if ((R.n_[i + (j++)] += oneData.u4.low) < oneData.u4.low) oneData.u4.high++;
            if ((R.n_[i + j] += oneData.u4.high) >= oneData.u4.high) continue;
            for (uint32_t k = i + j + 1; ++R.n_[k] == 0; k++) {}
        }
    }

    // Modulo reduce by P
    for (i = NN::N; i-- > 0; ) {
        oneData.u8 = (uint64_t)R.n.N1.n_[i] * 38; R.n.N1.n_[i] = 0;
        oneData.u4.high += ((R.n.N0.n_[i] += oneData.u4.low) < oneData.u4.low);
        for (j = i + 1; oneData.u4.high = ((R.n.N0.n_[j] += oneData.u4.high) < oneData.u4.high); j++);
        i += (R.n.N1.n_[i] > 0);
    }

    while (R.n.N0 >= NN::P_) {
        R.n.N0.n_[NN::N - 1] -= 0x80000000; j = 19;
        for (i = 0; (j = ((R.n.N0.n_[i] += j) < j)); i++);
    }

    return R.n.N0;
}

// Generic modulo inverse by prime RR.p. RR is a modulo reduction helper.
NN NN::inverse(const RR& r) const
{
    NN x1(*this), x2(r.p - x1);
    NN r1(1), r2(r.p- r1);

    for (;;) {
        uint32_t b1 = x1.lead0(), b2 = x2.lead0();
        if ((b1 | b2) & (N << 5)) break;  // x1 or x2 is 0.
        if (x2 > x1) {
            if (b1 - b2 > 1) {
                NN x3 = x1 << (b1 - b2 - 1);
                NN r3 = (r1 * (NN(1) << (b1 - b2 - 1))).reduce(r);
                while (x2 > x3) {
                    x2 -= x3;
                    if (r2 >= r3) r2 -= r3;
                    else r2 += r.p - r3;
                }
            } else {
                while (x2 > x1) {
                    x2 -= x1;
                    if (r2 >= r1) r2 -= r1;
                    else r2 += r.p - r1;
                }
            }
            if (x2.is1()) {
                return r2;
            }
        } else {
            if (b2 - b1 > 1) {
                NN x3 = x2 << (b2 - b1 - 1);
                NN r3 = (r2 * (NN(1) << (b2 - b1 - 1))).reduce(r);
                while (x1 > x3) {
                    x1 -= x3;
                    if (r1 >= r3) r1 -= r3;
                    else r1 += r.p - r3;
                }
            }
            else {
                while (x1 > x2) {
                    x1 -= x2;
                    if (r1 >= r2) r1 -= r2;
                    else r1 += r.p - r2;
                }
            }
            if (x1.is1()) {
                return r1;
            }
        }
    }
    // Error. Impossible.
    return NN();
}

// Modulo inverse by modulo of x25519 prime.
NN NN::inverse() const
{
    NN x1(*this), x2(NN::P_ - x1);
    NN r1(1), r2(NN::P_ - r1);

    for (;;) {
        uint32_t b1 = x1.lead0(), b2 = x2.lead0();
        if ((b1 | b2) & (N << 5)) break;  // x1 or x2 is 0.
        if (x2 > x1) {
            if (b1 - b2 > 1) {
                NN x3 = x1 << (b1 - b2 - 1);
                NN r3 = r1 ^ (NN)(NN(1) << (b1 - b2 - 1));
                while (x2 > x3) {
                    x2 -= x3;
                    if (r2 >= r3) r2 -= r3;
                    else r2 += NN::P_ - r3;
                }
            }
            else {
                while (x2 > x1) {
                    x2 -= x1;
                    if (r2 >= r1) r2 -= r1;
                    else r2 += NN::P_ - r1;
                }
            }
            if (x2.is1()) {
                return r2;
            }
        }
        else {
            if (b2 - b1 > 1) {
                NN x3 = x2 << (b2 - b1 - 1);
                NN r3 = r2 ^ (NN)(NN(1) << (b2 - b1 - 1));
                while (x1 > x3) {
                    x1 -= x3;
                    if (r1 >= r3) r1 -= r3;
                    else r1 += NN::P_ - r3;
                }
            }
            else {
                while (x1 > x2) {
                    x1 -= x2;
                    if (r1 >= r2) r1 -= r2;
                    else r1 += NN::P_ - r2;
                }
            }
            if (x1.is1()) {
                return r1;
            }
        }
    }
    // Error. Impossible.
    return NN();
}

// Modulo inverse of modulo by x25519 base point order.
NN NN::inverseb() const
{
    const NN& P(ecc_BPO);
    NN x1(*this); x1.reduceb();
    NN x2(P - x1);
    NN r1(1), r2(P - r1);

    for (;;) {
        uint32_t b1 = x1.lead0(), b2 = x2.lead0();
        if ((b1 | b2) & (N << 5)) break;  // x1 or x2 is 0.
        if (x2 > x1) {
            if (b1 - b2 > 1) {
                NN x3 = x1 << (b1 - b2 - 1);
                NN r3 = (r1 * (NN(1) << (b1 - b2 - 1))).reduceb();
                while (x2 > x3) {
                    x2 -= x3;
                    if (r2 >= r3) r2 -= r3;
                    else r2 += P - r3;
                }
            }
            else {
                while (x2 > x1) {
                    x2 -= x1;
                    if (r2 >= r1) r2 -= r1;
                    else r2 += P - r1;
                }
            }
            if (x2.is1()) {
                return r2;
            }
        }
        else {
            if (b2 - b1 > 1) {
                NN x3 = x2 << (b2 - b1 - 1);
                NN r3 = (r2 * (NN(1) << (b2 - b1 - 1))).reduceb();
                while (x1 > x3) {
                    x1 -= x3;
                    if (r1 >= r3) r1 -= r3;
                    else r1 += P - r3;
                }
            }
            else {
                while (x1 > x2) {
                    x1 -= x2;
                    if (r1 >= r2) r1 -= r2;
                    else r1 += P - r2;
                }
            }
            if (x1.is1()) {
                return r1;
            }
        }
    }
    // Error. Impossible.
    return NN();
}

// Calculate R that (1+R/2^256)/2^256 = 1/P. Helpful in modulo reduction.
NN NN::reverse(const NN& P)
{
    N2	PP;
    NN  R;

    PP.n.N1 -= P;
    R = PP.n.N1;
    PP -= R*P;

    while (PP.n.N1) {
        NN d(PP.n.N1);
        d += (d*R).n.N1;
        R += d;
        PP -= d*P;
    }

    while (PP.n.N0 >= P) {
        R += 1;
        PP.n.N0 -= P;
    }

    return R;
}

// Y = X ** E mod P. E is in little-endian format
void NN::EMod(NN& Y, const NN& E) const
{
    Y = 1;
    for (uint32_t bytes = N; bytes-- > 0; )
    {
        uint32_t e = E.n_[bytes];
        for (uint32_t i = 0; i < 32; i++)
        {
            Y = Y ^ Y;
            if (e & 0x80000000) Y = Y ^ *this;
            e <<= 1;
        }
    }
    Y.reduce();
}

// Sub then modulo reduction by x25519 prime.
NN& NN::subr(const NN& a, const NN& b)
{
    *this = a;
    if (a < b) *this += P_;
    *this -= b;
    return *this;
}

// Add then modulo reduction by x25519 prime.
NN& NN::addr(const NN& a, const NN& b)
{
    *this = a;
    *this += b;
    this->reduce();
    return *this;
}

N2::N2() : n{0, 0}
{
}

N2::N2(const NN& n1, uint32_t n0) : n{ n0, n1 }
{
}

N2::N2(const N2& s) : n(s.n)
{
}

// Initialize x25519 parameters. P is the x25519 prime.
void N2::init(const NN& P)
{
    NN::init(P);

    P_ = P;
    P_ <<= P_.lead0();
    R_ = NN::reverse(P_);
}

bool N2::operator == (const N2& m) const
{
    return ((n.N0 == m.n.N0) && (n.N1 == m.n.N1));
}

N2& N2::operator = (const N2& s)
{
    n.N0 = s.n.N0; n.N1 = s.n.N1;
    return (*this);
}

N2 N2::operator + (const N2& m) const
{
    N2 r(*this);
    for (uint32_t i = 0; i < N; i++)
    {
        if ((r.n_[i] += m.n_[i]) >= m.n_[i]) continue;
        for (uint32_t j = i + 1; j < N; j++) { if (++r.n_[j]) break; }
    }

    return r;
}

N2 N2::operator + (const NN& m) const
{
    N2 r(*this);
    for (uint32_t i = 0; i < NN::N; i++)
    {
        if ((r.n_[i] += m.n_[i]) >= m.n_[i]) continue;
        for (uint32_t j = i + 1; j < N; j++) { if (++r.n_[j]) break; }
    }

    return r;
}

N2& N2::operator += (const NN& m)
{
    for (uint32_t i = 0; i < NN::N; i++)
    {
        if ((n_[i] += m.n_[i]) >= m.n_[i]) continue;
        for (uint32_t j = i + 1; j < N; j++) { if (++n_[j]) break; }
    }

    return *this;
}

N2& N2::operator += (const N2& m)
{
    for (uint32_t i = 0; i < N; i++)
    {
        if ((n_[i] += m.n_[i]) >= m.n_[i]) continue;
        for (uint32_t j = i + 1; j < N; j++) { if (++n_[j]) break; }
    }

    return *this;
}

N2& N2::operator -= (const N2& m)
{
    for (uint32_t i = 0; i < N; i++)
    {
        if (n_[i] >= m.n_[i]) { n_[i] -= m.n_[i]; continue; }
        n_[i] -= m.n_[i];
        for (uint32_t j = i + 1; j < N; j++) { if (n_[j]--) break; }
    }

    return *this;
}

N2& N2::operator <<= (uint32_t w)
{
    int32_t i = N, j = i - (w >> 5), d1 = w & 31, d2 = 32 - d1;
    if (d1 == 0) {
        while (j-- > 0) n_[--i] = n_[j];
        while (i-- > 0) n_[i] = 0;
        return *this;
    }
    j--;
    while (j > 0) {
        n_[--i] = n_[j--] << d1;
        n_[i] |= n_[j] >> d2;
    }
    n_[--i] = n_[j] << d1;
    while (i > 0) n_[--i] = 0;

    return *this;
}

N2& N2::operator >>= (uint32_t w)
{
    int32_t i = 0, j = i + (w >> 5), d1 = w & 31, d2 = 32 - d1;
    if (d1 == 0) {
        while (j < N) n_[i++] = n_[j++];
        while (i < N) n_[i++] = 0;
        return *this;
    }
    while (j < N - 1) {
        n_[i] = n_[j] >> d1;
        n_[i++] |= n_[++j] << d2;
    }
    n_[i++] = n_[j] >> d1;
    while (i < N) n_[i++] = 0;

    return *this;
}

// Modulo reduction by X25519 prime.
NN& N2::reduce()
{
    uint32_t i,j;
    U8			oneData{ 0 };
    for (i = 0; i < NN::N; ) {
        oneData.u8 = (uint64_t)n.N1.n_[i] * 38;
        n.N1.n_[i] = 0;
        n.N0.n_[i] += oneData.u4.low;
        if (n.N0.n_[i++] < oneData.u4.low) oneData.u4.high++;
        n.N0.n_[i] += oneData.u4.high;
        if (n.N0.n_[i] >= oneData.u4.high) continue;
        for (j = i + 1; ++n.N0.n_[j] == 0; j++) {}
    }
    oneData.u4.high = n.N1.n_[0]; n.N1.n_[0] = 0;
    while (oneData.u4.high) {
        oneData.u4.low = oneData.u4.high * 38;
        if ((n.N0.n_[0] += oneData.u4.low) < oneData.u4.low) {
            for (uint32_t k = 1; ++n.N0.n_[k] == 0; k++) {}
        }
        oneData.u4.high = n.N1.n_[0]; n.N1.n_[0] = 0;
    }
    while (n.N0 >= NN::P_) {
        n.N0.n_[NN::N - 1] -= 0x80000000;
        if ((n.N0.n_[0] += 19) >= 19) continue;
        for (j = 1; ++n.N0.n_[j] == 0; ) if (++j >= NN::N) break;
    }

    return n.N0;
}

// Modulo reduction by x25519 base point order.
N2& N2::reduceb()
{
    static const NN bpr{ 0xcf5d3ed0, 0x812631a5, 0x2f79cd65, 0x4def9dea, 1, 0, 0, 0 };
    NN bpo(ecc_BPO);
    bpo <<= bpo.lead0();
    N2 d(n.N1, 0);
    d -= d.n.N1 * bpr;
    d.n.N0 = 0;
    d += d.n.N1 * bpr;
    *this -= d;

    while (n.N1) {
        if (n.N0 < bpo) n.N1 -= 1;
        n.N0 -= bpo;
    }

    n.N0.reduceb();
    return *this;
}

// Generic reduction with a helper RR.
NN& N2::reduce(const RR& r)
{
    NN n1(n.N1);
    *this -= n1 * r.p;
    n1 = (n1 * r.r).n.N1;
    *this -= (n1 * r.p);
    while (n.N1) {
        if (n.N0 < r.p) n.N1 -= 1;
        n.N0 -= r.p;
    }
    while (n.N0 >= r.p) n.N0 -= r.p;
    return n.N0;
}
