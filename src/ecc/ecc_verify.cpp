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

#include "ecc_verify.h"
#include "ecc.h"
#include "ecc_sign.h"
#include "ecc_x25519.h"

#include "sha.h"
#include "cipher.h"
#include "ssl_defs.h"

/*
 * Arithmetic on twisted Edwards curve y^2 - x^2 = 1 + dx^2y^2
 * with d = -(121665/121666) mod p
 *      d = 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3
 *      p = 2**255 - 19
 *      p = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
 * Base point: y=4/5 mod p
 *      x = 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
 *      y = 0x6666666666666666666666666666666666666666666666666666666666666658
 * Base point order:
 *      l = 2**252 + 27742317777372353535851937790883648493
 *      l = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
 */


#define minusR_0    0xCF5D3ED0
#define minusR_1    0x812631A5
#define minusR_2    0x2F79CD65
#define minusR_3    0x4DEF9DEA
#define minusR_4    1
#define minusR_5    0
#define minusR_6    0
#define minusR_7    0

// Calculate: Y = [b:X] mod BPO
// For R = 2^256, we calculate Y = b*R + X mod BPO
// Since -R mod BPO is only 129-bits, it reduces number of multiplications if
// we calculate: Y = X - b*(-R) mod BPO instead
// Note that b*(-R) is 161-bits at most and does not need reduction.

#define w_Zero     gPreFold[0].T2d
#define w_One      gPreFold[0].YpX

const NN EdpSigv::w_I{ 0x4A0EA0B0,0xC4EE1B27,0xAD2FE478,0x2F431806,0x3DFBD7A7,0x2B4D0099,0x4FC1DF0B,0x2B832480 }; // sqrt(-1)

const NN EdpSigv::w_d{ 0x135978A3,0x75EB4DCA,0x4141D8AB,0x00700A4D,0x7779E898,0x8CC74079,0x2B6FFE73,0x52036CEE };

static void ecp_ModExp2523(NN& Y, const NN& X);

// Return Y = D mod BPO where D is 512-bit message digest (i.e SHA512 digest)
void eco_DigestToWords(NN& Y, const uint8_t* md)
{
    N2 R;
    R.n.N0.bytesIn(md); R.n.N1.bytesIn(md + 32);
    Y = R.reduceb();
}

void EdpSigv::edd_CalculateX(NN& X, const NN& Y, uint8_t parity)
{
    // Calculate sqrt((y^2 - 1)/(d*y^2 + 1))

    NN u(Y ^ Y);            // u = y^2
    NN v(u ^ w_d);          // v = dy^2

    u.subr(u, w_One);       // u = y^2-1
    (v += w_One).reduce();  // v = dy^2+1

    // Calculate:  sqrt(u/v) = u*v^3 * (u*v^7)^((p-5)/8)
    NN b(v ^ v);
    NN a(u ^ b);

    a = a ^ v;          // a = u*v^3
    b = b ^ b;          // b = v^4
    b = a ^ b;          // b = u*v^7

    ecp_ModExp2523(b, b);
    X = b ^ a;

    // Check if we have correct sqrt, else, multiply by sqrt(-1)
    b = X ^ X;
    b = b ^ v;
    b.subr(b, u);
    //b.reduce();

    if (b != w_Zero) {
        X = X ^ w_I;
    }

    while (X >= NN::P_) {
        X -= NN::P_;
    }

    // match parity
    if (((X.n0 ^ parity) & 1) != 0) {
        X = NN::P_ - X;
    }
}

void edd_UnpackPoint(XY* r, const uint8_t* p)
{
    uint8_t parity = ecp_DecodeKey(r->y, p);
    EdpSigv::edd_CalculateX(r->x, r->y, parity);
}

static void ecp_SrqMulReduce(NN& Z, const NN& X, uint32_t n, const NN& Y)
{
    NN t( X ^ X);
    while (n-- > 1) t = t ^ t;
    Z = t ^ Y;
}

void ecp_ModExp2523(NN&Y, const NN& X)
{
    NN x2(X ^ X);                       // 2

    NN x9;
    ecp_SrqMulReduce(x9, x2, 2, X);     // 9

    NN x11(x9 ^ x2);                    // 11
    NN t(x11 ^ x11);                    // 22
    NN x5(t ^ x9);                      // 31 = 2^5 - 2^0

    NN x10;
    ecp_SrqMulReduce(x10, x5, 5, x5);   // 2^10 - 2^0

    NN x20;
    ecp_SrqMulReduce(x20, x10, 10, x10);    // 2^20 - 2^0
    ecp_SrqMulReduce(t, x20, 20, x20);      // 2^40 - 2^0

    NN x50;
    ecp_SrqMulReduce(x50, t, 10, x10);      // 2^50 - 2^0

    NN x100;
    ecp_SrqMulReduce(x100, x50, 50, x50);   // 2^100 - 2^0
    ecp_SrqMulReduce(t, x100, 100, x100);   // 2^200 - 2^0
    ecp_SrqMulReduce(t, t, 50, x50);        // 2^250 - 2^0

    t = t ^ t; t = t ^ t;       // 2^252 - 2^2
    Y = t ^ X;                  // 2^252 - 3
}


//  Assumptions: pre-computed q
//  Cost: 8M + 6add
//  Return: P = P + Q
void edp_AddPoint(Ext_PT* r, const Ext_PT* p, const PE_PT* q)
{
    NN a((p->y >= p->x) ? p->y - p->x : p->y - (NN::P_ - p->x));
    a = a ^ q->YmX; // A = (Y1-X1)*(Y2-X2)

    NN b((p->y + p->x).reduce());
    b = b ^ q->YpX; // B = (Y1+X1)*(Y2+X2)

    NN c(p->t ^ q->T2d);    // C = T1*2d*T2
    NN d(p->z ^ q->Z2);     // D = Z1*2*Z2
    NN e((b >= a)? b - a : b + (NN::P_ - a));   // E = B-A

    (b += a).reduce();      // H = B+A
    a = (d >= c)? d - c : d + (NN::P_ - c); // F = D-C
    (d += c).reduce();      // G = D+C

    r->x = e ^ a;           // E*F
    r->y = b ^ d;           // H*G
    r->t = e ^ b;           // E*H
    r->z = d ^ a;           // G*F
}

int edd_VerifySignature(
    CIPHER& cipher,         // Message Digest Algorithm
    const unsigned char *signature, // IN: signature (R,S)
    const unsigned char *publicKey, // IN: public key
    const unsigned char *msg, size_t msg_size)  // IN: message to sign
{
    EdpSigv ctx((const uint8_t*)publicKey);
    return ctx.Verify(cipher, signature, msg, msg_size);
}

bool X25519::ECDSign::Test(const uint8_t* pubKey, const uint8_t* pMsg, uint32_t nSize) const
{
    EdpSigv ctx(pubKey);
    return ctx.Verify(c_, *this, pMsg, nSize);
}

EdpSigv::EdpSigv(const uint8_t pubKey[32])
{
#define QTABLE_SET(d,s) \
    T = Q; T.AddPoint(&q_table[s]); \
    q_table[d].fromExtPT(T)

    int i;
    Ext_PT Q, T;

    memcpy(pk, pubKey, 32);
    i = ecp_DecodeKey(Q.y, pubKey);
    edd_CalculateX(Q.x, Q.y, ~i);   // Invert parity for -Q 

    Q.t = Q.x ^ Q.y;
    Q.z = 1;

    // pre-compute q-table

    // Calculate: Q0=Q, Q1=(2^64)*Q, Q2=(2^128)*Q, Q3=(2^192)*Q
    q_table[0].YpX = 1;             // -- -- -- --
    q_table[0].YmX = 1;
    q_table[0].T2d = 0;
    q_table[0].Z2 = 2;

    q_table[1].fromExtPT(Q);       // -- -- -- q0

    for (i = 0; i < 64; i++) Q.DoublePoint();

    q_table[2].fromExtPT(Q);       // -- -- q1 --
    QTABLE_SET(3, 1);               // -- -- q1 q0

    do { Q.DoublePoint(); } while (++i < 128);

    q_table[4].fromExtPT(Q);       // -- q2 -- --
    QTABLE_SET(5, 1);               // -- q2 -- q0
    QTABLE_SET(6, 2);               // -- q2 q1 --
    QTABLE_SET(7, 3);               // -- q2 q1 q0

    do { Q.DoublePoint(); } while (++i < 192);

    q_table[8].fromExtPT(Q);       // q3 -- -- --
    QTABLE_SET(9, 1);               // q3 -- -- q0
    QTABLE_SET(10, 2);              // q3 -- q1 --
    QTABLE_SET(11, 3);              // q3 -- q1 q0
    QTABLE_SET(12, 4);              // q3 q2 -- --
    QTABLE_SET(13, 5);              // q3 q2 -- q0
    QTABLE_SET(14, 6);              // q3 q2 q1 --
    QTABLE_SET(15, 7);              // q3 q2 q1 q0
#undef QTABLE_SET
}

bool EdpSigv::Verify(
    const CIPHER& cipher,           // Message Digest Algorithm
    const unsigned char *signature, // signature (R,S)
    const unsigned char *msg,       // Message text
    size_t msg_size
) const
{
    XY  T;
    NN  h, s;
    uint8_t md[64];
    CTX     ctx;

    // h = H(enc(R) + pk + m)  mod BPO
    cipher.Init(&ctx, cipher.pIData);
    cipher.Input(&ctx, signature, 32);   // enc(R)
    cipher.Input(&ctx, pk, 32);
    cipher.Input(&ctx, msg, msg_size);
    cipher.Digest(&ctx, md);

    eco_DigestToWords(h, md);

    h.reduceb();

    // T = s*P + h*(-Q) = (s - h*a)*P = r*P = R

    s.bytesIn(signature + 32);

    eddp_PolyPointMultiply(&T, s, h);
    ecp_EncodeKey(md, T.y, uint8_t(T.x.n_[0] & 1));

    return (memcmp(md, signature, 32) == 0);
}

//  Assumptions: qtable = pre-computed Q
//  Calculate: point R = a*P + b*Q  where P is base point
void EdpSigv::eddp_PolyPointMultiply(
    XY*     r, 
    const NN& a, 
    const NN& b) const
{
    int i = 1;
    Ext_PT S;
    const PE_PT* q0;
    uint8_t u[32], v[64];

    ecp_8fold(u, a.n_);
    ecp_4fold(v, b.n_);

    /* Set initial value of S */
    q0 = &q_table[v[0]];

    S.x.subr(q0->YpX, q0->YmX); // 2x
    S.y.addr(q0->YpX, q0->YmX); // 2y 

    S.t = q0->T2d ^ w_di;       // 2xy
    S.z = q0->Z2;               // 2z

    do
    {   // 31D + 31A
        S.DoublePoint();
        S.AddPoint(&q_table[v[i]]);
    } while (++i < 32);

    do
    {   // 32D + 64A
        S.DoublePoint();
        S.AddAffinePoint(&gPreFold[u[i-32]]);
        S.AddPoint(&q_table[v[i]]);
    } while (++i < 64);

    S.z = S.z.inverse();

    r->x = S.x ^ S.z;
    r->y = S.y ^ S.z;
}
