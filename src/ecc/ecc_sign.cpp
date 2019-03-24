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

#include "ecc_sign.h"
#include "ecc.h"
#include "ecc_verify.h"
#include "ecc_x25519.h"

#include "sha.h"
#include "base_type.h"
#include "ssl_defs.h"
#include "cipher.h"

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

/* Maximum number of prime p that fits into 256-bits */
const NN w_maxP{   /* 2*P < 2**256 */
    0xFFFFFFDA,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF
};


// -- custom blind ---------------------------------------------------------
//
// edp_custom_blinding is defined in source/custom_blind.c
// source/custom_blind is created randomly on every new build
//
// -------------------------------------------------------------------------

const NN w_2d{ 0x26B2F159, 0xEBD69B94, 0x8283B156, 0x00E0149A, 0xEEF3D130, 0x198E80F2, 0x56DFFCE7, 0x2406D9DC }; // 2*d
const NN w_di{ 0xCDC9F843, 0x25E0F276, 0x4279542E, 0x0B5DD698, 0xCDB9CF66, 0x2B162114, 0x14D5CE43, 0x40907ED2 }; // 1/d


/* Trim private key   */
void ecp_TrimSecretKey(uint8_t* X)
{
    X[0] &= 0xf8;
    X[31] = (X[31] | 0x40) & 0x7f;
}

uint8_t* ecp_EncodeKey(uint8_t* Y, const NN& X, uint8_t parity)
{
    int i;
    const M32* m = (const M32*) X.n_;;

    for (i = 0; i < 32;)
    {
        Y[i++] = m->u8.b0;
        Y[i++] = m->u8.b1;
        Y[i++] = m->u8.b2;
        Y[i++] = m->u8.b3;
        m++;
    }

    Y[31] = (Y[31] & 0x7F) | (parity << 7);
    return Y;
}

uint8_t ecp_DecodeKey(NN& Y, const uint8_t* X)
{
    int i;
    M32 m;

    for (i = 0; i < 8; i++)
    {
        m.u8.b0 = *X++;
        m.u8.b1 = *X++;
        m.u8.b2 = *X++;
        m.u8.b3 = *X++;

        Y.n_[i] = m.u32;
    }

    Y.n_[7] &= 0x7FFFFFFF;
    return (X[-1] >> 7);
}

void ecp_4fold(uint8_t* Y, const uint32_t* X)
{
    int i, j;
    uint8_t a, b;
    for (i = 32; i-- > 0; Y++)
    {
        a = 0;
        b = 0;
        for (j = 8; j > 1;)
        {
            j -= 2;
            a = (a << 1) + ((X[j + 1] >> i) & 1);
            b = (b << 1) + ((X[j] >> i) & 1);
        }
        Y[0] = a;
        Y[32] = b;
    }
}

void ecp_8fold(uint8_t* Y, const uint32_t* X)
{
    int i, j;
    uint8_t a = 0;
    for (i = 32; i-- > 0;)
    {
        for (j = 8; j-- > 0;) a = (a << 1) + ((X[j] >> i) & 1);
        *Y++ = a;
    }
}

// Reference: http://eprint.iacr.org/2008/522
// Cost: 7M + 7add
// Return: R = P + BasePoint
void Ext_PT::AddBasePoint()
{
    x.reduce(); y.reduce(); z.reduce(); t.reduce();

    NN a; a.subr(y, x);         // A = (Y1-X1)*(Y2-X2)
    a = a ^ gPreFold[1].YmX;

    NN b; b.addr(y, x);         // B = (Y1+X1)*(Y2+X2)
    b = b ^ gPreFold[1].YpX;

    NN c(t ^ gPreFold[1].T2d);  // C = T1*2d*T2
    NN d((z + z).reduce());     // D = 2*Z1
    NN e; e.subr(b, a);         // E = B-A

    (b += a).reduce();          // H = B+A
    a.subr(d, c);               // F = D-C
    (d += c).reduce();          // G = D+C

    x = e ^ a;              // E*F
    y = b ^ d;              // H*G
    t = e ^ b;              // E*H
    z = d ^ a;              // G*F
}

// Assumptions: pre-computed q. Cost: 8M + 6add. Return: P = P + Q
void Ext_PT::AddPoint(const PE_PT* q)
{
    NN a;               // A = (Y1-X1)*(Y2-X2)
    a.subr(y, x);
    a = a ^ q->YmX;

    NN b;               // B = (Y1+X1)*(Y2+X2)
    b.addr(y, x);
    b = b ^ q->YpX;

    NN c(t ^ q->T2d); // C = T1*2d*T2
    NN d(z ^ q->Z2); // D = Z1*2*Z2
    NN e; e.subr(b , a); // E = B-A

    (b += a).reduce();  // H = B+A
    a.subr(d, c);       // F = D-C
    (d += c).reduce();  // G = D+C

    x = e ^ a;       // E*F
    y = b ^ d;       // H*G
    t = e ^ b;       // E*H
    z = d ^ a;       // G*F
}

// Reference: http://eprint.iacr.org/2008/522 Cost: 4M + 4S + 7add
// Return: P = 2*P
void Ext_PT::DoublePoint()
{
    x.reduce(); y.reduce(); z.reduce(); t.reduce();

    NN a(x ^ x);      // A = X1^2
    NN b(y ^ y);      // B = Y1^2
    NN c(z ^ z);      // C = 2*Z1^2

    c = (c + c).reduce();

    NN d(w_maxP); d.reduce(); // D = -A
    d = (d >= a) ? d - a : d + (NN::P_ - a);
    a.subr(d, b);           // H = D-B
    (d += b).reduce();      // G = D+B
    b.subr(d, c);           // F = G-C

    NN e((x + y).reduce());   // E = (X1+Y1)^2-A-B = (X1+Y1)^2+H

    e = e ^ e;
    (e += a).reduce();

    x = e ^ b;       // E*F
    y = a ^ d;       // H*G
    z = d ^ b;       // G*F
    t = e ^ a;       // E*H
}

// Assumptions: pre-computed q, q->Z=1. Cost: 7M + 7add
// Return: P = P + Q
void Ext_PT::AddAffinePoint(const PA_PT *q)
{
    y.reduce(); x.reduce(); z.reduce();

    NN a; a.subr(y, x); // A = (Y1-X1)*(Y2-X2)
    a = a ^ q->YmX;

    NN b; b.addr(y, x); // B = (Y1+X1)*(Y2+X2)
    b = b ^ q->YpX;

    NN c(t ^ q->T2d);   // C = T1*2d*T2
    NN d; d.addr(z, z); // D = Z1*2*Z2 (Z2=1)
    NN e; e.subr(b, a); // E = B-A

    (b += a).reduce();  // H = B+A
    a.subr(d, c);       // F = D-C
    (d += c).reduce();  // G = D+C

    x = e ^ a;          // E*F
    y = b ^ d;          // H*G
    t = e ^ b;          // E*H
    z = d ^ a;          // G*F
}

/* -- FOLDING ---------------------------------------------------------------
//
//    The performance boost is achieved by a process that I call it FOLDING.
//    Folding can be viewed as an extension of Shamir's trick but it is based
//    on break down of the scalar multiplier of a*P into a polynomial of the
//    form:
//
//        a*P = SUM(a_i*2^(i*w))*P    for i = 0,1,2,...n-1
//
//        a*P = SUM(a_i*P_i)
//
//        where P_i = (2^(i*w))*P
//              n = number of folds
//              w = bit-length of a_i
//
//    For folding of 8, 256-bit multiplier 'a' is chopped into 8 limbs of
//    32-bits each (a_0, a_1,...a_7). P_0 - P_7 can be pre-calculated and
//    their 256-different permutations can be cached or hard-coded
//    directly into the code.
//    This arrangement combined with double-and-add approach reduces the
//    number of EC point calculations by a factor of 8. We only need 31
//    double & add operations.
//
//       +---+---+---+---+---+---+- .... -+---+---+---+---+---+---+
//  a = (|255|254|253|252|251|250|        | 5 | 4 | 3 | 2 | 1 | 0 |)
//       +---+---+---+---+---+---+- .... -+---+---+---+---+---+---+
//
//                     a_i                       P_i
//       +---+---+---+ .... -+---+---+---+    ----------
// a7 = (|255|254|253|       |226|225|224|) * (2**224)*P
//       +---+---+---+ .... -+---+---+---+
// a6 = (|225|224|223|       |194|193|192|) * (2**192)*P
//       +---+---+---+ .... -+---+---+---+
// a5 = (|191|190|189|       |162|161|160|) * (2**160)*P
//       +---+---+---+ .... -+---+---+---+
// a4 = (|159|158|157|       |130|129|128|) * (2**128)*P
//       +---+---+---+ .... -+---+---+---+
// a3 = (|127|126|125|       | 98| 97| 96|) * (2**96)*P
//       +---+---+---+ .... -+---+---+---+
// a2 = (| 95| 94| 93|       | 66| 65| 64|) * (2**64)*P
//       +---+---+---+ .... -+---+---+---+
// a1 = (| 63| 62| 61|       | 34| 33| 32|) * (2**32)*P
//       +---+---+---+ .... -+---+---+---+
// a0 = (| 31| 30| 29|       | 2 | 1 | 0 |) * (2**0)*P
//       +---+---+---+ .... -+---+---+---+
//         |   |                   |   |
//         |   +--+                |   +--+
//         |      |                |      |
//         V      V     slices     V      V
//       +---+  +---+    ....    +---+  +---+
//       |255|  |254|            |225|  |224|   P7
//       +---+  +---+    ....    +---+  +---+
//       |225|  |224|            |193|  |192|   P6
//       +---+  +---+    ....    +---+  +---+
//       |191|  |190|            |161|  |160|   P5
//       +---+  +---+    ....    +---+  +---+
//       |159|  |158|            |129|  |128|   P4
//       +---+  +---+    ....    +---+  +---+
//       |127|  |126|            | 97|  | 96|   P3
//       +---+  +---+    ....    +---+  +---+
//       | 95|  | 94|            | 65|  | 64|   P2
//       +---+  +---+    ....    +---+  +---+
//       | 63|  | 62|            | 33|  | 32|   P1
//       +---+  +---+    ....    +---+  +---+
//       | 31|  | 30|            | 1 |  | 0 |   P0
//       +---+  +---+    ....    +---+  +---+
// cut[]:  0      1      ....      30     31
// --------------------------------------------------------------------------
// Return S = a*P where P is ed25519 base point and R is random
*/
void Ext_PT::BasePointMult(const NN& sk, const NN& r)
{
    int i = 1;
    uint8_t cut[32];

    ecp_8fold(cut, sk.n_);

    const PA_PT* P0 = &(gPreFold[cut[0]]);

    NN rR(r); rR.reduce();

    x.subr(P0->YpX, P0->YmX);    // 2x
    y.addr(P0->YpX, P0->YmX);    // 2y
    t = P0->T2d ^ w_di;          // 2xy

    // Randomize starting point
    z.addr(rR, rR);      // Z = 2R
    x = x ^ rR;       // X = 2xR
    t = t ^ rR;       // T = 2xyR
    y = y ^ rR;       // Y = 2yR

    do
    {
        DoublePoint();
        AddAffinePoint(&gPreFold[cut[i]]);
    } while (i++ < 31);
}

static void edp_BasePointMultiply(
    XY*         R,
    const NN&   sk,
    const BLINDING* blinding)
{
    Ext_PT S;

    if (blinding)
    {
        NN t; t.addr(sk, blinding->bl);
        S.BasePointMult(t, blinding->zr);
        S.AddPoint(&(blinding->BP));
    }
    else
    {
        S.BasePointMult(sk, edp_blinding.zr);
    }

    S.z = S.z.inverse();
    R->x = S.x ^ S.z;
    R->y = S.y ^ S.z;
}

void PE_PT::fromExtPT(const Ext_PT& p)
{
    NN  x(p.x), y(p.y), z(p.z);
    x.reduce(); y.reduce(); z.reduce();

    YpX.addr(y, x);
    YmX.subr(y , x);
    T2d = p.t ^ w_2d;
    Z2 = (z + z).reduce();
}

// -- Blinding -------------------------------------------------------------
//
//  Blinding is a measure to protect against side channel attacks.
//  Blinding randomizes the scalar multiplier.
//
//  Instead of calculating a*P, calculate (a+b mod BPO)*P + B
//
//  Where b = random blinding and B = -b*P
//
// -------------------------------------------------------------------------
BLINDING::BLINDING(
    CIPHER& cipher,   // Message Digest Context
    const uint8_t* seed,    // Random blinding seed 
    uint32_t       cbSize   // size of blinding seed
)
{
    struct {
        Ext_PT  T;
        NN      t;
        uint8_t digest[64];
    } d;

    CTX ctx;

    // Use edp_custom_blinding to protect generation of the new blinder
    cipher.Init(&ctx, cipher.pIData);
    cipher.Input(&ctx, (const uint8_t*)edp_blinding.zr.n_, 32);
    cipher.Input(&ctx, seed, cbSize);
    cipher.Digest(&ctx, d.digest);

    zr.bytesIn(d.digest + 32);
    d.t.bytesIn(d.digest);
    d.t.reduceb();
    bl = ecc_BPO - d.t;

    (d.t += edp_blinding.bl).reduceb();
    d.T.BasePointMult(d.t, edp_blinding.zr);
    d.T.AddPoint(&edp_blinding.BP);

    BP.fromExtPT(d.T);

    // clear potentially sensitive data
    memset(&d, 0, sizeof(d));
}

// Generate public and private key pair associated with the secret key
void edd_CreateKeyPair(
    CIPHER& cipher,             // Message Digest algorithm
    unsigned char *pubKey,      // Public key out
    unsigned char *privKey,     // Private key out
    const BLINDING* blinding,   // [optional] null or blinding context
    const unsigned char *sk)    // Secret key (32 bytes)
{
    uint8_t md[64];
    XY  Q;
    NN  t;
    CTX ctx;

    // [a:b] = H(sk)
    cipher.Init(&ctx, cipher.pIData);
    cipher.Input(&ctx, sk, 32);
    cipher.Digest(&ctx, md);

    ecp_TrimSecretKey(md);
    t.bytesIn(md);

    edp_BasePointMultiply((XY*)&Q, t, blinding);

    ecp_EncodeKey(pubKey, Q.y, uint8_t(Q.x.n_[0]&1));

    memcpy(privKey, sk, 32);
    memcpy(privKey + 32, pubKey, 32);
}

// Generate message signature
void edd_SignMessage(
    CIPHER& cipher,             // Message Digest Algorithm
    uint8_t* signature,         // OUT: [64 bytes] signature (R,S)
    const uint8_t* keyPair,     // [64 bytes] private key (sk,pk)
    const BLINDING* blinding,   // [optional] null or blinding context
    const uint8_t* msg,         // [msg_size bytes] message to sign
    size_t msg_size)
{
    XY  R;
    NN  a, t, r;
    uint8_t md[64];
    CTX ctx;

    // [a:b] = H(sk)
    cipher.Init(&ctx, cipher.pIData);
    cipher.Input(&ctx, keyPair, 32);
    cipher.Digest(&ctx, md);

    ecp_TrimSecretKey(md);              // a = first 32 bytes
    a.bytesIn(md);

    // r = H(b + m) mod BPO
    cipher.Init(&ctx, cipher.pIData);
    cipher.Input(&ctx, md + 32, 32);
    cipher.Input(&ctx, msg, msg_size);
    cipher.Digest(&ctx, md);

    eco_DigestToWords(r, md);
    r.reduceb();                        // r mod BPO

                                        // R = r*P
    edp_BasePointMultiply(&R, r, blinding);
    ecp_EncodeKey(signature, R.y, uint8_t(R.x.n_[0]&1)); // R part of signature

    // S = r + H(encoded(R) + pk + m) * a  mod BPO
    cipher.Init(&ctx, cipher.pIData);
    cipher.Input(&ctx, signature, 32);   // encoded(R)
    cipher.Input(&ctx, keyPair + 32, 32);// pk
    cipher.Input(&ctx, msg, msg_size);   // m
    cipher.Digest(&ctx, md);

    eco_DigestToWords(t, md);

    t = (t * a).reduceb();      // h()*a
    t = (t + r).reduceb();

    t.bytesOut(signature + 32);  // S part of signature

    // Clear sensitive data
    a = 0;
    r = 0;
}

// Generate public and private key pair associated with the secret key
void X25519::genPubKey(
    CIPHER& cipher,         // Message Digest algorithm. Mustbe sha512
    uint8_t* pubKey,        // Public key out
    const uint8_t* priKey   // Private key in
    )
{
    CTX ctx;
    uint8_t md[64];
    const BLINDING* blinding = nullptr; // [optional] null or blinding context

    // [a:b] = H(sk)
    cipher.Init(&ctx, cipher.pIData);
    cipher.Input(&ctx, priKey, 32);
    cipher.Digest(&ctx, md);

    ecp_TrimSecretKey(md);

    XY  Q;
    edp_BasePointMultiply(&Q, NN().bytesIn(md), blinding);

    ecp_EncodeKey(pubKey, Q.y, uint8_t(Q.x.n_[0] & 1));
}


void X25519::ECDSign::Sign(const uint8_t* keyPair, const uint8_t* pMsg, uint32_t nSize)
{
    NN  a, z;
    CTX ctx;
    uint8_t md[64];
    const BLINDING* blinding = nullptr; // [optional] null or blinding context

    // [a:b] = H(sk)
    c_.Init(&ctx, c_.pIData);
    c_.Input(&ctx, keyPair, 32);
    c_.Digest(&ctx, md);

    ecp_TrimSecretKey(md);              // a = first 32 bytes
    a.bytesIn(md);

    // r = H(b + m) mod BPO
    c_.Init(&ctx, c_.pIData);
    c_.Input(&ctx, md + 32, 32);
    c_.Input(&ctx, pMsg, nSize);
    c_.Digest(&ctx, md);

    eco_DigestToWords(z, md);
    z.reduceb();    // r mod BPO

    // R = r*P
    {XY&  R(*(XY*)&ctx); // Save memory. OK to use ctx.
    edp_BasePointMultiply(&R, z, blinding);
    r = R.y; r.n7 |= uint32_t(R.x.n_[0] & 1) << 31; }

    // S = r + H(encoded(R) + pk + m) * a  mod BPO
    c_.Init(&ctx, c_.pIData);
    c_.Input(&ctx, r, 32);   // encoded(R)
    c_.Input(&ctx, keyPair + 32, 32);// pk
    c_.Input(&ctx, pMsg, nSize);   // m
    c_.Digest(&ctx, md);

    eco_DigestToWords(s, md);

    a = (s * a).reduceb();      // h()*a
    s = (a + z).reduceb();      // r + h()*a

    // Calculated signature is stored in class member r and s.
}
