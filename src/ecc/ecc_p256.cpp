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
#include <new>
#include <assert.h>

#include "ecc.h"
#include "ecc_p256.h"

// Explicit formulas batabase: http://hyperelliptic.org/EFD/index.html

// NIST P256 curve parameters.
static const EccParam gP256{
    {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF},
    {0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF},
    {0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0, 0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8},
    {{0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81, 0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2},
    {0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357, 0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2}},
    {0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF}};

// Helper RR for modulo reduction against P256 prime.
static const struct RR gRR {
    {0x00000003, 0x00000000, 0xffffffff, 0xfffffffe, 0xfffffffe, 0xfffffffe, 0xffffffff, 0x00000000},
    {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF}};

// Helper RR for modulo reduction against P256 order.
static const struct RR gRN {
    {0xeedf9bfe, 0x012ffd85, 0xdf1a6c21, 0x43190552, 0xffffffff, 0xfffffffe, 0xffffffff, 0x00000000},
    { 0xfc632551, 0xf3b9cac2, 0xa7179e84, 0xbce6faad, 0xffffffff, 0xffffffff, 0x00000000, 0xffffffff }
};


// Test vectors at: http://point-at-infinity.org/ecc/nisttv
// Useful ECC references:
// https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates
// http://hyperelliptic.org/EFD/g1p/index.html
// https://eprint.iacr.org/2013/816.pdf
// http://www.christelbach.com/ECCalculator.aspx

namespace P256 {
struct XY_PT : XY {
    XY_PT Mult(const NN& m) const;
};

struct XYZ_PT
{
    NN x;
    NN y;
    NN z;
    XYZ_PT() {}
    XYZ_PT(const XY& s);

    XYZ_PT& Double();
    XYZ_PT& Add(const XYZ_PT& q);

    void Out(XY& t) const;
};
} // namespace P256

using P256::XY_PT;
using P256::XYZ_PT;
using P256::ECDSign;
using P256::ECDKeyPair;
using P256::G;

static const XY_PT& g(*(const XY_PT*)&gP256.g);

// Construct a Jacobian coordinate from an [X,Y] Affine point.
XYZ_PT::XYZ_PT(const XY& s) : x(s.x), y(s.y), z(1) {}

// Convert [X,Y,Z] Jacobian coordinate back to [X,Y] Affine point.
void XYZ_PT::Out(XY& t) const
{
    NN z1(z.inverse(gRR));
    NN z2((z1 * z1).reduce(gRR));
    t.x = (x * z2).reduce(gRR);
    t.y = ((y * z2).reduce(gRR) * z1).reduce(gRR);
}

// Point double in Jacobian coordinate.
XYZ_PT& XYZ_PT::Double()
{
    //Point Doubling. Input : (X, Y, Z)
    // S = 4XY^2;
    NN S((NN(4) * x).reduce(gRR));
    S = ((y * y).reduce(gRR) * S).reduce(gRR);

    // M = 3X^2 + aZ^4
    NN M((z * z).reduce(gRR));
    M = (M * M).reduce(gRR);
    M = (M * gP256.a).reduce(gRR);
    N2 M2((x * x)); M2.reduce(gRR);
    M = ((M2.n.N0 * uint32_t(3)) += M).reduce(gRR);

    // Z' = 2YZ
    M2.n.N0 = (y * z).reduce(gRR); M2.n.N1 = 0;
    NN mt(M2.n.N0); M2 += mt;
    z = M2.reduce(gRR);

    // X' = M^2 - 2S
    M2 = M * M; M2.reduce(gRR);
    NN d = gRR.p - S;
    //M2 += d; M2 += d;
    x = (M2 + d + d).reduce(gRR);

    // Y' = M(S - X') - 8Y^4
    M2.n.N0 = (y * y).reduce(gRR);
    M2.n.N0 = (M2.n.N0 * M2.n.N0).reduce(gRR);
    (M2 <<= 3).reduce(gRR);
    d = (S >= x) ? (S - x) : S + (gRR.p - x);
    M2 = (M * d) + (gRR.p - M2.n.N0);
    y = M2.reduce(gRR);

    return *this;
}

// Point addition in Jacobian coordinate.
XYZ_PT& XYZ_PT::Add(const XYZ_PT& q)
{
    //Point Addition
    //put : (X1, Y1, Z1), (X2, Y2, Z2)
    //U1 = X1Z2^2 U2 = X2Z1^2 S1 = Y1Z2^3 S2 = Y2Z1^3
    NN u1((q.z*q.z).reduce(gRR));
    NN u2((z * z).reduce(gRR));
    NN s1(((y * q.z).reduce(gRR) * u1).reduce(gRR));
    NN s2(((q.y * z).reduce(gRR) * u2).reduce(gRR));
    u1 = (u1 * x).reduce(gRR);
    u2 = (u2 * q.x).reduce(gRR);

    //H = U2 - U1; R = S2 - S1
    NN h((u2 >= u1) ? u2 - u1 : u2 + (gRR.p - u1));
    NN r((s2 >= s1) ? s2 - s1 : s2 + (gRR.p - s1));

    if (h.is0()) {
        if (!r.is0()) {/*Impossible error*/}
        return Double();
    }

    //X3 = R^2 - H^3 - 2*U1*H^2
    u2 = (h*h).reduce(gRR);
    u1 = gRR.p - (u1 * u2).reduce(gRR);
    u2 = gRR.p - (u2 * h).reduce(gRR);
    x = ((r * r) + u2 + u1 + u1).reduce(gRR);

    //Y3 = R*(U1*H^2 - X3) - S1*H^3
    u1 = gRR.p - u1;
    if (u1 < x) u1 += gRR.p;
    u1 -= x;
    y = ((s1 * u2) + (r * u1).reduce(gRR)).reduce(gRR);

    //Z3 = HZ1Z2
    z = (h * (z * q.z).reduce(gRR)).reduce(gRR);

    //Output : (X3, Y3, Z3)
    return *this;
}

// Point Double and Add using Montgomery Ladder for constant time operation.
// https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
XY_PT XY_PT::Mult(const NN& m) const
{
    uint32_t i, j, k;
    XY_PT   r;
    const XY g1{ x, y };
    const XYZ_PT gP(g1);
    XYZ_PT  R0(gP), R1(gP);

    // Search for first set bit
    j = m.lead0();
    if (j >= (NN::N << 5)) {
        return r;
    }
    i = NN::N - (j >> 5) - 1; j &= 31;
    R1.Double();
    k = m.n_[i] << j;
    for (;;) {
        k <<= 1;
        if (++j >= 32) {
            if (i-- == 0) break;
            j = 0; k = m.n_[i];
        }

        XYZ_PT *p0, *p1;
        if (k & 0x80000000) {
            p0 = &R0; p1 = &R1;
        } else {
            p1 = &R0; p0 = &R1;
        }
        p0->Add(*p1);
        p1->Double();
    }

    R0.Out(r);
    return r;
}

void ECDSign::Sign(const uint8_t digest[32], const uint8_t nounce[32], const NN& priKey)
{
    r.netIn(nounce);
    s.netIn(digest); s.reduce(gRN.p);
    NN k1 = r.inverse(gRN);
    r = g.Mult(r).x;
    s = ((r * priKey) + s).reduce(gRN);
    s = (k1 * s).reduce(gRN);
}

bool ECDSign::Test(const uint8_t digest[32], const XY& pbKey) const
{
    const XY_PT& pubKey(*(const XY_PT*)&pbKey);
    XYZ_PT P;
    P.x.netIn(digest).reduce(gRN.p);
    P.y = s.inverse(gRN);
    P.x = (P.x * P.y).reduce(gRN);
    NN u2((P.y * r).reduce(gRN));

    new (&P) XYZ_PT(g.Mult(P.x));
    P.Add(XYZ_PT(pubKey.Mult(u2))).Out(*(XY*)&P);

    return (P.x == r);
}

void ECDSign::OutR(uint8_t* pR) const
{
    r.netOut(pR);
}

void ECDSign::OutS(uint8_t* pS) const
{
    s.netOut(pS);
}

uint32_t ECDSign::Verify(
    const uint8_t digest[32],
    const uint8_t pubKey[64],
    const uint8_t R[32],
    const uint8_t S[32])
{
    ECDSign sig;
    sig.r.netIn(R);
    sig.s.netIn(S);
    P256::G gBase;
    gBase.netIn(pubKey, 0x20);
    return sig.Test(digest, gBase);
}

#include "cipher.h"

extern "C" void SetP256(ECC* pEcc)
{
    pEcc->Verify = ECDSign::Verify;
}

void ECDKeyPair::Create(EntropyFunc fn)
{
    do {
        for (uint32_t i = 0; i < NN::N; i++) {
            priKey.n_[i] ^= fn();
        }
        priKey.reduce(gP256.n);
    } while ((priKey.n_[0] & 0x07) || ((priKey.n_[NN::N - 1] & 0xC0000000) != 0x40000000));
    pubKey = g.Mult(priKey);
}

void ECDKeyPair::Generate(const NN& nounce)
{
    pubKey = g.Mult(priKey = nounce);
}

G::G() : XY(gP256.g)
{
}

void G::PointMult(uint8_t* PublicKey, const NN& SecretKey) const
{
    ((XY_PT&)(*this)).Mult(SecretKey).x.bytesOut(PublicKey);
}

G& G::bytesIn(const uint8_t* pBytes)
{
    uint32_t i, j, k;
    x.bytesIn(pBytes);
    // Then needs to calculate y from x
    NN z(x);

    // z = x*x
    z = (z * x).reduce(gRR);
    // z = (x*x + a)
    if (z < uint32_t(3)) {
        z += gP256.p;
    }
    z -= 3;

    // z = (x*x+a)*x)
    z = (z * x).reduce(gRR);

    {
        NN d(gP256.p);
        d -= gP256.b;
        if (z >= d) z -= d;
        else z += gP256.b;
    }

    NN e(gP256.p);
    e += 1; e >>= 2;

    // Calculate z ^ (p+1)/4
    // Search for first set bit
    j = e.lead0();
    i = NN::N - (j >> 5) - 1; j &= 31;
    k = e.n_[i] << j;
    y = z;
    for (;;) {
        k <<= 1;
        if (++j >= 32) {
            j -= 32;
            if (i-- == 0) break;
            k = e.n_[i];
        }
        y = (y*y).reduce(gRR);
        if (k < 0x80000000) continue;
        y = (y*z).reduce(gRR);
    }

    return *this;
}

G& G::netIn(const uint8_t* pBytes, size_t cbLen)
{
    uint32_t i, j, k;
    x.netIn(pBytes);
    if (cbLen >= (NN::N * sizeof(uint32_t)*2)) {
        y.netIn(pBytes + (NN::N * sizeof(uint32_t)));
        return *this;
    }

    // Then needs to calculate y from x
    NN z(x);

    // z = x*x
    z = (z * x).reduce(gRR);
    // z = (x*x + a)
    if (z < uint32_t(3)) {
        z += gP256.p;
    }
    z -= 3;

    // z = (x*x+a)*x)
    z = (z * x).reduce(gRR);

    {
        NN d(gP256.p);
        d -= gP256.b;
        if (z >= d) z -= d;
        else z += gP256.b;
    }

    NN e(gP256.p);
    e += 1; e >>= 2;

    // Calculate z ^ (p+1)/4
    // Search for first set bit
    j = e.lead0();
    i = NN::N - (j >> 5) - 1; j &= 31;
    k = e.n_[i] << j;
    y = z;
    for (;;) {
        k <<= 1;
        if (++j >= 32) {
            j -= 32;
            if (i-- == 0) break;
            k = e.n_[i];
        }
        y = (y*y).reduce(gRR);
        if (k < 0x80000000) continue;
        y = (y*z).reduce(gRR);
    }

    return *this;
}

#if Test_Vectors

// From: http://point-at-infinity.org/ecc/nisttv

Curve: P256
    ------------ -
    k = 1
    x = 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    y = 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

    k = 2
    x = 7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978
    y = 07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1

    k = 3
    x = 5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C
    y = 8734640C4998FF7E374B06CE1A64A2ECD82AB036384FB83D9A79B127A27D5032

    k = 4
    x = E2534A3532D08FBBA02DDE659EE62BD0031FE2DB785596EF509302446B030852
    y = E0F1575A4C633CC719DFEE5FDA862D764EFC96C3F30EE0055C42C23F184ED8C6

    k = 5
    x = 51590B7A515140D2D784C85608668FDFEF8C82FD1F5BE52421554A0DC3D033ED
    y = E0C17DA8904A727D8AE1BF36BF8A79260D012F00D4D80888D1D0BB44FDA16DA4

    k = 6
    x = B01A172A76A4602C92D3242CB897DDE3024C740DEBB215B4C6B0AAE93C2291A9
    y = E85C10743237DAD56FEC0E2DFBA703791C00F7701C7E16BDFD7C48538FC77FE2

    k = 7
    x = 8E533B6FA0BF7B4625BB30667C01FB607EF9F8B8A80FEF5B300628703187B2A3
    y = 73EB1DBDE03318366D069F83A6F5900053C73633CB041B21C55E1A86C1F400B4

    k = 8
    x = 62D9779DBEE9B0534042742D3AB54CADC1D238980FCE97DBB4DD9DC1DB6FB393
    y = AD5ACCBD91E9D8244FF15D771167CEE0A2ED51F6BBE76A78DA540A6A0F09957E

    k = 9
    x = EA68D7B6FEDF0B71878938D51D71F8729E0ACB8C2C6DF8B3D79E8A4B90949EE0
    y = 2A2744C972C9FCE787014A964A8EA0C84D714FEAA4DE823FE85A224A4DD048FA

    k = 10
    x = CEF66D6B2A3A993E591214D1EA223FB545CA6C471C48306E4C36069404C5723F
    y = 878662A229AAAE906E123CDD9D3B4C10590DED29FE751EEECA34BBAA44AF0773

    k = 11
    x = 3ED113B7883B4C590638379DB0C21CDA16742ED0255048BF433391D374BC21D1
    y = 9099209ACCC4C8A224C843AFA4F4C68A090D04DA5E9889DAE2F8EEFCE82A3740

    k = 12
    x = 741DD5BDA817D95E4626537320E5D55179983028B2F82C99D500C5EE8624E3C4
    y = 0770B46A9C385FDC567383554887B1548EEB912C35BA5CA71995FF22CD4481D3

    k = 13
    x = 177C837AE0AC495A61805DF2D85EE2FC792E284B65EAD58A98E15D9D46072C01
    y = 63BB58CD4EBEA558A24091ADB40F4E7226EE14C3A1FB4DF39C43BBE2EFC7BFD8

    k = 14
    x = 54E77A001C3862B97A76647F4336DF3CF126ACBE7A069C5E5709277324D2920B
    y = F599F1BB29F4317542121F8C05A2E7C37171EA77735090081BA7C82F60D0B375

    k = 15
    x = F0454DC6971ABAE7ADFB378999888265AE03AF92DE3A0EF163668C63E59B9D5F
    y = B5B93EE3592E2D1F4E6594E51F9643E62A3B21CE75B5FA3F47E59CDE0D034F36

    k = 16
    x = 76A94D138A6B41858B821C629836315FCD28392EFF6CA038A5EB4787E1277C6E
    y = A985FE61341F260E6CB0A1B5E11E87208599A0040FC78BAA0E9DDD724B8C5110

    k = 17
    x = 47776904C0F1CC3A9C0984B66F75301A5FA68678F0D64AF8BA1ABCE34738A73E
    y = AA005EE6B5B957286231856577648E8381B2804428D5733F32F787FF71F1FCDC

    k = 18
    x = 1057E0AB5780F470DEFC9378D1C7C87437BB4C6F9EA55C63D936266DBD781FDA
    y = F6F1645A15CBE5DC9FA9B7DFD96EE5A7DCC11B5C5EF4F1F78D83B3393C6A45A2

    k = 19
    x = CB6D2861102C0C25CE39B7C17108C507782C452257884895C1FC7B74AB03ED83
    y = 58D7614B24D9EF515C35E7100D6D6CE4A496716E30FA3E03E39150752BCECDAA

    k = 20
    x = 83A01A9378395BAB9BCD6A0AD03CC56D56E6B19250465A94A234DC4C6B28DA9A

    y = 76E49B6DE2F73234AE6A5EB9D612B75C9F2202BB6923F54FF8240AAA86F640B8

    k = 112233445566778899
    x = 339150844EC15234807FE862A86BE77977DBFB3AE3D96F4C22795513AEAAB82F
    y = B1C14DDFDC8EC1B2583F51E85A5EB3A155840F2034730E9B5ADA38B674336A21

    k = 112233445566778899112233445566778899
    x = 1B7E046A076CC25E6D7FA5003F6729F665CC3241B5ADAB12B498CD32F2803264
    y = BFEA79BE2B666B073DB69A2A241ADAB0738FE9D2DD28B5604EB8C8CF097C457B

    k = 29852220098221261079183923314599206100666902414330245206392788703677545185283
    x = 9EACE8F4B071E677C5350B02F2BB2B384AAE89D58AA72CA97A170572E0FB222F
    y = 1BBDAEC2430B09B93F7CB08678636CE12EAAFD58390699B5FD2F6E1188FC2A78

    k = 57896042899961394862005778464643882389978449576758748073725983489954366354431
    x = 878F22CC6DB6048D2B767268F22FFAD8E56AB8E2DC615F7BD89F1E350500DD8D
    y = 714A5D7BB901C9C5853400D12341A892EF45D87FC553786756C4F0C9391D763E

    k = 1766845392945710151501889105729049882997660004824848915955419660366636031
    x = 659A379625AB122F2512B8DADA02C6348D53B54452DFF67AC7ACE4E8856295CA
    y = 49D81AB97B648464D0B4A288BD7818FAB41A16426E943527C4FED8736C53D0F6

    k = 28948025760307534517734791687894775804466072615242963443097661355606862201087
    x = CBCEAAA8A4DD44BBCE58E8DB7740A5510EC2CB7EA8DA8D8F036B3FB04CDA4DE4
    y = 4BD7AA301A80D7F59FD983FEDBE59BB7B2863FE46494935E3745B360E32332FA

    k = 113078210460870548944811695960290644973229224625838436424477095834645696384
    x = F0C4A0576154FF3A33A3460D42EAED806E854DFA37125221D37935124BA462A4
    y = 5B392FA964434D29EEC6C9DBC261CF116796864AA2FAADB984A2DF38D1AEF7A3

    k = 12078056106883488161242983286051341125085761470677906721917479268909056
    x = 5E6C8524B6369530B12C62D31EC53E0288173BD662BDF680B53A41ECBCAD00CC
    y = 447FE742C2BFEF4D0DB14B5B83A2682309B5618E0064A94804E9282179FE089F

#endif //Test_Vectors

