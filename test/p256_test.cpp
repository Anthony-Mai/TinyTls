/******************************************************************************
*
* Copyright © 2018-2019 Anthony Mai Mai_Anthony@hotmail.com. All Rights Reserved.
*
* This software is written by Anthony Mai who retains full copyright of this
* work. As such any Copyright Notices contained in this code. are NOT to be
* removed or modified. If this package is used in a product, Anthony Mai
* should be given attribution as the author of the parts of the library used.
* This can be in the form of a textual message at program startup or in
* documentation (online or textual) provided with the package.
*
* This library is free for commercial and non-commercial use, subject to
* following conditions, applicable to all code found in this distribution:
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
* The licence and distribution terms for any publically available version or derivative
* of this code cannot be changed.  i.e. this code cannot simply be copied and put under
* another distribution licence [including the GNU Public Licence.]
*
******************************************************************************/

/******************************************************************************
*
*  File Name:       p256_test.cpp
*
*  Description:     Integrity test code for implementation of Curve secp256r1.
*
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
#include <new>

#include "ecc_p256.h"

static const EccParam gP256{
    {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF},
    {0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF},
    {0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0, 0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8},
    {{0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81, 0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2},
    {0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357, 0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2}},
    {0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF}};

static const struct RR gRR {
    {0x00000003, 0x00000000, 0xffffffff, 0xfffffffe, 0xfffffffe, 0xfffffffe, 0xffffffff, 0x00000000},
    {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF}};

static const struct RR gRN {
    {0xeedf9bfe, 0x012ffd85, 0xdf1a6c21, 0x43190552, 0xffffffff, 0xfffffffe, 0xffffffff, 0x00000000},
    {0xfc632551, 0xf3b9cac2, 0xa7179e84, 0xbce6faad, 0xffffffff, 0xffffffff, 0x00000000, 0xffffffff}};

// Test vectors at: http://point-at-infinity.org/ecc/nisttv
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


int doubleTest()
{
    int err = 0;
    XY_PT g1(*(const XY_PT*)&gP256.g);

    XYZ_PT pt2(g1);
    XYZ_PT xyzPt(g1);

    static const NN sX2{
        0x47669978, 0xA60B48FC, 0x77F21B35, 0xC08969E2, 0x04B51AC3, 0x8A523803, 0x8D034F7E, 0x7CF27B18 };
    static const NN sY2{
        0x227873D1, 0x9E04B79D, 0x3CE98229, 0xBA7DADE6, 0x9F7430DB, 0x293D9AC6, 0xDB8ED040, 0x07775510 };

    xyzPt.Double();
    XY  r;
    xyzPt.Out(r);
    err += (r.x != sX2 || r.y != sY2);

    static const NN sX3{
        0xC6E7FD6C, 0xFB41661B, 0xEFADA985, 0xE6C6B721, 0x1D4BF165, 0xC8F7EF95, 0xA6330A44, 0x5ECBE4D1 };
    static const NN sY3{
        0xA27D5032, 0x9A79B127, 0x384FB83D, 0xD82AB036, 0x1A64A2EC, 0x374B06CE, 0x4998FF7E, 0x8734640C };

    xyzPt.Add(pt2);
    xyzPt.Out(r);
    err += (r.x != sX3 || r.y != sY3);

    XY  gOut;
    NN m(17);
    gOut = g1.Mult(m);
    return err;
}

int inverseTest()
{
    int err = 0;
    NN a0(1);
    NN b = a0.inverse(gRR);
    b.is1();
    NN a = 17;
    b = a.inverse(gRR);
    NN c = (a * b).reduce(gRR);
    err += !c.is1();

    a = 0x3FEF8927;
    b = a.inverse(gRR);
    c = (b * gRR.p).reduce(gRR);
    c.is1();
    c = (a * b).reduce(gRR);
    err += !c.is1();

    a = NN{0x6f7ea3ea, 0x976c80d0, 0xd662bd9c, 0x579c66ae, 0xf81f3c2c, 0x1dcfd694, 0xfc34ff36, 0x9fc685c4};
    b = a.inverse(gRR);
    c = (a * b).reduce(gRR);
    err += !c.is1();
    return err;
}

int tryTest()
{
    int err = 0;
    NN x(gP256.n);
    NN r = NN::reverse(x);
    int c = r.lead0();

    N2 mm(NN(137) * x);
    mm.n.N0 += 61;
    mm.reduce(gRN);
    err = (mm.n.N0.n_[0] == 61) ? 0 : 1;
    return err;
}


#ifdef WIN32
__declspec( naked ) uint64_t time_tick()
{
    _asm {
        rdtsc
        ret
    }
}
#else //WIN32
//Depend on the platform. Please implement a timer function
extern "C" {
extern uint64_t rd_clk();
}

#define time_tick rd_clk

#endif //WIN32

uint32_t myRand()
{
    static uint32_t seed1 = 0x12345679, seed2 = 0xfdc7b391;
    seed2 += uint32_t(time_tick()) + seed1;
    seed1 ^= (seed2 + (seed1 >> 5)) * 1001;
    return seed1;
}

void P256_getNounce(NN& nounce)
{
    do {
        for (uint32_t i = 0; i < NN::N; i++) {
            nounce.n_[i] ^= myRand();
        }
        while (nounce >= gRN.p) nounce -= gRN.p;
    } while (nounce.is0());
}

void P256_CreateKeyPair(ECDKeyPair& keyPair)
{
    keyPair.Create(myRand);
}

typedef uint8_t uchar;
typedef uint32_t uint;
#include "sha256.h"

int SignTest()
{
    ECDKeyPair keyPair;
    NN nounce;
    NN digest;
    NN digest2;
    const char theSecretMessage[] = "Amy and Bob's Secret Message.";

    P256_CreateKeyPair(keyPair);

    // Sign Digest. First generate message digest using SHA256.
    Sha256Hash((const uchar*)theSecretMessage, sizeof(theSecretMessage), (uchar*)&digest);
    digest.reduce(gP256.p);
    digest2 = digest;
    // Important! Must supply unique nounce each time.
    P256_getNounce(nounce);

    ECDSign sig;  // Use this struct to sign signature.
    sig.Sign((const uint8_t*)&digest, (const uint8_t*)&nounce, keyPair.priKey);

    // Test to find out if the signature is authentic.
    return sig.Test((const uint8_t*)&digest2, keyPair.pubKey) ? 0 : 1;
}

// Diffie Hellman key exchange test.
int dhTest()
{
    ECDKeyPair AmyKeyPair;
    ECDKeyPair BobKeyPair;

    P256_CreateKeyPair(AmyKeyPair);
    P256_CreateKeyPair(BobKeyPair);

    // Amy and Bob will exchange each other's public key
    const XY_PT AmyPubKey(*(const XY_PT*)&AmyKeyPair.pubKey);
    const XY_PT BobPubKey(*(const XY_PT*)&BobKeyPair.pubKey);

    // Amy will generate a secret key for Bob.
    ECDKeyPair randKey;
    P256_getNounce(randKey.priKey);
    randKey.Generate(randKey.priKey);

    XY_PT R(*(const XY_PT*)&randKey.pubKey); //To be given to Bob
    XY_PT AmySecret = BobPubKey.Mult(randKey.priKey);

    // Bob receives R and he can create the secret, too
    const NN BobPriKey(BobKeyPair.priKey);
    XY  BobSecret = R.Mult(BobPriKey);

    // Now AmySecret and BobSecret should be the same. Each of them
    // can then use the shared secret to generate a symmetric key.
    return (AmySecret == BobSecret) ? 0 : 1;
}

int yTest()
{
    int ret = 0;
    uchar a[256];
    uchar b[256];
    uchar x[256];
    uchar s1[256];
    uchar s2[256];

    ECDKeyPair AmyKeyPair;
    ECDKeyPair BobKeyPair;

    P256_CreateKeyPair(AmyKeyPair);
    P256_CreateKeyPair(BobKeyPair);

    AmyKeyPair.priKey.bytesOut(a);
    BobKeyPair.priKey.bytesOut(b);

    P256::G gBase;

    NN secKey, pubKey;
    secKey.bytesIn(a);

    gBase.PointMult(x, secKey);
    pubKey.bytesIn(x);

    ret = (pubKey == AmyKeyPair.pubKey.x) ? 0 : 1;

    gBase.bytesIn(x);
    gBase.PointMult(s1, BobKeyPair.priKey);

    new(&gBase) P256::G;

    gBase.PointMult(x, BobKeyPair.priKey);
    gBase.bytesIn(x);
    gBase.PointMult(s2, AmyKeyPair.priKey);

    ret |= memcmp(s1, s1, 256);

    return 0;
}

static const uchar gServerKE[] = {
    0x0C, 0x00, 0x00, 0x6F, 0x03, 0x00, 0x1D, 0x20, 0x6C, 0x4B, 0x5B, 0xDC, 0x0D, 0x95, 0x5D, 0x5E,
    0x9E, 0xDC, 0xBC, 0x69, 0xBB, 0x0D, 0x6B, 0x2B, 0x30, 0x47, 0x51, 0x6B, 0x5C, 0x99, 0x9A, 0x01,
    0x4D, 0x17, 0x53, 0xE4, 0xDA, 0x98, 0x6D, 0x5D, 0x04, 0x03, 0x00, 0x47, 0x30, 0x45, 0x02, 0x20,
    0x2A, 0xF2, 0xCE, 0x04, 0xFD, 0x89, 0xB3, 0x55, 0x07, 0xBF, 0x34, 0xDB, 0xAF, 0xE9, 0x68, 0xDD,
    0x95, 0x65, 0x06, 0xBA, 0x30, 0x1B, 0x96, 0x0B, 0x11, 0xBE, 0xEE, 0x49, 0x86, 0xA1, 0xBF, 0x5C,
    0x02, 0x21, 0x00, 0x83, 0xC6, 0x51, 0x42, 0xEA, 0xC3, 0x4F, 0x68, 0xEC, 0x5C, 0x4D, 0x1F, 0xFA,
    0xC7, 0x9E, 0xFA, 0xFD, 0x22, 0x9D, 0xB4, 0x17, 0xED, 0xB9, 0x47, 0xE1, 0xAE, 0xC3, 0x56, 0xDB,
    0xFD, 0x0D, 0xC1
};

static const uchar cRandom[] = {
    0xbf, 0xfd, 0x43, 0xb8, 0x7c, 0x38, 0x2d, 0x9a, 0xaa, 0x3d, 0xb3, 0x30, 0x62, 0x64, 0x29, 0x9b,
    0x2a, 0x09, 0xbb, 0xdb, 0xe2, 0xf6, 0x17, 0x25, 0x47, 0xba, 0xa4, 0xad, 0xa2, 0x76, 0xdf, 0xed
};

static const uchar sRandom[] = {
    0x5c, 0x64, 0xd8, 0x18, 0x6d, 0xe4, 0x63, 0x5c, 0x27, 0x90, 0x8b, 0x42, 0x96, 0xdf, 0x52, 0x8b,
    0xfc, 0xcc, 0x16, 0x13, 0x2b, 0xf6, 0x6f, 0xa9, 0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01
};

static const uchar gCertPub[] = {
    0xce, 0xd7, 0x61, 0x49, 0x49, 0xfd, 0x4b, 0x35, 0x8b, 0x1b, 0x86, 0xbc, 0xa3, 0xc5, 0xbc, 0xd8,
    0x20, 0x6e, 0x31, 0x17, 0x2d, 0x92, 0x8a, 0xb7, 0x34, 0xf4, 0xdb, 0x11, 0x70, 0x4e, 0x49, 0x16,
    0x61, 0xfc, 0xae, 0xfa, 0x7f, 0xba, 0x6f, 0x0c, 0x05, 0x53, 0x74, 0xc6, 0x79, 0x7f, 0x81, 0x12,
    0x8a, 0xf7, 0xe2, 0x5e, 0x6c, 0xf5, 0xfa, 0x10, 0x69, 0x6b, 0x67, 0xd9, 0xd5, 0x96, 0x51, 0xb0
};

int realTest()
{
    uchar msg[32];
    NN digest;

    SHA256 sha;

    Sha256Init(&sha, NULL);
    Sha256Input(&sha, cRandom, sizeof(cRandom));
    Sha256Input(&sha, sRandom, sizeof(sRandom));
    Sha256Input(&sha, gServerKE+4, 0x24);
    Sha256Digest(&sha, msg);

    digest.netIn(msg);
    digest.reduce(gP256.p);

    ECDSign sig;

    // Test to find out if the signature is authentic.
    P256::G gBase;
    gBase.netIn(gCertPub);

    NN y = gP256.p - gBase.y;

    sig.r.netIn(gServerKE + 48);
    sig.s.netIn(gServerKE + 83);
    bool success = sig.Test(msg, gBase);
    return 0;
}

int p256_test()
{
    int err = 0;

    err += realTest();
    err += yTest();
    err += tryTest();
    err += SignTest();
    err += dhTest();

    NN r = NN::reverse(gP256.p);
    NN r2 = NN(0) - gP256.p;
    NN dd = r - r2;
    N2 d = r * gP256.p;
    d.n.N1 += gP256.p;

    N2 x = gP256.n * gP256.p;
    x.n.N0 += 3;

    x.reduce(gRR);

    err += (x.n.N0 != NN(3));

    err += inverseTest();
    err += doubleTest();

    return err;
}

