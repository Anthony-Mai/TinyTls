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
*  File Name:       aes_test.cpp
*
*  Description:     Integrity test for AES-128-GCM implementation.
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         10/18/2018 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <new>

#include "aes128.h"
#include "aes_test.h"

#include <stdio.h>

int gcm_test();

int aes_test()
{
    int ret = 0, i;

    printf("Do GCM test\n");

    gcm_test();

    static const AesText oText{ 0x1d842539, 0xfb09dc02, 0x978511dc, 0x320b6a19 };

    printf("Main AES test\n");

    AesText mText{ 0xa8f64332, 0x8d305a88, 0xa2983131, 0x340737e0 };
    AesKey myKey{0x16157e2b, 0xa6d2ae28, 0x8815f7ab, 0x3c4fcf09};

    AesCtx ctx(myKey);
    AesText mText2(mText);

    ctx(mText2);

    AesCtx c2;

    new (&c2) AesCtx(myKey);

    if (mText2 == oText) {
        ret |= 0;
    }  else {
        ret |= -1;
    }

    AesKey roundKey(myKey);

    // Initial round.
    mText.AddRound(roundKey);
    //AesText mText{ 0xbee33d19, 0x2be2f4a0, 0x2a8dc69a, 0x0848f8e9 };

    // 9 main rounds
    for (i = 0; i++ < 9;) {
        mText.SubBytes();
        mText.ShiftRows();
        mText.MixColumns();
        aes_NewRound(roundKey, i);
        mText.AddRound(roundKey);
    }

    // Final round. No MixColumns.
    mText.SubBytes();
    mText.ShiftRows();
    //mText.MixColumns();
    aes_NewRound(roundKey, i);
    mText.AddRound(roundKey);

    // We now have the final outoput in mText.
    //static const AesText oText{ 0x1d842539, 0xfb09dc02, 0x978511dc, 0x320b6a19 };

    if (mText == oText) {
        ret |= 0; // Correct
    }
    else {
        ret |= -1; // Incorrect
    }

    return ret;
}

// https://tools.ietf.org/html/rfc7714
int gcm_test1()
{
    int ret = 0;

    const uint8_t key[16] = { 0xc3, 0xac, 0x02, 0x01, 0xe2, 0xfe, 0x6c, 0xa7, 0x72, 0xa6, 0x89, 0xdb, 0x38, 0x97, 0x59, 0x23 };
    const uint8_t iv[16] = { 0x14, 0xfa, 0x87, 0x3d, 0x02, 0xa0, 0xf5, 0xc5, 0x79, 0xb0, 0x79, 0x0a, 0x00, 0x00, 0x00, 0x02 };
    const uint8_t in[16] = { 0x14, 0x00, 0x00, 0x0c, 0x0a, 0xc4, 0x20, 0x5d, 0x14, 0x51, 0xfe, 0x52, 0x08, 0xcc, 0xe4, 0x76 };
    const uint8_t out[16] = { 0x43, 0xc0, 0xda, 0x60, 0x0d, 0xbf, 0x52, 0x19, 0xe7, 0x70, 0xc1, 0x3f, 0xb1, 0x94, 0x58, 0x74 };

    AesKey myKey{ 0x23599738, 0xdb89a672, 0xa76cfee2, 0x0102acc3 };
    AesText myIV{ 0x02000000, 0x0a79b079, 0xc5f5a002, 0x3d87fa14 };
    AesText myText{ 0x76e4cc08, 0x52fe5114, 0x5d20c40a, 0x0c000014 };
    AesText myOut{ 0x745894b1, 0x3fc170e7, 0x1952bf0d, 0x60dac043 };

    myKey.set(key);
    myIV.set(iv);
    myText.set(in);
    myOut.set(out);

    AesCtx ctx(myKey);

    AesText myCB = myIV;

    ctx(myCB);
    myCB.Enc(myText);

    if (myText == myOut) {
        ret |= 0;
    } else {
        ret |= -1;
    }

    // Test https://tools.ietf.org/html/rfc7714 16.1.1
    const uint8_t key1[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const uint8_t iv1[16] = { 0x51, 0x75, 0x3c, 0x65, 0x80, 0xc2, 0x72, 0x6f, 0x20, 0x71, 0x84, 0x14, 0x00, 0x00, 0x00, 0x02 };
    const uint8_t txt1[16] = { 0x47, 0x61, 0x6c, 0x6c, 0x69, 0x61, 0x20, 0x65, 0x73, 0x74, 0x20, 0x6f, 0x6d, 0x6e, 0x69, 0x73 };
    const uint8_t cxt1[16] = { 0xf2, 0x4d, 0xe3, 0xa3, 0xfb, 0x34, 0xde, 0x6c, 0xac, 0xba, 0x86, 0x1c, 0x9d, 0x7e, 0x4b, 0xca };

    const uint8_t h_exp[16] = { 0xc6, 0xa1, 0x3b, 0x37, 0x87, 0x8f, 0x5b, 0x82, 0x6f, 0x4f, 0x81, 0x62, 0xa1, 0xc8, 0xd8, 0x79 };

    AesText H{ 0,0,0,0 };
    AesText hExp; hExp.set(h_exp);

    myKey.set(key1);
    AesCtx myCtx(myKey);

    myIV.set(iv1);
    myIV.text[3].b[3] = 0x01;
    myCB = myIV;
    myCtx(H);

    if (H == hExp) {
        ret |= 0;
    } else {
        ret |= -1;
    }

    myKey.set(key1);
    myIV.set(iv1);
    myText.set(txt1);
    myOut.set(cxt1);

    //AesCtx myCtx(myKey);
    myCB = myIV;
    myCtx(myCB);
    myCB.Enc(myText);

    if (myText == myOut) {
        ret |= 0;
    } else {
        ret |= -1;
    }

    //AesText cb{1, 0x20718414, 0x80c2726f, 0x51753c65 };
    AesText cb{ 1, 0xb2c28465, 0xc0895e81, 0x12153524 };
    H = AesText{ 0,0,0,0 };

    AesText cbt(cb);
    ctx(cbt);
    cbt.Enc(H);

    cbt = cb.inc();
    ctx(cbt);
    AesText pb1{ 0x6d6e6973, 0x7374206f, 0x69612065, 0x47616c6c };
    cbt.Enc(pb1);

    ret = 0;
    return ret;
}

int gcm_test0()
{
    const uint8_t k[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    const uint8_t iv[12] = {0,0,0,0,0,0,0,0,0,0,0,0};
    const uint8_t h[16] = { 0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e };
    const uint8_t y0[16] = { 0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a };

    int ret = 0;

    AesKey myKey; myKey.set(k);
    AesCtx ctx(myKey);
    AesText H{ 0,0,0,0 };
    AesText cBlock{ 0,0,0,0x01000000 };
    AesText Y0(cBlock);

    ctx(H);
    if (!(H == *(AesText*)h)) ret |= -1;
    ctx(Y0);
    if (!(Y0 == *(AesText*)y0)) ret |= -1;

    return ret;
}

void HMult(AesText& r, const AesText h, const AesText x)
{
    u128 z{ 0llu, 0llu};
    u128 v; v.netIn(h.text[0].b);
    for (int j = 0; j < sizeof(x); j++) {
        uint8_t b = x.text[0].b[j];
        for (int i = 8; i-- > 0; b<<=1) {
            uint64_t d = uint64_t(0) - (b >> 7);
            z.d[1] ^= d & v.d[1];
            z.d[0] ^= d & v.d[0];
            v.shiftR();
        }
    }
    z.netOut(r.text[0].b);
}

int ghash_test()
{
    int ret = 0;
    const uint8_t iv[16]{ 0x51, 0x75, 0x3c, 0x65, 0x80, 0xc2, 0x72, 0x6f, 0x20, 0x71, 0x84, 0x14, 0x00, 0x00, 0x00, 0x01 };
    const uint8_t k[16]{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const uint8_t k0[16]{ 0x92, 0x0b, 0x3f, 0x40, 0xb9, 0x3d, 0x2a, 0x1d, 0x1c, 0x8b, 0x5c, 0xd1, 0xe5, 0x67, 0x5e, 0xaa };
    const uint8_t k1[16]{ 0xb5, 0x2c, 0x8f, 0xcf, 0x92, 0x55, 0xfe, 0x09, 0xdf, 0xce, 0xa6, 0x73, 0xf0, 0x10, 0x22, 0xb9 };
    const uint8_t h[16]{ 0xc6, 0xa1, 0x3b, 0x37, 0x87, 0x8f, 0x5b, 0x82, 0x6f, 0x4f, 0x81, 0x62, 0xa1, 0xc8, 0xd8, 0x79 };
    const uint8_t aa[16]{ 0x80, 0x40, 0xf1, 0x7b, 0x80, 0x41, 0xf8, 0xd3, 0x55, 0x01, 0xa0, 0xb2, 0x00, 0x00, 0x00, 0x00 };
    const uint8_t h1[16]{ 0xbc, 0xfb, 0x3d, 0x1d, 0x0e, 0x6e, 0x3e, 0x78, 0xba, 0x45, 0x40, 0x33, 0x77, 0xdb, 0xa1, 0x1b };
    const uint8_t p1[16]{ 0x47, 0x61, 0x6c, 0x6c, 0x69, 0x61, 0x20, 0x65, 0x73, 0x74, 0x20, 0x6f, 0x6d, 0x6e, 0x69, 0x73 };
    const uint8_t c1[16]{ 0xf2, 0x4d, 0xe3, 0xa3, 0xfb, 0x34, 0xde, 0x6c, 0xac, 0xba, 0x86, 0x1c, 0x9d, 0x7e, 0x4b, 0xca };
    const uint8_t h2[16]{ 0x0e, 0xbc, 0x0a, 0xbe, 0x1b, 0x15, 0xb3, 0x2f, 0xed, 0xd2, 0xb0, 0x78, 0x88, 0xc1, 0xef, 0x61 };
    const uint8_t c2[16]{ 0xbe, 0x63, 0x3b, 0xd5, 0x0d, 0x29, 0x4e, 0x6f, 0x42, 0xa5, 0xf4, 0x7a, 0x51, 0xc7, 0xd1, 0x9b };
    const uint8_t h3[16]{ 0x43, 0x8e, 0x57, 0x97, 0x01, 0x1e, 0xa8, 0x60, 0x58, 0x57, 0x09, 0xa2, 0x89, 0x9f, 0x46, 0x85 };
    const uint8_t c3[16]{ 0x36, 0xde, 0x3a, 0xdf, 0x88, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const uint8_t h4[16]{ 0x33, 0x6f, 0xb6, 0x43, 0x31, 0x0d, 0x7b, 0xac, 0x2a, 0xea, 0xa7, 0x62, 0x47, 0xf6, 0x03, 0x6d };

    const uint8_t cl[16]{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x30 };
    const uint8_t hf[16]{ 0x1b, 0x96, 0x40, 0x67, 0x07, 0x8c, 0x40, 0x8c, 0x4e, 0x44, 0x2a, 0x8f, 0x01, 0x5e, 0x52, 0x64 };
    const uint8_t tg[16]{ 0x89, 0x9d, 0x7f, 0x27, 0xbe, 0xb1, 0x6a, 0x91, 0x52, 0xcf, 0x76, 0x5e, 0xe4, 0x39, 0x0c, 0xce };


    AesKey key; key.set(k);
    AesText H{ 0,0,0,0 };
    AesText ctr; ctr.set(iv);
    AesText kb0(ctr), kb;
    AesCtx ctx(key);
    ctx(H);
    ret |= (H == *(const AesText*)h) ? 0 : -1;
    u128 HKey; HKey.netIn(H.text[0].b);

    ctx(kb0);
    ret |= (kb0 == *(const AesText*)k0) ? 0 : -1;

    //Process the AAD
    //    AAD word : 8040f17b8041f8d35501a0b200000000
    //    partial hash : bcfb3d1d0e6e3e78ba45403377dba11b

    AesText r, t;
    //HMult(r, H, *(const AesText*)aa);
    r.set(aa); HKey.pmult(r);
    //HMult(r, H, *(const AesText*)aa);
    ret |= (r == *(const AesText*)h1) ? 0 : -1;

    //kb = ctr.inc();
    ctx(kb = ctr.inc());
    ret |= (kb == *(const AesText*)k1) ? 0 : -1;

    t.set(p1); kb.Enc(t);
    ret |= (t == *(const AesText*)c1) ? 0 : -1;

    t.Enc(r);
    HKey.pmult(r); //HMult(r, H, r);
    ret |= (r == *(const AesText*)h2) ? 0 : -1;

    ((AesText*)c2)->Enc(r);
    HKey.pmult(r); // HMult(r, H, r);
    ret |= (r == *(const AesText*)h3) ? 0 : -1;

    ((AesText*)c3)->Enc(r);
    HKey.pmult(r); // HMult(r, H, r);
    ret |= (r == *(const AesText*)h4) ? 0 : -1;

    ((AesText*)cl)->Enc(r);
    HKey.pmult(r); //HMult(r, H, r);
    ret |= (r == *(const AesText*)hf) ? 0 : -1;

    kb0.Enc(r);
    ret |= (r == *(const AesText*)tg) ? 0 : -1;

    return ret;
}

int ghash_exp()
{
    int ret = 0;
    const uint8_t iv[16]{ 0x51, 0x75, 0x3c, 0x65, 0x80, 0xc2, 0x72, 0x6f, 0x20, 0x71, 0x84, 0x14, 0x00, 0x00, 0x00, 0x01 };

    AesKey key;
    AesText H{ 0,0,0,0 };
    AesCtx ctx(key);
    ctx(H);

    u128 hKey; hKey.netIn(H.text[0].b);

    AesText t1{0x80000000, 0, 0, 0};
    AesText t2{ 0x08000000, 0, 0, 0 };
    AesText t3{ 0xF0000000, 0, 0, 0 };

    hKey.pmult(t1);
    hKey.pmult(t2);
    hKey.pmult(t3);

    u128 z, t; t.netIn(t1.text[0].b);
    z = t;
    t.shiftR(); z ^= t;
    t.shiftR(); z ^= t;
    t.shiftR(); z ^= t;
    t.shiftR();

    t.netOut(t1.text[0].b);
    ret |= (t1 == t2) ? 0 : -1;

    z.netOut(t1.text[0].b);
    ret |= (t1 == t3) ? 0 : -1;

    HKey myH(H);
    t1.set(iv);
    myH.pmult(t1);
    t2.set(iv);
    hKey.pmult(t2);
    ret |= (t1 == t2) ? 0 : -1;

    return ret;
}

int enc_test()
{
    int ret = 0;
    uint8_t iv[12] =  { 0x51, 0x75, 0x3c, 0x65, 0x80, 0xc2, 0x72, 0x6f, 0x20, 0x71, 0x84, 0x14 };
    uint8_t aad[12] = { 0x80, 0x40, 0xf1, 0x7b, 0x80, 0x41, 0xf8, 0xd3, 0x55, 0x01, 0xa0, 0xb2 };
    uint8_t key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t ptxt[38] = {
        0x47, 0x61, 0x6c, 0x6c, 0x69, 0x61, 0x20, 0x65, 0x73, 0x74, 0x20, 0x6f, 0x6d, 0x6e, 0x69, 0x73,
        0x20, 0x64, 0x69, 0x76, 0x69, 0x73, 0x61, 0x20, 0x69, 0x6e, 0x20, 0x70, 0x61, 0x72, 0x74, 0x65,
        0x73, 0x20, 0x74, 0x72, 0x65, 0x73 };
    const uint8_t ctxt[38]{
        0xf2, 0x4d, 0xe3, 0xa3, 0xfb, 0x34, 0xde, 0x6c, 0xac, 0xba, 0x86, 0x1c, 0x9d, 0x7e, 0x4b, 0xca,
        0xbe, 0x63, 0x3b, 0xd5, 0x0d, 0x29, 0x4e, 0x6f, 0x42, 0xa5, 0xf4, 0x7a, 0x51, 0xc7, 0xd1, 0x9b,
        0x36, 0xde, 0x3a, 0xdf, 0x88, 0x33 };
    const uint8_t ctag[16]{ 0x89, 0x9d, 0x7f, 0x27, 0xbe, 0xb1, 0x6a, 0x91, 0x52, 0xcf, 0x76, 0x5e, 0xe4, 0x39, 0x0c, 0xce };

    uint8_t ivExp[8];
    uint8_t stxt[38];
    uint8_t stag[16];
    memcpy(stxt, ptxt, sizeof(ptxt));

    Aes128Gcm cipher(key, iv);
    int r = 0, i=0;
    r = cipher.Encrypt(stxt, sizeof(ctxt), ivExp, stag, aad, 12);
    ret |= memcmp(ivExp, iv + 4, 8);
    ret |= memcmp(stxt, ctxt, sizeof(ctxt));
    ret |= memcmp(stag, ctag, sizeof(ctag));
    return ret;
}

// More test cases at: // https://pdfs.semanticscholar.org/114a/4222c53f1a6879f1a77f1bae2fc0f8f55348.pdf
int gcm_test()
{
    int ret = 0;

    ret |= enc_test();
    ret |= ghash_exp();
    ret |= ghash_test();
    ret |= gcm_test0();
    ret |= gcm_test1();
    return ret;
}

