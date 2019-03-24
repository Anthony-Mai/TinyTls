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
*  File Name:       ecc_test.cpp
*
*  Description:     Integrity test code for Elliptic Curve Cryptography library.
*
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         10/18/2018 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <new>

#include "ecc_x25519.h"
#include "ecc_sign.h"
#include "ecc_verify.h"
#include "base_type.h"
#include "ssl_defs.h"
#include "sha512.h"
#include "cipher.h"

#include "p256_test.h"

using X25519::G;

int SubReduceTest()
{
    NN y(0x9715bf86, 0x6a6600e0, 0x3ce4c8da, 0xe6e9f57f, 0x9429568f, 0xf127b6d7, 0x9761adf5, 0x5d66373f);
    NN x(0x9f026a88, 0xef60aac3, 0x788b32c2, 0xc452e263, 0x9eaf4281, 0xc57630c2, 0x66274c37, 0x9899945c);
    NN r(0xf81354d8, 0x7b05561c, 0xc4599617, 0x2297131b, 0xf57a140e, 0x2bb18614, 0x313a61be, 0xc4cca2e3);
    x.reduce();
    y.reduce();
    r.reduce();

    NN rr;
    if (y >= x) rr = y - x;
    else rr = y + (NN::P_ - x);

    if (rr == r) {
        printf("Result CORRECT!\n");
        return 0;
    } else {
        printf("Result WRONG!\n");
        return -1;
    }
}

typedef uint8_t U8;
typedef uint32_t U32;

void ecp_PrintHexBytes(const char *name, const U8 *data, U32 size)
{
    printf("%s = 0x", name);
    while (size > 0) printf("%02X", data[--size]);
    printf("\n");
}

void ecp_PrintBytes(const char *name, const U8 *data, U32 size)
{
    U32 i;
    printf("\nstatic const unsigned char %s[%d] =\n  { 0x%02X", name, size, *data++);
    for (i = 1; i < size; i++) {
        if ((i & 15) == 0)
            printf(",\n    0x%02X", *data++);
        else
            printf(",0x%02X", *data++);
    }
    printf(" };\n");
}

// check if y^2 == x^3 + 486662x^2 + x  mod 2^255 - 19
bool ecp_IsOnCurve(const NN& X, const NN& Y)
{
    NN A(486662);

    (A += X).reduce();  // x + 486662
    A = A ^ X;          // x^2 + 486662*x
    A = A ^ X;          // x^3 + 486662x^2
    (A += X).reduce();  // x^3 + 486662x^2 + x

    NN B(Y ^ Y);

    if (B == A) return true;

    // check if sqrt(-1) was applied incorrectly
    B = NN::P_ - B;

    return (B == A);
}

static const U8 sha512_abc[] = {    /* 'abc' */
    0xDD,0xAF,0x35,0xA1,0x93,0x61,0x7A,0xBA,0xCC,0x41,0x73,0x49,0xAE,0x20,0x41,0x31,
    0x12,0xE6,0xFA,0x4E,0x89,0xA9,0x7E,0xA2,0x0A,0x9E,0xEE,0xE6,0x4B,0x55,0xD3,0x9A,
    0x21,0x92,0x99,0x2A,0x27,0x4F,0xC1,0xA8,0x36,0xBA,0x3C,0x23,0xA3,0xFE,0xEB,0xBD,
    0x45,0x4D,0x44,0x23,0x64,0x3C,0xE8,0x0E,0x2A,0x9A,0xC9,0x4F,0xA5,0x4C,0xA4,0x9F };

static const U8 sha512_ax1m[] = {   /* 'a' repeated 1,000,000 times */
    0xE7,0x18,0x48,0x3D,0x0C,0xE7,0x69,0x64,0x4E,0x2E,0x42,0xC7,0xBC,0x15,0xB4,0x63,
    0x8E,0x1F,0x98,0xB1,0x3B,0x20,0x44,0x28,0x56,0x32,0xA8,0x03,0xAF,0xA9,0x73,0xEB,
    0xDE,0x0F,0xF2,0x44,0x87,0x7E,0xA6,0x0A,0x4C,0xB0,0x43,0x2C,0xE5,0x77,0xC3,0x1B,
    0xEB,0x00,0x9C,0x5C,0x2C,0x49,0xAA,0x2E,0x4E,0xAD,0xB2,0x17,0xAD,0x8C,0xC0,0x9B };

int hash_test(int level) {
    int i, rc = 0;
    SHA512 sha;
    U8 buff[100], md[SHA512_SIZE];

    /* [a:b] = H(sk) */
    Sha512Init(&sha, Sha512Cd());
    Sha512Input(&sha, (const uint8_t*)"abc", 3);
    Sha512Digest(&sha, md);
    if (memcmp(md, sha512_abc, SHA512_SIZE) != 0) {
        rc++;
        printf("KAT: SHA512('abc') FAILED!!\n");
        ecp_PrintHexBytes("H_1", md, SHA512_SIZE);
    }

    Sha512Init(&sha, Sha512Cd());
    memset(buff, 'a', 100);
    for (i = 0; i < 10000; i++) Sha512Input(&sha, buff, 100);
    Sha512Digest(&sha, md);
    if (memcmp(md, sha512_ax1m, SHA512_SIZE) != 0) {
        rc++;
        printf("KAT: SHA512('a'*1000000) FAILED!!\n");
        ecp_PrintHexBytes("H_2", md, SHA512_SIZE);
    }
    return rc;
}

void ecp_PrintHexWords(const char* name, const NN& data)
{
    printf("%s = 0x", name);
    for (uint32_t size = NN::N; size-- > 0; ) printf("%08X", data.n_[size]);
    printf("\n");
}

static const NN w_I{ 0x4a0ea0b0, 0xc4ee1b27, 0xad2fe478, 0x2f431806, 0x3dfbd7a7, 0x2b4d0099, 0x4fc1df0b, 0x2b832480 }; // Sqrt(-1)
static const NN w_D{ 0x135978A3, 0x75EB4DCA, 0x4141D8AB, 0x00700A4D, 0x7779E898, 0x8CC74079, 0x2B6FFE73, 0x52036CEE };
static const NN w_IxD{ 0x9e451edd, 0x71c41b45, 0x7fbcc19e, 0x49800849, 0xbbcb7c34, 0xf4c5ce99, 0xb32c1ab4, 0x024aee07 };

static const U8 _b_Om1[32] = {      /* O-1 */
    0xEC,0xD3,0xF5,0x5C,0x1A,0x63,0x12,0x58,0xD6,0x9C,0xF7,0xA2,0xDE,0xF9,0xDE,0x14,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10 };

// (P + 3)/8
static const NN gPp3d8{
    0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0x0fffffff};


/* R = 2**256 mod BPO */
/* R = 0x0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC6EF5BF4737DCF70D6EC31748D98951D */
static const NN _w_R{ 0x8D98951D, 0xD6EC3174, 0x737DCF70, 0xC6EF5BF4,
    0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0x0FFFFFFF }; /* R mod BPO */

/* R2 = R**2 mod BPO */
/* R2 = 0x0399411B7C309A3DCEEC73D217F5BE65D00E1BA768859347A40611E3449C0F01 */
static const NN _w_R2{ 0x449C0F01, 0xA40611E3, 0x68859347, 0xD00E1BA7,
    0x17F5BE65, 0xCEEC73D2, 0x7C309A3D, 0x0399411B }; /* R**2 mod BPO */

static const NN _w_IxDmodBPO{ 0xFDC0315D, 0x598EF460, 0xE11649F4, 0x2DEBEE7C,
    0x0278EFB4, 0x331877FE, 0xFBE03ECE, 0x00A63CC5 }; // I*D mod BPO


/*
This library provides support for mod BPO (Base Point Order) operations

BPO = 2**252 + 27742317777372353535851937790883648493
BPO = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED

If you keep adding points together, the result repeats every BPO times.
Based on this, you may use:

public_key = (private_key mod BPO)*BasePoint
Split key example:
k1 = random()
k2 = 1/k1 mod BPO   --> k1*k2 = 1 mod BPO
P1 = k1*P0 --> P2 = k2*P1 = k2*k1*P0 = P0
See selftest code for some examples of BPO usage

This library is used for implementation of EdDSA sign/verify.
*/

const NN g_NxBPO[16] = {  /* n*BPO */
    {0,0,0,0,0,0,0,0},
    {0x5CF5D3ED,0x5812631A,0xA2F79CD6,0x14DEF9DE,0,0,0,0x10000000},
    {0xB9EBA7DA,0xB024C634,0x45EF39AC,0x29BDF3BD,0,0,0,0x20000000},
    {0x16E17BC7,0x0837294F,0xE8E6D683,0x3E9CED9B,0,0,0,0x30000000},
    {0x73D74FB4,0x60498C69,0x8BDE7359,0x537BE77A,0,0,0,0x40000000},
    {0xD0CD23A1,0xB85BEF83,0x2ED6102F,0x685AE159,0,0,0,0x50000000},
    {0x2DC2F78E,0x106E529E,0xD1CDAD06,0x7D39DB37,0,0,0,0x60000000},
    {0x8AB8CB7B,0x6880B5B8,0x74C549DC,0x9218D516,0,0,0,0x70000000},
    {0xE7AE9F68,0xC09318D2,0x17BCE6B2,0xA6F7CEF5,0,0,0,0x80000000},
    {0x44A47355,0x18A57BED,0xBAB48389,0xBBD6C8D3,0,0,0,0x90000000},
    {0xA19A4742,0x70B7DF07,0x5DAC205F,0xD0B5C2B2,0,0,0,0xA0000000},
    {0xFE901B2F,0xC8CA4221,0x00A3BD35,0xE594BC91,0,0,0,0xB0000000},
    {0x5B85EF1C,0x20DCA53C,0xA39B5A0C,0xFA73B66F,0,0,0,0xC0000000},
    {0xB87BC309,0x78EF0856,0x4692F6E2,0x0F52B04E,1,0,0,0xD0000000},
    {0x157196F6,0xD1016B71,0xE98A93B8,0x2431AA2C,1,0,0,0xE0000000},
    {0x72676AE3,0x2913CE8B,0x8C82308F,0x3910A40B,1,0,0,0xF0000000}
};


static const U8 _b_Pm1d2[32] = {    /* (p-1)/d */
    0xF6,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x3F };

static const NN _w_Pm1{ 0xFFFFFFEC, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF };

static const NN _w_Gy{ 0x7ECED3D9, 0x29E9C5A2, 0x6D7C61B2, 0x923D4D7E, 0x7748D14C, 0xE01EDD2C, 0xB8A086B4, 0x20AE19A1 };

static const U8 _b_O[32] = {        /* O    order of the base point */
    0xED,0xD3,0xF5,0x5C,0x1A,0x63,0x12,0x58,0xD6,0x9C,0xF7,0xA2,0xDE,0xF9,0xDE,0x14,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10 };

static const uint8_t sk1[32] = {
    0x4c,0xcd,0x08,0x9b,0x28,0xff,0x96,0xda,0x9d,0xb6,0xc3,0x46,0xec,0x11,0x4e,0x0f,
    0x5b,0x8a,0x31,0x9f,0x35,0xab,0xa6,0x24,0xda,0x8c,0xf6,0xed,0x4f,0xb8,0xa6,0xfb };
static const uint8_t pk1[edd_public_key_size] = {
    0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a,0x92,0xb7,0x0a,0xa7,0x4d,0x1b,0x7e,0xbc,
    0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c,0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c };
static const uint8_t msg1[] = { 0x72 };
static const uint8_t msg1_sig[edd_signature_size] = {
    0x92,0xa0,0x09,0xa9,0xf0,0xd4,0xca,0xb8,0x72,0x0e,0x82,0x0b,0x5f,0x64,0x25,0x40,
    0xa2,0xb2,0x7b,0x54,0x16,0x50,0x3f,0x8f,0xb3,0x76,0x22,0x23,0xeb,0xdb,0x69,0xda,
    0x08,0x5a,0xc1,0xe4,0x3e,0x15,0x99,0x6e,0x45,0x8f,0x36,0x13,0xd0,0xf1,0x1d,0x8c,
    0x38,0x7b,0x2e,0xae,0xb4,0x30,0x2a,0xee,0xb0,0x0d,0x29,0x16,0x12,0xbb,0x0c,0x00
};


// k1*k2 = 1 mod l ==> Q1 = k1.Q0 --> k2.Q1 = k2.k1.Q0 = Q0
static const U8 _b_k1[32] = {
    0x0B,0xE3,0xBE,0x63,0xBC,0x01,0x6A,0xAA,0xC9,0xE5,0x27,0x9F,0xB7,0x90,0xFB,0x44,
    0x37,0x2B,0x2D,0x4D,0xA1,0x73,0x5B,0x5B,0xB0,0x1A,0xC0,0x31,0x8D,0x89,0x21,0x03 };

static const U8 _b_k2[32] = {
    0x39,0x03,0xE3,0x27,0x7E,0x41,0x93,0x61,0x2D,0x3D,0x40,0x19,0x3D,0x60,0x68,0x21,
    0x60,0x25,0xEF,0x90,0xB9,0x8B,0x24,0xF2,0x50,0x60,0x94,0x21,0xD4,0x74,0x36,0x05 };

const uint32_t BPO_MINV32 = 0x12547E1B; // -1/BPO mod 2**32

#define ECP_MULADD_W0(Z,Y,b,X) c.u64 = (uint64_t)(b)*(X) + (Y); Z = c.u32.lo;
#define ECP_MULADD_W1(Z,Y,b,X) c.u64 = (uint64_t)(b)*(X) + (uint64_t)(Y) + c.u32.hi; Z = c.u32.lo;

#define g_BPO g_NxBPO[1]
#define g_maxBPO   g_NxBPO[15]

#define w_One      gPreFold[0].YpX


// Z = (X*Y)/R mod BPO
void eco_MontMul(NN& Z, const NN& X, const NN& Y)
{
    int i, j;
    uint32_t T[10] = { 0 };
    NN& T1(*(NN*)(T + 1));

    for (i = 0; i < 8; i++) {
        M64 c{ 0llu };
        uint32_t b = X.n_[i];
        for (j = 0; j < 8; j++) {
            c.u64 = (uint64_t)b*Y.n_[j]+T[j+1]+c.u32.hi;
            T[j] = c.u32.lo;
        }
        c.u64 = (uint64_t)T[9] + c.u32.hi;
        T[8] = c.u32.lo; T[9] = c.u32.hi;
        b = BPO_MINV32 * T[0]; c.u32.hi = 0;
        for (j = 0; j < 8; j++) {
            c.u64 = (uint64_t)b*g_BPO.n_[j] + T[j] + c.u32.hi;
            T[j] = c.u32.lo;
        }
        c.u64 = (uint64_t)T[8] + c.u32.hi;
        T[8] = c.u32.lo; T[9] += c.u32.hi;
        // T + (-1/BPO)*T*BPO mod 2**32 = 0 --> T[0] = 0
    }
    // T[9] could be 2 at most
    while (T[9] != 0) {
        if (T1 < g_maxBPO) T[9]--;
        T1 -= g_maxBPO;
    }
    Z = T1;
}

// This is faster method
void ecp_CalculateY0(NN& Y, const NN& X)
{
    NN tmp(NN::P_);
    tmp += 3;
    tmp >>= 3;

    NN T(X);
    NN A(486662);
    (A += T).reduce();      // x + 486662
    A = A ^ T;              // x^2 + 486662x
    A = A ^ T;              // x^3 + 486662x^2
    (A += T).reduce();      // x^3 + 486662x^2 + x

    A.EMod(T, gPp3d8);

    // if T*T != A: T *= sqrt(-1)
    NN B(T ^ T);
    if (B != A) T = T ^ w_I;
    Y = T;
}

// https://www.johannes-bauer.com/compsci/ecc/#anchor14
// https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
// This is more generic method.
bool ecp_CalculateY(NN& Y, const NN& X)
{
    NN T(X);
    NN A(486662);
    (A += T).reduce();      // x + 486662
    A = A ^ T;              // x^2 + 486662x
    A = A ^ T;              // x^3 + 486662x^2
    (A += T).reduce();      // x^3 + 486662x^2 + x

    NN n(A);

    // Step 1
    NN Q(NN::P_); Q -= 1;
    NN hP1(Q); hP1 >>= 1;
    uint32_t i = 0, s = 0;
    while ((Q.n0 & 1) == 0) {
        Q >>= 1; s++;
    }
    NN hQ1(Q); hQ1 += 1; hQ1 >>= 1;

    // Step 2
    NN z(1);
    do {
        z += 1;
        z.EMod(T, hP1);
    } while (T.is1());

    //Step 3
    uint32_t m = s;
    NN c; z.EMod(c, Q);
    n.EMod(T, Q);
    NN R; n.EMod(R, hQ1);

    // Step 4
    while (!T.is1()) {
        NN t(T);
        for (i = 1; i < m; i++) {
            if ((t = t ^ t).is1())
                break;
        }
        if (i >= m) {
            return false;
        }
        
        NN b(c);
        while (--m > i) b = b ^ b;
        c = b ^ b;
        T = T ^ c;
        R = R ^ b;
    }
    Y = R;
    return true;
}

void PrtNN(const char* name, const NN& nn)
{
  printf("%s=", name);
  for (int i=0; i<8; i++) {
    printf(" %08X", nn.n_[i]);
  }
  printf("\n");
}

int ecp_SelfTest(int level)
{
    printf("Enter ecp self test\n");
    int i, rc = 0;
    NN A, B, C;
    N2 T;
    uint8_t a[32], b[32], c[32], d[32];

    printf("Doing ecp self test\n");
    rc = hash_test(level);
    printf("hash_test = %d\n", rc);


    A = EdpSigv::w_I + NN::P_;
    A.reduce();
    if (A != EdpSigv::w_I)
    {
    rc++;
    printf("assert I+p == I mod p FAILED!!\n");
    ecp_PrintHexWords("A_1", A);
    }
    printf("I+p mod test OK\n");

    PrtNN("I", w_I); PrtNN("D", w_D);
    B = w_I ^ w_D;
    PrtNN("B", B); PrtNN("IxD", w_IxD);

        printf("memcmp is %d\n", memcmp(&B, &w_IxD, sizeof(NN)));

    if (B != w_IxD)
    {
    rc++;
    printf("assert I*D FAILED!!\n");
    }

    B = w_I ^ w_I;
    B += 1;
    B.reduce();
    if (B != NN(0)) {
    rc++;
    printf("assert w_I Sqrt(-1) FAILED!!\n");
    }

    // calculate I*D mod BPO using different interfaces
    eco_MontMul(A, w_I, _w_R2);
    eco_MontMul(B, w_D, _w_R2);

    eco_MontMul(C, A, B);
    eco_MontMul(A, C, w_One);
    A.reduceb();
    if (A != _w_IxDmodBPO)
    {
    rc++;
    printf("methods 1 of I*D mod BPO FAILED!!\n");
    ecp_PrintHexWords("Calc", A);
    ecp_PrintHexWords("Expt", _w_IxDmodBPO);
    }

    B = (w_I * w_D).reduceb();

    if (B != _w_IxDmodBPO)
    {
    rc++;
    printf("methods 2 of I*D mod BPO FAILED!!\n");
    ecp_PrintHexWords("Calc", B);
    ecp_PrintHexWords("Expt", _w_IxDmodBPO);
    }

    B = (w_I * w_D).reduceb();
    if (B != _w_IxDmodBPO)
    {
    rc++;
    printf("methods 3 of I*D mod BPO FAILED!!\n");
    ecp_PrintHexWords("Calc", B);
    ecp_PrintHexWords("Expt", _w_IxDmodBPO);
    }

    for (i = 0; i < 1000; i++)
    {
    C = C.n_[0] + i;
    // method 1
    eco_MontMul(A, C, _w_R2);
    eco_MontMul(B, w_D, _w_R2);
    eco_MontMul(T.n.N0, A, B);
    eco_MontMul(A, T.n.N0, w_One);
    A.reduceb();
    // method 2
    B = (C * w_D).reduceb();
    if (A != B)
    {
        rc++;
        printf("methods 2 MulMod BPO FAILED!!\n");
        ecp_PrintHexWords("Calc", B);
        ecp_PrintHexWords("Expt", A);
    }
    }

    A = 50153;
    B = A.inverse();
    A = A ^ B;
    if (A != w_One)
    {
    rc++;
    printf("invmod FAILED!!\n");
    ecp_PrintHexWords("inv_50153", B);
    ecp_PrintHexWords("expected_1", A);
    }

    // assert expmod(d,(p-1)/2,p) == p-1
    w_D.EMod(A, *(const NN*)_b_Pm1d2);
    if (A != _w_Pm1)
    {
    rc++;
    printf("assert expmod(d,(p-1)/2,p) == p-1 FAILED!!\n");
    ecp_PrintHexWords("A_3", A);
    }

    // assert I**2 == p-1
    A = w_I ^ w_I;
    if (A != _w_Pm1)
    {
    rc++;
    printf("assert expmod(I,2,p) == p-1 FAILED!!\n");
    ecp_PrintHexWords("A_4", A);
    }

    G g;
    ecp_CalculateY(A, g);
    if (A != _w_Gy)
    {
    rc++;
    printf("assert clacY(Base) == Base.y FAILED!!\n");
    ecp_PrintHexBytes("Calculated_Base.y", a, 32);
    }

    g.PointMult(a, *(const NN*)_b_Om1);
    if (*(const NN*)a != g)
    {
    rc++;
    printf("assert (l-1).Base == Base FAILED!!\n");
    ecp_PrintHexBytes("A_5", a, 32);
    }

    g.PointMult(a, *(const NN*)_b_O);  //??? Problem
    A.bytesIn(a);
    if (!A.is0())
    {
    rc++;
    printf("assert l.Base == 0 FAILED!!\n");
    ecp_PrintHexBytes("A_6", a, 32);
    }

    // Key generation
    G& ga(*(NN*)a);
    G& gb(*(NN*)b);
    G& gc(*(NN*)c);
    {
    const NN pk_1{ 0x09d2f946, 0xac6953c7, 0x28a3975f, 0xc77a66a1, 0xc95e6df8, 0x5c510db2, 0x56a23911, 0x6013103b };
    const NN pk_2{ 0xd36a265a, 0x9b9e8dd0, 0xcc2ad98b, 0xb9d587cd, 0xbadbd196, 0x75c9bcb6, 0x61d77662, 0xa75f37f9 };

    g.PointMult(a, pk_1);
    g.PointMult(b, pk_2);

    // ECDH - key exchange
    gb.PointMult(c, pk_1);
    ga.PointMult(d, pk_2);
    }

    if (memcmp(c, d, 32) != 0)
    {
    rc++;
    printf("ECDH key exchange FAILED!!\n");
    ecp_PrintHexBytes("PublicKey1", a, 32);
    ecp_PrintHexBytes("PublicKey2", b, 32);
    ecp_PrintHexBytes("SharedKey1", c, 32);
    ecp_PrintHexBytes("SharedKey2", d, 32);
    }

    memset(a, 0x44, 32);        // our secret key
    g.PointMult(b, *(NN*)a);    // public key
    gb.PointMult(c, *(NN*)_b_k1);
    gc.PointMult(d, *(NN*)_b_k2);
    if (memcmp(d, b, 32) != 0)
    {
    rc++;
    printf("assert k1.k2.D == D FAILED!!\n");
    ecp_PrintHexBytes("D", d, 32);
    ecp_PrintHexBytes("C", c, 32);
    ecp_PrintHexBytes("A", a, 32);
    }

    A.bytesIn(_b_k1);
    B.bytesIn(_b_k2);
    C = (A * B).reduceb();
    C = A.inverseb();
    if (C != B)
    {
    rc++;
    printf("assert 1/k1 == k2 mod BPO FAILED!!\n");
    ecp_PrintHexWords("Calc", C);
    ecp_PrintHexWords("Expt", B);
    }

    C = (A * B).reduceb();
    if (!C.is1())
    {
    rc++;
    printf("assert k1*k2 == 1 mod BPO FAILED!!\n");
    ecp_PrintHexWords("Calc", C);
    }

    /* expriment:
    pick x and find its associated y
    - check if P=(x,y) is on the curve
    - check order of P is same as BPO (same sub-group as base point)
    interestingly:
    OnCurve=True  Order=DIFFERENT
    x = 0x000000000000000000000000000000000000000000000000000000000000000A
    y = 0x7FA11E2C10248F175E1C49E162A38AF68B311C6719C9B2F6A042B8742E891F65
    OnCurve=FALSE  Order=DIFFERENT
    x = 0x000000000000000000000000000000000000000000000000000000000000000C
    y = 0x79F72F9D93C775B921FB784C4B441492F5DCBECBAA69F549FA7CB8CEB80FD0DE
    OnCurve=True  Order=BPO
    x = 0x0000000000000000000000000000000000000000000000000000000000000010
    y = 0x36B20194B9EE7885E888642D2006D60CDCC836D17F615E8416989556B3941598
    */
    memset(b, 0, 32);
    for (i = 0; i < 100; i++)
    {
    if (i == 1) {
        i = i;
    }
    int order_test, on_curve, on_curve2;
    b[0] = (U8)(i + 8);
    b[31] &= 0x7f;
    const G g(*(const NN*)b);

    g.PointMult(a, *(NN*)_b_Om1);

    order_test = (memcmp(a, b, 32) == 0) ? 1 : 0;

    // It it on the curve?
    B.bytesIn(b);
    ecp_CalculateY(*(NN*)a, *(NN*)b);
    A.bytesIn(a);
    on_curve2 = ecp_IsOnCurve(B, A);

    ecp_CalculateY0(*(NN*)a, *(NN*)b);
    A.bytesIn(a);
    on_curve = ecp_IsOnCurve(B, A);

    printf("OnCurve=%c%c ", on_curve?'Y':'N', on_curve2?'Y':'N');
    if (order_test) printf("  Order=BPO\n"); else printf("  Order=DIFFERENT\n");
    ecp_PrintHexBytes("x", b, 32);
    ecp_PrintHexBytes("y", a, 32);
    }

    return rc;
}

static const G ecp_baseG(9);

// Return public key associated with sk
void dh_CalculatePublicKey(
    unsigned char *pk,          // [32-bytes] OUT: Public key
    unsigned char *sk)          // [32-bytes] IN/OUT: Your secret key
{
    ecp_TrimSecretKey(sk);
    NN sKey;
    sKey.bytesIn(sk);
    ecp_baseG.PointMult(pk, sKey);
}

// Create a shared secret
void dh_CreateSharedKey(
    unsigned char *shared,      // [32-bytes] OUT: Created shared key
    const unsigned char *pk,    // [32-bytes] IN: Other side's public key
    unsigned char *sk)          // [32-bytes] IN/OUT: Your secret key
{
    ecp_TrimSecretKey(sk);
    NN sKey;
    G pKey;
    sKey.bytesIn(sk).reduce();
    pKey.bytesIn(pk).reduce();
    pKey.PointMult(shared, sKey);
}


int dh_test()
{
    int rc = 0;
    unsigned char alice_public_key[32], alice_shared_key[32];
    unsigned char bruce_public_key[32], bruce_shared_key[32];

    unsigned char alice_secret_key[32] = { // #1234
        0x03,0xac,0x67,0x42,0x16,0xf3,0xe1,0x5c,
        0x76,0x1e,0xe1,0xa5,0xe2,0x55,0xf0,0x67,
        0x95,0x36,0x23,0xc8,0xb3,0x88,0xb4,0x45,
        0x9e,0x13,0xf9,0x78,0xd7,0xc8,0x46,0xf4 };

    unsigned char bruce_secret_key[32] = { // #abcd
        0x88,0xd4,0x26,0x6f,0xd4,0xe6,0x33,0x8d,
        0x13,0xb8,0x45,0xfc,0xf2,0x89,0x57,0x9d,
        0x20,0x9c,0x89,0x78,0x23,0xb9,0x21,0x7d,
        0xa3,0xe1,0x61,0x93,0x6f,0x03,0x15,0x89 };

    printf("\n-- curve25519 -- key exchange test -----------------------------\n");
    // Step 1. Alice and Bruce generate their own random secret keys

    ecp_PrintHexBytes("Alice_secret_key", alice_secret_key, 32);
    ecp_PrintHexBytes("Bruce_secret_key", bruce_secret_key, 32);

    // Step 2. Alice and Bruce create public keys from their
    // secret keys and then exchange their public keys.
    dh_CalculatePublicKey(alice_public_key, alice_secret_key);
    dh_CalculatePublicKey(bruce_public_key, bruce_secret_key);
    ecp_PrintHexBytes("Alice_public_key", alice_public_key, 32);
    ecp_PrintHexBytes("Bruce_public_key", bruce_public_key, 32);

    // Step 3. Alice and Bruce create their shared key
    dh_CreateSharedKey(bruce_shared_key, alice_public_key, bruce_secret_key);
    dh_CreateSharedKey(alice_shared_key, bruce_public_key, alice_secret_key);

    ecp_PrintHexBytes("Alice_shared", alice_shared_key, 32);
    ecp_PrintHexBytes("Bruce_shared", bruce_shared_key, 32);

    // Alice and Bruce should end up with idetntical keys
    if (memcmp(alice_shared_key, bruce_shared_key, 32) != 0)
    {
        rc++;
        printf("DH key exchange FAILED!!\n");
    }
    return rc;
}

static unsigned char secret_blind[32] =
{
    0xea,0x30,0xb1,0x6d,0x83,0x9e,0xa3,0x1a,0x86,0x34,0x01,0x9d,0x4a,0xf3,0x36,0x93,
    0x6d,0x54,0x2b,0xa1,0x63,0x03,0x93,0x85,0xcc,0x03,0x0a,0x7d,0xe1,0xae,0xa7,0xbb
};

int ecdTest()
{
    static const uchar sk[32] = {
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
        0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb};

    int r = 0;
    CIPHER cipher;
    SetSha512(&cipher);
    uchar keyPair[64];
    uchar digest[64];
    char msgText[] = "r";

    memcpy(keyPair, sk, 32);
    X25519::genPubKey(cipher, keyPair+32, sk);

    cipher.Hash((const uchar*)msgText, strlen(msgText), digest);
    X25519::ECDSign sig(cipher);

    NN priKey; priKey.bytesIn(sk);
    sig.Sign(keyPair, (const uchar*)msgText, strlen(msgText));
    uchar R[32], S[32];
    sig.OutR(R); sig.OutS(S);

    X25519::ECDSign sig2(cipher);
    sig2.r.bytesIn(R); sig2.s.bytesIn(S);

    r |= !sig2.Test(keyPair + 32, (const uint8_t*)msgText, strlen(msgText));

    r = r;
    return r;
}

int signature_test(
    const unsigned char *sk,
    const unsigned char *expected_pk,
    const unsigned char *msg, size_t size,
    const unsigned char *expected_sig)
{
    int rc = 0;
    CIPHER cipher;
    SetSha512(&cipher);
    unsigned char sig[edd_signature_size];
    unsigned char pubKey[edd_public_key_size];
    unsigned char privKey[edd_private_key_size];
    BLINDING blinding(cipher, secret_blind, sizeof(secret_blind));

    printf("\n-- ed25519 -- sign/verify test ---------------------------------\n");
    printf("\n-- CreateKeyPair --\n");
    const BLINDING* myBlinding = NULL;

    myBlinding = &blinding;

    edd_CreateKeyPair(cipher, pubKey, privKey, myBlinding, sk);
    ecp_PrintHexBytes("secret_key", sk, edd_secret_key_size);
    ecp_PrintHexBytes("public_key", pubKey, edd_public_key_size);
    ecp_PrintBytes("private_key", privKey, edd_private_key_size);

    if (expected_pk && memcmp(pubKey, expected_pk, edd_public_key_size) != 0)
    {
    rc++;
    printf("ed25519_CreateKeyPair() FAILED!!\n");
    ecp_PrintHexBytes("Expected_pk", expected_pk, edd_public_key_size);
    }

    printf("-- Sign/Verify --\n");
    edd_SignMessage(cipher, sig, privKey, 0, msg, size);
    ecp_PrintBytes("message", msg, (U32)size);
    ecp_PrintBytes("signature", sig, edd_signature_size);
    if (expected_sig && memcmp(sig, expected_sig, edd_signature_size) != 0)
    {
    rc++;
    printf("Signature generation FAILED!!\n");
    ecp_PrintBytes("Calculated", sig, edd_signature_size);
    ecp_PrintBytes("ExpectedSig", expected_sig, edd_signature_size);
    }

    if (!edd_VerifySignature(cipher, sig, pubKey, msg, size))
    {
    rc++;
    printf("Signature verification FAILED!!\n");
    ecp_PrintBytes("sig", sig, edd_signature_size);
    ecp_PrintBytes("pk", pubKey, edd_public_key_size);
    }

    printf("\n-- ed25519 -- sign/verify test w/blinding ----------------------\n");
    printf("\n-- CreateKeyPair --\n");
    edd_CreateKeyPair(cipher, pubKey, privKey, &blinding, sk);
    ecp_PrintHexBytes("secret_key", sk, edd_secret_key_size);
    ecp_PrintHexBytes("public_key", pubKey, edd_public_key_size);
    ecp_PrintBytes("private_key", privKey, edd_private_key_size);

    if (expected_pk && memcmp(pubKey, expected_pk, edd_public_key_size) != 0)
    {
    rc++;
    printf("ed25519_CreateKeyPair() FAILED!!\n");
    ecp_PrintHexBytes("Expected_pk", expected_pk, edd_public_key_size);
    }

    printf("-- Sign/Verify --\n");
    edd_SignMessage(cipher, sig, privKey, &blinding, msg, size);
    ecp_PrintBytes("message", msg, (U32)size);
    ecp_PrintBytes("signature", sig, edd_signature_size);
    if (expected_sig && memcmp(sig, expected_sig, edd_signature_size) != 0)
    {
    rc++;
    printf("Signature generation FAILED!!\n");
    ecp_PrintBytes("Calculated", sig, edd_signature_size);
    ecp_PrintBytes("ExpectedSig", expected_sig, edd_signature_size);
    }

    if (!edd_VerifySignature(cipher, sig, pubKey, msg, size))
    {
    rc++;
    printf("Signature verification FAILED!!\n");
    ecp_PrintBytes("sig", sig, edd_signature_size);
    ecp_PrintBytes("pk", pubKey, edd_public_key_size);
    }

    if (rc == 0)
    {
    printf("  ++ Signature Verified Successfully. ++\n");
    }

    return rc;
}

// Create own ECC curve:
// https://csrc.nist.gov/csrc/media/events/workshop-on-elliptic-curve-cryptography-standards/documents/papers/session1-miele-paper.pdf

// https://defuse.ca/big-number-calculator.htm

int ecc_Test()
{
    int ret = 0, rc = 0;

    NN P;
    P.n7 = 0x80000000;
    P -= 19;

    PrtNN("P", P);

    N2::init(P);

    printf("After N2 init\n");


    rc |= p256_test();
    printf("P256 test %s\n", (rc==0)? "OK":"FAILED");

    {
        NN a{ 0x56789453, 0x56789453, 0x56789453, 0x56789453, 0x5678945, 0x5678945, 0x56789453, 0x56789453 };
        N2 b(a * ecc_BPO);
        b.reduceb();
        b.n.N0.n_[0] |= 0;
    }

    rc |= ret = ecp_SelfTest(10);
    printf("Self test %s\n", (ret == 0) ? "OK" : "ERROR");
    
    rc |= ret = dh_test();
    printf("\nDH test %s\n", (ret == 0)? "OK":"ERROR");

    rc |= ret = ecdTest();
    printf("X25519 sign test %s\n", (ret == 0) ? "OK" : "ERROR");

    rc |= ret = signature_test(sk1, pk1, msg1, sizeof(msg1), msg1_sig);
    printf("Signature test %s\n", (ret == 0) ? "OK" : "ERROR");

    printf("ECC test done with %s\n", rc? "SOME ERROR":"SUCCESS");

    return rc;
}
