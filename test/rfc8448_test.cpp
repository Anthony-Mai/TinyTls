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
*  File Name:       rfc8448_test.cpp
*
*  Description:     Running SSL/TLS dry run Test on TLS1.3, based on RFC8448
*
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         10/08/2018 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <assert.h>

#include "rfc8448_test.h"

#define TestBuddy MyTestContext
#include "MockSock.h"

#include "TlsFactory.h"
#include "TlsCallback.h"
#include "BaseTls.h"
#include "cert.h"
#include "ssl_ciphers.h"
#include "certSamples.h"
#include "cipher.h"


class MyTestContext {
    const CIPHER& sha_;
public:
    BaseTls* clt_;
    BaseTls* svr_;
    int      it_;
    int      ct_;
    static const char server_name_[];

    MyTestContext(const CIPHER& sha) : sha_(sha), clt_(nullptr), svr_(nullptr), it_(0), ct_(0) {}
    int      Validate();

    MyTestContext& operator ++ () { it_++; return *this; }
};

const char MyTestContext::server_name_[]{ "server" };

static struct TestCase {
    uint16_t seq;
    uint16_t off;
    uint16_t len;
    uint16_t md[13];
} gCases[] = {
    {0x0009, 0, 201, {0xd7f0, 0x1eb6, 0x0f8a, 0xff97, 0xec2c, 0x185a, 0xfe73, 0xe788, 0x07b9, 0x8dee, 0xd27c, 0x2ed2, 0xedef }}, // 0x438c, 0xf149, 0xb854
    {0x8015, 0, 840, {0x8fe0, 0x9be7, 0xcde9, 0x3f8f, 0x4eaa, 0x803d, 0x22b2, 0x61a6, 0xb13d, 0xfb50, 0x51b4, 0x74a3, 0x643e }}, // 0xfc59, 0x094d, 0x391a
    {0x001b, 0, 259, {0x9c9d, 0xfd4a, 0x6d59, 0xb4f0, 0x8c95, 0xaef2, 0x49e4, 0x106e, 0x8d9d, 0x6680, 0x7dc3, 0xaca9, 0x03c7 }}, // 0xb8da, 0x76ea, 0x5ffa
    {0x001e, 0, 301, {0xe7b5, 0x5f03, 0xc343, 0x3c9b, 0x3ebd, 0xbd43, 0x36d4, 0xa85b, 0x29b9, 0x2f96, 0x379a, 0x3b6c, 0xbc61 }}, // 0x71df, 0xcd68, 0x3bf7
    {0x8021, 0, 882, {0x1397, 0x5439, 0x2d3b, 0x16eb, 0x4c0e, 0x6bc9, 0x015e, 0xfc24, 0xd023, 0x049f, 0xae8e, 0xf9fa, 0xa8d2 }}, // 0xdbf3, 0x5005, 0xf038
};

TestCase* GetTestCase(uint32_t n)
{
    for (int i = 0; i < sizeof(gCases) / sizeof(gCases[0]); i++) {
        if ((n ^ gCases[i].seq) & 0x7FFF) continue;
        return &(gCases[i]);
    }
    return nullptr;
}

int MyTestContext::Validate()
{
    int r = 0;
    uint len = MockSock::m_nCOut;
    MockSock::m_Client2Server;

    TestCase* pCase = GetTestCase(it_);
    if (pCase == nullptr) {
        return 0;
    }

    const uchar* p = (pCase->seq & 0x8000)
        ? (MockSock::m_Server2Client)
        : (MockSock::m_Client2Server);

    const uint32_t* pN = (pCase->seq & 0x8000)
        ? &(MockSock::m_nSOut)
        : &(MockSock::m_nCOut);

    p += pCase->off;

    uchar md[32];

    sha_.Hash(p + pCase->off, pCase->len, md);
    r |= (pCase->off + pCase->len) ^ (*pN);
    r |= memcmp(md, pCase->md, sizeof(pCase->md));

    if (0) {
        printf("Traffic[%d]:", (*pN));
        for (int i = 0, j = *pN; i < j; i++) {
            printf("%s%02X", ((i & 15) ? " " : "\n    "), p[i]);
        }
        printf("\n");
    }

    if (r) {
        printf("Integrity test FAILURE at iteration %d\n", it_);
    }

    return r;
}


static unsigned int ClientCallback(void* pUserContext, TlsCBData* pCBData)
{
    MyTestContext& testCtx(*reinterpret_cast<MyTestContext*>(pUserContext)); ++testCtx;

    unsigned int ret = 0;
    switch (pCBData->cbType) {
    case TlsCBData::CB_RANDOM: {
        static const uchar c_clientRandom[32] = { // https://tools.ietf.org/html/rfc8448#section-3
            0xcb, 0x34, 0xec, 0xb1, 0xe7, 0x81, 0x63, 0xba, 0x1c, 0x38, 0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d,
            0xff, 0xa2, 0x1a, 0x8d, 0x99, 0x12, 0xec, 0x18, 0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d, 0xec, 0xe7 };
        memcpy(pCBData->data.ptrs[0], c_clientRandom, 32); break; }
    case TlsCBData::CB_SERVER_NAME:
        pCBData->data.ptrs[0] = (void*)MyTestContext::server_name_;
        ret = pCBData->data.rawSize[1] = strlen((const char*)pCBData->data.ptrs[0]);
        break;
    case TlsCBData::CB_CLIENT_CIPHER:
        pCBData->data.rawInt[0] = TLS_AES_128_GCM_SHA256;
        pCBData->data.rawInt[1] = TLS_CHACHA20_POLY1305_SHA256;
        pCBData->data.rawInt[2] = TLS_AES_256_GCM_SHA384;
        pCBData->data.rawInt[3] = 0;
        ret = 3; // Only 3 ciphers supported.
        break;
    case TlsCBData::CB_SUPPORTED_GROUPS:
        pCBData->data.rawInt[0] = ECC_x25519; // Supported Group: x25519 (0x001d)
        pCBData->data.rawInt[1] = ECC_secp256r1; // Supported Group: secp256r1(0x0017)
        pCBData->data.rawInt[2] = ECC_secp384r1; // Supported Group: secp384r1 (0x0018)
        pCBData->data.rawInt[3] = ECC_secp521r1; // Supported Group: secp521r1 (0x0019)
        pCBData->data.rawInt[4] = ECC_ffdhe2048; // Supported Group: ffdhe2048 (0x0100) RFC7919
        pCBData->data.rawInt[5] = ECC_ffdhe3072; // Supported Group: ffdhe3072 (0x0101) RFC7919
        pCBData->data.rawInt[6] = ECC_ffdhe4096; // Supported Group: ffdhe4096 (0x0102) RFC7919
        pCBData->data.rawInt[7] = ECC_ffdhe6144; // Supported Group: ffdhe6144 (0x0103) RFC7919
        pCBData->data.rawInt[8] = ECC_ffdhe8192; // Supported Group: ffdhe8192 (0x0104) RFC7919
        ret = 9; // Only 9 entries of supported ECC groups
        break;
    case TlsCBData::CB_SESSIONTICKET_TLS:
        ret = 0; break;
    case  TlsCBData::CB_PSK_INFO:
        ret = 0; break;
    case TlsCBData::CB_ECDHE_PRIVATEKEY: {
        // pCBData->data.ptrs[0] is the ephemeral ECC private key
        // pCBData->data.rawSize[1] is the ECC_GROUP which should also be returned.
        static const uchar c_privKey[32] = { // https://tools.ietf.org/html/rfc8448#section-3
            0x49, 0xaf, 0x42, 0xba, 0x7f, 0x79, 0x94, 0x85, 0x2d, 0x71, 0x3e, 0xf2, 0x78, 0x4b, 0xcb, 0xca,
            0xa7, 0x91, 0x1d, 0xe2, 0x6a, 0xdc, 0x56, 0x42, 0xcb, 0x63, 0x45, 0x40, 0xe7, 0xea, 0x50, 0x05};
        memcpy(pCBData->data.ptrs[0], c_privKey, sizeof(c_privKey));
        ret = pCBData->data.rawSize[1] = ECC_x25519;
        break; }
    case TlsCBData::CB_SIGNATURE_ALGORITHM:
        // https://tools.ietf.org/html/rfc8448#section-3
        pCBData->data.rawInt[0] = ecdsa_secp256r1_sha256; // Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
        pCBData->data.rawInt[1] = ecdsa_secp384r1_sha384; // Signature Algorithm: ecdsa_secp384r1_sha384 (0x0503)
        pCBData->data.rawInt[2] = ecdsa_secp521r1_sha512; // Signature Algorithm: ecdsa_secp521r1_sha512 (0x0603)
        pCBData->data.rawInt[3] = ecdsa_sha1;             // Signature Algorithm: ecdsa_sha1 (0x0203)
        pCBData->data.rawInt[4] = rsa_pss_rsae_sha256;    // Signature Algorithm: rsa_pss_rsae_sha256 (0x0804)
        pCBData->data.rawInt[5] = rsa_pss_rsae_sha384;    // Signature Algorithm: rsa_pss_rsae_sha384 (0x0805)
        pCBData->data.rawInt[6] = rsa_pss_rsae_sha512;    // Signature Algorithm: rsa_pss_rsae_sha512 (0x0806)
        pCBData->data.rawInt[7] = rsa_pkcs1_sha256;       // Signature Algorithm: rsa_pkcs1_sha256 (0x0401)
        pCBData->data.rawInt[8] = rsa_pkcs1_sha384;       // Signature Algorithm: rsa_pkcs1_sha384 (0x0501)
        pCBData->data.rawInt[9] = rsa_pkcs1_sha512;       // Signature Algorithm: rsa_pkcs1_sha512 (0x0601)
        pCBData->data.rawInt[10] = rsa_pkcs1_sha1;        // Signature Algorithm: rsa_pkcs1_sha1 (0x0201)
        pCBData->data.rawInt[11] = SHA256_DSA;            // Signature Algorithm: SHA256 DSA (0x0402)
        pCBData->data.rawInt[12] = SHA384_DSA;            // Signature Algorithm: SHA384 DSA (0x0502)
        pCBData->data.rawInt[13] = SHA512_DSA;            // Signature Algorithm: SHA512 DSA (0x0602)
        pCBData->data.rawInt[14] = SHA1_DSA;              // Signature Algorithm: SHA1 DSA (0x0202)
        ret = 15; break;
    case TlsCBData::CB_CERTIFICATE_ALERT: { // Client receives questionable server certificate.
        const CERT* pCert = reinterpret_cast<const CERT*>(pCBData->data.ptrs[0]);
        CERT_STATUS eStatus = (CERT_STATUS)reinterpret_cast<size_t>(pCBData->data.ptrs[1]);
        // See CERT_STATUS defined in cert.h for meaning of its bits. For purpose of test
        // we accept self-signed cert. In real production self signed certificate should be rejected.
        if ((eStatus & CS_BAD) == 0 && ((eStatus & CS_OK) || ((eStatus & CS_SELF)))) {
            ret = 1; // Return 1 is accept the certificate. 0 is to reject it and abort connection.
        }
        break; }

    default:
        break;
    }

    return ret;
}

static unsigned int ServerCallback(void* pUserContext, TlsCBData* pCBData)
{
    MyTestContext& testCtx(*reinterpret_cast<MyTestContext*>(pUserContext)); ++testCtx;

    static uchar s_Certificate[432] = {
        0x30, 0x82, 0x01, 0xac, 0x30, 0x82, 0x01, 0x15, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02,
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30,
        0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x72, 0x73, 0x61, 0x30,
        0x1e, 0x17, 0x0d, 0x31, 0x36, 0x30, 0x37, 0x33, 0x30, 0x30, 0x31, 0x32, 0x33, 0x35, 0x39, 0x5a,
        0x17, 0x0d, 0x32, 0x36, 0x30, 0x37, 0x33, 0x30, 0x30, 0x31, 0x32, 0x33, 0x35, 0x39, 0x5a, 0x30,
        0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x72, 0x73, 0x61, 0x30,
        0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
        0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xb4, 0xbb, 0x49, 0x8f,
        0x82, 0x79, 0x30, 0x3d, 0x98, 0x08, 0x36, 0x39, 0x9b, 0x36, 0xc6, 0x98, 0x8c, 0x0c, 0x68, 0xde,
        0x55, 0xe1, 0xbd, 0xb8, 0x26, 0xd3, 0x90, 0x1a, 0x24, 0x61, 0xea, 0xfd, 0x2d, 0xe4, 0x9a, 0x91,
        0xd0, 0x15, 0xab, 0xbc, 0x9a, 0x95, 0x13, 0x7a, 0xce, 0x6c, 0x1a, 0xf1, 0x9e, 0xaa, 0x6a, 0xf9,
        0x8c, 0x7c, 0xed, 0x43, 0x12, 0x09, 0x98, 0xe1, 0x87, 0xa8, 0x0e, 0xe0, 0xcc, 0xb0, 0x52, 0x4b,
        0x1b, 0x01, 0x8c, 0x3e, 0x0b, 0x63, 0x26, 0x4d, 0x44, 0x9a, 0x6d, 0x38, 0xe2, 0x2a, 0x5f, 0xda,
        0x43, 0x08, 0x46, 0x74, 0x80, 0x30, 0x53, 0x0e, 0xf0, 0x46, 0x1c, 0x8c, 0xa9, 0xd9, 0xef, 0xbf,
        0xae, 0x8e, 0xa6, 0xd1, 0xd0, 0x3e, 0x2b, 0xd1, 0x93, 0xef, 0xf0, 0xab, 0x9a, 0x80, 0x02, 0xc4,
        0x74, 0x28, 0xa6, 0xd3, 0x5a, 0x8d, 0x88, 0xd7, 0x9f, 0x7f, 0x1e, 0x3f, 0x02, 0x03, 0x01, 0x00,
        0x01, 0xa3, 0x1a, 0x30, 0x18, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00,
        0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30, 0x0d, 0x06,
        0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00,
        0x85, 0xaa, 0xd2, 0xa0, 0xe5, 0xb9, 0x27, 0x6b, 0x90, 0x8c, 0x65, 0xf7, 0x3a, 0x72, 0x67, 0x17,
        0x06, 0x18, 0xa5, 0x4c, 0x5f, 0x8a, 0x7b, 0x33, 0x7d, 0x2d, 0xf7, 0xa5, 0x94, 0x36, 0x54, 0x17,
        0xf2, 0xea, 0xe8, 0xf8, 0xa5, 0x8c, 0x8f, 0x81, 0x72, 0xf9, 0x31, 0x9c, 0xf3, 0x6b, 0x7f, 0xd6,
        0xc5, 0x5b, 0x80, 0xf2, 0x1a, 0x03, 0x01, 0x51, 0x56, 0x72, 0x60, 0x96, 0xfd, 0x33, 0x5e, 0x5e,
        0x67, 0xf2, 0xdb, 0xf1, 0x02, 0x70, 0x2e, 0x60, 0x8c, 0xca, 0xe6, 0xbe, 0xc1, 0xfc, 0x63, 0xa4,
        0x2a, 0x99, 0xbe, 0x5c, 0x3e, 0xb7, 0x10, 0x7c, 0x3c, 0x54, 0xe9, 0xb9, 0xeb, 0x2b, 0xd5, 0x20,
        0x3b, 0x1c, 0x3b, 0x84, 0xe0, 0xa8, 0xb2, 0xf7, 0x59, 0x40, 0x9b, 0xa3, 0xea, 0xc9, 0xd9, 0x1d,
        0x40, 0x2d, 0xcc, 0x0c, 0xc8, 0xf8, 0x96, 0x12, 0x29, 0xac, 0x91, 0x87, 0xb4, 0x2b, 0x4d, 0xe1 };

    static const uchar s_pubKey[128] = {
        0xb4, 0xbb, 0x49, 0x8f, 0x82, 0x79, 0x30, 0x3d, 0x98, 0x08, 0x36, 0x39, 0x9b, 0x36, 0xc6, 0x98,
        0x8c, 0x0c, 0x68, 0xde, 0x55, 0xe1, 0xbd, 0xb8, 0x26, 0xd3, 0x90, 0x1a, 0x24, 0x61, 0xea, 0xfd,
        0x2d, 0xe4, 0x9a, 0x91, 0xd0, 0x15, 0xab, 0xbc, 0x9a, 0x95, 0x13, 0x7a, 0xce, 0x6c, 0x1a, 0xf1,
        0x9e, 0xaa, 0x6a, 0xf9, 0x8c, 0x7c, 0xed, 0x43, 0x12, 0x09, 0x98, 0xe1, 0x87, 0xa8, 0x0e, 0xe0,
        0xcc, 0xb0, 0x52, 0x4b, 0x1b, 0x01, 0x8c, 0x3e, 0x0b, 0x63, 0x26, 0x4d, 0x44, 0x9a, 0x6d, 0x38,
        0xe2, 0x2a, 0x5f, 0xda, 0x43, 0x08, 0x46, 0x74, 0x80, 0x30, 0x53, 0x0e, 0xf0, 0x46, 0x1c, 0x8c,
        0xa9, 0xd9, 0xef, 0xbf, 0xae, 0x8e, 0xa6, 0xd1, 0xd0, 0x3e, 0x2b, 0xd1, 0x93, 0xef, 0xf0, 0xab,
        0x9a, 0x80, 0x02, 0xc4, 0x74, 0x28, 0xa6, 0xd3, 0x5a, 0x8d, 0x88, 0xd7, 0x9f, 0x7f, 0x1e, 0x3f };

    static const uchar s_priKey[128] = {
        0x04, 0xde, 0xa7, 0x05, 0xd4, 0x3a, 0x6e, 0xa7, 0x20, 0x9d, 0xd8, 0x07, 0x21, 0x11, 0xa8, 0x3c,
        0x81, 0xe3, 0x22, 0xa5, 0x92, 0x78, 0xb3, 0x34, 0x80, 0x64, 0x1e, 0xaf, 0x7c, 0x0a, 0x69, 0x85,
        0xb8, 0xe3, 0x1c, 0x44, 0xf6, 0xde, 0x62, 0xe1, 0xb4, 0xc2, 0x30, 0x9f, 0x61, 0x26, 0xe7, 0x7b,
        0x7c, 0x41, 0xe9, 0x23, 0x31, 0x4b, 0xbf, 0xa3, 0x88, 0x13, 0x05, 0xdc, 0x12, 0x17, 0xf1, 0x6c,
        0x81, 0x9c, 0xe5, 0x38, 0xe9, 0x22, 0xf3, 0x69, 0x82, 0x8d, 0x0e, 0x57, 0x19, 0x5d, 0x8c, 0x84,
        0x88, 0x46, 0x02, 0x07, 0xb2, 0xfa, 0xa7, 0x26, 0xbc, 0xf7, 0x08, 0xbb, 0xd7, 0xdb, 0x7f, 0x67,
        0x9f, 0x89, 0x34, 0x92, 0xfc, 0x2a, 0x62, 0x2e, 0x08, 0x97, 0x0a, 0xac, 0x44, 0x1c, 0xe4, 0xe0,
        0xc3, 0x08, 0x8d, 0xf2, 0x5a, 0xe6, 0x79, 0x23, 0x3d, 0xf8, 0xa3, 0xbd, 0xa2, 0xff, 0x99, 0x41 };

    // This is ServerCallback
    unsigned int ret = 0;
    switch (pCBData->cbType) {
    case TlsCBData::CB_SERVER_NAME: {
        const uchar* p = (const uchar*)pCBData->data.ptrs[0];
        uint32_t slen = pCBData->data.rawSize[1];
        if (slen != strlen(MyTestContext::server_name_)) ret = -1;
        ret |= memcmp(p, MyTestContext::server_name_, slen);
        if (ret) {
            printf("Error. Debug me!");
        }
        }
        break;
    case TlsCBData::CB_RANDOM: {
        static const uchar s_clientRandom[32] = { // https://tools.ietf.org/html/rfc8448#section-3
            0xa6, 0xaf, 0x06, 0xa4, 0x12, 0x18, 0x60, 0xdc, 0x5e, 0x6e, 0x60, 0x24, 0x9c, 0xd3, 0x4c, 0x95,
            0x93, 0x0c, 0x8a, 0xc5, 0xcb, 0x14, 0x34, 0xda, 0xc1, 0x55, 0x77, 0x2e, 0xd3, 0xe2, 0x69, 0x28 };
        memcpy(pCBData->data.ptrs[0], s_clientRandom, 32); break; }

    case TlsCBData::CB_SERVER_CIPHER:
        // Set 1 if prefer ECDHE_ECDSA
        if (pCBData->data.rawInt[1] == TLS_AES_128_GCM_SHA256) {
            pCBData->data.rawInt[1] = pCBData->data.rawInt[0];
            pCBData->data.rawInt[0] = TLS_AES_128_GCM_SHA256;
        }
        break;

    case TlsCBData::CB_SUPPORTED_GROUPS:
        pCBData->data.rawInt[0] = ECC_x25519;    // Supported Group: x25519 (0x001d)
        pCBData->data.rawInt[1] = ECC_secp256r1; // Supported Group: secp256r1(0x0017)
        pCBData->data.rawInt[2] = ECC_secp384r1; // Supported Group: secp384r1 (0x0018)
        pCBData->data.rawInt[3] = ECC_secp521r1; // Supported Group: secp521r1 (0x0019)
        pCBData->data.rawInt[4] = ECC_ffdhe2048; // Supported Group: ffdhe2048 (0x0100) RFC7919
        pCBData->data.rawInt[5] = ECC_ffdhe3072; // Supported Group: ffdhe3072 (0x0101) RFC7919
        pCBData->data.rawInt[6] = ECC_ffdhe4096; // Supported Group: ffdhe4096 (0x0102) RFC7919
        pCBData->data.rawInt[7] = ECC_ffdhe6144; // Supported Group: ffdhe6144 (0x0103) RFC7919
        pCBData->data.rawInt[8] = ECC_ffdhe8192; // Supported Group: ffdhe8192 (0x0104) RFC7919
        ret = 9; // Only 9 entries of supported ECC groups
        break;

    case TlsCBData::CB_SERVER_CERTS:
        pCBData->data.ptrs[0] = static_cast<void*>(s_Certificate); // Pointers to certs one by one.
        pCBData->data.ptrs[1] = nullptr; // After last one, the pointer is set to nullptr to end.
        break;

    case TlsCBData::CB_SERVER_KEYPAIR:
        pCBData->data.ptrs[0] = (void*)s_pubKey;
        pCBData->data.ptrs[1] = (void*)s_priKey;
        pCBData->data.ptrs[2] = (void*)s_Certificate;
        pCBData->data.ptrs[3] = (void*)ECC_NONE; // (void*)ECC_secp256r1 if using ECC ECDSA P256
        pCBData->data.ptrs[4] = nullptr;
        ret = 128; // RSA 1024 bits key.
        break;
    case TlsCBData::CB_ECDHE_PUBLICKEY:
        // pCBData->data.ptrs[0] will be the ECC public key
        // pCBData->data.rawSize[1] is the ECC_GROUP.
        ret = ECC_x25519; // Returns the ECC_GROUP to be used. Or 0 for no change.
        break;
    case TlsCBData::CB_ECDHE_PRIVATEKEY: {
        // pCBData->data.ptrs[0] is the ephemeral ECC private key
        // pCBData->data.rawSize[1] is the ECC_GROUP which should also be returned.
        static const uchar s_privKey[32] = { // Page 5: https://tools.ietf.org/html/rfc8448#section-3
            0xb1, 0x58, 0x0e, 0xea, 0xdf, 0x6d, 0xd5, 0x89, 0xb8, 0xef, 0x4f, 0x2d, 0x56, 0x52, 0x57, 0x8c,
            0xc8, 0x10, 0xe9, 0x98, 0x01, 0x91, 0xec, 0x8d, 0x05, 0x83, 0x08, 0xce, 0xa2, 0x16, 0xa2, 0x1e };
        memcpy(pCBData->data.ptrs[0], s_privKey, sizeof(s_privKey));
        ret = pCBData->data.rawSize[1] = ECC_x25519; // // Return 0 for no change proposed.
        break; }

    case TlsCBData::CB_SESSIONTICKET_TLS:
        ret = 0;  break;

    case TlsCBData::CB_NEW_SESSION_TICKET:
        ret = 0; break;
    }

    return ret;
}


static uint MyMockRand()
{
    static uint sCnt = 0;
    static uint it = 0x12345679;
    it += (it >> 5) + (it * 1001);
    sCnt++;
    return it;
}

static void InitializeCerts(const CIPHERSET& cset)
{
    CERT* pRoot;
    uint len;
    CERT_STATUS eStatus = CS_UNKNOWN;

    StartCerts(malloc, free, &cset);

    pRoot = CreateCert(CS_ROOT, 0);
    len = ParseCert(pRoot, gGeoTrustRoot, sizeof(gGeoTrustRoot));
    assert(len == sizeof(gGeoTrustRoot));
    eStatus = AuthenticateCert(pRoot, NULL);
    assert(eStatus == (CS_ROOT | CS_SELF | CS_OK | CS_VERIFIED));
    InsertCert(pRoot, NULL);

    CERT* pRoot2 = CreateCert(CS_ROOT, 0);
    len = ParseCert(pRoot2, gRootCert1, CERT_SIZE(gRootCert1));
    assert(len == CERT_SIZE(gRootCert1));
    eStatus = AuthenticateCert(pRoot2, NULL);
    assert(eStatus == (CS_ROOT | CS_SELF | CS_OK | CS_VERIFIED));
    InsertCert(pRoot2, NULL);

    CERT* pRoot3 = CreateCert(CS_ROOT, 0);
    len = ParseCert(pRoot3, gRootCert2, CERT_SIZE(gRootCert2));
    assert(len == CERT_SIZE(gRootCert2));
    eStatus = AuthenticateCert(pRoot3, NULL);
    assert(eStatus == (CS_ROOT | CS_SELF | CS_OK | CS_VERIFIED));
    InsertCert(pRoot3, NULL);
}

uint32_t rfc8448_test(const CIPHERSET& cset)
{
    int i, ret = 0;
    MockSock cSock, sSock, &Listen(*(MockSock*)nullptr); // client and server sock
    uint32_t nTime(0x5C0B0980), nTime2(nTime);
    const bool isClient = true, isServer = false;
    MyTestContext testCtx(cset.sha256);

    InitializeCerts(cset);

    static const char msg1[] = "Hello this is client";
    static const char msg2[] = "Hello this is server";

    sSock.Accept(*(const TcpSock*)NULL);

    BaseTls::SetRandFunc(MockSock::MockRand);

    BaseTls* clt = CreateTls(cSock, cset, nTime, isClient, ClientCallback, &testCtx);
    BaseTls* svr = CreateTls(sSock, cset, nTime, isServer, ServerCallback, &testCtx);

    uchar len = 0;
    uchar inMsg[1024];

    for (i = 0; i < 8; i++) {
        // By the time i == 2 both client and server should be connected. But we test at i=3.
        if (i == 3) {
            clt->Write((const uchar*)msg1, strlen(msg1));
        }
        clt->Work(nTime); ++testCtx;
        if (i == 5) {
            len = clt->Read(inMsg, 1024);
            if (len != strlen(msg2)) {
                printf("Server send to client FAILURE\n"); break;
            } if (memcmp(msg2, inMsg, strlen(msg2))) {
                printf("Server send to client CORRUPT\n"); break;
            } else {
                printf("Server send to client CORRECT\n");
            }
        }
        if (ret |= testCtx.Validate()) break;
        svr->Work(nTime2); ++testCtx;
        if (ret |= testCtx.Validate()) break;
        if (i == 3) {
            len = svr->Read(inMsg, 1024);
            if (len != strlen(msg1)) {
                printf("Client send to server FAILURE\n"); break;
            } if (memcmp(msg1, inMsg, strlen(msg1))) {
                printf("Client send to server CORRUPT\n"); break;
            } else {
                printf("Client send to server CORRECT\n");
            }

            // Let server try to send to client as well.
            svr->Write((const uchar*)msg2, strlen(msg2));
        }
    }

    //CleanupCerts(NULL); // This should be done by main app.

    printf("RFC8448 Integrity test %s\n", (i == 8) ? "SUCCESS" : "FAILURE");

    return (i^8);
}
