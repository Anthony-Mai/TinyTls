/******************************************************************************
*
* Copyright © 2019 Anthony Mai Mai_Anthony@hotmail.com. All Rights Reserved.
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
*  File Name:       certgen_test.cpp
*
*  Description:     X.509 digital certificate generation test code.
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         2/18/2019 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#ifdef _WIN32
#include <windows.h>
#endif _WIN32
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "certgen_test.h"
#include "cert_gen.h"
#include "x509.h"
#include "hmac.h"
#include "cipher.h"
#include "BN.h"
#include "ssl_defs.h"
#include "cert.h"
#include "ecc_p256.h"

extern const CIPHERSET* gpCipherSet;

static uint myConsistentRand()
{
    static uint it = 12345;
    static const char myKey[] = "Tiny TLS Certificate";
    static const char myLabel[] = "03/28/2019 12:00:00pm";
    static uint buff[16];
    static PrfHash prf(gpCipherSet->sha256, (const uchar*)myKey, strlen(myKey), (const uchar*)myLabel, strlen(myLabel));

    for (; it >= 16; it -= 16) {
        prf.Output((uchar*)buff, sizeof(buff));
    }

    return buff[it++];
}

uint getCurTime()
{
    uint curTime = 0x5C800000;
#ifdef _WIN32
    SYSTEMTIME stime;
    GetSystemTime((LPSYSTEMTIME)&stime);

    curTime = ((stime.wMonth + 10) * 367) / 12;
    curTime += (stime.wYear * 1461) >> 2;
    curTime -= (0 - (stime.wMonth > 2))&((8 - (stime.wYear & 3)) >> 2);
    curTime += stime.wDay;
    curTime -= 719879; // Epoch
    curTime *= 24; curTime += stime.wHour;
    curTime *= 60; curTime += stime.wMinute;
    curTime *= 60; curTime += stime.wSecond;
#endif //_WIN32
    return curTime;
}

int do_CertGenTest(const CIPHERSET& cipherSet)
{
    X509::X509NAME issuer;
    X509::X509NAME subject;
    KEYPAIR isKeyPair, subPubKey;
    uchar cpubKey[256];
    uchar cpriKey[256];
    uchar spubKey[256];
    uchar spriKey[256];
    uchar spubEcc[64];
    uchar spriEcc[32];

    memset(cpubKey, 0, sizeof(cpubKey));
    memset(cpriKey, 0, sizeof(cpriKey));

    // First generate a root RSA keypair.
    BN_KeyGen(myConsistentRand, 65537, 256, spubKey, spriKey);

    // Second generate a root ECC keypair.
    {
        // Generate a server ECC KeyPair.
        P256::ECDKeyPair kp;

        kp.Create(myConsistentRand);
        kp.priKey.bytesOut(spriEcc);
        kp.pubKey.x.netOut(spubEcc);
        kp.pubKey.y.netOut(spubEcc + 0x20);
    }

    // Third generate a server ECC keypair.
    {
        // Generate a ECC KeyPair.
        P256::ECDKeyPair kp;

        kp.Create(myConsistentRand);
        kp.priKey.bytesOut(cpriKey);
        kp.pubKey.x.netOut(cpubKey);
        kp.pubKey.y.netOut(cpubKey + 0x20);
    }

    // Set up the root CA identity.
    issuer.country = "US";
    issuer.state = "CA";
    issuer.local = "San Jose";
    issuer.company = "Tiny TLS Technology";
    issuer.unitname = "Secure Certificate Authority";
    issuer.commonname = "Tiny Root Authority V1.0";

    // Set up serevr subject identity
    subject.country = "US";
    subject.state = "CA";
    subject.local = "Mountain View";
    subject.company = "Newbie Blockchain Startup Inc.";
    subject.unitname = "Amazing ZK Stark Security";
    subject.commonname = "blockchain.server.com";

    // This is used by the root CA which does not have alternative names.
    const char* altNames1[] = { nullptr };
    // This is used by the server certificate who needs the alt names.
    const char* altNames2[] = { "127.0.0.*", "10.0.0.*", nullptr };

    uint64_t rootSerial = 0x0100000000000001llu;
    uint64_t serverSerial = 0x0100000000001234llu;

    uint32_t nCurTime = getCurTime();

    isKeyPair.pPriKey = spriKey;
    isKeyPair.pPubKey = spubKey;
    isKeyPair.nEccGroup = ECC_NONE; // For RSA certificate.

    subPubKey.pPriKey = cpriKey;
    subPubKey.pPubKey = cpubKey;
    subPubKey.nEccGroup = ECC_secp256r1; // For ECC Using P256

    uint iTime1 = 0x50D4C2A5, eTime1 = 0x70DBD87F;
    uint iTime2 = 0x5C19560A, eTime2 = 0x6EFAA4FF;

    // First generate an RSA root certificate.
    const uint8_t* pRootCert = certGen(
        &cipherSet, &isKeyPair, &isKeyPair, &issuer, &issuer, altNames1, iTime1, eTime1, rootSerial);
    uint nCertSize = CERT_SIZE(pRootCert);
    {
        CERT* pCert = CreateCert(CS_ROOT, nCurTime);
        uint nParsed = ParseCert(pCert, pRootCert, nCertSize);
        CERT_STATUS status = AuthenticateCert(pCert, NULL);
        printf("Root Certificate Status 0x%02X %s\n", status, (status == (CS_OK | CS_VERIFIED | CS_ROOT | CS_SELF)) ? "OK" : "BAD");
        InsertCert(pCert, nullptr);
    }
    if (1) {
        FILE* fout = fopen("TinyTlsRoot001.cer", "wb");
        fwrite(pRootCert, 1, nCertSize, fout);
        fclose(fout);
        // TODO: Save spriKey some where for later use. Without you do not own the root cert.
    }

    // Second generate a ECC server certificate signed by the RSA root certificate.
    const uint8_t* pServerCert = certGen(
        &cipherSet, &isKeyPair, &subPubKey, &issuer, &subject, altNames2, iTime2, eTime2, serverSerial);
    uint nCertSize2 = CERT_SIZE(pServerCert);
    {
        CERT* pCert2 = CreateCert(CS_UNKNOWN, nCurTime);
        uint nParsed = ParseCert(pCert2, pServerCert, nCertSize2);
        CERT_STATUS status = AuthenticateCert(pCert2, NULL);
        printf("Server Certificate Status 0x%02X %s\n", status, (status == (CS_OK | CS_VERIFIED)) ? "OK" : "BAD");
        DestroyCert(pCert2);
    }
    if (1) {
        FILE* fout = fopen("TinyTlsServer001.cer", "wb");
        fwrite(pServerCert, 1, nCertSize2, fout);
        fclose(fout);
        // TODO: Save cpriKey some where for later use. Without you do not own the server cert.
    }

    // Replace RSA root keypair with ECC root keypair.
    isKeyPair.pPriKey = spriEcc;
    isKeyPair.pPubKey = spubEcc;
    isKeyPair.nEccGroup = ECC_secp256r1; // For ECC Using P256

    issuer.commonname = "Tiny Root Authority V1.1";

    // Third generate an ECC root certificate.
    pRootCert = certGen(
        &cipherSet, &isKeyPair, &isKeyPair, &issuer, &issuer, altNames1, iTime1, eTime1, rootSerial+1);
    nCertSize = CERT_SIZE(pRootCert);
    {
        CERT* pCert = CreateCert(CS_ROOT, nCurTime);
        uint nParsed = ParseCert(pCert, pRootCert, nCertSize);
        CERT_STATUS status = AuthenticateCert(pCert, NULL);
        printf("ECC Root Certificate Status 0x%02X %s\n", status, (status == (CS_OK | CS_VERIFIED | CS_ROOT | CS_SELF)) ? "OK" : "BAD");
        InsertCert(pCert, nullptr);
    }
    if (1) {
        FILE* fout = fopen("TinyTlsRoot002.cer", "wb");
        fwrite(pRootCert, 1, nCertSize, fout);
        fclose(fout);
        // TODO: Save spriKey some where for later use. Without you do not own the root cert.
    }

    // Fourth generate an ECC server certificate signed by a ECC root certificate.
    pServerCert = certGen(
        &cipherSet, &isKeyPair, &subPubKey, &issuer, &subject, altNames2, iTime2, eTime2, serverSerial+1);
    nCertSize2 = CERT_SIZE(pServerCert);
    {
        CERT* pCert2 = CreateCert(CS_UNKNOWN, nCurTime);
        uint nParsed = ParseCert(pCert2, pServerCert, nCertSize2);
        CERT_STATUS status = AuthenticateCert(pCert2, NULL);
        printf("ECC Server Certificate Status 0x%02X %s\n", status, (status == (CS_OK | CS_VERIFIED)) ? "OK" : "BAD");
        DestroyCert(pCert2);
    }
    if (1) {
        FILE* fout = fopen("TinyTlsServer002.cer", "wb");
        fwrite(pServerCert, 1, nCertSize2, fout);
        fclose(fout);
        // TODO: Save cpriKey some where for later use. Without you do not own the server cert.
    }

    return 0;
}
