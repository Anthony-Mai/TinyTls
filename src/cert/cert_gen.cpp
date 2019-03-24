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
*  File Name:       cert_gen.cpp
*
*  Description:     X.509 digital certificate generation code.
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         2/18/2019 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "cert_gen.h"

#include "x509.h"
#include "cipher.h"
#include "ecc_p256.h"
#include "ssl_defs.h"

using ASN::Asn;
using ASN::Asn0;
using ASN::Int;
using ASN::Seq0;
using ASN::Seq1;
using ASN::Seq2;

using X509::X509v3;
using X509::CB_DATA;


class MyCertSet {
public:
    const CIPHERSET& cset_;

    const KEYPAIR& caKeyPair_;
    const KEYPAIR& subPubKey_;
    const X509::X509NAME& issuer_;
    const X509::X509NAME& subject_;
    const char** altNames_;
    uint32_t issueTime_;
    uint32_t expireTime_;
    uint64_t serial_;
    uint32_t n_;

    MyCertSet(const CIPHERSET& c, const KEYPAIR& caKeyPair, const KEYPAIR& subPubKey, const X509::X509NAME& ca, const X509::X509NAME& sub, const char* names[], uint32_t isTime, uint32_t exTime, uint64_t sn)
        : cset_(c), caKeyPair_(caKeyPair), subPubKey_(subPubKey), issuer_(ca), subject_(sub), altNames_(names), issueTime_(isTime), expireTime_(exTime), n_(0), serial_(sn) {}
};


static uint myCallback(void* context, const CB_DATA& cbData)
{
    MyCertSet& myCertSet(*static_cast<MyCertSet*>(context));
    switch (cbData.eType) {
    case X509::CB_ALGORITHM:
        return (myCertSet.caKeyPair_.nEccGroup)? OID_HASH_SHA256_ECDSA : OID_HASH_SHA256_RSA;
    case X509::CB_SERIAL:
        *((uint64_t*)cbData.pOut) = myCertSet.serial_;
        return 0;
    case X509::CB_HASH:
    {
        const CIPHERSET& c(((MyCertSet*)context)->cset_);
        const CIPHER& s(c.sha256);
        s.Hash((const uchar*)cbData.pIn, cbData.nInSize, (uchar*)cbData.pOut);
    }
    break;

    case X509::CB_SUBJECT_NAME:
    {
        X509::X509NAME& name(*reinterpret_cast<X509::X509NAME*>(cbData.pOut));
        name = myCertSet.subject_;
        return 0;
    }

    case X509::CB_ISSUER_NAME:
    {
        X509::X509NAME& name(*reinterpret_cast<X509::X509NAME*>(cbData.pOut));
        name = myCertSet.issuer_;
        return 0;
    }

    case X509::CB_ISSUE_TIME:
        return myCertSet.issueTime_;
    case X509::CB_EXPIRE_TIME:
        return myCertSet.expireTime_;
    case X509::CB_PKEY_INFO:
        *((void**)cbData.pOut) = (void*)reinterpret_cast<const void*>(myCertSet.subPubKey_.pPubKey);
        if (myCertSet.subPubKey_.nEccGroup) {
            return OID_ECCGROUP_SECP256R1;
        } else {
            return OID_PUBKEY_RSA;
        }
        break;
    case X509::CB_KEY_USAGE:
        if (myCertSet.subPubKey_.pPubKey == myCertSet.caKeyPair_.pPubKey) {
            return (KEYUSAGE_DIGITALSIGNATURE | KEYUSAGE_KEYCERTSIGN | KEYUSAGE_CRLSIGN);
        } else {
            return KEYUSAGE_DIGITALSIGNATURE;
        }
    case X509::CB_BASIC_CONSTRAINT:
        return 1;
    case X509::CB_SUBJECT_ALTNAME:
    {
        uint32_t n = myCertSet.n_;
        *((const char**)cbData.pOut) = myCertSet.altNames_[n];
        if (myCertSet.altNames_[n]) {
            myCertSet.n_++; return 1;
        } else {
            myCertSet.n_ = 0; return 0;
        }
    }
    break;
    case X509::CB_SIGN:
        if (myCertSet.caKeyPair_.nEccGroup) {
            // Generate a ECC signature using the input cbData.pIn of 32 bytes.
            P256::ECDSign sig;
            NN secKey; secKey.bytesIn(myCertSet.caKeyPair_.pPriKey);
            uchar nc[32];
            {
                const CIPHER& sha(myCertSet.cset_.sha256);
                CTX  ctx;
                sha.Hash((const uchar*)cbData.pIn, 32, nc);
                sha.Init(&ctx, NULL);
                sha.Input(&ctx, myCertSet.caKeyPair_.pPriKey, 32);
                sha.Input(&ctx, nc, 32);
                sha.Digest(&ctx, nc);
            }
            sig.Sign((const uchar*)cbData.pIn, nc, secKey);
            uchar* pMsg = (uchar*)cbData.pOut;
            sig.OutR(pMsg); pMsg += 0x20;
            sig.OutS(pMsg); pMsg += 0x20;
            return (pMsg - (uchar*)cbData.pOut);
        } else {
            memcpy((pu8)cbData.pOut+256-32, cbData.pIn, 32);
            myCertSet.cset_.rsa.RsaDecrypt((pu8)cbData.pOut, myCertSet.caKeyPair_.pPubKey, myCertSet.caKeyPair_.pPriKey, 256);
            return 256;
        }
    default:
        break;
    }
    return 0;
}

#include "cert.h"

// https://letsencrypt.org/2018/04/04/sct-encoding.html
// $ openssl x509 -noout -text -inform der -in Downloads/031f2484307c9bc511b3123cb236a480d451

const uint8_t* certGen(
    const CIPHERSET* cipherSet,
    const KEYPAIR* pCaKeyPair, // Issuer kerpair including public and private key.
    const KEYPAIR* pSubPubKey, // The private key portion is not set and not used.
    const X509::X509NAME* issuer,
    const X509::X509NAME* subject,
    const char* altNames[],
    uint32_t issueTime,
    uint32_t expireTime,
    uint64_t serial_num
)
{
    static u8 tmp[2048];
    u8* p0 = tmp;
    u8* p = p0;
    uint32_t n= 0;

    MyCertSet myCertSet(*cipherSet, *pCaKeyPair, *pSubPubKey, *issuer, *subject, altNames, issueTime, expireTime, serial_num);

    memset(tmp, 0, sizeof(tmp));

    uint nSize = 0, nCurTime = 0x5c68d200;

    {
        X509v3 cer(p, myCallback, &myCertSet);
        nSize = cer.size();
    }
    return tmp;
/*
    {
        FILE* fout = fopen(certName, "wb");
        fwrite(tmp, 1, nSize, fout);
        fclose(fout);
    }
    {
        CERT* pCert = CreateCert(CS_ROOT, nCurTime);
        uint nParsed = ParseCert(pCert, tmp, nSize);
        CERT_STATUS status = AuthenticateCert(pCert, NULL);

        status = status;
    }

    return 0;
*/
}
