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
*  File Name:       x509.cpp
*
*  Description:     ASN1 encoding wrapper.
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         2/18/2019 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <stdint.h>

#ifdef __linux__
typedef __SIZE_TYPE__ size_t;
#endif //__linux__

#include "x509.h"
#include "oid.h"

using X509::X509v3;
using X509::X509Callback;

namespace X509 {

size_t X509NAME::totalSize() const
{
    size_t n = 0, i = 0;
    if (country) { for (i = 0; country[i]; i++); n += i; n += 11; }
    if (state)   { for (i = 0; state[i]; i++); n += i; n += 11; }
    if (local)   { for (i = 0; local[i]; i++); n += i; n += 11; }
    if (company) { for (i = 0; company[i]; i++); n += i; n += 11; }
    if (unitname) { for (i = 0; unitname[i]; i++); n += i; n += 11; }
    if (commonname) { for (i = 0; commonname[i]; i++); n += i; n += 11; }
    return n;
}

class tbsCertificate : public ASN::Seq2 {public: tbsCertificate(pu8& s, X509Callback cb, void* ctx, OID eOid);};
class signatureAlgorithm : public ASN::Seq0 { public: signatureAlgorithm(pu8& s, OID eOid); };
class signatureValue { public: signatureValue(pu8& s, const u8* pSign, size_t n); };
class x509Id : public ASN::Seq { public: x509Id(pu8& s, const X509NAME& name); };

x509Id::x509Id(pu8& s, const X509NAME& name) : Seq(s, name.totalSize()) {
    {ASN::Set idSet(p_); {ASN::Seq0 sq(idSet); {{ASN::Oid oid(sq, OID_NAME_COUNTRY);} {ASN::Pstr pstr(sq, name.country);}}}}
    {ASN::Set idSet(p_); {ASN::Seq0 sq(idSet); {{ASN::Oid oid(sq, OID_NAME_STATE);} {ASN::Pstr pstr(sq, name.state); }}}}
    {ASN::Set idSet(p_); {ASN::Seq0 sq(idSet); {{ASN::Oid oid(sq, OID_NAME_LOCAL);} {ASN::Pstr pstr(sq, name.local); }}}}
    {ASN::Set idSet(p_); {ASN::Seq0 sq(idSet); {{ASN::Oid oid(sq, OID_NAME_ORG); }  {ASN::Pstr pstr(sq, name.company); }}}}
    {ASN::Set idSet(p_); {ASN::Seq0 sq(idSet); {{ASN::Oid oid(sq, OID_NAME_UNIT);}  {ASN::Pstr pstr(sq, name.unitname); }}}}
    {ASN::Set idSet(p_); {ASN::Seq0 sq(idSet); {{ASN::Oid oid(sq, OID_NAME_COMMON);} {ASN::Pstr pstr(sq, name.commonname);}}}}
}

signatureAlgorithm::signatureAlgorithm(pu8& s, OID eOid) : Seq0(s)
{
    {ASN::Oid oid(p_, eOid); }
    {ASN::NullTag nullTag(p_); }
}

signatureValue::signatureValue(pu8& s, const u8* pSign, size_t n)
{
    if (n >= 256) {
        ASN::Bstr2 bstr(s);
        while (n-- > 0) *bstr++ = *pSign++;
    } else {
        ASN::Bstr bstr(s); {
            ASN::Seq0 seq(bstr);
            {ASN::Intb r(seq, pSign, 0x20);}
            {ASN::Intb s(seq, pSign+0x20, 0x20); }
        }
    }
}

// nSecs is number of seconds since 01/01 00:00:00 UTC
uint SetUTC(u8* p, uint32_t nSecs)
{
    const uchar* p0 = p;
    uint days, secs, n;
    uint year, month, day, hour, minute, second;

    // Calculate time from 01/01/2000 00:00:00 UTC
    days = nSecs / 86400;
    secs = nSecs - (days * 86400);

    // Convert to baseline 01/01/2000 00:00:00 UTC
    days -= 10957; // Days between 01/01/1970 and 01/01/2000

    minute = (secs / 60); second = secs - (minute * 60);
    hour = (minute / 60); minute -= (hour * 60);

    year = (days / 1461);
    days -= year * 1461;
    year <<= 2;

    if (days >= 60) {
        days -= 1;
        year += n = (days / 365);
        days -= n * 365;
        if (days >= 59) days += 2; // Pretend Feb is 30 days vs 28
    }

    month = (days * 12 + 7) / 367;
    day = days - ((month * 367 + 5) / 12);
    month++; day++;

    // Now format the UTC string
    *p++ = '0' + (year / 10); *p++ = '0' + year - ((year / 10) * 10);
    *p++ = '0' + (month / 10); *p++ = '0' + month - ((month / 10) * 10);
    *p++ = '0' + (day / 10);  *p++ = '0' + day - ((day / 10) * 10);
    *p++ = '0' + (hour / 10); *p++ = '0' + hour - ((hour / 10) * 10);
    *p++ = '0' + (minute / 10); *p++ = '0' + minute - ((minute / 10) * 10);
    *p++ = '0' + (second / 10); *p++ = '0' + second - ((second / 10) * 10);
    *p++ = 'Z';

    return (p - p0);
}

tbsCertificate::tbsCertificate(pu8& s, X509Callback cb, void* ctx, OID eOid) : Seq2(s)
{
    CB_DATA cbData;
    cbData.eType = X509::x509CB(0);  cbData.nInSize = 0; cbData.pIn = nullptr; cbData.pOut = nullptr;

    //TBSCertificate  :: = SEQUENCE{
    //    version[0]  EXPLICIT Version DEFAULT v1,
    { ASN::Version ver(p_); }

    //    serialNumber         CertificateSerialNumber,
    uint64_t serial_num = 0; // Obtain the serial number from callback
    cbData.eType = CB_SERIAL; cbData.pOut = &serial_num; cb(ctx, cbData);
    { ASN::Int ser(p_, serial_num); }

    //    signature            AlgorithmIdentifier
    {signatureAlgorithm   AlgorithmIdentifier(p_, eOid); }

    //    issuer               Name,
    X509NAME issuer{nullptr, nullptr, nullptr, nullptr, nullptr, nullptr};
    cbData.eType = CB_ISSUER_NAME; cbData.pOut = &issuer; cb(ctx, cbData);
    {x509Id               issuerName(p_, issuer); }

    //    validity             Validity,
    uint32_t nIssueTime=0, nExpireTime=0;
    cbData.pOut = nullptr;
    cbData.eType = CB_ISSUE_TIME;  nIssueTime  = cb(ctx, cbData);
    cbData.eType = CB_EXPIRE_TIME; nExpireTime = cb(ctx, cbData);
    {ASN::Seq0 timeStamp(p_); {
    {ASN::Utc issueTime(timeStamp); issueTime += SetUTC(issueTime, nIssueTime); }
    {ASN::Utc expireTime(timeStamp); expireTime += SetUTC(expireTime, nExpireTime); }}}

    //    subject              Name,
    X509NAME subject{ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr };
    cbData.eType = CB_SUBJECT_NAME; cbData.pOut = &subject; cb(ctx, cbData);
    {x509Id               subjectName(p_, subject); }

    //    subjectPublicKeyInfo SubjectPublicKeyInfo,
    const u8* pKey = nullptr;
    cbData.eType = CB_PKEY_INFO; cbData.pOut = &pKey; OID eType = OID(cb(ctx, cbData));
    {ASN::PubKey pubKeyInfo(p_, eType, pKey); }

    //    issuerUniqueID[1]  IMPLICIT UniqueIdentifier OPTIONAL,
    //    --If present, version MUST be v2 or v3

    // Certificate extensions. http://www.oid-info.com/get/2.5.29
    {ASN::Ext extensions(p_); {ASN::Seq0 seq(extensions); {
        cbData.pIn = cbData.pOut = nullptr; cbData.nInSize = 0;
        cbData.eType = CB_KEY_USAGE; uint nKeyUsage = cb(ctx, cbData);
        if (nKeyUsage) {
            ASN::Seq0 sq(&seq); {
                {ASN::Oid  oid(sq, OID_X509V3_KEY_USAGE); }
                {ASN::Bool b(sq, true); }
                {ASN::Oct  o(sq); {ASN::Bstr bs(o); *bs++ = u8(nKeyUsage); } }
            }
        }
        cbData.eType = CB_BASIC_CONSTRAINT; uint nBasicConstraint = cb(ctx, cbData);
        if (nBasicConstraint) {
            ASN::Seq0 sq(&seq); {
                {ASN::Oid  oid(sq, OID_X509V3_BASIC_CONSTRAINTS); }
                {ASN::Bool b(sq, true); }
                {ASN::Oct  o(sq); {ASN::Seq0 s(o); {ASN::Bool b(s, true);  ASN::Int in(s, uint32_t(0)); }}}
            }
        }
        const char* pAltName = nullptr; cbData.pOut = &pAltName; cbData.eType = CB_SUBJECT_ALTNAME;
        if (cb(ctx, cbData) && pAltName != nullptr) {
            ASN::Seq0 sq(&seq); {
                {ASN::Oid  oid(sq, OID_X509V3_SUBJECT_ALTNAME); }
                {ASN::Bool b(sq, true); }
                {ASN::Oct  o(sq); {ASN::Seq0 s(o);
                do {
                    ASN::Altn dn(s, pAltName); pAltName = nullptr;
                } while (cb(ctx, cbData) && pAltName != nullptr);
                }}
            }
        }
    }}}
}

// RFC5288 for X509 v3 digital certificate https://tools.ietf.org/html/rfc5280
X509v3::X509v3(pu8& s, X509Callback cb, void* ctx) : Seq2(s)
{
    CB_DATA cbData;
    cbData.eType = x509CB(0);  cbData.nInSize = 0; cbData.pIn = nullptr; cbData.pOut = nullptr;

    // Obtain signature algorithm.
    cbData.eType = CB_ALGORITHM;
    OID eOid = OID(cb(ctx, cbData));

    //Certificate  :: = SEQUENCE{
    cbData.eType = CB_HASH; cbData.pIn = p_;
    //    tbsCertificate       TBSCertificate,
    {tbsCertificate       TBSCertificate(p_, cb, ctx, eOid); }
    cbData.nInSize = p_ - pu8(cbData.pIn);

    //    signatureAlgorithm   AlgorithmIdentifier,
    {signatureAlgorithm   AlgorithmIdentifier(p_, eOid); }

    u8 digest[32]; cbData.pOut = digest; cbData.nInSize = cb(ctx, cbData);
    u8 sign[256]; pu8 p = sign; size_t n = SetOID(sign, OID_DIGEST_SHA256); // eOid
    n = 256 - n - 32 - 11; for (size_t i = 0; i < n; i++) sign[i] = 0xFF;
    sign[0] = 0x00; sign[1] = 0x01; p = sign + n; *p++ = 0x00;
    {ASN::Seq0 seq(p);
    {ASN::Seq0 s2(&seq);
    {ASN::Oid oid(s2, OID_DIGEST_SHA256); } // eOid
    {ASN::NullTag nullTag(s2); }}
    {ASN::Oct oct(seq); oct += 32; }}
    cbData.pIn = digest; cbData.pOut = sign;
    cbData.eType = CB_SIGN; cbData.nInSize = cb(ctx, cbData);

    //    signatureValue       BIT STRING }
    {signatureValue       SignatureValue(p_, sign, cbData.nInSize); }
}

} // namespace X509