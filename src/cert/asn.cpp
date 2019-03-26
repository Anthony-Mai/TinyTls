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
*  File Name:       asn.cpp
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

#include <stdlib.h>
#include <stdint.h>

#include "asn.h"
#include "oid.h"


// Tag classes
#define CLASS_MASK          0xC0    // Bits 8 and 7
#define CLASS_UNIVERSAL     0x00    // 0 = Universal (defined by ITU X.680)
#define CLASS_APPLICATION   0x40    // 1 = Application
#define CLASS_CONTEXT       0x80    // 2 = Context-specific
#define CLASS_PRIVATE       0xC0    // 3 = Private

// Encoding type
#define FORM_MASK           0x20    // Bit 6
#define FORM_PRIMITIVE      0x00    // 0 = primitive
#define FORM_CONSTRUCTED    0x20    // 1 = constructed

// Universal tags
#define TAG_MASK		    0x1F    // Bits 5 - 1
#define TAG_ZERO            0x00    // Constructed [0]
#define TAG_EOC             0x00    //  0: End-of-contents octets
#define TAG_BOOLEAN         0x01    //  1: Boolean
#define TAG_INTEGER         0x02    //  2: Integer
#define TAG_BITSTRING       0x03    //  2: Bit string
#define TAG_OCTETSTRING     0x04    //  4: Byte string
#define TAG_NULLTAG         0x05    //  5: NULL
#define TAG_OID             0x06    //  6: Object Identifier
#define TAG_OBJDESCRIPTOR   0x07    //  7: Object Descriptor
#define TAG_EXTERNAL        0x08    //  8: External
#define TAG_REAL            0x09    //  9: Real
#define TAG_ENUMERATED      0x0A    // 10: Enumerated
#define TAG_EMBEDDED_PDV    0x0B    // 11: Embedded Presentation Data Value
#define TAG_UTF8STRING      0x0C    // 12: UTF8 string
#define TAG_SEQUENCE        0x10    // 16: Sequence/sequence of
#define TAG_SET             0x11    // 17: Set/set of
#define TAG_NUMERICSTRING   0x12    // 18: Numeric string
#define TAG_PRINTABLESTRING 0x13    // 19: Printable string (ASCII subset)
#define TAG_T61STRING       0x14    // 20: T61/Teletex string
#define TAG_VIDEOTEXSTRING  0x15    // 21: Videotex string
#define TAG_IA5STRING       0x16    // 22: IA5/ASCII string
#define TAG_UTCTIME         0x17    // 23: UTC time
#define TAG_GENERALIZEDTIME 0x18    // 24: Generalized time
#define TAG_GRAPHICSTRING   0x19    // 25: Graphic string
#define TAG_VISIBLESTRING   0x1A    // 26: Visible string (ASCII subset)
#define TAG_GENERALSTRING   0x1B    // 27: General string
#define TAG_UNIVERSALSTRING 0x1C    // 28: Universal string
#define TAG_BMPSTRING       0x1E    // 30: Basic Multilingual Plane/Unicode string

// X.509 spec: https://tools.ietf.org/html/rfc5280#section-4.1
#define TAG_V1              0x00    // 00: Version V1
#define TAG_V2              0x01    // 00: Version V2
#define TAG_V3              0x02    // 00: Version V3

#define INTEGER_TAG     (CLASS_UNIVERSAL|FORM_PRIMITIVE|TAG_INTEGER)
#define OID_TAG         (CLASS_UNIVERSAL|FORM_PRIMITIVE|TAG_OID)
#define SEQUENCE_TAG    (CLASS_UNIVERSAL|FORM_CONSTRUCTED|TAG_SEQUENCE)
#define NULL_TAG        (CLASS_UNIVERSAL|FORM_PRIMITIVE|TAG_NULLTAG)
#define BITSTRING_TAG   (CLASS_UNIVERSAL|FORM_PRIMITIVE|TAG_BITSTRING)
#define OCTETSTRING_TAG (CLASS_UNIVERSAL|FORM_PRIMITIVE|TAG_OCTETSTRING)
#define SET_TAG         (CLASS_UNIVERSAL|FORM_CONSTRUCTED|TAG_SET)
#define PRINTABLE_STRING_TAG    (CLASS_UNIVERSAL|FORM_PRIMITIVE|TAG_PRINTABLESTRING)
#define IA5STRING_TAG   (CLASS_UNIVERSAL|FORM_PRIMITIVE|TAG_IA5STRING)
#define UTF8STRING_TAG  (CLASS_UNIVERSAL|FORM_PRIMITIVE|TAG_UTF8STRING)

#define UTCTIME_TAG     (CLASS_UNIVERSAL|FORM_PRIMITIVE|TAG_UTCTIME)
#define GENTIME_TAG     (CLASS_UNIVERSAL|FORM_PRIMITIVE|TAG_GENERALIZEDTIME)

#define EXTENSION_TAG   (CLASS_CONTEXT|FORM_CONSTRUCTED|TAG_BITSTRING)
#define VERSION_TAG     (CLASS_CONTEXT|FORM_CONSTRUCTED|TAG_ZERO)
#define DNAME_TAG       (CLASS_CONTEXT|FORM_PRIMITIVE|0x02)

using ASN::Asn;
using ASN::Asn1;
using ASN::Asn2;
using ASN::Asn3;
using ASN::Int;
using ASN::Intb;

Asn::Asn(const pu8& s) : po_(s), p0_(s), p_((pu8&)s)
{
}

Asn::Asn(pu8& s, u8 t, size_t n) : po_(s), p0_(s + 2 + (n >= 128) + (n >= 256)), p_((*s++ = t, *s++ = u8((n < 0x80)
    ? n : (n<0x100 ? (*s++ = 0x81, n) : (*s++ = (n<65536) ? 0x82 : u8(n >> 16), *s++ = u8(n >> 8), n))), s)) {}

Asn::~Asn() { if (po_ == p0_) return; size_t n = p_ - p0_; p0_[-1] = u8(n);
    if (n>65535) p0_[-3] = u8(n>>16); if (n>255) p0_[-2] = u8(n>>8); if (n>127) po_[1] = 0x7E + (p0_-po_); }

ASN::Seq::Seq(pu8& s, size_t n) : Asn(s, SEQUENCE_TAG, n) {}
ASN::Seq0::Seq0(pu8& s) : Asn0(s, SEQUENCE_TAG) {}
ASN::Seq1::Seq1(pu8& s) : Asn1(s, SEQUENCE_TAG) {}
ASN::Seq2::Seq2(pu8& s) : Asn2(s, SEQUENCE_TAG) {}

Int::Int(pu8& s, uint32_t v) : Asn0(s, INTEGER_TAG) {
    if (v > 0x80000000) *p_++ = 0x00;
    if (v > 0x800000) *p_++ = u8(v >> 24);
    if (v > 0x8000) *p_++ = u8(v >> 16);
    if (v > 0x80) *p_++ = u8(v >> 8);
    *p_++ = u8(v);
}

Int::Int(pu8& s, uint64_t v) : Asn0(s, INTEGER_TAG) {
    if (v >= 0x8000000000000000LLU) *p_++ = 0x00;
    if (v >= 0x80000000000000LLU) *p_++ = u8(v >> 56);
    if (v >= 0x800000000000LLU) *p_++ = u8(v >> 48);
    if (v >= 0x8000000000LLU) *p_++ = u8(v >> 40);
    if (v >= 0x80000000) *p_++ = u8(v>>32);
    if (v >= 0x800000) *p_++ = u8(v>>24);
    if (v >= 0x8000) *p_++ = u8(v>>16);
    if (v >= 0x80) *p_++ = u8(v>>8);
    *p_++ = u8(v);
}

Intb::Intb(pu8& s, const u8* pI, size_t nLen)
    : Asn(s, INTEGER_TAG, nLen +(*pI>0x7f))
{
    if (*pI >= 0x80) *p_++ = 0x00;
    while (nLen-- > 0) *p_++ = *pI++;
}

ASN::Oid::Oid(pu8& s, OID oid) : Asn0(s, OID_TAG) {
    p_ += SetOID(p_, (OID)oid);
}

ASN::NullTag::NullTag(pu8& s) : Asn0(s, NULL_TAG) {}

ASN::Version::Version(pu8& s) : Asn0(s, VERSION_TAG) { Int it(p_, uint32_t(TAG_V3)); }
ASN::Utc::Utc(pu8& s) : Asn0(s, UTCTIME_TAG) {}
ASN::Set::Set(pu8& s) : Asn0(s, SET_TAG) {}
ASN::Oct::Oct(pu8& s) : Asn0(s, OCTETSTRING_TAG) {}
ASN::Ext::Ext(pu8& s) : Asn0(s, EXTENSION_TAG) {}
ASN::Bool::Bool(pu8& s, bool b) : Asn0(s, TAG_BOOLEAN) { *p_++ = b ? 0xFF : 0x00; }

ASN::Pstr::Pstr(pu8& s, const char* p) : Asn0(s, PRINTABLE_STRING_TAG) {
    if (p == nullptr) { p_ -= 2; return; }
    while (*p) *p_++ = u8(*p++);
}

ASN::Altn::Altn(pu8& s, const char* p) : Asn0(s, DNAME_TAG) {
    while (*p) *p_++ = u8(*p++);
}

ASN::Bstr::Bstr(pu8& s) : Asn0(s, BITSTRING_TAG) { *p_++ = 0x00; } // Bitstream always starts with a 0x00 byte.
void ASN::Bstr::add(const u8* p, size_t n) { while (n-- > 0) *p_++ = *p++; }

ASN::Bstr2::Bstr2(pu8& s) : Asn2(s, BITSTRING_TAG) { *p_++ = 0x00; } // Bitstream always starts with a 0x00 byte.

void ASN::Bstr2::add(const u8* p, size_t n) {
    while (n-- > 0) *p_++ = *p++;
}


ASN::PubKey::PubKey(pu8& s, OID eType, const u8* p) : Seq(s, (eType == OID_PUBKEY_RSA) ? 0x101 : 0x59) {
    if (eType == OID_PUBKEY_RSA) {
        {ASN::Seq2 seq(p_);
        {ASN::Oid oidType(seq, OID_PUBKEY_RSA); }
        {ASN::NullTag nullTag(&seq); }}
        {ASN::Bstr2 bstr(p_);
        {ASN::Seq2 seq(bstr);
        {ASN::Intb it(seq, p, 256); }
        {ASN::Int e(seq, uint32_t(0x10001)); }}}
    } else {
        {ASN::Seq2 seq(p_);
        {ASN::Oid oidType(seq, OID_PUBKEY_ECC); }
        {ASN::Oid oidType(seq, eType); }}
        {ASN::Bstr bstr(p_); *bstr++ = 0x04; bstr.add(p, 0x40); }
    }
}
