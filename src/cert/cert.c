/******************************************************************************
*
* Copyright © 2014-2019 Anthony Mai Mai_Anthony@hotmail.com. All Rights Reserved.
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
*  File Name:       cert.c
*
*  Description:     X.509 digital certificate parsing and processing.
*
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         6/27/2014 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "cert.h"
#include "oid.h"

#include "cipher.h"
#include "BN.h"
#include "sha256.h"
#include "sha512.h"


#define MD5 CTX
#define SHA CTX

#define MD5_SIZE                    16
#define SHA1_SIZE                   20
#define SHA256_SIZE                 32


#define VERSION_V1      0   //Default is V1
#define VERSION_V2      1
#define VERSION_V3      2


#define HASH_NONE           0
#define HASH_MD2_WITH_RSA   1
#define HASH_MD4_WITH_RSA   2
#define HASH_MD5_WITH_RSA   3
#define HASH_SHA1_WITH_RSA  4
#define HASH_SHA256_WITH_RSA 5
#define HASH_SHA384_WITH_RSA 6
#define HASH_SHA512_WITH_RSA 7
#define HASH_SHA256_WITH_ECDSA 8


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

#define MAX_RSA_KEY_SIZE    2048

#define KEYUSAGE_DIGITALSIGNATURE 0x80 // digitalSignature(0),
#define KEYUSAGE_NONREPUDIATION   0x40 // nonRepudiation(1), --recent editions of X.509 have renamed this bit to contentCommitment
#define KEYUSAGE_KEYENCIPHERMENT  0x20 // keyEncipherment(2),
#define KEYUSAGE_DATAENCIPHERMENT 0x10 // dataEncipherment(3),
#define KEYUSAGE_KEYAGREEMENT     0x08 // keyAgreement(4),
#define KEYUSAGE_KEYCERTSIGN      0x04 // keyCertSign(5),
#define KEYUSAGE_CRLSIGN          0x02 // cRLSign(6),
#define KEYUSAGE_ENCIPHERONLY     0x01 // encipherOnly(7),
                                       // decipherOnly(8)
enum ECC_GROUP {
    ECC_NONE = 0,   // No ECC Support
    ECC_x25519 = 0x001D, // Supported Group: x25519 (0x001d)
    ECC_secp256k1 = 0x0016, // Supported Group: secp256k1(0x0016)
    ECC_secp256r1 = 0x0017, // Supported Group: secp256r1(0x0017)
    ECC_secp521r1 = 0x0019, // Supported Group: secp521r1 (0x0019)
    ECC_secp384r1 = 0x0018, // Supported Group: secp384r1 (0x0018)
    ECC_x448 = 0x001e, // Supported Group: x448 (0x001e)
    ECC_LAST = 0x7FFF
};


typedef struct CTX {
    uint    data[24];
} CTX;


typedef struct ASN1ITEM {
    uint    nType;
    uint    iClass;
    uint    iForm;
    uint    iTag;
    uint    nSize;
} ASN1ITEM;


typedef struct X509NAME {
    uchar   digest[20];             //Digest the whole thing using sha-1
    char    emailaddress[32];
    char    CommonName[64];         //commonName is most used identifying string
    char    orgUnit[64];
    char    orgName[64];
    char    localName[32];
    char    state[16];
    char    country[16];
} X509NAME;


// See this web site for Julian date info:
//  http://scienceworld.wolfram.com/astronomy/JulianDate.html
typedef struct DATETIME {
    uint    second;     // Julian second
    uint    day;        // Julian day
} DATETIME;


struct CERT {
    CERT*       prev;           //These two pointers are used to easily chain
    CERT*       next;           //a number of certificates into linked list.
    CERT*       pRootCert;      //Pointer to certificate of the signer.
    uint        version;        //0:V1, 1:V2, 2:V3. Default: V1
    uint        status;         //Certificate Status
    uint        hashAlgorithm;  //1:HASH_MD5_WITH_RSA, 2:HASH_SHA1_WITH_RSA
    uint        serialLen;      //Length of the serial number, in bytes
    uint        pubKeyLen;      //Length of public key, in bytes, not bits!
    uint        pubExp;
    uint        receiveTime;    //The UNIX time when the X.509 certificate is received.
    uint        validTime;      //The UNIX time how longer will it be valid. Not used.
    DATETIME    enableTime;     //Julian date of effective date
    DATETIME    expireTime;     //Julian date of expiration date
    uchar       serialNum[20];
    uchar       digest[32];     //Maximum digest size 20 bytes for SHA-1
    X509NAME    name;
    X509NAME    issuer;
    uchar       pubKey[MAX_RSA_KEY_SIZE/8];
    uchar       signature[MAX_RSA_KEY_SIZE/8];
};


static FMalloc gfMalloc = NULL;
static FFree   gfFree   = NULL;
static const CIPHERSET* gpCipherSet = NULL;

static CERT* gpRootCerts = NULL;
static CERT* gpMidCerts  = NULL;

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

extern X509NAME gTempCA; //Expose this variable to other libraries.
X509NAME gTempCA; //An instance that some one can used without declaring their own.

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


//Function Protocol Declarations
static uint GetASN1Item(ASN1ITEM* pItem, const uchar* pMsg);
uint ParseTBS(CERT* pCert, const uchar* pMsg, uint nMsgSize);
static uint ParseUTCTime(DATETIME* pTime, const uchar* pMsg, uint nMsgSize);
static uint ParseGENTime(DATETIME* pTime, const uchar* pMsg, uint nMsgSize);
static uint VerifySignature(const CERT* pCert, const CERT* pSigner);
static uint NotSameX509Name(const X509NAME* pName1, const X509NAME* pName2);
static CERT* FindCert(const X509NAME* pX509Name, CERT** ppIntermedateCerts);


/******************************************************************************
* Function:     InsertCert
*
* Description:  Insert a certificate into the certificate depository.
*
* Returns:      Pointer to the certificate inserted if OK. else NULL.
******************************************************************************/
CERT* InsertCert(CERT* pCert, CERT** ppMidCerts) {
    CERT*   pCert2;

    // Sanity check.
    if (NULL == pCert) {
        return NULL;
    }

    if (ppMidCerts == NULL) {
        ppMidCerts = &gpMidCerts;
    }

    //First make sure we do not already have the certificate in the deposit.
    pCert2 = FindCert(&(pCert->name), ppMidCerts);
    if (NULL != pCert2) {
        //If there was one with the same name. Delete the old one, unless the
        //old one was a root certificate.
        if (pCert2->status & CS_ROOT) {
            //We can not flush out our root certificate! Especially not by a
            //self-signed certificate coming from the network.
            return NULL;    //Tell caller the certificate not inserted.
        } else {
            //Get rid of the old certificate and insert the new one.
            //DestroyCert(DeleteCert(pCert2, ppMidCerts));

            //The old and new certificate has the same name but are they exactly identical?
            if (memcmp(pCert->pubKey, pCert2->pubKey, pCert->pubKeyLen)) {
                //We have a problem, the two certs have same name but are different
                assert(0);
            } else {
                //We are OK.
            }
            
            return NULL;
        }
    }

    if (pCert->status & CS_ROOT) {
        // We are suppose to insert it as a root certificate.
        if (NULL == gpRootCerts) {
            gpRootCerts = pCert;
            pCert->prev = gpRootCerts;
            pCert->next = gpRootCerts;
        } else {
            pCert->prev = gpRootCerts->prev;
            pCert->next = gpRootCerts;
            pCert->prev->next = pCert;
            pCert->next->prev = pCert;
        }
    } else {
        // We are suppose to insert it as a intermedia certificate.
        if (NULL == *ppMidCerts) {
            *ppMidCerts = pCert;
            pCert->prev = *ppMidCerts;
            pCert->next = *ppMidCerts;
        } else {
            pCert->prev = (*ppMidCerts)->prev;
            pCert->next = *ppMidCerts;
            pCert->prev->next = pCert;
            pCert->next->prev = pCert;
        }
    }

    return pCert;
}


/******************************************************************************
* Function:     DeleteCert
*
* Description:  Remove a certificate from the certificate depository. The
*               certificate is NOT destroyed so the caller still has to call
*               DestroyCert().
*
* Returns:      Pointer to the certificate removed if successful. Else NULL.
******************************************************************************/
CERT* DeleteCert(CERT* pCert, CERT** ppMidCerts) {
    CERT* pCert2 = NULL;

    if (NULL == pCert) {
        return NULL;
    }

    if (ppMidCerts == NULL) {
        ppMidCerts = &gpMidCerts;
    }

    if (pCert == *ppMidCerts) {
        pCert2 = *ppMidCerts;
        *ppMidCerts = pCert2->next;
        if (*ppMidCerts == pCert2) {
            *ppMidCerts = NULL;
        }
    } else if (pCert == gpRootCerts) {
        pCert2 = gpRootCerts;
        gpRootCerts = pCert2->next;
        if (gpRootCerts == pCert2) {
            gpRootCerts = NULL;
        }
    } else {
        // We need to verify that pCert is within the deposit of either
        // gpRootCerts or gpMidCerts.
        pCert2 = pCert;
        while (NULL != pCert2) {
            if ((pCert2 == gpRootCerts) || (pCert2 == *ppMidCerts)) {
                break;
            }

            pCert2 = pCert2->next;
            if (pCert2 == pCert) {
                pCert2 = NULL;
                break;
            }
        }
    }

    if (NULL == pCert2) {
        return NULL;
    }

    //Unhook the certificate.
    pCert->next->prev = pCert->prev;
    pCert->prev->next = pCert->next;

    return pCert;
}


/******************************************************************************
* Function:     NotSameX509Name
*
* Description:  Determine if the two X509 name entities are exactly same or not.
*
* Returns:      None zero if the name entities do not match. Zero if matches.
******************************************************************************/
uint NotSameX509Name(const X509NAME* pName1, const X509NAME* pName2) {
    return memcmp(pName1->digest, pName2->digest, sizeof(pName1->digest));
}


/******************************************************************************
* Function:     FindCert
*
* Description:  Find a certificate that matches the given X509 name entity.
*
* Returns:      Pointer to the certificate if found. Else NULL.
******************************************************************************/
CERT* FindCert(const X509NAME* pX509Name, CERT** ppMidCerts) {
    CERT* pCert;

    // First look among root certificates.
    pCert = gpRootCerts;
    while (NULL != pCert) {
        if (0 == NotSameX509Name(&(pCert->name), pX509Name)) {
            return pCert;
        }

        pCert = pCert->next;

        if (pCert == gpRootCerts) {
            break;
        }
    }

    // Then look among imtermediate certificates.
    if (ppMidCerts == NULL) {
        ppMidCerts = &gpMidCerts;
    }

    pCert = *ppMidCerts;
    while (NULL != pCert) {
        if (0 == NotSameX509Name(&(pCert->name), pX509Name)) {
            return pCert;
        }

        pCert = pCert->next;

        if (pCert == *ppMidCerts) {
            break;
        }
    }

    return NULL;
}


/******************************************************************************
* Function:     EnumCerts
*
* Description:  Enumerate the certificates in the certificate deposit, first
*               root certificates and then non-root certificates. The callback
*               function tells us to stop when it returns a non-zero value.
*
* Returns:      Number of certificates enumerated when we stop.
******************************************************************************/
uint EnumCerts
(
    ENUMCERT_FUNC   pEnumFunc,
    void*           pUserData
)
{
    uint    nTotal = 0;
    CERT*   pCert;
    CERT**  ppMidCerts = NULL;

    if (ppMidCerts == NULL) {
        ppMidCerts = &gpMidCerts;
    }

    // First enumerate root certificates.
    pCert = gpRootCerts;
    while (NULL != pCert) {
        nTotal ++;
        if (0 != pEnumFunc(pCert, pUserData)) {
            //The application tells us do not enumerate more. So return.
            return nTotal;
        }

        pCert = pCert->next;

        if (pCert == gpRootCerts) {
            break;
        }
    }

    // Then look among imtermediate certificates.
    pCert = *ppMidCerts;
    while (NULL != pCert) {
        nTotal ++;
        if (0 != pEnumFunc(pCert, pUserData)) {
            //The application tells us do not enumerate more. So return.
            return nTotal;
        }

        pCert = pCert->next;

        if (pCert == *ppMidCerts) {
            break;
        }
    }

    return nTotal;
}


/******************************************************************************
* Function:     GetASN1Item
*
* Description:  Parse to get one ASN1 tag. Note special handling for BITSTRING.
*
* Returns:      The size of the tag header, could be 2, 3, or 4 bytes.
******************************************************************************/
uint GetASN1Item(ASN1ITEM* pItem, const uchar* pMsg) {
    uint    nParsed = 0;

    pItem->nType = *pMsg++;
    nParsed ++;

    pItem->iClass = (pItem->nType & CLASS_MASK);
    pItem->iForm  = (pItem->nType & FORM_MASK);
    pItem->iTag   = (pItem->nType & TAG_MASK);

    if (pItem->nType) {
        pItem->nSize = *pMsg++;
        nParsed ++;

        if (pItem->nSize & 0x80) {
            if (pItem->nSize == 0x81) {
                pItem->nSize  = *pMsg++;
                nParsed ++;
            }
            else if (pItem->nSize == 0x82) {
                pItem->nSize  = *pMsg++;
                pItem->nSize<<= 8;
                pItem->nSize += *pMsg++;
                nParsed += 2;
            }
        }
    }

    //Special case for BITSTRING, eat the next 0x00 byte.
    if ((pItem->nType == BITSTRING_TAG) && (0x00 == *pMsg)) {
        pItem->nSize --;
        nParsed ++;
    }

    return nParsed;
}


/******************************************************************************
* Function:     StartCerts
*
* Description:  Set up certificate memory management functions.
*
* Returns:      None.
******************************************************************************/
void StartCerts(FMalloc pMallocFunc, FFree pFreeFunc, const CIPHERSET* pCipherSet) {
    gfMalloc = pMallocFunc;
    gfFree   = pFreeFunc;
    gpCipherSet = pCipherSet;
}


/******************************************************************************
* Function:     CreateCert
*
* Description:  Create a certificate. the eStatus used should be either
*               CS_ROOT if it is to be a root certificate, or CS_UNKNOWN.
*
* Returns:      Pointer to the certificate initially created.
******************************************************************************/
CERT* CreateCert(CERT_STATUS eStatus, uint nUnixTime) {
    CERT* pCert = NULL;

    if (NULL == gfMalloc) {
        //Can't do anything without the malloc function.
        return NULL;
    }

    if ((eStatus != CS_ROOT) && (NULL == gpRootCerts)) {
        //Needs to load root certificates first.
        return NULL;
    }

    pCert = (CERT*)gfMalloc(sizeof(*pCert));
    if (NULL != pCert) {
        memset(pCert, 0, sizeof(*pCert));

        pCert->status = eStatus;
        pCert->receiveTime = nUnixTime;
    }

    return pCert;
}


/******************************************************************************
* Function:     DestroyCert
*
* Description:  Cleanup and deallocate memory used by the certificate.
*
* Returns:      None
******************************************************************************/
void DestroyCert(CERT* pCert) {
    if ((NULL != pCert) && (NULL != gfFree)) {
        gfFree(pCert);
    }
}


/******************************************************************************
* Function:     CleanupCerts
*
* Description:  Cleanup and destroy all certificates we have. Usually this is
*               done when we cleanup to quit the application.
*
* Returns:      None.
******************************************************************************/
void CleanupCerts(CERT** ppMidCerts) {
    CERT* pCert;

    if (ppMidCerts != NULL) {
        while (NULL != (pCert = *ppMidCerts)) {
            DeleteCert(pCert, ppMidCerts);
            DestroyCert(pCert);
        }
        return;
    }

    while (NULL != (pCert = gpMidCerts)) {
        DeleteCert(pCert, NULL);
        DestroyCert(pCert);
    }
    while (NULL != (pCert = gpRootCerts)) {
        DeleteCert(pCert, NULL);
        DestroyCert(pCert);
    }
}

/******************************************************************************
* Function:     PutASN1Item
*
* Description:  Parse to get one ASN1 tag. Note special handling for BITSTRING.
*
* Returns:      The size of the tag header, could be 2, 3, or 4 bytes.
******************************************************************************/
uint PutASN1Item(ASN1ITEM* pItem, uchar* pMsg) {
    const uchar* p0 = pMsg;

    if (pItem->nType == 0) {
        pItem->nType = (pItem->iClass & CLASS_MASK);
        pItem->nType |= (pItem->iForm & FORM_MASK);
        pItem->nType |= (pItem->iTag & TAG_MASK);
    }

    *pMsg++ = pItem->nType;

    if (pItem->nType == BITSTRING_TAG) pItem->nSize++;

    if (pItem->nSize >= 0x0100) {
        *pMsg++ = 0x82;
        *pMsg++ = (pItem->nSize >> 8);
        *pMsg++ = (pItem->nSize & 0xFF);
    } else if (pItem->nSize >= 0x0080) {
        *pMsg++ = 0x81;
        *pMsg++ = (pItem->nSize & 0xFF);
    } else {
        *pMsg++ = (pItem->nSize & 0xFF);
    }

    //Special case for BITSTRING, append a 0x00 byte.
    if (pItem->nType == BITSTRING_TAG) *pMsg++ = 0x00;

    return (pMsg - p0);
}

uint PutKeyItem(uchar* pMsg, const uchar* pKey, uint cbKey) {
    int n = 0;
    const uchar* p0 = pMsg;
    *pMsg++ = TAG_INTEGER; *pMsg++ = 0x82;
    *pMsg++ = (cbKey >> 8); *pMsg++ = cbKey;
    if (pKey[0] & 0x80) {
        pMsg[-1]++; *pMsg++ = 0x00;
    }
    memcpy(pMsg, pKey, cbKey); pMsg += cbKey;

    return (pMsg - p0);
}

uint PutIntItem(uchar* pMsg, uint64_t val) {
    int n = 0;
    const uchar* p0 = pMsg;
    while ((val >> ((n++)<<3)) >= 0x80);
    *pMsg++ = TAG_INTEGER; *pMsg++ = n;
    while (n--) *pMsg++ = (uint8_t)(val >> (n<<3));
    return (pMsg - p0);
}

uint PutX509ID(X509NAME* pID, uchar* pMsg) {
    const uchar* p0 = pMsg;
    uint        nOne, it, slen;
    ASN1ITEM    item;

    //Name :: = CHOICE{ --only one possibility for now --
    //    rdnSequence  RDNSequence }
    //
    //    RDNSequence :: = SEQUENCE OF RelativeDistinguishedName
    //
    //    RelativeDistinguishedName :: =
    //    SET SIZE(1..MAX) OF AttributeTypeAndValue
    //
    //    AttributeTypeAndValue :: = SEQUENCE{
    //    type     AttributeType,
    //    value    AttributeValue }
    //
    //    AttributeType :: = OBJECT IDENTIFIER
    //
    //    AttributeValue :: = ANY -- DEFINED BY AttributeType
    //
    //    DirectoryString :: = CHOICE{
    //    teletexString           TeletexString(SIZE(1..MAX)),
    //    printableString         PrintableString(SIZE(1..MAX)),
    //    universalString         UniversalString(SIZE(1..MAX)),
    //    utf8String              UTF8String(SIZE(1..MAX)),
    //    bmpString               BMPString(SIZE(1..MAX)) }
    //

    item.nType = SEQUENCE_TAG; item.nSize = 0xf0;
    pMsg += PutASN1Item(&item, pMsg);
    uchar* pPayload = pMsg;
    for (it = 0; it < 6; it++) {
        uchar* pSet = pMsg;
        item.nType = SET_TAG; item.nSize = 0x0b;
        pMsg += PutASN1Item(&item, pMsg);

        item.nType = SEQUENCE_TAG; item.nSize = 0x09;
        pMsg += PutASN1Item(&item, pMsg);

        OID oid = 0;
        const char* pName = NULL;
        switch (it) {
        case 0: // Country
            oid = OID_NAME_COUNTRY;
            pName = pID->country;
            break;
        case 1: // State
            oid = OID_NAME_STATE;
            pName = pID->state;
            break;
        case 2: // Locality
            oid = OID_NAME_LOCAL;
            pName = pID->localName;
            break;
        case 3: // Organization Name
            oid = OID_NAME_ORG;
            pName = pID->orgName;
            break;
        case 4: // Organization Name
            oid = OID_NAME_UNIT;
            pName = pID->orgUnit;
            break;
        default: // Common name
            oid = OID_NAME_COMMON;
            pName = pID->CommonName;
            break;
        }
        item.nType = OID_TAG; item.nSize = 0x07;
        pMsg += PutASN1Item(&item, pMsg);
        nOne = SetOID(pMsg, oid);
        pMsg[-1] = nOne; pMsg += nOne;
        slen = strlen(pName);
        item.nType = PRINTABLE_STRING_TAG; item.nSize = slen;
        pMsg += PutASN1Item(&item, pMsg);
        memcpy(pMsg, pName, slen);
        pMsg += slen;

        // Adjust the set and sequence size
        slen = (pMsg - pSet) - 2;
        pSet[1] = slen;
        pSet[3] = slen - 2;
    }

    slen = pMsg - pPayload;
    pPayload[-1] = slen;

    return (pMsg - p0);
}


uint PutUTCTime(DATETIME* pDT, uchar* pMsg) {
    const uchar* p0 = pMsg;
    uint days, secs, n;
    uint year, month, day, hour, minute, second;
    
    // Calculate time from 01/01/2000 00:00:00 UTC
    if (pDT->second >= 43200) {
        days = pDT->day - 2451544;
        secs = pDT->second - 43200;
    } else {
        days = pDT->day - 2451545;
        secs = pDT->second + 43200;
    }

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
    *pMsg++ = '0' + (year/10); *pMsg++ = '0' + year - ((year/10)*10);
    *pMsg++ = '0' + (month/10);*pMsg++ = '0' + month- ((month/10)*10);
    *pMsg++ = '0' + (day/10);  *pMsg++ = '0' + day  - ((day/10)*10);
    *pMsg++ = '0' + (hour/10); *pMsg++ = '0' + hour - ((hour/10)*10);
    *pMsg++ = '0' + (minute/10); *pMsg++ = '0' + minute - ((minute/10)*10);
    *pMsg++ = '0' + (second/10); *pMsg++ = '0' + second - ((second/10)*10);
    *pMsg++ = 'Z';

    return (pMsg - p0);
}

static uint PutPubKey(CERT* pCert, uchar* pMsg) {
    uchar*      p0 = pMsg;
    uint        nOne;
    ASN1ITEM    item;

    // A sequence of the entire public key info
    item.nType = SEQUENCE_TAG; item.nSize = 0x272;
    pMsg += PutASN1Item(&item, pMsg);

    // A sequence of the public key OID type.
    uchar* pSeq = pMsg;
    item.nType = SEQUENCE_TAG; item.nSize = 0x1E;
    pMsg += PutASN1Item(&item, pMsg);
    item.nType = OID_TAG; item.nSize = 0x10;
    pMsg += PutASN1Item(&item, pMsg);
    nOne = SetOID(pMsg, OID_PUBKEY_RSA);
    pMsg[-1] = nOne; pMsg += nOne;

    item.nType = NULL_TAG; item.nSize = 0;
    pMsg += PutASN1Item(&item, pMsg);
    pSeq[1] = pMsg - pSeq - 2;

    // A Bitstream of public keys etc.
    uchar* pBits = pMsg;
    item.nType = BITSTRING_TAG; item.nSize = 0x10F;
    pMsg += PutASN1Item(&item, pMsg);

    // A sequence of public key and exponent
    item.nType = SEQUENCE_TAG; item.nSize = 0x10A;
    pMsg += PutASN1Item(&item, pMsg);

    pMsg += PutKeyItem(pMsg, pCert->pubKey, pCert->pubKeyLen);

    pMsg += PutIntItem(pMsg, pCert->pubExp);

    // Correct bitstream size
    nOne = pMsg - pBits - 4;
    pBits[2] = (nOne >> 8); pBits[3] = nOne;
    nOne -= 5; // Correct sequence size as well.
    pBits[7] = (nOne >> 8); pBits[8] = nOne;

    // Correct the whole sequence size
    nOne = pMsg - p0 - 4;
    p0[2] = (nOne >> 8); p0[3] = nOne;

    return (pMsg - p0);
}

static uint PutPubEcc(CERT* pCert, uchar* pMsg) {
    uchar*      p0 = pMsg;
    uint        nOne;
    ASN1ITEM    item;

    // A sequence of the entire public key info
    item.nType = SEQUENCE_TAG; item.nSize = 0x59;
    pMsg += PutASN1Item(&item, pMsg);

    // A sequence of the public key OID type.
    uchar* pSeq = pMsg;
    item.nType = SEQUENCE_TAG; item.nSize = 0x1E;
    pMsg += PutASN1Item(&item, pMsg);

    item.nType = OID_TAG; item.nSize = 0x07;
    pMsg += PutASN1Item(&item, pMsg);
    nOne = SetOID(pMsg, OID_PUBKEY_ECC);
    pMsg[-1] = nOne; pMsg += nOne;

    item.nType = OID_TAG; item.nSize = 0x08;
    pMsg += PutASN1Item(&item, pMsg);
    nOne = SetOID(pMsg, OID_ECCGROUP_SECP256R1);
    pMsg[-1] = nOne; pMsg += nOne;

    pSeq[1] = pMsg - pSeq - 2;

    // A Bitstream of ECC public key.
    uchar* pBits = pMsg;
    item.nType = BITSTRING_TAG; item.nSize = 0x42;
    pMsg += PutASN1Item(&item, pMsg);

    if (pCert->pubKeyLen >= 0x40) {
        *pMsg++ = 0x04; // Uncompressed
    } else {
        *pMsg++ = 0x02; // Compressed. 0x02 or 0x03
    }
    memcpy(pMsg, &(pCert->pubKey[sizeof(pCert->pubKey) - pCert->pubKeyLen]), pCert->pubKeyLen);
    pMsg += pCert->pubKeyLen;

    // Correct bitstream size
    nOne = pMsg - pBits - 2; pBits[1] = nOne;

    // Correct the whole sequence size
    nOne = pMsg - p0 - 2; p0[1] = nOne;

    return (pMsg - p0);
}

uint PutAlgID(CERT* pCert, uchar* pMsg) {
    uchar*      p0 = pMsg;
    uint        nOne;
    ASN1ITEM    item;

    //    signature            AlgorithmIdentifier, We use Sha256_RSA
    item.nType = SEQUENCE_TAG; item.nSize = 0x0B;
    pMsg += PutASN1Item(&item, pMsg);
    item.nType = OID_TAG; item.nSize = 0x09;
    pMsg += PutASN1Item(&item, pMsg);
    switch (pCert->hashAlgorithm) {
    case HASH_SHA256_WITH_ECDSA:
        nOne = SetOID(pMsg, OID_HASH_SHA256_ECDSA); break;
    case HASH_SHA256_WITH_RSA:
    default:
        nOne = SetOID(pMsg, OID_HASH_SHA256_RSA); break;
    }
    pMsg[-1] = nOne;
    pMsg += nOne;
    // Followed by a NULL tag
    item.nType = NULL_TAG; item.nSize = 0;
    pMsg += PutASN1Item(&item, pMsg);
    nOne = pMsg - p0;
    p0[1] = nOne - 2;

    return (pMsg - p0);
}

// https://tools.ietf.org/html/rfc528
uint GenTBSCert(CERT* pCert, uchar* pMsg, uint64_t nSerial) {
    uint            nOne = 0;
    ASN1ITEM        item;

    //TBSCertificate  :: = SEQUENCE{
    //    version[0]  EXPLICIT Version DEFAULT v1,
    //    serialNumber         CertificateSerialNumber,
    //    signature            AlgorithmIdentifier,
    //    issuer               Name,
    //    validity             Validity,
    //    subject              Name,
    //    subjectPublicKeyInfo SubjectPublicKeyInfo,
    //    issuerUniqueID[1]  IMPLICIT UniqueIdentifier OPTIONAL,
    //    --If present, version MUST be v2 or v3

    uchar* p0 = pMsg;

    //TBSCertificate  :: = SEQUENCE{
    item.nType = SEQUENCE_TAG; item.nSize = 0x03d0;
    pMsg += PutASN1Item(&item, pMsg);

    //    version[0]  EXPLICIT Version DEFAULT v1. We use V3
    item.nType = (CLASS_CONTEXT | FORM_CONSTRUCTED | TAG_ZERO); item.nSize = 3;
    pMsg += PutASN1Item(&item, pMsg);
    // Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
    pMsg += PutIntItem(pMsg, TAG_V3);

    //    serialNumber         CertificateSerialNumber,
    pMsg += PutIntItem(pMsg, nSerial);

    //    signature            AlgorithmIdentifier, We use Sha256_RSA
    pMsg += PutAlgID(pCert, pMsg);
    /*
    item.nType = SEQUENCE_TAG; item.nSize = 0x0B;
    pMsg += PutASN1Item(&item, pMsg);
    item.nType = OID_TAG; item.nSize = 0x09;
    pMsg += PutASN1Item(&item, pMsg);
    nOne = SetOID(pMsg, OID_HASH_SHA256_RSA);
    pMsg[-1] = nOne; pMsg[-3] = nOne + 2;
    pMsg += nOne;
    // Followed by a NULL tag
    item.nType = NULL_TAG; item.nSize = 0;
    pMsg += PutASN1Item(&item, pMsg);
    */

    //    issuer               Name,
    // https://tools.ietf.org/html/rfc5280#section-4.1.2.4
    pMsg += PutX509ID(&(pCert->issuer), pMsg);

    //    validity             Validity,
    //Validity :: = SEQUENCE{
    //    notBefore      Time,
    //    notAfter       Time }

    //Validity :: = SEQUENCE{
    item.nType = SEQUENCE_TAG; item.nSize = 0x1E;
    pMsg += PutASN1Item(&item, pMsg);
    //    notBefore      Time,
    item.nType = TAG_UTCTIME; item.nSize = 0x0D;
    pMsg += PutASN1Item(&item, pMsg);
    pMsg += PutUTCTime(&(pCert->enableTime), pMsg);
    //    notAfter       Time }
    item.nType = TAG_UTCTIME; item.nSize = 0x0D;
    pMsg += PutASN1Item(&item, pMsg);
    pMsg += PutUTCTime(&(pCert->expireTime), pMsg);

    //    subject              Name,
    // https://tools.ietf.org/html/rfc5280#section-4.1.2.4
    pMsg += PutX509ID(&(pCert->name), pMsg);

    //    subjectPublicKeyInfo SubjectPublicKeyInfo,
    if (pCert->pubKeyLen >= sizeof(pCert->pubKey)) {
        pMsg += PutPubKey(pCert, pMsg);
    } else {
        pMsg += PutPubEcc(pCert, pMsg);
    }

    // X.509V3 extensions
    if (pCert->status & CS_ROOT) {
        item.nType = EXTENSION_TAG; item.nSize = 0x23;
        pMsg += PutASN1Item(&item, pMsg);
        uchar* pExt = pMsg;

        item.nType = SEQUENCE_TAG; item.nSize = 0x21;
        pMsg += PutASN1Item(&item, pMsg);

        // Key Usage extension
        item.nType = SEQUENCE_TAG; item.nSize = 0x0e;
        pMsg += PutASN1Item(&item, pMsg);

        item.nType = OID_TAG; item.nSize = 0x03;
        pMsg += PutASN1Item(&item, pMsg);
        nOne = SetOID(pMsg, OID_X509V3_KEY_USAGE);
        pMsg[-1] = nOne; pMsg += nOne;

        *pMsg++ = 0x01; *pMsg++ = 0x01; *pMsg++ = 0xFF; // Critical: TRUE

        *pMsg++ = 0x04; *pMsg++ = 0x04;
        *pMsg++ = 0x03; *pMsg++ = 0x02;
        *pMsg++ = 0x01; *pMsg++ = (KEYUSAGE_DIGITALSIGNATURE|KEYUSAGE_KEYCERTSIGN|KEYUSAGE_CRLSIGN); // 0x86 = bits 0, 5, 6 set, in network endian.

        // Basic Constraints extension
        item.nType = SEQUENCE_TAG; item.nSize = 0x0f;
        pMsg += PutASN1Item(&item, pMsg);

        item.nType = OID_TAG; item.nSize = 0x03;
        pMsg += PutASN1Item(&item, pMsg);
        nOne = SetOID(pMsg, OID_X509V3_BASIC_CONSTRAINTS);
        pMsg[-1] = nOne; pMsg += nOne;

        *pMsg++ = 0x01; *pMsg++ = 0x01; *pMsg++ = 0xFF; // Critical: TRUE

        *pMsg++ = 0x04; *pMsg++ = 0x05;
        *pMsg++ = 0x30; *pMsg++ = 0x03;
        *pMsg++ = 0x01; *pMsg++ = 0x01; *pMsg++ = 0xFF; // CA: TRUE

        nOne = pMsg - pExt;
        pExt[-1] = nOne; pExt[1] = nOne - 2;
    }

    // Adjust whole sequence size
    item.nSize = pMsg - p0 - 4;
    p0[2] = (item.nSize >> 8); p0[3] = (item.nSize);

    return (pMsg - p0);
}

void CalcDigest(CERT* pCert, const uchar* pHashContent, uint nHashSize) {
    //Calculate the digest of the TBSCertificate part
    switch (pCert->hashAlgorithm) {
    case HASH_MD2_WITH_RSA:
        assert(0); //Not supported
        return;
    case HASH_MD4_WITH_RSA:
        assert(0); //Not supported
        return;
    case HASH_MD5_WITH_RSA:
        assert(0);
        //gpCipherSet->md5.Hash(
        //    pHashContent,
        //    nHashSize,
        //    &(pCert->digest[sizeof(pCert->digest) - MD5_SIZE])
        //);
        break;
    case HASH_SHA1_WITH_RSA:
        gpCipherSet->sha1.Hash(
            pHashContent,
            nHashSize,
            &(pCert->digest[sizeof(pCert->digest) - SHA1_SIZE])
        );
        break;
    case HASH_SHA256_WITH_RSA:
    case HASH_SHA256_WITH_ECDSA:
        gpCipherSet->sha256.Hash(
            pHashContent,
            nHashSize,
            &(pCert->digest[sizeof(pCert->digest) - SHA256_SIZE])
        );
        break;
    case HASH_SHA384_WITH_RSA:
        gpCipherSet->sha384.Hash(
            pHashContent,
            nHashSize,
            &(pCert->digest[sizeof(pCert->digest) - SHA384_SIZE])
        );
        break;
    case HASH_SHA512_WITH_RSA:
        gpCipherSet->sha512.Hash(
            pHashContent,
            nHashSize,
            &(pCert->digest[sizeof(pCert->digest) - SHA512_SIZE])
        );
        break;
    default:
        assert(0);  //Unknown hash algorithm.
        return;
    }
}

void SetCertIssuer(CERT* pCert, const CertName* pCName) {
    strcpy(pCert->issuer.country, pCName->country);
    strcpy(pCert->issuer.state, pCName->state);
    strcpy(pCert->issuer.localName, pCName->local);
    strcpy(pCert->issuer.orgName, pCName->company);
    strcpy(pCert->issuer.orgUnit, pCName->unitname);
    strcpy(pCert->issuer.CommonName, pCName->commonname);
}

void SetCertSubject(CERT* pCert, const CertName* pCName) {
    strcpy(pCert->name.country, pCName->country);
    strcpy(pCert->name.state, pCName->state);
    strcpy(pCert->name.localName, pCName->local);
    strcpy(pCert->name.orgName, pCName->company);
    strcpy(pCert->name.orgUnit, pCName->unitname);
    strcpy(pCert->name.CommonName, pCName->commonname);
}

void SetCertCommonName(CERT* pCert, const char* pCName) {
    strcpy(pCert->name.CommonName, pCName);
}

uint GenCert(CERT* pCert, CERT* pRoot, uchar* pMsg, uint64_t nSerial, const uchar* pPrivateRootKey) {
    const uchar*    pHashContent;
    uint            nHashSize;
    ASN1ITEM        item;
    uchar*          p0 = pMsg;

    //memcpy(pCert->pubKey, pPublicRSAKey, pCert->pubKeyLen);

    // Set signature hash algorithm.
    if (pRoot->pubKeyLen >= sizeof(pCert->pubKey)) {
        // RSA signature
        pCert->hashAlgorithm = HASH_SHA256_WITH_RSA; // Only support SHA256
    } else if (pRoot->pubExp == ECC_secp256r1) {
        pCert->hashAlgorithm = HASH_SHA256_WITH_ECDSA;
    } else {
        pCert->hashAlgorithm = HASH_SHA256_WITH_ECDSA;
    }

    if (pCert == pRoot) {
        pCert->enableTime.second = 0;
        pCert->expireTime.second = 0;
        pCert->expireTime.day = pCert->enableTime.day + 9131;
    } else {
        // Set issuer info based on the root
        strcpy(pCert->issuer.country, pRoot->name.country);
        strcpy(pCert->issuer.state, pRoot->name.state);
        strcpy(pCert->issuer.localName, pRoot->name.localName);
        strcpy(pCert->issuer.orgName, pRoot->name.orgName);
        strcpy(pCert->issuer.orgUnit, pRoot->name.orgUnit);
        strcpy(pCert->issuer.CommonName, pRoot->name.CommonName);
    }

    //Certificate  :: = SEQUENCE{
    //    tbsCertificate       TBSCertificate,
    //    signatureAlgorithm   AlgorithmIdentifier,
    //    signatureValue       BIT STRING }

    uchar* pCertHead = pMsg;
    // Certificate  :: = SEQUENCE{
    item.nType = SEQUENCE_TAG;
    item.nSize = 0x03d0;
    pMsg += PutASN1Item(&item, pMsg);

    //    tbsCertificate       TBSCertificate,
    pHashContent = pMsg;
    pMsg += GenTBSCert(pCert, pMsg, nSerial);
    nHashSize = (pMsg - pHashContent);

    //    signatureAlgorithm   AlgorithmIdentifier,
    pMsg += PutAlgID(pCert, pMsg);

    CalcDigest(pCert, pHashContent, nHashSize);

    //    signatureValue       BIT STRING 
    // TODO: Handle ECC
    assert(pRoot->pubKeyLen == 256);
    *pMsg++ = BITSTRING_TAG; *pMsg++ = 0x82;
    *pMsg++ = pRoot->pubKeyLen >> 8; *pMsg++ = pRoot->pubKeyLen + 1;
    *pMsg++ = 0x00;

    uchar* pSign = pMsg;
    uchar oidBuf[16];
    uint nDigestSize, nOidSize = SetOID(oidBuf, OID_DIGEST_SHA256);

    switch (pCert->hashAlgorithm) {
    case HASH_MD2_WITH_RSA:
        assert(0); //Not supported
        return 0;
    case HASH_MD4_WITH_RSA:
        assert(0); //Not supported
        return 0;
        break;
    case HASH_MD5_WITH_RSA:
        //nDigestSize = MD5_SIZE;
        //nOidSize = SetOID(oidBuf, OID_DIGEST_MD5);
        assert(0); //Not supported
        return 0;
    case HASH_SHA1_WITH_RSA:
        nDigestSize = SHA1_SIZE;
        nOidSize = SetOID(oidBuf, OID_DIGEST_SHA1);
        break;
    case HASH_SHA256_WITH_RSA:
        nDigestSize = SHA256_SIZE;
        nOidSize = SetOID(oidBuf, OID_DIGEST_SHA256);
        //&(pCert->digest[sizeof(pCert->digest) - SHA256_SIZE])
        break;
    default:
        assert(0);  //Unknown hash algorithm.
        return 0;
    }

    item.nType = SEQUENCE_TAG; item.nSize = (nDigestSize + nOidSize + 11);
    memset(pSign, -1, pRoot->pubKeyLen - (nDigestSize+nOidSize+11));
    pSign[0] = 0x00; pSign[1] = 0x01;
    pMsg += pRoot->pubKeyLen - (nDigestSize + nOidSize + 11);
    *pMsg++ = 0x00;

    item.nSize -= 3;
    pMsg += PutASN1Item(&item, pMsg);
    item.nType = SEQUENCE_TAG; item.nSize = nOidSize + 4;
    pMsg += PutASN1Item(&item, pMsg);
    item.nType = OID_TAG; item.nSize = nOidSize;
    pMsg += PutASN1Item(&item, pMsg);
    memcpy(pMsg, oidBuf, nOidSize);
    pMsg += nOidSize;
    item.nType = NULL_TAG; item.nSize = 0;
    pMsg += PutASN1Item(&item, pMsg);

    item.nType = TAG_OCTETSTRING; item.nSize = nDigestSize;
    pMsg += PutASN1Item(&item, pMsg);
    memcpy(pMsg, &(pCert->digest[sizeof(pCert->digest) - nDigestSize]), nDigestSize);
    pMsg += nDigestSize;
    assert((pMsg - pSign) == pRoot->pubKeyLen);

    uint nCertSize = pMsg - p0 - 4;
    p0[2] = nCertSize >> 8; p0[3] = nCertSize;

    // Now encrypt the signature block;
    gpCipherSet->rsa.RsaDecrypt(pSign, PubKey(pRoot), pPrivateRootKey, pRoot->pubKeyLen);

    return (pMsg - p0);
}

/******************************************************************************
* Function:     ParseCert
*
* Description:  Parse the content of DER encoded binary X.509 (.cer) certificate
*               and put the information into a CERT.
*
* Returns:      Number of bytes parsed. Zero if the parsing failed.
******************************************************************************/
uint ParseCert(CERT* pCert, const uchar* pMsg, uint nMsgSize) {
    const uchar*    p0 = pMsg;
    uint            nParseSize;
    uint            nCertSize;
    const uchar*    pHashContent;
    uint            nHashSize;
    ASN1ITEM        item;

    // First is a SEQUENCE tag that encloses the whole certificate.
    pMsg += GetASN1Item(&item, pMsg);
    if ((item.nType != SEQUENCE_TAG) ||
        ((pMsg - p0 + item.nSize) != nMsgSize)) {
        //assert(item.nType == SEQUENCE_TAG);
        return 0;
    }

    nCertSize = item.nSize;
    pHashContent = pMsg;

    // Next is a SEQUENCE tag enclosing the TBSCertificate part.
    pMsg += GetASN1Item(&item, pMsg);
    if (item.nType != SEQUENCE_TAG) {return 0;}

    //Parse the TBSCertificate part.
    nParseSize = ParseTBS(pCert, pMsg, item.nSize);
    if (nParseSize != item.nSize) {return 0;}

    pMsg += item.nSize;
    nHashSize = pMsg - pHashContent;


    //Calculate the digest of the TBSCertificate part
    //CalcDigest(pCert, pHashContent, nHashSize);

    // Following TBSCertificate is a SEQUENCE enclosing OID of hash algorithm.
    pMsg += GetASN1Item(&item, pMsg);
    if (item.nType == SEQUENCE_TAG) {
        OID     oid = OID_UNKNOWN;
        uint    hashAlgorithm = HASH_NONE;
        const uchar* pSeq = pMsg;
        int nSeqLen = item.nSize;

        //First is an OID tag identifying the hashAlgorithm
        pMsg += GetASN1Item(&item, pMsg);
        if (item.nType == OID_TAG) {
            oid = GetOID(pMsg, item.nSize);
        } else {
            //assert(item.nType == OID_TAG);
            return 0;
        }

        pMsg += item.nSize;
 
        //The hashAlgorithm must match that in the TBSCertificate part.
        switch (oid) {
        case OID_HASH_MD2_RSA:
            hashAlgorithm = HASH_MD2_WITH_RSA;
            break;
        case OID_HASH_MD4_RSA:
            hashAlgorithm = HASH_MD4_WITH_RSA;
            break;
        case OID_HASH_MD5_RSA:
            hashAlgorithm = HASH_MD5_WITH_RSA;
            break;
        case OID_HASH_SHA1_RSA:
            hashAlgorithm = HASH_SHA1_WITH_RSA;
            break;
        case OID_HASH_SHA256_RSA:
            hashAlgorithm = HASH_SHA256_WITH_RSA;
            break;
        case OID_HASH_SHA384_RSA:
            hashAlgorithm = HASH_SHA384_WITH_RSA;
            break;
        case OID_HASH_SHA512_RSA:
            hashAlgorithm = HASH_SHA512_WITH_RSA;
            break;
        case OID_HASH_SHA256_ECDSA:
            hashAlgorithm = HASH_SHA256_WITH_ECDSA;
            break;
        default:
            return 0;
            break;
        }

        if (hashAlgorithm != pCert->hashAlgorithm) {
            // HashAlgorithm does not match. The certificate is corrupted.
            pCert->status &= ~CS_OK;
            pCert->status |= CS_BAD;
        }

        // Following the OID there might be a NULL tag
        if ((pMsg - pSeq) < nSeqLen) {
            pMsg += GetASN1Item(&item, pMsg);
            pMsg += item.nSize;
        }
    } else {
        return 0;
    }

    //Calculate the digest of the TBSCertificate part
    CalcDigest(pCert, pHashContent, nHashSize);

    // In case of ECC certificate, we are probably done here.
    if ((pMsg - p0) >= (int)nMsgSize) {
        return (pMsg - p0);
    }

    // Following OID of hash algorithm is the signature block
    pMsg += GetASN1Item(&item, pMsg);
    if (item.nType == BITSTRING_TAG) {
        uint    nCopySize = item.nSize;

        if (nCopySize > sizeof(pCert->signature)) {
            //Should not occur. If it happens it is an error condition
            //and the certificate can not be properly parsed.
            nCopySize = sizeof(pCert->signature);
        }
        if ((nCopySize == sizeof(pCert->signature)) || (nCopySize == 128)) {
            // RSA signature. Just copy the whole thing
            memcpy(
                &(pCert->signature[sizeof(pCert->signature) - nCopySize]),
                pMsg,
                nCopySize
            );
        } else {
            // ECC signature. More parsing is needed.
            const uchar* pSig = pMsg;
            ASN1ITEM    itm;
            pSig += GetASN1Item(&itm, pSig);
            if (itm.nType == SEQUENCE_TAG) {
                pSig += GetASN1Item(&itm, pSig);
                if (itm.nType == INTEGER_TAG) {
                    if ((*pSig == 0x00) && (itm.nSize & 1)) {
                        pSig++; itm.nSize--;
                    }
                    memcpy(&(pCert->signature[sizeof(pCert->signature) - itm.nSize - itm.nSize]),
                        pSig, itm.nSize);
                    pSig += itm.nSize;
                }
                pSig += GetASN1Item(&itm, pSig);
                if (itm.nType == INTEGER_TAG) {
                    if ((*pSig == 0x00) && (itm.nSize & 1)) {
                        pSig++; itm.nSize--;
                    }
                    memcpy(&(pCert->signature[sizeof(pCert->signature) - itm.nSize]),
                        pSig, itm.nSize);
                    pSig += itm.nSize;
                }
            }
        }
    } else {
        return 0;
    }

    pMsg += item.nSize;

    //All of the certificate have been parsed.
    return ((pMsg - p0) == nMsgSize) ? (pMsg - p0) : 0;
}

uint ParseExtensions(CERT* pCert, const uchar* pMsg) {
    const uchar* p0 = pMsg;
    ASN1ITEM    item;

    pMsg += GetASN1Item(&item, pMsg);
    if (item.nType != EXTENSION_TAG) {
        pMsg += item.nSize;
        return (pMsg - p0);
    }
    uint nMsgSize = (pMsg - p0) + item.nSize;

    while ((pMsg - p0) < (int)nMsgSize) {
        pMsg += GetASN1Item(&item, pMsg);
        switch (item.nType) {

        }
        pMsg += item.nSize;
    }
    return (pMsg - p0);
}


/******************************************************************************
* Function:     ParseTBS
*
* Description:  Parse the TBSCertificate portion of the X.509 certificate.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseTBS(CERT* pCert, const uchar* pMsg, uint nMsgSize) {
    const uchar* p0 = pMsg;
    //uint        nParsed = 0;
    uint        nParseSize;
    uint        nHeadSize;
    ASN1ITEM    item;

    pCert->version = VERSION_V1; //Default to V1

    // 1. First tag is either the certificate sequence number, or
    // a version before the sequence.
    for (;;) {
        uint    nCopySize;

        pMsg += GetASN1Item(&item, pMsg);
        if (item.nType == (CLASS_CONTEXT | FORM_CONSTRUCTED | TAG_ZERO)) {
            // The tag is Constructed type [0].
            // The optional version tag is present.
            pMsg += GetASN1Item(&item, pMsg);
            pCert->version = *pMsg++;
            continue;   //This is the only case that continue
        }

        if (item.nType == INTEGER_TAG) {
            nCopySize = item.nSize;
            if (nCopySize > sizeof(pCert->serialNum)) {
                if (nCopySize > 32) {
                    //Very long serial number. Must be bogus so bail out.
                    return 0;
                }
                nCopySize = sizeof(pCert->serialNum);
            }
            memcpy(
                &(pCert->serialNum[sizeof(pCert->serialNum) - nCopySize]),
                &(pMsg[item.nSize - nCopySize]),
                nCopySize
                );
            pCert->serialLen = nCopySize;
        } else {
            //Bail out on any suspected data corruption.
            return 0;
        }

        pMsg += item.nSize;
        break; //Always break except for the case of optional version tag
    }

    // 2. Should be a sequence containing the OID for hash algorithm
    pMsg += GetASN1Item(&item, pMsg);
    if (item.nType == SEQUENCE_TAG) {
        OID     oid = OID_UNKNOWN;
        uint    nSeqLen = item.nSize;
        const uchar* pSeq = pMsg;

        pMsg += GetASN1Item(&item, pMsg);
        if (item.nType == OID_TAG) {
            oid = GetOID(pMsg, item.nSize);

            switch (oid) {
            case OID_HASH_MD2_RSA:
                pCert->hashAlgorithm = HASH_MD2_WITH_RSA;
                break;
            case OID_HASH_MD4_RSA:
                pCert->hashAlgorithm = HASH_MD4_WITH_RSA;
                break;
            case OID_HASH_MD5_RSA:
                pCert->hashAlgorithm = HASH_MD5_WITH_RSA;
                break;
            case OID_HASH_SHA1_RSA:
                pCert->hashAlgorithm = HASH_SHA1_WITH_RSA;
                break;
            case OID_HASH_SHA256_RSA:
                pCert->hashAlgorithm = HASH_SHA256_WITH_RSA;
                break;
            case OID_HASH_SHA384_RSA:
                pCert->hashAlgorithm = HASH_SHA384_WITH_RSA;
                break;
            case OID_HASH_SHA512_RSA:
                pCert->hashAlgorithm = HASH_SHA512_WITH_RSA;
                break;
            case OID_HASH_SHA256_ECDSA:
                pCert->hashAlgorithm = HASH_SHA256_WITH_ECDSA;
                break;
            default:
                assert(0);
                break;
            }
        }
        pMsg += item.nSize;

        while ((pMsg - pSeq) < (int)nSeqLen) {
            // This should be a NULL tag
            pMsg += GetASN1Item(&item, pMsg);
            pMsg += item.nSize;
        }
    } else {
        //Bail out on any suspected data corruption.
        return 0;
    }

    // 3. A sequence containing the Issuer identity information
    nHeadSize = GetASN1Item(&item, pMsg);
    nParseSize = ParseX509ID(&(pCert->issuer), pMsg, (item.nSize+nHeadSize));
    //assert(nParseSize == (item.nSize+nHeadSize));
    pMsg += nParseSize;

    // 4. A sequence containing the begin and end validity date.
    pMsg += GetASN1Item(&item, pMsg);

    if (item.nType == SEQUENCE_TAG) {
        // First the certificate activation datetime.
        pMsg += GetASN1Item(&item, pMsg);

        if (item.nType == UTCTIME_TAG) {
            nParseSize = ParseUTCTime(&(pCert->enableTime), pMsg, item.nSize);
        } else if (item.nType == GENTIME_TAG) {
            nParseSize = ParseGENTime(&(pCert->enableTime), pMsg, item.nSize);
        } else {
            nParseSize = item.nSize;
        }

        pMsg    += nParseSize;

        // Then the certificate expiration datetime.
        pMsg += GetASN1Item(&item, pMsg);
        if (item.nType == UTCTIME_TAG) {
            nParseSize = ParseUTCTime(&(pCert->expireTime), pMsg, item.nSize);
        } else if (item.nType == GENTIME_TAG) {
            nParseSize = ParseGENTime(&(pCert->expireTime), pMsg, item.nSize);
        } else {
            nParseSize = item.nSize;
        }

        if (nParseSize != item.nSize) {
            //Bail out on any suspected data corruption.
            return 0;
        }

        pMsg    += nParseSize;
    } else {
        pMsg += item.nSize;

        //Bail out on any suspected data corruption.
        return 0;
    }


    // 5. A sequence containing the Subject identity information
    nHeadSize = GetASN1Item(&item, pMsg);
    nParseSize = ParseX509ID(&(pCert->name), pMsg, (item.nSize+nHeadSize));
    //assert(nParseSize == (item.nSize+nHeadSize));
    pMsg += nParseSize;

    // 6. A sequence containing the public key information
    pMsg += GetASN1Item(&item, pMsg);
    if (item.nType == SEQUENCE_TAG) {
        pMsg += GetASN1Item(&item, pMsg);
        if (item.nType == SEQUENCE_TAG) {
            OID     oid = OID_UNKNOWN;
            int     nSeqLen = item.nSize;
            const uchar* pSeq = pMsg;

            while ((pMsg - pSeq) < nSeqLen) {
                pMsg += GetASN1Item(&item, pMsg);

                if (item.nType == OID_TAG) switch ((oid = GetOID(pMsg, item.nSize))) {
                case OID_PUBKEY_RSA:
                    pCert->pubExp = 65537;
                    break;
                case OID_PUBKEY_ECC:
                    pCert->pubExp = 0;
                    break;
                case OID_ECCGROUP_SECP256R1:
                    pCert->pubExp = ECC_secp256r1;
                    break;
                case OID_ECGROUP_SECP384R1:
                    pCert->pubExp = ECC_secp384r1;
                    break;
                default:
                    assert(0);
                    break;
                }

                pMsg += item.nSize;
            }
        } else {
            pMsg += item.nSize;
        }

        pMsg += GetASN1Item(&item, pMsg);

        if ((pCert->pubExp < 65536) && (item.nSize < 256) && (item.nType == BITSTRING_TAG)) {
            // Found ECC public key.
            uint8_t ptFormat = *pMsg++; item.nSize--;
            // ptFormat = 2: compressed; 3: compressed; 4: uncompressed, x:y
            memset(&(pCert->pubKey), 0, sizeof(pCert->pubKey));
            memcpy(
                &(pCert->pubKey[sizeof(pCert->pubKey) - item.nSize]),
                pMsg,
                item.nSize
            );
            pCert->pubKeyLen = item.nSize;
            pMsg += item.nSize;
        } else if (item.nType == BITSTRING_TAG) {
            pMsg += GetASN1Item(&item, pMsg);
            if (item.nType == SEQUENCE_TAG) {
                // First an Integer which is the RSA public key
                pMsg += GetASN1Item(&item, pMsg);
                if (item.nType == INTEGER_TAG) {
                    if (0 == (item.nSize & 0x00000001)) {
                        // OK. We have exactly even bytes.
                    } else if (0x00 == (*pMsg)) {
                        // We have odd bytes, but 1st byte is 0. Discard it.
                        pMsg++; item.nSize --;
                    } else {
                        //assert(0);  //We may be in trouble.
                    }
                    
                    if (item.nSize <= sizeof(pCert->pubKey)) {
                        memset(&(pCert->pubKey), 0, sizeof(pCert->pubKey));
                        memcpy(
                            &(pCert->pubKey[sizeof(pCert->pubKey) - item.nSize]),
                            pMsg,
                            item.nSize
                            );
                        pCert->pubKeyLen = item.nSize;
                    }
                }
                pMsg    += item.nSize;

                // Then an Integer which is the public exponent
                pMsg += GetASN1Item(&item, pMsg);
                if (item.nType == INTEGER_TAG) {
                    pCert->pubExp = 0;
                    for (uint i=0; i<item.nSize; i++) {
                        pCert->pubExp <<= 8;
                        pCert->pubExp += *pMsg++;
                    }
                } else {
                    pMsg    += item.nSize;
                }
            } else {
                pMsg += item.nSize;
            }
        } else {
            pMsg += item.nSize;
        }
    } else {
        pMsg += item.nSize;

        //Bail out on any suspected data corruption.
        return 0;
    }


    //There may be additional fields
    while ((pMsg - p0) < (int)nMsgSize) {
        nHeadSize = GetASN1Item(&item, pMsg);
        if (item.nType != EXTENSION_TAG) {
            pMsg += nHeadSize;

            //assert((item.nType & (CLASS_MASK|FORM_MASK)) == (CLASS_CONTEXT|FORM_CONSTRUCTED));
            //If we are interested in the additional fields, maining the constructed
            //field [1], [2], [3], parse it here.

            pMsg += item.nSize;
            continue;
        }
        pMsg += ParseExtensions(pCert, pMsg);
    }

    //assert (nParsed == nMsgSize);
    if ((pMsg - p0) != nMsgSize) {
        //Bail out on any suspected data corruption.
        return 0;
    }

    return (pMsg - p0);
}


/******************************************************************************
* Function:     ParseX509ID
*
* Description:  Parse the X.509 identity information. This largely replaces
*               the old ParseX509Name() function.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseX509ID(X509NAME* pName, const uchar* pMsg, uint nMsgSize) {
    uint        nParsed = 0, nParseSize = 0;
    uint        nHeadSize;
    ASN1ITEM    item;

    memset(pName, 0, sizeof(*pName));

    while (nParsed < nMsgSize) {
        // 3. A sequence containing the Issuer identity information
        nHeadSize = GetASN1Item(&item, pMsg);
        pMsg    += nHeadSize;
        nParsed += nHeadSize;

        if (item.nType != SEQUENCE_TAG) {
            pMsg += item.nSize;
            nParsed += item.nSize;

            continue;
        }

        //X.509 identity parsing. First hash everyting as a unique identifier.
        gpCipherSet->sha1.Hash(pMsg, item.nSize, pName->digest);

        while (nParsed < nMsgSize) {
            OID     oid = OID_UNKNOWN;

            nHeadSize = GetASN1Item(&item, pMsg);
            pMsg    += nHeadSize;
            nParsed += nHeadSize;

            if (item.nType != SET_TAG) {
                pMsg += item.nSize;
                nParsed += item.nSize;
                continue;
            }

            nHeadSize = GetASN1Item(&item, pMsg);
            pMsg    += nHeadSize;
            nParsed += nHeadSize;

            if (item.nType != SEQUENCE_TAG) {
                pMsg += item.nSize;
                nParsed += item.nSize;
                continue;
            }

            //Each Sequence within the SET is one OID followed by one PrintableString.

            //First the OID tag.
            nHeadSize = GetASN1Item(&item, pMsg);
            pMsg    += nHeadSize;
            nParsed += nHeadSize;

            if (item.nType == OID_TAG) {
                oid = GetOID(pMsg, item.nSize);
            }
            pMsg    += item.nSize;
            nParsed += item.nSize;

            //Then the PrintableString.
            nHeadSize = GetASN1Item(&item, pMsg);
            pMsg    += nHeadSize;
            nParsed += nHeadSize;

            if ((item.nType == PRINTABLE_STRING_TAG) ||
                (item.nType == UTF8STRING_TAG) ||
                (item.nType == TAG_IA5STRING) ||
                (item.nType == TAG_T61STRING) )
            {
                uint    nSize = item.nSize;
                char    tmpStr[sizeof(pName->CommonName)];

                if (nSize > (sizeof(tmpStr)-1)) {
                    nSize = sizeof(tmpStr)-1;
                }
                memcpy(tmpStr, pMsg, nSize);
                memset(tmpStr+nSize, 0, sizeof(tmpStr)-nSize);

                switch (oid) {
                case OID_NAME_COMMON:
                    memcpy(pName->CommonName, tmpStr, sizeof(pName->CommonName));
                    break;
                case OID_NAME_ORG:
                    //pMd5->Input(&md5Ctx, pMsg, item.nSize);
                    memcpy(pName->orgName, tmpStr, sizeof(pName->orgName));
                    break;
                case OID_NAME_UNIT:
                    //pMd5->Input(&md5Ctx, pMsg, item.nSize);
                    memcpy(pName->orgUnit, tmpStr, sizeof(pName->orgUnit));
                    //Just in case there is no common name.
                    //memcpy(pName->CommonName, tmpStr, sizeof(pName->CommonName));
                    break;
                case OID_NAME_LOCAL:
                    //pMd5->Input(&md5Ctx, pMsg, item.nSize);
                    memcpy(pName->localName, tmpStr, sizeof(pName->localName));
                    break;
                case OID_NAME_STATE:
                    memcpy(pName->state, tmpStr, sizeof(pName->state));
                    break;
                case OID_NAME_COUNTRY:
                    memcpy(pName->country, tmpStr, sizeof(pName->country));
                    break;
                case OID_EMAIL2:
                    tmpStr[0] |= 0x80;
                    //Fall through
                case OID_EMAIL:
                    memcpy(pName->emailaddress, tmpStr, sizeof(pName->emailaddress));
                    break;
                default:
                    pMsg = pMsg;
                    break;
                }
            }
            pMsg    += item.nSize;
            nParsed += item.nSize;
        }
    }

    //pMd5->Digest(&md5Ctx, pName->md5digest2);

    // We should have parsed exactly all the bytes.
    if (nParsed != nMsgSize) {
        //Bail out on any suspected data corruption.
        return 0;
    }

    return nParsed;
}


/******************************************************************************
* Function:     ParseUTCTime
*
* Description:  Parse the UTC Time string and return the date time in Julian
*               seconds.
*
* Returns:      The number of bytes parsed.
******************************************************************************/
uint ParseUTCTime(DATETIME* pTime, const uchar* pMsg, uint nMsgSize) {
    int     year;
    int     month;
    int     day;
    int     hour;
    int     minute;
    int     second;

    year  = 0x0F&(*pMsg++); year  += year<<2;  year  += year  + (0x0F&(*pMsg++));
    month = 0x0F&(*pMsg++); month += month<<2; month += month + (0x0F&(*pMsg++));
    day  =  0x0F&(*pMsg++); day  +=  day << 2; day  +=  day  +  (0x0F&(*pMsg++));
    hour =  0x0F&(*pMsg++); hour += hour << 2; hour +=  hour +  (0x0F&(*pMsg++));
    minute= 0x0F&(*pMsg++); minute+=minute<<2; minute+=minute + (0x0F&(*pMsg++));
    second= 0x0F&(*pMsg++); second+=second<<2; second+=second + (0x0F&(*pMsg++));

    // This calculation is good for year 00-99 (2000-2099).
    pTime->day = 367*year;
    pTime->day -= (((year+((month+9)/12))*7)/4);
    pTime->day += (month*275)/9;
    pTime->day += day + 2451513;

    if (year >= 70) {
        //the year is 1970-1999, not 2070 to 2099! So adjust by 36525 days,
        //Which is the exact difference between same date 19XX and 20XX.
        pTime->day -= 36525;
    }

    if (hour >= 12) {
        pTime->day ++;
        hour -= 12;
    } else {
        hour += 12;
    }

    pTime->second = (((hour*60)+minute)*60)+second;
    
    return nMsgSize;
}


/******************************************************************************
* Function:     ParseGENTime
*
* Description:  Parse the Generalized Time string and return the date time in
*               Julian day and seconds. NOTE: I do not know what is the
*               difference between UTCTime and GeneralizedTime. For now
*               treat them the same.
*
* Returns:      The number of bytes parsed.
******************************************************************************/
uint ParseGENTime(DATETIME* pTime, const uchar* pMsg, uint nMsgSize) {
    int     year;
    int     month;
    int     day;
    int     hour;
    int     minute;
    int     second;

    if (nMsgSize >= 15) {
        //The year is 4 digits, not two, ignore the first two digits.
        pMsg += 2;
    }

    year  = 0x0F&(*pMsg++); year  += year << 2;  year  += year +  (0x0F&(*pMsg++));
    month = 0x0F&(*pMsg++); month += month << 2; month += month + (0x0F&(*pMsg++));
    day  =  0x0F&(*pMsg++); day  +=  day  <<  2; day  +=  day  +  (0x0F&(*pMsg++));
    hour =  0x0F&(*pMsg++); hour +=  hour <<  2; hour +=  hour +  (0x0F&(*pMsg++));
    minute= 0x0F&(*pMsg++); minute += minute<<2; minute += minute+(0x0F&(*pMsg++));
    second= 0x0F&(*pMsg++); second += second<<2; second += second+(0x0F&(*pMsg++));

    if (*pMsg == '+' || *pMsg == '-') {
        //Time zone adjustment
        char    c = *pMsg++;
        int     nAdjust = 0x0F&(*pMsg++);
        nAdjust += nAdjust << 2; nAdjust += nAdjust + (0x0F & (*pMsg++));
 
        if (c == '+') {
            hour -= nAdjust;
        } else if (c == '-') {
            hour += nAdjust;
        } else {
            //No time zone adjustment.
        }

        if (hour >= 24) {
            day ++;
            hour -= 24;
        }

        if (hour < 0) {
            day --;
            hour += 24;
        }
    }

    // This calculation is good for year 00-99 (2000-2099).
    pTime->day = 367*year;
    pTime->day -= (((year+((month+9)/12))*7)/4);
    pTime->day += (month*275)/9;
    pTime->day += day + 2451513;

    if (year >= 90) {
        //the year is 1990-1999, not 2070 to 2099! So adjust by 36525 days,
        //Which is the exact difference between same date 19XX and 20XX.
        pTime->day -= 36525;
    }

    if (hour >= 12) {
        pTime->day ++;
        hour -= 12;
    } else {
        hour += 12;
    }

    pTime->second = (((hour*60)+minute)*60)+second;

    return nMsgSize;
}


/******************************************************************************
* Function:     VerifySignature
*
* Description:  Verify if signature contained in one certificate is signed by
*               the holder of another certificate. This can also be used to
*               verify a self-signing signature.
*
* Returns:      Zero if all verify OK. Else a none-zero return.
******************************************************************************/
uint VerifySignature(const CERT* pCert, const CERT* pSigner) {
    uint    nDigestSize = sizeof(pCert->signature), r=0, i=0;
    uchar   signature[sizeof(pCert->signature)];

    //First, is the issuer certificate the correct one to use?
    if (NotSameX509Name(&(pCert->issuer), &(pSigner->name))) {
        return SIGNATURE_WRONG_CERTIFICATE;
    }

    if ((0 == pSigner->pubKeyLen) || (0x00 == (0x01 & pSigner->pubKey[sizeof(pSigner->pubKey) - 1]))) {
        return SIGNATURE_WRONG_CERTIFICATE;
    }

    memcpy(signature, pCert->signature, sizeof(signature));

    switch (pCert->hashAlgorithm) {
    case HASH_MD2_WITH_RSA:
        nDigestSize = 0;
        break;
    case HASH_MD4_WITH_RSA:
        nDigestSize = 0;
        break;
    case HASH_MD5_WITH_RSA:
        nDigestSize = MD5_SIZE;
        break;
    case HASH_SHA1_WITH_RSA:
        nDigestSize = SHA1_SIZE;
        break;
    case HASH_SHA256_WITH_RSA:
    case HASH_SHA256_WITH_ECDSA:
        nDigestSize = SHA256_SIZE;
        break;
    case HASH_SHA384_WITH_RSA:
        nDigestSize = SHA384_SIZE;
        break;
    case HASH_SHA512_WITH_RSA:
        nDigestSize = SHA512_SIZE;
        break;
    default:
        break;
    }

    if ((pSigner->pubKeyLen < sizeof(signature)) && (pSigner->pubKeyLen != 128)) {
        const uchar* R = &(signature[sizeof(signature) - pSigner->pubKeyLen]);
        const uchar* S = R + ((pSigner->pubKeyLen) >> 1);
        // TODO: ECC Signature verification.
        switch (pSigner->pubExp) {
        case ECC_secp256r1:
            return gpCipherSet->p256.Verify(
                &(pCert->digest[sizeof(pCert->digest) - nDigestSize]),
                &(pSigner->pubKey[sizeof(pSigner->pubKey) - pSigner->pubKeyLen]),
                R, S)? SIGNATURE_OK : SIGNATURE_INVALID;
        case ECC_secp384r1:
            break;
        }
        return SIGNATURE_OK;
        return SIGNATURE_INVALID;
    }

    // RSA signature;
    gpCipherSet->rsa.RsaEncrypt(
        &(signature[sizeof(signature) - pSigner->pubKeyLen]),
        &(pSigner->pubKey[sizeof(pSigner->pubKey) - pSigner->pubKeyLen]),
        pSigner->pubExp,
        pSigner->pubKeyLen
    );

    // Optionally parse the prefix
    while (r == 0) {
        const uchar* pSign = &(signature[sizeof(signature) - pSigner->pubKeyLen]);
        const uchar* p = NULL;
        ASN1ITEM    item;

        r |= pSign[0] ^ 0x00; r |= pSign[1] ^ 0x01;
        for (i = 2; i < pSigner->pubKeyLen; i++) {
            if (pSign[i] == 0x00) break;
            r |= pSign[i] ^ 0xFF;
        }
        if (r |= pSign[i]) break;
        p = pSign + i + 1;

        p += GetASN1Item(&item, p);
        r |= item.nType ^ SEQUENCE_TAG;
        p += GetASN1Item(&item, p);
        r |= item.nType ^ SEQUENCE_TAG;
        p += GetASN1Item(&item, p);
        r |= item.nType ^ OID_TAG;
        if (r == 0) {
            OID oid = GetOID(p, item.nSize);
            //r |= oid ^ OID_DIGEST_SHA1;
        }
        assert(r == 0);
        break;
    }

    r |= memcmp(
        &(pCert->digest[sizeof(pCert->digest) - nDigestSize]),
        &(signature[sizeof(signature) - nDigestSize]),
        nDigestSize);

    return (r? SIGNATURE_INVALID : SIGNATURE_OK);
}


/******************************************************************************
* Function:     GetPubKeyLen
*
* Description:  Obtain the length of the public key of the certificate. This
*               is length of the certificate holder's public key, not the
*               certificate signer's public key.
*
* Returns:      Public Key length in bytes, not bits.
******************************************************************************/
uint GetPubKeyLen(const CERT* pCert) {
    return pCert->pubKeyLen;
}


/******************************************************************************
* Function:     EncryptByCert
*
* Description:  Encrypt using the public key contained in the certificate.
*               The size of data to be encrypted must match the length of
*               the public key. Note only public key is needed to do RSA
*               encryption but private key is needed to do decryption.
*
* Returns:      Bytes encrypted, if encrypted. Else zero.
******************************************************************************/
uint EncryptByCert(const CERT* pCert, uchar* pData, uint nDataSize) {
    if (nDataSize != pCert->pubKeyLen) {return 0;}

    gpCipherSet->rsa.RsaEncrypt(
        pData,
        &(pCert->pubKey[sizeof(pCert->pubKey) - pCert->pubKeyLen]),
        pCert->pubExp,
        pCert->pubKeyLen
        );

    return nDataSize;
}


/******************************************************************************
* Function:     AuthenticateCert
*
* Description:  Attempt to authenticate a certificate. Note we are returning
*               more information than simply a Yes or NO.
*
* Returns:      The status of the certificate, to be interpretted based on
*               the bit combination of the status.
******************************************************************************/
CERT_STATUS AuthenticateCert(CERT* pCert, CERT** ppMidCerts) {
    CERT_STATUS         eStatus;
    CERT*     pCert2;

    if (NULL == pCert) {return CS_NONE_EXIST;}

    if (pCert->status & CS_VERIFIED) {
        return pCert->status;
    }

    if (ppMidCerts == NULL) {
        ppMidCerts = &gpMidCerts;
    }

    //We only check expiration time if we know the time.
    if (0 != pCert->receiveTime) {
        //Has the certificate expired?
        DATETIME        curTime;

        //The UnixTime in seconds is counted from 1970 01/01 00:00am UTC,
        //which in Julian date is 2440587.5. See US Navy Site:
        //  http://aa.usno.navy.mil/data/docs/JulianDate.html
        curTime.day    = pCert->receiveTime/86400;
        curTime.second = pCert->receiveTime - (curTime.day*86400) + 43200;
        curTime.day   += 2440587;
        if (curTime.second >= 86400) {
            curTime.day ++;
            curTime.second -= 86400;
        }

        if (curTime.day < pCert->expireTime.day) {
            //We are OK.
        } else if ((curTime.day > pCert->expireTime.day) ||
            (curTime.second >= pCert->expireTime.second) ) {
            //The certificate expired.
            pCert->status |= CS_EXPIRED;
        }
    }

    if (NULL == pCert->pRootCert) {
        if (0 == NotSameX509Name(&(pCert->name), &(pCert->issuer))) {
            pCert->status |= CS_SELF;
            pCert2 = pCert;
        } else {
            pCert->status &= ~CS_SELF;
            pCert2 = FindCert(&(pCert->issuer), ppMidCerts);
        }

        pCert->pRootCert = pCert2;

        if ((NULL != pCert2) && (0 == VerifySignature(pCert, pCert2))) {
            if (pCert->status & CS_SELF) {
                pCert->status &= ~CS_PENDING;
                pCert->status |= CS_VERIFIED;
                if (pCert->status & CS_ROOT) {
                    pCert->status |= CS_OK;
                }
            } else {
                pCert->status |= CS_PENDING;
            }
        } else {
            pCert->status &= ~CS_PENDING;
            pCert->status |= CS_BAD;
            pCert->status |= CS_VERIFIED;
        }
    }

    if ((pCert->status & CS_PENDING) != CS_PENDING) {
        return pCert->status;
    }

    if (pCert->status & CS_SELF) {
        return pCert->status;
    } else {
        eStatus = AuthenticateCert(pCert->pRootCert, ppMidCerts);

        if ((eStatus & CS_PENDING) != CS_PENDING) {
            pCert->status &= ~CS_PENDING;
            pCert->status |= eStatus & (CS_PENDING | CS_EXPIRED);
            pCert->status |= CS_VERIFIED;
        }
    }

    return pCert->status;
}

void SetEcc(CERT* pCert, const uchar* eccPubKey, uint eccGroup) {
    switch (eccGroup) {
    case ECC_secp256r1:
        pCert->pubExp = ECC_secp256r1;
        pCert->pubKeyLen = 0x40;
        break;
    default:
        assert(0);
        pCert->pubExp = ECC_secp256r1;
        pCert->pubKeyLen = 0x40;
        break;
    }
    memcpy(&(pCert->pubKey[sizeof(pCert->pubKey) - pCert->pubKeyLen]), eccPubKey, pCert->pubKeyLen);
    pCert->pubKeyLen |= 0;
    eccGroup;
}

/******************************************************************************
* Function:     PubKey
*
* Description:  Returns the public key contained in the certificate, in the
*               big endian convention, same as in the certificate.
*
* Returns:      Size of the public key in bytes. Or zero if no key found.
******************************************************************************/
const uchar* PubKey(const CERT* pCert) {
    return &(pCert->pubKey[sizeof(pCert->pubKey) - pCert->pubKeyLen]);
}


/******************************************************************************
* Function:     GetPubKey
*
* Description:  Returns the public key contained in the certificate, in the
*               big endian convention, same as in the certificate.
*
* Returns:      Size of the public key in bytes. Or zero if no key found.
******************************************************************************/
uint GetPubKey(const CERT* pCert, uchar* pKey) {
    if (NULL != pKey) {
        memcpy(pKey, &(pCert->pubKey[sizeof(pCert->pubKey) - pCert->pubKeyLen]), pCert->pubKeyLen);
        return pCert->pubKeyLen;
    }

    return 0;
}


/******************************************************************************
* Function:     GetPubExp
*
* Description:  Returns the public key exponent contained in the certificate,
*               which is mostly a small integer. Most likely 17 or 65537.
*
* Returns:      Integer representing the public exponent.
******************************************************************************/
uint GetPubExp(const CERT* pCert) {
    return pCert->pubExp;
}


/******************************************************************************
* Function:     GetCertName
*
* Description:  Get the common name of the certificate already parsed.
*
* Returns:      A const pointer to the null terminated common name string.
******************************************************************************/
const char* GetCertName(const struct CERT* pCert) {
    return pCert->name.CommonName;
}


/******************************************************************************
* Function:     GetUniqueName
*
* Description:  Extract the distinguished name block by parsing the message
*               normally what's being parsed is part of a certificate and we
*               want to extract the certificate holder's name. But by intentionally
*               negate the nMsgSize to negative, we may parse a unique name block and
*               the pCert pointer is actually a pointer to struct X509NAME.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint GetUniqueName (const CERT* pCert, uchar* pMsgBuff, uint nMsgSize) {
#define SET_COUNT       7   //Magic number, do not change.
#define SET_OVERHEAD    11  //Magic number, do not change.
#define SET_OVERHEAD2   17  //Magic number, do not change.

    uint            i, nLen = 0, nMagic;
    OID             oid;
    uchar*  pMsg =  pMsgBuff;
    const X509NAME* pName = &(pCert->name);
    uint            nSizes[SET_COUNT];

    //Do a little bit magic here
    if (((int)nMsgSize) < 0) {
        //What we passed in is X509NAME pointer, not cert pointer
        pName = (const X509NAME*)pCert;
        nMsgSize = 0 - nMsgSize;
    }

    memset(&nSizes, 0, sizeof(nSizes));

    //First calculate the total message length
    //The message is composed of 1 to 6 sets, each set is 11 bytes plus
    //the length of the string. Do not change the following order!
    if ((nSizes[0] = strlen(pName->country)) > 0) {nLen += nSizes[0] + SET_OVERHEAD;}
    if ((nSizes[1] = strlen(pName->state  )) > 0) {nLen += nSizes[1] + SET_OVERHEAD;}
    if ((nSizes[2] = strlen(pName->localName))>0) {nLen += nSizes[2] + SET_OVERHEAD;}
    if ((nSizes[3] = strlen(pName->orgName)) > 0) {nLen += nSizes[3] + SET_OVERHEAD;}
    if ((nSizes[4] = strlen(pName->orgUnit)) > 0) {nLen += nSizes[4] + SET_OVERHEAD;}
    if ((nSizes[5] = strlen(pName->CommonName))>0){nLen += nSizes[5] + SET_OVERHEAD;}
    if ((nSizes[6] = strlen(pName->emailaddress))>0){nLen += nSizes[6] + SET_OVERHEAD2;}

    //OK we can start to construct the message
    *pMsg++ = SEQUENCE_TAG;
    if (nLen >= 0x0100) {
    *pMsg++ = 0x82;
    *pMsg++ = (uchar)(nLen>>8);
    }
    else if (nLen >= 0x0080)
    {
    *pMsg++ = 0x81;
    }
    *pMsg++ = (uchar)(nLen>>0);

    for (i=0; i<SET_COUNT; i++) {
        const char* pString = NULL;

        //Set 1: Country
        if ((nMagic = nSizes[i]) == 0) continue;

        switch (i)  {
        case 0: oid = OID_NAME_COUNTRY;
                pString = pName->country;
                break;
        case 1: oid = OID_NAME_STATE;
                pString = pName->state;
                break;
        case 2: oid = OID_NAME_LOCAL;
                pString = pName->localName;
                break;
        case 3: oid = OID_NAME_ORG;
                pString = pName->orgName;
                break;
        case 4: oid = OID_NAME_UNIT;
                pString = pName->orgUnit;
                break;
        case 5: oid = OID_NAME_COMMON;
                pString = pName->CommonName;
                break;
        case 6: oid = OID_EMAIL;
                if (pName->emailaddress[0] & 0x80) {
                    nMagic ++;
                    oid = OID_EMAIL2;
                }
                pString = pName->emailaddress;
                nMagic += SET_OVERHEAD2-SET_OVERHEAD;
                break;
        default:
            oid = OID_UNKNOWN;
            break;
        }

        nMagic += SET_OVERHEAD - 2;
        *pMsg++ = SET_TAG;
        *pMsg++ = (uchar)(nMagic>>0);

        nMagic -= 2;
        *pMsg++ = SEQUENCE_TAG;
        *pMsg++ = (uchar)(nMagic>>0);

        nMagic -= 2;
        *pMsg++ = OID_TAG;
        *pMsg++ = (uchar)(0x03);

        nMagic -= 2;
        pMsg[-1] = SetOID(pMsg, oid);
        nMagic -= pMsg[-1];
        pMsg += pMsg[-1];

        *pMsg++ = (oid == OID_EMAIL)?IA5STRING_TAG:PRINTABLE_STRING_TAG;
        *pMsg++ = (uchar)(nMagic>>0);

        memcpy(pMsg, pString, nMagic);

        if (oid == OID_EMAIL2) {
            pMsg[0] &= 0x7F;
        }
        pMsg += nMagic;
    }

    return (pMsg - pMsgBuff);
}


#ifdef CERT_TEST

#include <malloc.h>

#include "certSamples.h"

uint DoCertTest()
{
    uint        len = 0, size=0, ret = 0;
    CERT*       pRoot = NULL;
    CERT*       pCert = NULL;
    CERT_STATUS eStatus = CS_UNKNOWN;
    const CIPHERSET* pMyCiphers = NULL;

    pMyCiphers = InitCiphers(&gCipherSet, NULL);

    StartCerts(malloc, free, pMyCiphers);
    pRoot = CreateCert(CS_ROOT, 0);
    len = ParseCert(pRoot, gGeoTrustRoot, sizeof(gGeoTrustRoot));
    ret |= len - sizeof(gGeoTrustRoot);
    eStatus = AuthenticateCert(pRoot, NULL);
    ret |= eStatus ^ (CS_ROOT|CS_SELF|CS_OK|CS_VERIFIED);
    InsertCert(pRoot, NULL);

    pCert = CreateCert(CS_UNKNOWN, 0);
    len = ParseCert(pCert, gGoogleCA, sizeof(gGoogleCA));
    ret |= len - sizeof(gGoogleCA);
    eStatus = AuthenticateCert(pCert, NULL);
    ret |= eStatus ^ (CS_OK|CS_VERIFIED);
    InsertCert(pCert, NULL);

    CleanupCerts(NULL);

    return ret;
}

#endif //CERT_TEST
