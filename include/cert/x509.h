#ifndef X509_H_INCLUDED
#define X509_H_INCLUDED

#include "asn.h"

namespace X509 {

#define KEYUSAGE_DIGITALSIGNATURE 0x80 // digitalSignature(0),
#define KEYUSAGE_NONREPUDIATION   0x40 // nonRepudiation(1), --recent editions of X.509 have renamed this bit to contentCommitment
#define KEYUSAGE_KEYENCIPHERMENT  0x20 // keyEncipherment(2),
#define KEYUSAGE_DATAENCIPHERMENT 0x10 // dataEncipherment(3),
#define KEYUSAGE_KEYAGREEMENT     0x08 // keyAgreement(4),
#define KEYUSAGE_KEYCERTSIGN      0x04 // keyCertSign(5),
#define KEYUSAGE_CRLSIGN          0x02 // cRLSign(6),
#define KEYUSAGE_ENCIPHERONLY     0x01 // encipherOnly(7),
                                       // decipherOnly(8)

//enum ALG {
//    ALG_SHA256 = 0,
//};

enum x509CB {
    CB_ALGORITHM = 0,
    CB_SERIAL = 1,
    CB_HASH = 2,
    CB_ISSUER_NAME = 3,
    CB_SUBJECT_NAME = 4,
    CB_PKEY_INFO = 5,
    CB_ISSUE_TIME = 6,
    CB_EXPIRE_TIME = 7,
    CB_SIGN = 8,
    CB_KEY_USAGE = 9,
    CB_BASIC_CONSTRAINT=10,
    CB_SUBJECT_ALTNAME=11,
};

struct CB_DATA {
    x509CB  eType;
    const void* pIn;
    uint    nInSize;
    void*   pOut;
};

struct X509NAME {
    const char* country;
    const char* state;
    const char* local;
    const char* company;
    const char* unitname;
    const char* commonname;
    size_t totalSize() const;
};

typedef uint (*X509Callback)(void* context, const CB_DATA& cbData);

class X509v3 : public ASN::Seq2 {
public:
    X509v3(pu8& s, X509Callback cb, void* ctx);
};

} //namespace X509

#endif //X509_H_INCLUDED
