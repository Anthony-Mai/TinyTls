#ifndef OID_H_INCLUDED
#define OID_H_INCLUDED

typedef unsigned char uchar;
typedef unsigned int  uint;

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

typedef enum OID
{
    OID_UNKNOWN = 0,
    OID_RSAA = 1,
    OID_EMAIL = 2,
    OID_EMAIL2 = 3,

    OID_HASH_MD2_RSA = 8,
    OID_HASH_MD4_RSA = 9,
    OID_HASH_MD5_RSA = 10,
    OID_HASH_SHA1_RSA = 11,
    OID_HASH_SHA256_RSA = 12,
    OID_HASH_SHA384_RSA = 13,
    OID_HASH_SHA512_RSA = 14,
    OID_HASH_SHA256_ECDSA = 15,

    OID_ECCGROUP_SECP256R1 = 16,
    OID_ECGROUP_SECP384R1 = 17,

    OID_PUBKEY_RSA = 24,
    OID_PUBKEY_ECC = 25,

    OID_X509V3_KEY_USAGE=32,
    OID_X509V3_SUBJECT_ALTNAME = 33,
    OID_X509V3_BASIC_CONSTRAINTS=34,

    OID_NAME_COMMON     = 64,
    OID_NAME_UNIT       = 65,
    OID_NAME_ORG        = 66,
    OID_NAME_LOCAL      = 67,
    OID_NAME_STATE      = 68,
    OID_NAME_COUNTRY    = 69,

    OID_DIGEST_MD2      = 72,
    OID_DIGEST_MD4      = 73,
    OID_DIGEST_MD5      = 74,
    OID_DIGEST_SHA1     = 75,
    OID_DIGEST_SHA256   = 76
} OID;

OID GetOID(const uchar* pMsg, uint nMsgSize);
uint SetOID(uchar* pBuff, OID oid);

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus

#endif //OID_H_INCLUDED
