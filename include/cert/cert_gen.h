#ifndef CERT_GEN_INCLUDED_
#define CERT_GEN_INCLUDED_

struct CIPHERSET;
namespace X509 { struct X509NAME; }

struct KEYPAIR {
    const uint8_t* pPubKey;
    const uint8_t* pPriKey;
    uint32_t       nEccGroup;
};

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

//int certGen(const CIPHERSET& cipherSet, const X509::X509NAME& name, const char* outName);
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
    );


#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


#endif //CERT_GEN_INCLUDED_
