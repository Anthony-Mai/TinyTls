#ifndef _SHA512_H_INCLUDED_
#define _SHA512_H_INCLUDED_


#define TEST_SHA256     //Define this to test SHA256 against the test suite


// The SHA512 block size and message digest sizes, in bytes
#define SHA512_DATA     128
#define SHA384_SIZE     48
#define SHA512_SIZE     64

struct CDAT;
struct CIPHER;
typedef struct CDAT     CDAT;
typedef struct CIPHER   CIPHER;

// The SHS hash context
typedef struct SHA512
{
    uint64_t h_[8];
    uint64_t Nl, Nh;
    union {
        uint64_t    d[8];
        uint8_t     p[SHA512_DATA];
    } u;
    uint32_t num, md_len;
} SHA512;

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

const CDAT* Sha384Cd();
const CDAT* Sha512Cd();
void SetSha384(CIPHER* pCipher);
void SetSha512(CIPHER* pCipher);

void Sha384Init(SHA512* pShaCtx, const CDAT* pIData);
void Sha512Init (SHA512* pShaCtx, const CDAT* pIData);
void Sha512Input(SHA512* pShaCtx, const uint8_t* pBuffer, uint32_t nCount);
void Sha512Digest(const SHA512* pSha, uint8_t pDigest[SHA512_SIZE]);
void Sha512Hash(const uchar* pData, uint32_t nSize, uint8_t pDigest[SHA512_SIZE]);

void Sha384Digest(const SHA512* pSha, uint8_t pDigest[SHA384_SIZE]);
void Sha384Hash(const uchar* pData, uint32_t nSize, uint8_t pDigest[SHA384_SIZE]);

#ifdef TEST_SHA512
uint sha512Test();
#endif //TEST_SHA512

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


#endif //_SHA512_H_INCLUDED_
