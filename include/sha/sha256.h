#ifndef _SHA256_H_INCLUDED_6_28_2014_
#define _SHA256_H_INCLUDED_6_28_2014_


#define TEST_SHA256     //Define this to test SHA256 against the test suite


// The SHA256 block size and message digest sizes, in bytes
#define SHA256_DATA     64
#define SHA256_SIZE     32

// The SHS hash context
typedef struct SHA256
{
    uint wdat[16];
    uint hash[8];
    uint count[2];
} SHA256;

struct CDAT;
struct CIPHER;
typedef struct CDAT     CDAT;
typedef struct CIPHER   CIPHER;


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

const CDAT* Sha256Cd();
void SetSha256(CIPHER* pCipher);

void Sha256Init (SHA256* pShaCtx, const CDAT* pIData);
void Sha256Input(SHA256* pShaCtx, const uchar* pBuffer, uint nCount);
void Sha256Digest(const SHA256* pSha, uchar pDigest[SHA256_SIZE]);
void Sha256Hash(const uchar* pData, uint nSize, uchar pDigest[SHA256_SIZE]);

#ifdef TEST_SHA256
uint sha256Test();
#endif //TEST_SHA256

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


#endif //#ifndef _SHA256_H_INCLUDED_6_28_2014_
