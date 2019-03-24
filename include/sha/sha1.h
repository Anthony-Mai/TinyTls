#ifndef _SHA1_H_INCLUDED_6_27_2014_
#define _SHA1_H_INCLUDED_6_27_2014_


#define TEST_SHA1    //Define this to test SHA1 against the test suite


// The SHS block size and message digest sizes, in bytes
#define SHA1_DATA       64
#define SHA1_SIZE       20

// The SHA1 Context
typedef struct SHA
{
    uint    ints[SHA1_DATA>>2]; // SHS data buffer in 4 byte integers
    uint    state[SHA1_SIZE>>2];// SHS digest state
	uint    countHi, countLo;   // 64-bit byte count. Must Hi first Lo second
} SHA;

struct CDAT;
struct CIPHER;
typedef struct CDAT     CDAT;
typedef struct CIPHER   CIPHER;


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

const CDAT* Sha1Cd();
void SetSha1(CIPHER* pCipher);

void Sha1Init(  SHA* pSha, const CDAT* pIData);
void Sha1Input( SHA* pSha, const uchar* pBuffer, uint nBytes);
void Sha1Digest(const SHA* pSha, uchar* pDigest);
void Sha1Hash(const uchar* pData, uint nSize, uchar pDigest[SHA1_SIZE]);

#ifdef TEST_SHA1
int sha1Test();
#endif //TEST_SHA1

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


#endif //#ifndef _SHA1_H_INCLUDED_6_27_2014_
