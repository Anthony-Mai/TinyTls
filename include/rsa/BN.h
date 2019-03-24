#ifndef _BN_H_INCLUDED_6_14_2014_
#define _BN_H_INCLUDED_6_14_2014_

typedef uint8_t uchar;
typedef uint32_t uint;

#define BN_SIZE 64  //64 x 32 bits per uint represents a total of 2048 bites.

#ifdef WIN32
#define LITTLE_ENDIAN   1
#elif _WIN64
#define LITTLE_ENDIAN   1
#else //WIN32
//Define one of the endianness below, depending on the platform.
//#define BIG_ENDIAN   1
//#define LITTLE_ENDIAN   1
#endif //WIN32

typedef uint (*FRND)(void);

typedef struct BN
{
    uint    data[BN_SIZE];
} BN;


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

void BN_set(BN* pX, uint M);
uint BN_modw(const BN* pX, uint M);
uint BN_getBits(const BN* pX);
uint BN_isZero(const BN* pX);
uint BN_isOne(const BN* pX);
uint BN_isEven(const BN* pX);
uint BN_isEqual(const BN* pX, const BN* pY);
uint BN_topOff(BN* pX);
uint BN_ShiftW(BN* pX, uint s);
void BN_ShiftR(BN* pX, uint s);
uint BN_isNotBigger(const BN* pX, const BN* pY);
uint BN_add(BN* pR, const BN* pY);
uint BN_sub(BN* pR, const BN* pY);
uint BN_sub2(const BN* pX, const BN* pY, BN* pR);
void BN_iadd(BN* pX, uint M);
void BN_isub(BN* pX, uint M);
void BN_divide(const BN* pX, const BN* pM, BN* pQ, BN* pR);
void BN_mult(const BN* pX, const BN* pY, BN pR[2]);
uint BN_multW(const BN* pX, uint W, BN* pR);
void BN_multModR(const BN* pX, const BN* pY, const BN* pM, const BN* pR, BN* pResult);
void BN_iModR(BN* pX, const BN* pM, const BN* pR);
void BN_reverse(const BN* pM, BN* pR);
void BN_MInverse(const BN* pX, const BN* pM, BN* pR);
uint BN_RMTest(const BN* pX, uint testBase);
void BN_MontMult(const BN* pX, const BN* pY, const BN* pM, uint w, BN* pResult);
void BN_ExpMod(const BN* pX, const BN* pE, const BN* pM, BN* pResult);

void BN_Random(FRND pfRnd, BN* pR, uint nKeyBytes);
void BN_Prime (FRND pfRnd, BN* pR, uint nKeyBytes);
uint BN_isPrime(const BN* pR);

void BN_KeyGen(FRND pfRnd, uint nPubExp, uint nKeyBytes, uchar* pPubKey, uchar* pPriKey);
void BN_Encrypt(uchar* pText, const uchar* pPubKey, uint nPubExp, uint nKeyBytes);
void BN_Decrypt(uchar* pText, const uchar* pPubKey, const uchar* pPriKey, uint nKeyBytes);

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


#endif //#ifndef _BN_H_INCLUDED_6_14_2014_
