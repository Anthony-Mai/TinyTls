#ifndef _SHA_H_INCLUDED_03_12_2019_
#define _SHA_H_INCLUDED_03_12_2019_

struct CIPHER;

void SsaSign(const CIPHER& sha, uint8_t* block, uint32_t nSize, const uint8_t* pCtx, uint32_t nCtxLen);
uint32_t SsaTest(const CIPHER& sha, const uint8_t* block, uint32_t nSize, const uint8_t* pCtx, uint32_t nCtxLen);

#endif //_SHA_H_INCLUDED_03_12_2019_
