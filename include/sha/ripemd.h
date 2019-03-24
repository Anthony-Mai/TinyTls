// Copyright (c) 2014-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_RIPEMD_H
#define BITCOIN_CRYPTO_RIPEMD_H

#include "cipher.h"

#define TEST_RIP     //Define this to test SHA256 against the test suite

//#include <stdint.h>
//#include <stdlib.h>

#define RIP_SIZE    20

// The RIPEMD160 context
typedef struct RIPCTX
{
    uchar buf[64];
    uint s[5];
    uint64 bytes;
} RIPCTX;

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

    const CDAT* ripCd();
    void SetRip(CIPHER* pCipher);

    void ripInit(RIPCTX* pCtx, const CDAT* pIData);
    void ripInput(RIPCTX* pCtx, const uchar* pBuffer, uint nCount);
    void ripDigest(const RIPCTX* pCtx, uchar pDigest[RIP_SIZE]);
    void ripHash(const uchar* pData, uint nSize, uchar pDigest[RIP_SIZE]);

#ifdef TEST_RIP
    uint ripTest();
#endif //TEST_RIP

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


/** A hasher class for RIPEMD-160. */
/*
class CRIPEMD160
{
private:
    uint32_t s[5];
    unsigned char buf[64];
    uint64_t bytes;

public:
    static const size_t OUTPUT_SIZE = 20;

    CRIPEMD160();
    CRIPEMD160& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CRIPEMD160& Reset();
};
*/

#endif // BITCOIN_CRYPTO_RIPEMD_H
