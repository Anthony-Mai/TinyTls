#ifndef ECC_K256_H
#define ECC_K256_H
#pragma once

#include "ecc.h"

namespace K256 {
struct ECDKeyPair
{
    XY  pubKey;
    NN  priKey;

    void Create(EntropyFunc fn);
    void Generate(const NN& nounce);
};

struct ECDSign
{
    NN r, s;
    void Sign(const uint8_t digest[32], const uint8_t nounce[32], const NN& priKey);
    bool Test(const uint8_t digest[32], const XY& pubKey) const;
    void OutR(uint8_t* pR) const;
    void OutS(uint8_t* pS) const;
};
} // namespace K256

#endif //ECC_K256_H
