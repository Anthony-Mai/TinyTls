#ifndef ECC_P256_H
#define ECC_P256_H
#pragma once

#include "ecc.h"

namespace P256 {
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
    static uint32_t Verify(const uint8_t digest[32], const uint8_t pubKey[64], const uint8_t R[32], const uint8_t S[32]);
};

struct G : XY
{
    G();
    //G(uint32_t s) : NN(s) {}
    //G(const NN& s) : NN(s) {}
    G& bytesIn(const uint8_t* pBytes);
    G& netIn(const uint8_t* pBytes, size_t cbLen = (NN::N)*sizeof(uint32_t));
    //operator NN& () { return *this; }
    //void MontXY(XZ_PT& P, XZ_PT& Q) const;
    void PointMult(uint8_t* PublicKey, const NN& SecretKey) const;
    //static void MontX2(XZ_PT& Y, const XZ_PT& X);
};

} // namespace P256

#endif //ECC_P256_H
