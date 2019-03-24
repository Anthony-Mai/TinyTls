#ifndef ECC_X25519_H_INCLUDED_
#define ECC_X25519_H_INCLUDED_
#pragma once

#include "ecc.h"

struct CIPHER;

namespace X25519 {

void genPubKey(
    CIPHER& cipher,         // Message Digest algorithm. Mustbe sha512
    uint8_t* pubKey,        // Public key out
    const uint8_t* priKey   // Private key in
    //const BLINDING* blinding,   // [optional] null or blinding context
);

struct ECDSign
{
    NN r, s;
    const CIPHER& c_;
    ECDSign(const CIPHER& c) : c_(c) {}
    void Sign(const uint8_t* keyPair, const uint8_t* pMsg, uint32_t nSize);
    bool Test(const uint8_t* pubKey, const uint8_t* pMsg, uint32_t nSize) const;
    void OutR(uint8_t* pR) const;
    void OutS(uint8_t* pS) const;
    operator const uint8_t* () const { return (const uint8_t*)r.n_; }
};

struct G : NN
{
    G() : NN(9) {}
    G(uint32_t s) : NN(s) {}
    G(const NN& s) : NN(s) {}
    operator NN& () { return *this; }
    void MontXY(XZ_PT& P, XZ_PT& Q) const;
    void PointMult(uint8_t* PublicKey, const NN& SecretKey) const;
    static void MontX2(XZ_PT& Y, const XZ_PT& X);
};

} // namespace X25519

#endif //ECC_X25519_H_INCLUDED_
