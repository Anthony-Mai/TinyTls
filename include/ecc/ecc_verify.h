#ifndef ECC_VERIFY_H_INCLUDED_
#define ECC_VERIFY_H_INCLUDED_
#pragma once

#include "ecc.h"

#define edd_public_key_size     32
#define edd_secret_key_size     32
#define edd_private_key_size    64
#define edd_signature_size      64

void eco_DigestToWords(NN& Y, const uint8_t* md);

class Sha;  // Defined in "sha.h"
struct CIPHER;

class EdpSigv {
public: // for test only
    static const NN w_I;
    static const NN w_d;

    uint8_t pk[32];
    PE_PT q_table[16];

public:
    EdpSigv(const uint8_t pubKey[32]);
    bool Verify(
        const CIPHER& cipher,           // Message Digest Algorithm
        const unsigned char *signature, // signature (R,S)
        const unsigned char *msg,       // Message text
        size_t msg_size
    ) const;

    void eddp_PolyPointMultiply(
        XY*     r,
        const NN& a,
        const NN& b) const;

    static void edd_CalculateX(NN& X, const NN& Y, uint8_t parity);
};

int edd_VerifySignature(
    CIPHER& cipher,                 // Message Digest Algorithm
    const unsigned char *signature, // IN: signature (R,S)
    const unsigned char *publicKey, // IN: public key
    const unsigned char *msg, size_t msg_size); // IN: message to sign

#endif //ECC_VERIFY_H_INCLUDED_

