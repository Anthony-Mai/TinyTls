#ifndef ECC_SIGN_H_INCLUDED_
#define ECC_SIGN_H_INCLUDED_
#pragma once

#define edd_public_key_size     32
#define edd_secret_key_size     32
#define edd_private_key_size    64
#define edd_signature_size      64

struct NN;
struct PE_PT;
struct PA_PT;
struct Ext_PT;
struct BLINDING;
struct CIPHER;

class Sha;

void ecp_TrimSecretKey(uint8_t* X);

void ecp_4fold(uint8_t* Y, const uint32_t* X);
void ecp_8fold(uint8_t* Y, const uint32_t* X);

uint8_t* ecp_EncodeKey(uint8_t* key, const NN& X, uint8_t parity);
uint8_t ecp_DecodeKey(NN& Y, const uint8_t* X);

void edd_CreateKeyPair(
    CIPHER& cipher,         // Message Digest Algorithm
    unsigned char *pubKey,  // public key out
    unsigned char *privKey, // private key out
    const BLINDING* blinding,   // [optional] null or blinding context
    const unsigned char *sk);   // secret key (32 bytes)

void edd_SignMessage(
    CIPHER& cipher,             // Message Digest Algorithm
    uint8_t* signature,         // OUT: [64 bytes] signature (R,S)
    const uint8_t* keyPair,     // [64 bytes] private/public key pair (sk,pk)
    const BLINDING* blinding,   // [optional] null or blinding context
    const uint8_t* msg,         // [msg_size bytes] message to sign
    size_t msg_size);

#endif //ECC_SIGN_H_INCLUDED_
