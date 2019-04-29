#ifndef AES_H_INCLUDED
#define AES_H_INCLUDED
#pragma once

#include <stdint.h>

#include "platform.h"

struct AesText;
union AesCtx;

union u32 {
    uint32_t v;
    uint8_t b[4];
};

struct HKey
{
    u128 h[32][16];
    HKey(const AesText& key);
    HKey(const AesCtx& ctx);
    void pmult(AesText& x);
};

struct AesKey {
    u32 data[4];
    AesKey& set(const uint8_t b[16]);
    AesKey& operator () (uint32_t n); // Key expansion
};


struct AesText {
    u32 text[4];
    bool operator == (const AesText& s);
    AesText& set(const uint8_t b[16]);
    void out(uint8_t b[16]);
    void SubBytes();
    void ShiftRows();
    void MixColumns();
    void AddRound(const AesKey& roundKey);

    AesText& inc();
    void Enc(AesText& x) const;
};

struct AesCtr : AesText {
    AesCtr(const uint8_t iv[12]);
    void incIV();
};

union AesCtx {
    AesKey rnd[11];
    struct {
        AesKey r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, rf;
    };
    AesCtx() {}
    AesCtx(const AesKey& key);
    const AesCtx& operator () (AesText& t) const;
};

class Aes128Gcm {
private:
    AesCtx aes_;
    AesCtr ctr_;
    HKey hkey_;
public:
    Aes128Gcm(const uint8_t key[16], const uint8_t iv[12]);
    ~Aes128Gcm();

    int Encrypt(uint8_t* pText, size_t cbLen, uint8_t ivExp[8], uint8_t sTag[16], const uint8_t* aadText, size_t cbAad);
    int Decrypt(uint8_t* pText, size_t cbLen, const uint8_t sTag[16], const uint8_t* aadText, size_t cbAad);
};

void aes_NewRound(AesKey& key, uint32_t it);

#endif //AES_H_INCLUDED
