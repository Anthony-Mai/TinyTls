#ifndef _CHACHA20_H_
#define _CHACHA20_H_
#pragma once

#include <stdint.h>

struct ChachaKey {
    uint32_t data_[8];
};

struct ChachaNounce {
    uint32_t n_[3];
    operator const uint8_t* () { return (const uint8_t*)n_; }
    void operator ^= (const uint32_t cnt[2]) { n_[1] ^= cnt[0]; n_[2] ^= cnt[1]; }
};

struct ChachaBlock {
    uint32_t data_[16];
    bool operator == (const ChachaBlock& r);
};

struct Chacha20 {
    uint32_t  state_[16];
public:
    // Initialize with seq counter 0, and good for initialize Poly1305.
    void Init(const ChachaKey& k, const ChachaNounce& nc);

    int Encode(uint8_t* pText, size_t cbLen, int off);

    int Encrypt(uint8_t* pText, size_t cbLen, uint8_t sTag[16], const uint8_t* aadText, size_t cbAad);

    void Block(ChachaBlock& b);

    uint32_t& operator [](int idx) { return state_[idx]; }

    bool operator == (const Chacha20& r);

    // Increment seq counter by 1.
    Chacha20& operator ++ ();

    Chacha20& operator += (const Chacha20& r);

    void operator ()(ChachaBlock& b) const;
    void QRound(int ia, int ib, int ic, int id);
    void InnerRound();
};

struct Poly1305 {
    uint32_t r_[4];
    uint32_t s_[4];
    uint32_t cc_[5];
    uint32_t ac_[5];
    uint32_t off_, cnt_;

public:
    Poly1305(const Chacha20& cha);
    void add(const uint8_t* pMsg, size_t cbBytes);
    void final(uint8_t tag[16]);
	void hash(uint8_t tag[16], const uint8_t* pMsg, size_t cbBytes);
private:
    void mreduce();
};

#endif //_CHACHA20_H_
