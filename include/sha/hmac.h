#ifndef HMAC1_H_INCLUDED
#define HMAC1_H_INCLUDED

#include "ssl_defs.h"

struct CIPHER;

class HMac
{
protected:
    const CIPHER& c_;
    CTX ctx1_;
    CTX ctx2_;
    uchar digest_[32];

public:
    HMac(const CIPHER& c, const uchar* key, size_t cbKeySize);
    HMac& hash(HMac& src, const uchar* text, size_t cbSize);
    HMac& hash(const uchar* text, size_t cbSize);
    operator const uchar* () const { return digest_; }
    uint size() const; // { return c_.dSize; }
};

class PrfHash
{
    const uchar* seed_;
    uint        nSeedSize_;
    uint        nGenSize_;
    uint        nUseSize_;
    HMac        mac_;
    HMac        a_;
public:
    PrfHash(const CIPHER& c, const uchar* key, size_t cbKeySize, const uchar* seed, size_t cbSeedSize);
    void Output(uchar* pOut, size_t cbBufSize);
};

#endif //HMAC1_H_INCLUDED
