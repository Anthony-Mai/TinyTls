#ifndef HKDF_H_INCLUDED
#define HKDF_H_INCLUDED

#include "ssl_defs.h"
#include "hmac.h"

struct CIPHER;


class Hkdf: public HMac
{
public:
    static const uchar null_[32];
private:
    const uchar* info_;
    uint        nsize_;
    uint        bsize_;
    uint        cnt_;
public:
    Hkdf(const CIPHER& c, const uchar* key, size_t cbKeySize, const uchar* ikm, size_t cbIkmSize);
    Hkdf(const Hkdf& src, const uchar* ikm, size_t cbIkmSize);
    void ExpandLabel(const char* label, const uchar* pInfo, size_t cbInfoSize, size_t L = 0);
    void Expand(const uchar* pInfo, size_t cbInfoSize);
    void Output(uchar* pOut, size_t cbBufSize);
};

#endif //HKDF_H_INCLUDED
