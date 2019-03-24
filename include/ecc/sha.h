#ifndef SHA_BASE_H
#define SHA_BASE_H

#include <stdint.h>

class Sha
{
public:
    Sha() {}
    virtual ~Sha() {}
    virtual void Init() = 0;
    virtual void Update(const uint8_t* data, size_t cbSize) = 0;
    virtual uint32_t Final(uint8_t* md) = 0;
};

#endif //SHA_BASE_H