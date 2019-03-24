#ifndef BASE_TYPE_H
#define BASE_TYPE_H

#define UINT64(X)   X##ULL

typedef union M16
{
    uint16_t u16;
    int16_t s16;
    uint8_t bytes[2];
    struct { uint8_t b0, b1; } u8;
    struct { uint8_t b0; int8_t b1; } s8;
} M16;

typedef union M32
{
    uint32_t u32;
    int32_t s32;
    uint8_t bytes[4];
    struct { uint16_t w0, w1; } u16;
    struct { uint16_t w0; int16_t w1; } s16;
    struct { uint8_t b0, b1, b2, b3; } u8;
    struct { M16 lo, hi; } m16;
} M32;

typedef union M64
{
    uint64_t u64;
    int64_t s64;
    uint8_t bytes[8];
    struct { uint32_t lo, hi; } u32;
    struct { uint32_t lo; int32_t hi; } s32;
    struct { uint16_t w0, w1, w2, w3; } u16;
    struct { uint8_t b0, b1, b2, b3, b4, b5, b6, b7; } u8;
    struct { M32 lo, hi; } m32;
} M64;

#endif //BASE_TYPE_H
