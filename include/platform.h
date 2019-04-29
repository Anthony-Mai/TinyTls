#ifndef PLATFORM_H_INCLUDED
#define PLATFORM_H_INCLUDED

struct AesText;

union u64 {
    struct { uint32_t lo, hi; } v32;
    uint64_t v64;
};

union u128 {
    uint64_t d[2];
    uint32_t w[4];
    uint8_t b[16];

    void netIn(const uint8_t s[16]);
    void netOut(uint8_t s[16]);
    u128& shiftR() {
        uint8_t c(0xE1 & (0x00 - (b[0] & 0x01)));
        d[0] = (d[1] << 63) | (d[0] >> 1); d[1] >>= 1;
        b[15] ^= c; return *this; }

    u128& operator += (const u128& s) { d[0] ^= s.d[0]; d[1] ^= s.d[1]; return *this; }
    u128& operator ^= (const u128& s) { d[0] ^= s.d[0]; d[1] ^= s.d[1]; return *this; }
    bool operator == (const u128& s) { return ((d[0] == s.d[0]) && (d[1] == s.d[1])); }
    operator bool () { return ((d[0] != 0llu) || (d[1] != 0llu)); }
    void pmult(AesText& x) const;
    u128& bitReverse();
};

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

extern uint64_t rd_clk();
extern uint32_t leadz32(uint32_t v);
extern uint32_t leadz64(uint64_t v);
extern uint64_t PMull8x8(uint64_t a, uint64_t b, uint64_t r[2]);
extern uint64_t PMull8x8r(uint64_t a, uint64_t b, uint64_t p);
extern void PMull64s(uint64_t* pData, uint32_t n, uint64_t p);
extern u128 PMull16x16(u128 a, u128 b, u128 r[2]);
extern u128 PMull16x16r(u128 a, u128 b, const u128* p);

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus

#endif //PLATFORM_H_INCLUDED

