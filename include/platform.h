#ifndef PLATFORM_H_INCLUDED
#define PLATFORM_H_INCLUDED


union u64 {
    struct { uint32_t lo, hi; } v32;
    uint64_t v64;
};

union u128 {
    struct { uint64_t lo, hi; } v64;
    uint32_t v32[4];

    u128& operator += (const u128& s) { v64.lo ^= s.v64.lo; v64.hi ^= s.v64.hi; return *this; }
    u128& operator ^= (const u128& s) { v64.lo ^= s.v64.lo; v64.hi ^= s.v64.hi; return *this; }
    bool operator == (const u128& s) { return ((v64.lo == s.v64.lo) && (v64.hi == s.v64.hi)); }
    operator bool () { return ((v64.lo != 0llu) || (v64.hi != 0llu)); }
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

