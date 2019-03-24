#ifndef ECC_H_INCLUDED_
#define ECC_H_INCLUDED_
#pragma once

struct N2;
struct RR;
struct XZ_PT;
struct PA_PT;
struct PE_PT;
namespace X25519 {
struct G;
}

struct CIPHER;

typedef uint32_t(*EntropyFunc)();

struct NN
{
	static const int N = 8;

	static uint32_t lead0_;
	static NN P_;
    
	union {
        uint32_t n_[N];
		struct {
			uint32_t n0, n1, n2, n3, n4, n5, n6, n7;
		};
	};

	static void init(const NN& P);
	static NN reverse(const NN& P);

	NN();
    NN(uint32_t d0);
    NN(uint32_t d0, uint32_t d1, uint32_t d2, uint32_t d3, uint32_t d4, uint32_t d5, uint32_t d6, uint32_t d7);
	NN(const NN& src);

	uint32_t lead0() const;

    NN& bytesIn(const uint8_t* pBytes);
    void bytesOut(uint8_t* pBytes) const;

    NN& netIn(const uint8_t* pBytes);
    void netOut(uint8_t* pBytes) const;

    NN& reduce();
    NN& reduceb();
    NN& reduce(const NN& p);

    NN inverse(const RR& r) const;
    NN inverse() const;
    NN inverseb() const;

    void EMod(NN& Y, const NN& E) const;

    operator X25519::G& () { return *((X25519::G*)this);  }

    NN& operator = (uint32_t m);
    N2 operator * (uint32_t m) const;
    N2 operator * (const NN& m) const;
	NN operator ^ (const NN& m) const;

	NN operator + (const NN& m) const;
    NN operator - (const NN& m) const;

    NN operator << (uint32_t w) const;
    NN operator >> (uint32_t w) const;

	NN& operator += (const NN& m);
	NN& operator -= (const NN& m);
	NN& operator += (uint32_t w);
	NN& operator -= (uint32_t w);
	NN& operator <<= (uint32_t w);
	NN& operator >>= (uint32_t w);
	operator bool () const;
    bool is0() const;
    bool is1() const;
	bool operator >= (const NN& t) const;
	bool operator <= (const NN& t) const;
	bool operator == (const NN& t) const;
    bool operator != (const NN& t) const;
    bool operator > (const NN& t) const;
	bool operator < (const NN& t) const;

    bool operator < (uint32_t t) const;

    operator uint8_t* () const { return (uint8_t*)n_; }

    NN& subr(const NN& a, const NN& b);
    NN& addr(const NN& a, const NN& b);
};


struct N2
{
	static const int N = NN::N<<1;

	static NN P_;
	static NN R_;

	union {
		uint32_t n_[N];
		struct {
            NN N0, N1;
        } n;
	};

	static void init(const NN& P);

	N2();
    N2(const NN& n1, uint32_t n0);
    N2(const N2& s);

    NN& reduce();
    N2& reduceb();
    NN& reduce(const RR& r);

	operator NN() { return n.N0; }
    bool operator == (const N2& m) const;
    N2& operator = (const N2& s);
    N2 operator + (const N2& m) const;
    N2 operator + (const NN& m) const;
    N2& operator += (const NN& m);
    N2& operator += (const N2& m);
	N2& operator -= (const N2& m);
	N2& operator <<= (uint32_t w);
	N2& operator >>= (uint32_t w);
};

// Helper for modulo reduction
struct RR
{
    NN r;   // (1+(r/2^256))/2^256 == 1/P
    NN p;   // The prime
};

// Projective coordinates
struct Ext_PT {
    NN x;  // x/z
    NN y;  // y/z
    NN z;
    NN t;  // xy/z
public:
    void AddBasePoint();
    void DoublePoint();
    void AddPoint(const PE_PT* q);
    void AddAffinePoint(const PA_PT *q);

    void BasePointMult(const NN& sk, const NN& R);
};

// Affine coordinates
struct XY {
    NN x;
    NN y;
    bool operator == (const XY& t) const {return ((x == t.x) && (y == t.y));}
};

struct XZ_PT
{
    NN X;   // x = X/Z
    NN Z;
};

// pre-computed, extended point
struct PE_PT
{
    NN YpX;     // Y+X
    NN YmX;     // Y-X
    NN T2d;     // 2d*T
    NN Z2;      // 2*Z
public:
    void fromExtPT(const Ext_PT& p);
};

// pre-computed, Affine point
struct PA_PT
{
    NN YpX;        // Y+X
    NN YmX;        // Y-X
    NN T2d;        // 2d*T
};

struct BLIND {
    NN bl;
    NN zr;
    PE_PT BP;
};

struct BLINDING : BLIND {
    BLINDING(CIPHER& cipher, const uint8_t* seed, uint32_t cbSize);
};

// ECC curve parameters.
struct EccParam
{
    NN p;   // The prime
    NN a;   // ECC parameter a
    NN b;   // ECC parameter b
    XY g;   // Generator point
    NN n;   // Order of generator point.
};

extern const NN w_di;
extern const NN ecc_BPO;
extern const BLIND edp_blinding;
extern const PA_PT gPreFold[256];

#endif //ECC_H_INCLUDED_

