#ifndef ASN_INCLUDED
#define ASN_INCLUDED
#pragma once

#include "oid.h"

typedef unsigned char  u8;
typedef unsigned char* pu8;

namespace ASN {

class Asn {
private: const pu8 po_; const pu8 p0_; protected: pu8& p_;
public:
    Asn(const pu8& s); // Constructor for already well formatted message
    Asn(pu8& s, u8 t, size_t n); ~Asn(); // Constructor to build message
    operator pu8& () const { return p_; }
    pu8& operator & () const { return p_; }
    u8 type() const { return po_[0]; }
    size_t size() const {
        if (p0_ == po_) {
            return (po_[1]<0x80)? size_t(po_[1])+2 : (po_[1]<0x82) ? size_t(po_[2])+3 : ((size_t(po_[2])<<8)+po_[3]+4);
        } else {
            size_t n = p_ - p0_; return (n + 2 + (n >= 128) + (n >= 256));
        }
    }
private:
    Asn(const Asn& s); // Prevent copying.
};

class Asn0 {
private: const pu8 p0_; protected: pu8& p_;
public:
    Asn0(pu8& s, u8 t) : p_((*s++ = t, *s++ = 0x00, s)), p0_(s + 2) {}
    ~Asn0() { p0_[-1] = u8(p_ - p0_); }

    operator pu8& () const { return p_; }
    pu8& operator & () const { return p_; }
    size_t size() const { return (p_ - p0_ + 2); }
private:
    Asn0(const Asn& s); // Prevent copying.
};

class Asn1 {
private: const pu8 p0_; protected: pu8& p_;
public:
    Asn1(pu8& s, u8 t) : p_((*s++ = t, *s++ = 0x81, *s++ = 0x00, s)), p0_(s + 3) {}
    ~Asn1() { p0_[-1] = u8(p_ - p0_); }

    operator pu8& () const { return p_; }
    pu8& operator & () const { return p_; }
    size_t size() const { return (p_ - p0_ + 3); }
private:
    Asn1(const Asn1& s); // Prevent copying.
};

class Asn2 {
private: const pu8 p0_; protected: pu8& p_;
public:
    Asn2(pu8& s, u8 t) : p_((*s++ = t, *s++ = 0x82, *s++ = 0x00, *s++ = 0x00, s)), p0_(s + 4) {}
    ~Asn2() { size_t n = p_ - p0_; p0_[-2] = u8(n >> 8); p0_[-1] = u8(n); }

    operator pu8& () const { return p_; }
    pu8& operator & () const { return p_; }
    size_t size() const { return (p_ - p0_ + 4); }
private:
    Asn2(const Asn2& s); // Prevent copying.
};

class Asn3 {
private: const pu8 p0_; protected: pu8& p_;
public:
    Asn3(pu8& s, u8 t) : p_((*s++ = t, *s++ = 0x00, *s++ = 0x00, *s++ = 0x00, s)), p0_(s + 4) {}
    ~Asn3() { size_t n = p_ - p0_; p0_[-3] = u8(n >> 16); p0_[-2] = u8(n >> 8), p0_[-1] = u8(n); }

    operator pu8& () const { return p_; }
    pu8& operator & () const { return p_; }
    size_t size() const { return (p_ - p0_ + 4); }
private: Asn3(const Asn2& s); // Prevent copying.
};

class Int : public Asn0 { public: Int(pu8& s, uint32_t v); Int(pu8& s, uint64_t v); };
class Intb : public Asn { public: Intb(pu8& s, const u8* pI, size_t nLen); };
class Seq : public Asn { public: Seq(pu8& s, size_t n); private: Seq(const Seq& s); };
class Seq0 : public Asn0 {public: Seq0(pu8& s); private: Seq0(const Seq0& s);};
class Seq1 : public Asn1 {public: Seq1(pu8& s); private: Seq1(const Seq1& s);};
class Seq2 : public Asn2 {public: Seq2(pu8& s); private: Seq2(const Seq2& s);};
class Oid : public Asn0 { public: Oid(pu8& s, OID oid); private: Oid(const Seq2& s); };
class NullTag : public Asn0 { public: NullTag(pu8& s); private: NullTag(const Seq2& s); };
class Version : public Asn0 { public: Version(pu8& s); private: Version(const Seq2& s); };
class Utc : public Asn0 { public: Utc(pu8& s); private: Utc(const Utc& s); };
class Set : public Asn0 { public: Set(pu8& s); private: Set(const Set& s); };
class Oct : public Asn0 { public: Oct(pu8& s); private: Oct(const Oct& s); };
class Ext : public Asn0 { public: Ext(pu8& s); private: Ext(const Ext& s); };
class Bool : public Asn0 { public: Bool(pu8& s, bool b); private: Bool(const Bool& s); };
class Pstr : public Asn0 { public: Pstr(pu8& s, const char* p); private: Pstr(const Pstr& s); };
class Altn : public Asn0 { public: Altn(pu8& s, const char* p); private: Altn(const Altn& s); };
class Bstr : public Asn0 { public: Bstr(pu8& s); void add(const u8* p, size_t n); private: Bstr(const Bstr& s); };
class Bstr2 : public Asn2 { public: Bstr2(pu8& s); void add(const u8* p, size_t n); private: Bstr2(const Bstr& s); };
class PubKey : public Seq { public: PubKey(pu8& s, OID eType, const u8* p); private: PubKey(const Pstr& s); };

} //namespace ASN

#endif //ASN_INCLUDED
