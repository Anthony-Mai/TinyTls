#ifndef CERTGEN_TEST_H_INCLUDED_
#define CERTGEN_TEST_H_INCLUDED_

struct CIPHERSET;
namespace X509 { struct X509NAME; }

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

uint32_t getCurTime();
int do_CertGenTest(const CIPHERSET& cipherSet);

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


#endif //CERTGEN_TEST_H_INCLUDED_
