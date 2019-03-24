#ifndef _SSLFACTORY_H_INCLUDED_10_28_2017_
#define _SSLFACTORY_H_INCLUDED_10_28_2017_

#include "TlsCallback.h"

class BaseTls;
class TcpSock;
struct CIPHERSET;
struct CERTKEY_INFO;

BaseTls* CreateTls(
    TcpSock& sock,
    const CIPHERSET& cipherSet,
    unsigned int curTimeSec,
    bool isClient,
    TlsCallback callBack,
    void* pUserContext);


#endif //_SSLFACTORY_H_INCLUDED_10_28_2017_
