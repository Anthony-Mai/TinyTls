#ifndef _TINYSSL_H_INCLUDED_03_08_2017_
#define _TINYSSL_H_INCLUDED_03_08_2017_

#include "BaseTls.h"

#include "ssl_defs.h"
#include "ssl_ciphers.h"

#include "TlsCallback.h"

typedef uint8_t uchar;
typedef uint32_t uint;

struct CERTKEY_INFO;
struct CIPHERSET;

class TcpSock;

class TinyTls : public BaseTls
{
public:
    TinyTls(
        TcpSock& sock,
        const CIPHERSET& cipherSet,
        unsigned int curTimeSec,
        bool isClient,
        TlsCallback callBack,
        void* pUserContext);
    ~TinyTls();

    int Write(const unsigned char* pData, size_t cbSize);
    int Read(unsigned char* pBuff, size_t cbSize) override;
    SSL_STATE Work(unsigned int curTimeSec, SSL_STATE newState = SSLSTATE_RESET) override;
    SSL_STATE State() override;

private:
    uint32_t SigAlgRank(SIG_ALG sigAlg);
    bool isTls13() const { return ((ePendingCipher >> 8) == 0x13); }

public:
    uint ProcessState();
    uint ProcessRecv();
    uint ProcessSend();

    void OnTcpConnect();
    void OnClientHello();
    void OnServerHello();

    void DigestInit();
    uint DigestOut(uchar* digest);
    void DigestMsg(const uchar* pMsg, uint cbLen);

    uint CreateNetMsg(uchar cContentType, const uchar* pData, uint nDataSize);

    uint CreateClientHelloMsg(uchar* pMsgBuff, uint nBuffSize);
    uint CreateClientKeyExchangeMsg(uchar* pMsgBuff, uint nBuffSize);

    uint CreateServerHelloMsg(uchar* pMsgBuff, uint nBuffSize);
    uint CreateEncryptedExtensions(uchar*  pMsgBuff, uint nBuffSize);
    uint CreateCertificateMsg(uchar* pMsgBuff, uint nBuffSize);
    uint CreateCertVerifyMsg(uchar* pMsgBuff, uint nBuffSize);
    uint CreateCertificateRequestMsg(uchar* pMsgBuff, uint nBuffSize);
    uint CreateServerKeyExchangeMsg(uchar* pMsgBuff, uint nBuffSize);
    uint CreateServerHelloDoneMsg(uchar* pMsgBuff, uint nBuffSize);

    uint CreateAlertMsg(uchar cCategory, uchar cType);

    uint EccParamSignBlock(uchar* pMsg, uint nMsgLen, const uchar* pEccParam, uint nEccParamSize);

    uint EncryptWithMAC(uchar cContentType, uchar* pMsg, uint nMsgSize);

    uint ParseNetMsg(const uchar* pNetMsg, uint cbLen);
    uint ParseHandshake(const uchar* pMsg, uint cbLen);
    uint ParseClientHello(const uchar* pMsg, uint cbLen);

    uint ParseClientKeyExchange(const uchar* pMsg, uint cbLen);
    uint ParseClientChangeCipherSpec(const uchar* pMsg, uint cbLen);

    uint ParseServerHello(const uchar* pMsg, uint cbLen);
    uint ParseServerKeyExchange(const uchar* pMsg, uint cbLen);
    uint ParseServerHelloDone(const uchar* pMsg, uint cbLen);
    uint ParseEncryptedExtensions(const uchar* pMsg, uint cbLen);

    uint ParseCertificateMsg(const uchar* pMsg, uint cbLen);
    uint ParseCertVerifyTls13(const uchar* pMsg, uint cbLen);
    uint ParseCertificateVerify(const uchar* pMsg, uint cbLen);
    uint GetClientVerifyInfo(uchar* pMsg);
    void CalculateVerifySignature(uchar*  pSignature, uint nKeyLen);

    uint CreateChangeCipherSpecMsg(uchar* pMsgBuff, uint nBuffSize);

    uint FinishedBlock(uchar* pMsgBuff, bool isClient);
    uint CreateFinishedMsg(uchar* pMsgBuff, uint nBuffSize);
    uint VerifyPeerFinished(const uchar* pMsg, uint cbLen);

    uint CreateNewSessionTicketMsg(uchar* pMsgBuff, uint nBuffSize);

    uint ParseAlertMsg(const uchar* pMsg, uint cbLen);
    uint ParseAppData(const uchar* pMsg, uint cbLen);

    void NewEccKey();
    uint PubEccKey(uchar* pMsg, uint eccGroup) const;
    void DoECDH(uchar* dhSecret) const;
    uint CreateCertContext(bool isClient, const uchar* pCert, uchar* pMsg);
    void CalcMasterSecret();
    void ChangeCipherSpec(bool isForClient);

    // Functions for TLS1.3
    void earlySecret(const uchar* pPsk, uint  nPskLen);
    void handshakeSecret();
    void mainSecret();
    void setClientKey();

private:
    TcpSock&    m_sock;
    const CIPHERSET& m_cipherSet;
    bool        m_bIsClient;

    enum ATTR {
        ATT_NONE = 0,
        ATT_ECC_format_uncompressed = 1,
        ATT_ECC_format_ansiX962_compressed_prime = 1 << 1,
        ATT_ECC_format_ansiX962_compressed_char2 = 1 << 2,
        ATT_SessionTicket_TLS = 1 << 4,
        ATT_extended_master_secret = 1 << 7,
    };
    uint        m_attrs;
    uint        hsCount_;

    TlsCallback m_userCallBack;
    void*       m_userContext;

    SSL_STATE   eState;
    SSL_CIPHER  ePendingCipher;
    SSL_CIPHER  eClientCipher;
    SSL_CIPHER  eServerCipher;

    uint    m_eccGroup;
    uint    m_sigAlg;

    uchar   m_eccClient[32];
    uchar   m_eccServer[32];

    uint    serverMsgOff;
    uint    serverMsgLen;
    uint    nNetOutSent;
    uint    nNetOutSize;
    uint    nAppOutSize;
    uint    nAppOutRead;
    uint    clientSequenceL;    //Low DWORD. Sequence Number is 64 bits
    uint    clientSequenceH;    //High DWORD.Sequence number is 64 bits
    uint    serverSequenceL;    //Low DWORD. Sequence Number is 64 bits
    uint    serverSequenceH;    //High DWORD.Sequence number is 64 bits

    SSL_RESULT      eLastError;         //Last processing error. Used by functions
    struct CERT*    pServerCert;
    const uchar*    pCertData;

    uint    nStartTime;         //These times are UNIX TIME. i.e. number of
    uint    nCurrentTime;       //seconds since EPOCH, 00:00AM 01/01/1970 UTC

                                //SSL_MALLOC  pMallocFunc;
                                //SSL_FREE    pFreeFunc;
                                //SSL_RANDOM  pRandomFunc;
    uint    nSessionIDLen;
    uint    nPreMasterSize;     // Size of PreMasterSecret

    uchar   sessionID[32];
public:
    uchar   clientRandom[RANDOM_SIZE];
    uchar   serverRandom[RANDOM_SIZE];
private:
    uchar   m_Secret[SSL_SECRET_LEN];  // Stores preMasterSecret, MasterSecret and carious TLS1.3 secrets
#define preMasterSecret m_Secret
#define masterSecret m_Secret
    uchar   clientMacSecret[20];
    uchar   serverMacSecret[20];
    uchar   clientWriteKey[32];
    uchar   serverWriteKey[32];
    uchar   clientIV[16];
    uchar   serverIV[16];
    uchar   clientAAD[16];
    uchar   serverAAD[16];

    CTX     sha256Ctx;

    uchar*  pTemp;      //These three are temporary variables
    uint    nTemp2;     //Do not rely on them being persisted.

    uchar   serverMsg[16384];
    uchar   appoutMsg[16384];
    uchar   netoutMsg[16384];
    uchar   clientVerify[36];
    uchar   serverVerify[36];

    struct CERT*    pMidCerts;
};



#endif //_TINYSSL_H_INCLUDED_03_08_2017_
