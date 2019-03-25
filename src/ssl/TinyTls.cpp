/******************************************************************************
*
* Copyright © 2018-2019 Anthony Mai Mai_Anthony@hotmail.com. All Rights Reserved.
*
* This file is a part of the software package TinyTls, originally known as TinySsl.
* This software is written by Anthony Mai and is provided under the terms and
* conditions of the GNU General Public License Version 3.0 (GPL V3.0). For the
* specific GPL V3.0 license terms please refer to:
*         https://www.gnu.org/licenses/gpl.html.
*
* This Copyright Notices contained in this code. are NOT to be removed or modified.
* If this package is used in a product, Anthony Mai should be given attribution as
* the author of the parts of the library used. This can be in the form of a textual
* message at program startup or in documentation provided with the package.
*
* This library is free for commercial and non-commercial use as long as the
* following conditions are aheared to. The following conditions apply to
* all code found in this distribution:
*
* 1. Redistributions of source code must retain the copyright notice, this
*    list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
*
* 3. All advertising materials mentioning features or use of this software
*    must display the following acknowledgement:
*
*    "This product contains software written by Anthony Mai (Mai_Anthony@hotmail.com)
*     The original source code can obtained from such and such internet sites or by
*     contacting the author directly."
*
* 4. This software may or may not contain patented technology owned by a third party.
*    Obtaining a copy of this software, with or without explicit authorization from
*    the author, does NOT imply that applicable patents have been licensed. It is up
*    to you to make sure that utilization of this software package does not infringe
*    on any third party's patents or other intellectual proerty rights.
* 
* THIS SOFTWARE IS PROVIDED BY ANTHONY MAI "AS IS". ANY EXPRESS OR IMPLIED WARRANTIES,
* INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
* FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
* BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
* IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
* 
* The license and distribution terms for any publically available version or derivative
* of this code cannot be changed.  i.e. this code cannot simply be copied and put under
* another distribution license [including the GNU Public License.]
*
******************************************************************************/

/******************************************************************************
*
*  File Name:       TinyTls.cpp
*
*  Description:     Implementation of TLS 1.2 and TLS 1.3 client and server.
*
*                   This is developed with the help of test data from RFC8448
*                   and another TLS 1.3 trace from https://tls13.ulfheim.net/
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         10/28/2019 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "TinyTls.h"
#include "TcpSock.h"
#include "cipher.h"
#include "cert.h"

#include "ecc_x25519.h"
#include "ecc_p256.h"

#include "hkdf.h"
#include "ssa.h"
#include "aes128.h"
#include "chacha20.h"

#define CONTENT_HEADER_LEN      5


static void CalcTrafficKey(const Hkdf& prk, uchar* pKey, uint keyLen, uchar* pIV, uint ivLen);


/******************************************************************************
* Function:     SSL_AddRootCertificate
*
* Description:  This function is used to add trusted root certificates.
*               Selected *.cer files dumped from the InternetExplorer
*               root certificates are OK, as long as the associated entities
*               can continue to be trusted.
*
* Returns:      SSL_OK if no error.
******************************************************************************/
SSL_RESULT SSL_AddRootCertificate
(
    const uchar*    pCertData,
    uint            nLen,
    uint            nUnixTime
)
{
    CERT_STATUS     eStatus = CS_ROOT;
    uint    nLen2;
    CERT*           pCert = NULL;

    pCert = CreateCert(eStatus, nUnixTime);

    nLen2 = ParseCert(pCert, pCertData, nLen);

    if (nLen2 != nLen)
    {
        DestroyCert(pCert);
        return SSL_ERROR_CERTIFICATE_BAD;
    }

    eStatus = AuthenticateCert(pCert, NULL);

    if (NULL == InsertCert(pCert, NULL))
    {
        DestroyCert(pCert);
        return SSL_ERROR_CERTIFICATE_EXISTS;
    }

    return SSL_OK;
}


static bool needServerKE(TLS_CIPHER eCipher) {
    static const TLS_CIPHER gSKECiphers[] = {
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_NONE };
    uint i;
    for (i = 0; gSKECiphers[i] != TLS_NONE; i++) {
        if (gSKECiphers[i] == eCipher) return true;
    }
    return false;
}

static const TLS_CIPHER gSupportedCipher[] = {
    // New TLS1.3 ciphers
    TLS_AES_128_GCM_SHA256,
    TLS_CHACHA20_POLY1305_SHA256,
    // TLS1.2 ciphers
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    // Old none ECC cipher.
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
    TLS_NONE };

static uint32_t CipherRank(TLS_CIPHER eCipher)
{
    uint i;
    for (i = 0; gSupportedCipher[i]; i++) {
        if (gSupportedCipher[i] == eCipher) break;
    }
    return i;
}

static const ECC_GROUP gSupportedGroup[] = {
    ECC_x25519,     // Supported Group: x25519 (0x001d)
    ECC_secp256r1,  // Supported Group : secp256r1(0x0017)
    //ECC_secp521r1,  // Supported Group: secp521r1 (0x0019)
    //ECC_secp384r1,  // Supported Group: secp384r1 (0x0018)
    ECC_NONE };

static uint32_t EccRank(ECC_GROUP eccGroup)
{
    uint i;
    for (i = 0; gSupportedGroup[i]; i++) {
        if (gSupportedGroup[i] == eccGroup) break;
    }
    return i;
}

typedef unsigned char u8;
typedef unsigned char* pu8;

class Handshake {
    TinyTls& s_;
    pu8  o_;
    pu8& p_;
public:
    Handshake(TinyTls& s, pu8& p) : s_(s), o_(p), p_(p) {
        *p_++ = CONTENT_HANDSHAKE; // For client hello, version is 0x0301. else 0x0303
        *p_++ = SSL_VERSION_MAJOR; *p_++ = SSL_VERSION_MINOR3; // TLS version 0x0303
        *p_++ = 0x00; *p_++ = 0x00; // Reserver two bytes for message size
    }
    ~Handshake() {
        size_t n = p_ - o_ - 5; o_[3] = u8(n >> 8); o_[4] = u8(n); o_[2] ^= u8((o_[5] == MSG_CLIENT_HELLO) && (o_[0]==CONTENT_HANDSHAKE)) << 1;
    }
    pu8 data() const { return (o_ + 5); }
    size_t size() const { return (p_ - o_ - 5); }
    size_t digestEncryptMac();
};

size_t Handshake::digestEncryptMac()
{
    size_t nMacSize = 0;
    //Hash the handshake content of just ServerHello
    s_.DigestMsg(data(), size());

    //If there is an existing cipher then we need to encrypt the message
    p_ += nMacSize = s_.EncryptWithMAC(o_[0], data(), size());
    return nMacSize;
}

static const SIG_ALG gSigAlgs[] = {
    ecdsa_secp256r1_sha256, // Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
    //ecdsa_secp384r1_sha384, // Signature Algorithm: ecdsa_secp384r1_sha384 (0x0503)
    //ecdsa_secp521r1_sha512, // Signature Algorithm: ecdsa_secp521r1_sha512 (0x0603)
    ed25519,                // Signature Algorithm: ed25519(0x0807),
    rsa_pkcs1_sha256,      // Signature Algorithm: rsa_pkcs1_sha256 (0x0401)
    rsa_pkcs1_sha384,      // Signature Algorithm: rsa_pkcs1_sha384 (0x0501)
    rsa_pkcs1_sha512,      // Signature Algorithm: rsa_pkcs1_sha512 (0x0601)
    rsa_pss_rsae_sha256,   // Signature Algorithm: rsa_pss_rsae_sha256 (0x0804)
    rsa_pss_rsae_sha384,   // Signature Algorithm: rsa_pss_rsae_sha384 (0x0805)
    rsa_pss_rsae_sha512,   // Signature Algorithm: rsa_pss_rsae_sha512 (0x0806)
    ecdsa_sha1,        // Signature Algorithm: ecdsa_sha1 (0x0203)
    rsa_pkcs1_sha1,    // Signature Algorithm: rsa_pkcs1_sha1 (0x0201)
    //SHA1_DSA,          // Signature Algorithm: SHA1 DSA (0x0202)
    //SHA256_DSA,        // Signature Algorithm: SHA256 DSA (0x0402)
    //SHA384_DSA,        // Signature Algorithm: SHA384 DSA (0x0502)
    //SHA512_DSA,        // Signature Algorithm: SHA512 DSA (0x0602)
    //ed448,             // Signature Algorithm: ed448(0x0808),
    SIGALG_NONE
};

uint32_t TinyTls::SigAlgRank(SIG_ALG sigAlg)
{
    uint i = 0;
    switch (ePendingCipher) {
    case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
    case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
    case TLS_AES_128_GCM_SHA256:
    case TLS_CHACHA20_POLY1305_SHA256:
        if (sigAlg == ecdsa_secp256r1_sha256) return 0;
        break;
    default:
        if (sigAlg == ecdsa_secp256r1_sha256) sigAlg = SIGALG_NONE;
        break;
    }

    for (i = 0; gSigAlgs[i]; i++) {
        if (gSigAlgs[i] == sigAlg) break;
    }
    return i;
}


TinyTls::TinyTls(
    TcpSock& sock,
    const CIPHERSET& cipherSet,
    unsigned int curTimeSec,
    bool isClient,
    TlsCallback callBack,
    void* pUserContext
    ) :
    m_sock(sock),
    m_cipherSet(cipherSet),
    m_bIsClient(isClient),
    m_attrs(ATT_NONE),
    hsCount_(0),
    m_userCallBack(callBack),
    m_userContext(pUserContext),
    eState(SSLSTATE_RESET),
    ePendingCipher(TLS_NONE),
    eClientCipher(TLS_NONE),
    eServerCipher(TLS_NONE),
    m_eccGroup(ECC_NONE),
    m_sigAlg(SIGALG_NONE),
    serverMsgOff(0),
    serverMsgLen(0),
    nNetOutSent(0),
    nNetOutSize(0),
    nAppOutRead(0),
    nAppOutSize(0),
    clientSequenceL(0),
    clientSequenceH(0),
    serverSequenceL(0),
    serverSequenceH(0),
    eLastError(SSL_OK),
    pServerCert(nullptr),
    pCertData(nullptr),
    nStartTime(curTimeSec),
    nCurrentTime(curTimeSec),
    nSessionIDLen(0),
    nPreMasterSize(SSL_SECRET_LEN),
    pTemp(nullptr),
    nTemp2(0),
    pMidCerts(nullptr)
{
    memset(m_Secret, 0, sizeof(m_Secret));
}

TinyTls::~TinyTls()
{
    memset(m_Secret, 0, sizeof(m_Secret));
    memset(clientWriteKey, 0, sizeof(clientWriteKey));
    memset(serverWriteKey, 0, sizeof(serverWriteKey));
}

int TinyTls::Write(const unsigned char* pData, size_t cbSize)
{
    if (eState != SSLSTATE_CONNECTED) return 0;

    // CreateNetMsg is all or nothing
    uint nMsgLen = CreateNetMsg(
        CONTENT_APPLICATION_DATA,
        pData,
        cbSize);

    return nMsgLen? cbSize : 0;
}

int TinyTls::Read(unsigned char* pBuff, size_t cbSize)
{
    unsigned char* pMsg = pBuff;
    while ((pMsg - pBuff) < (int)cbSize) {
        uint chunk = nAppOutSize - nAppOutRead;
        if (chunk == 0) break;
        uint off = nAppOutRead & (sizeof(appoutMsg) - 1);
        if (chunk > sizeof(appoutMsg) - off) { chunk = sizeof(appoutMsg) - off; }
        if ((int)chunk > pBuff +cbSize - pMsg) chunk = pBuff + cbSize - pMsg;
        memcpy(pMsg, appoutMsg + off, chunk);
        pMsg += chunk; nAppOutRead += chunk;
    }

    return pMsg - pBuff;
}

SSL_STATE TinyTls::State()
{
    return eState;
}

void TinyTls::OnTcpConnect()
{
    nStartTime = nCurrentTime;
    eClientCipher = TLS_NONE;
    eServerCipher = TLS_NONE;
    serverMsgOff = 0;
    serverMsgLen = 0;

    eState = m_bIsClient ? SSLSTATE_CLIENT_HELLO : SSLSTATE_HANDSHAKE_BEGIN;

    // Generate an Ephemeral ECC private key for use.
    NewEccKey();
}

uint TinyTls::ProcessState()
{
    switch (eState)
    {
    case SSLSTATE_RESET:
        if (m_sock.Connected()) {
            eState = SSLSTATE_TCPCONNECTED;
        }
        break;

    case SSLSTATE_TCPCONNECTED:
        OnTcpConnect(); break;
        nStartTime = nCurrentTime;
        eClientCipher = TLS_NONE;
        eServerCipher = TLS_NONE;
        serverMsgOff = 0;
        serverMsgLen = 0;

        preMasterSecret[0] = SSL_VERSION_MAJOR;
        preMasterSecret[1] = SSL_VERSION_MINOR3;

        eState = SSLSTATE_HANDSHAKE_BEGIN;
        break;

    case SSLSTATE_HANDSHAKE_BEGIN:  // Server waiting for client hello.
        break;

    case SSLSTATE_CLIENT_HELLO:
        if (m_bIsClient) OnClientHello();
        break;

    case SSLSTATE_SERVER_HELLO:
        if (!m_bIsClient) OnServerHello();
        break;

    case SSLSTATE_HANDSHAKE_SECRET:
        handshakeSecret();
        eState = SSLSTATE_ENCRYPTED_EXTENSIONS;
        break;

    case SSLSTATE_ENCRYPTED_EXTENSIONS:
        nNetOutSize += CreateEncryptedExtensions(
            &(netoutMsg[nNetOutSize]),
            (sizeof(netoutMsg) - nNetOutSize)
        );
        eState = SSLSTATE_SERVER_CERTIFICATE;
        break;

    case SSLSTATE_SERVER_CERTIFICATE:
        nNetOutSize += CreateCertificateMsg(
            &(netoutMsg[nNetOutSize]),
            (sizeof(netoutMsg) - nNetOutSize)
            );
        if (isTls13()) {
            eState = SSLSTATE_SERVER_CERT_VERIFY;
            break;
        }
        if (pTemp != NULL) {
            //If the server requests client certificate.
            pTemp = NULL; //Clean up things a bit.
            nNetOutSize += CreateCertificateRequestMsg(
                &(netoutMsg[nNetOutSize]),
                (sizeof(netoutMsg) - nNetOutSize));
            eState = SSLSTATE_SERVER_CERTREQUEST;
            break;
        } else if (needServerKE(ePendingCipher)) {
            // Has server key exchange message
            nNetOutSize += CreateServerKeyExchangeMsg(
                &(netoutMsg[nNetOutSize]),
                (sizeof(netoutMsg) - nNetOutSize));
        } else {
        }
        eState = SSLSTATE_SERVER_HELLO_DONE;
        break;

    case SSLSTATE_SERVER_CERT_VERIFY:
        nNetOutSize += CreateCertVerifyMsg(
            &(netoutMsg[nNetOutSize]),
            (sizeof(netoutMsg) - nNetOutSize));
        eState = SSLSTATE_SERVER_FINISH2;
        break;

    case SSLSTATE_SERVER_HELLO_DONE:
        nNetOutSize += CreateServerHelloDoneMsg(
            &(netoutMsg[nNetOutSize]),
            (sizeof(netoutMsg) - nNetOutSize));
        eState = SSLSTATE_CLIENT_KEYEXCHANGE;
        break;

    case SSLSTATE_CERTIFICATE_VERIFY:
    {
        //Verify server certificate.
        CERT_STATUS eStatus;

        eStatus = AuthenticateCert(pServerCert, &pMidCerts);

        //Please note here. The certificate may or may not be verified,
        //depends on eStatus. It is up to application to acccept if the
        // certificate is questionable.
        if ((eStatus & (CS_OK | CS_VERIFIED)) == (CS_OK | CS_VERIFIED))
        {
            //Certificate is OK and can be trusted.
            eState = SSLSTATE_CERTIFICATE_VERIFIED;
        }
        else
        {
            //Certificate questionable. Prompt the application to decide
            //either to goto
            //      SSLSTATE_CERTIFICATE_ACCEPTED
            //or to goto
            //      SSLSTATE_CERTIFICATE_REJECTED
            //Application should check pParam->nOutXData to decide.
            eState = SSLSTATE_CERTIFICATE_ACCEPTING;
        }
    }
    break;

    case SSLSTATE_CERTIFICATE_VERIFIED:
        //Certificate OK, valid and trusted. So go ahead.
        eState = SSLSTATE_CLIENT_KEYEXCHANGE;
        if (pTemp != NULL)
        {
            //If we are to supply client certificate, then do it first.
            eState = SSLSTATE_CLIENT_CERTIFICATE;
        }
        break;

    case SSLSTATE_CERTIFICATE_ACCEPTED:
        //Certificate may be questionable. But App accepted it any way.
        eState = SSLSTATE_CLIENT_KEYEXCHANGE;
        if (pTemp != NULL)
        {
            //If we are to supply client certificate, then do it first.
            eState = SSLSTATE_CLIENT_CERTIFICATE;
        }
        break;

    case SSLSTATE_CERTIFICATE_ACCEPTING:
        //The application undeciding on this one. So we do the default and
        //prepare to disconnect the questionable connection.
        //Fall through to SSLSTATE_CERTIFICATE_REJECTED as default.

    case SSLSTATE_CERTIFICATE_REJECTED:
        eState = SSLSTATE_ABORTING;
        break;

    // End inserted code
    case SSLSTATE_CLIENT_KEYEXCHANGE:
        if (!m_bIsClient) break;
        nNetOutSize += CreateClientKeyExchangeMsg(
            &(netoutMsg[nNetOutSize]),
            (sizeof(netoutMsg) - nNetOutSize));
        CalcMasterSecret();
        eState = SSLSTATE_CLIENT_FINISH1;
        break;

        // Begin inserted code
    case SSLSTATE_CLIENT_FINISH1:
        if (!m_bIsClient) break;
        if (!isTls13()) {
            //First send the client ChangeCipherSpec message.
            nNetOutSize += CreateChangeCipherSpecMsg(
                &(netoutMsg[nNetOutSize]),
                (sizeof(netoutMsg) - nNetOutSize)
            );
            // Calculate and change cipher here.
            ChangeCipherSpec(m_bIsClient);
        }
        //Then send the ClientFinished message.
        nNetOutSize += CreateFinishedMsg(
            &(netoutMsg[nNetOutSize]),
            (sizeof(netoutMsg) - nNetOutSize)
        );
        if (isTls13()) {
            setClientKey();
        }
        if (eServerCipher == TLS_NONE) {
            eState = SSLSTATE_SERVER_FINISH2;
        } else {
            eState = SSLSTATE_HANDSHAKE_DONE;
        }
        break;

    case SSLSTATE_CLIENT_FINISH2:
        if (!m_bIsClient) break;
        //First send the client ChangeCipherSpec message.
        nNetOutSize += CreateChangeCipherSpecMsg(
            &(netoutMsg[nNetOutSize]),
            (sizeof(netoutMsg) - nNetOutSize));
        //Then send the ClientFinished message.
        nNetOutSize += CreateFinishedMsg(
            &(netoutMsg[nNetOutSize]),
            (sizeof(netoutMsg) - nNetOutSize)
            );
        if (isTls13()) {
            // What to do here?
        }
        eState = SSLSTATE_HANDSHAKE_DONE;
        break;

    case SSLSTATE_SERVER_FINISH2:
        if (m_bIsClient) break;
        nNetOutSize += CreateNewSessionTicketMsg(
            &(netoutMsg[nNetOutSize]),
            (sizeof(netoutMsg) - nNetOutSize));

        if (!isTls13()) {
            //First send the client ChangeCipherSpec message.
            nNetOutSize += CreateChangeCipherSpecMsg(
                &(netoutMsg[nNetOutSize]),
                (sizeof(netoutMsg) - nNetOutSize)
            );

            // Calculate and change cipher here.
            ChangeCipherSpec(m_bIsClient);
        }

        //Then send the ServerFinished message.
        nNetOutSize += CreateFinishedMsg(
            &(netoutMsg[nNetOutSize]),
            (sizeof(netoutMsg) - nNetOutSize)
            );
        if (isTls13()) {
            mainSecret(); // For server only.
            eState = SSLSTATE_CLIENT_FINISH2;
        } else if (eClientCipher == TLS_NONE) {
            eState = SSLSTATE_CLIENT_FINISH2;
        } else {
            eState = SSLSTATE_HANDSHAKE_DONE;
        }

        eState = eState;
        break;

    case SSLSTATE_HANDSHAKE_DONE:
        eState = SSLSTATE_CONNECTED;
        break;

    case SSLSTATE_CONNECTED:
        //We are fully connected. Hope to stay that way indefinitely.
        break;

    case SSLSTATE_ABORT:
        eState = SSLSTATE_DISCONNECT;
        break;

    case SSLSTATE_DISCONNECT:
        //We were told by the App to initiate disconnect sequence.
        //This is done by sending a Close Alert to the server, then
        //notify the App to disconnect the TCP.
        CreateAlertMsg(ALERT_WARNING, ALERT_NOTIFY_CLOSE);
        eState = SSLSTATE_DISCONNECTING;
        break;

    case SSLSTATE_DISCONNECTED:
        //Do some cleanup and prepare for next connection.
        eState = SSLSTATE_UNCONNECTED;
        break;

    default:
        break;
    }

    return 0;
}

void TinyTls::OnClientHello()
{
    nNetOutSize += CreateClientHelloMsg(
        &(netoutMsg[nNetOutSize]),
        (sizeof(netoutMsg) - nNetOutSize)
        );
    //We now wait for a ServerHello message.
    eState = SSLSTATE_SERVER_HELLO;
}

void TinyTls::OnServerHello()
{
    // Send server hello
    nNetOutSize += CreateServerHelloMsg(
        &(netoutMsg[nNetOutSize]),
        (sizeof(netoutMsg) - nNetOutSize)
        );
}

uint TinyTls::ProcessRecv()
{
    int nParsed = 0, nNetIn = 0, nTotal = 0;
    uchar netBuff[16384];
    nNetIn = m_sock.Recv(netBuff, sizeof(netBuff));
    if (nNetIn < 0)
    {
        // Socket error happened.
        if (eState <= SSLSTATE_CONNECTED) {
            eState = SSLSTATE_ABORT; //Bail out.
        }
        return nTotal;
    }
    while (nParsed < nNetIn)
    {
        nParsed += ParseNetMsg(netBuff + nParsed, nNetIn - nParsed);
    }

    return 0;
}

uint TinyTls::ProcessSend()
{
    // Does  application has outgoing data?

    // Do we have data to send to the network.
    int nTotal = 0;
    while (nNetOutSize > nNetOutSent) {
        int nBytes = m_sock.Send(netoutMsg, nNetOutSize);
        if (nBytes > 0) {
            nNetOutSent += nBytes;
            nTotal += nBytes;
            continue;
        }  else if (nBytes < 0) {
            // Socket problem.
            eState = SSLSTATE_ABORT;
        }
        return nTotal;
    }
    nNetOutSent = nNetOutSize = 0;
    return nTotal;
}

SSL_STATE TinyTls::Work(unsigned int curTimeSec, SSL_STATE newState /*= SSLSTATE_RESET*/)
{
    nCurrentTime = curTimeSec;
    if (newState != SSLSTATE_RESET) eState = newState;

    SSL_STATE curState;
    uint  nIn = 0, nOut = 0;

    do {
        curState = eState;
        if (ProcessState()) break;
        if (curState != eState) continue;
        nIn = ProcessRecv();
        nOut = ProcessSend();
    } while (curState != eState || nIn || nOut);

    return eState;

    //First depends on the state do a few things
    switch (eState)
    {
    case SSLSTATE_RESET:
        if (m_sock.Connected()) {
            eState = SSLSTATE_TCPCONNECTED;
        }
        break;

    case SSLSTATE_TCPCONNECTED:
        nStartTime = nCurrentTime;
        eClientCipher = TLS_NONE;
        eServerCipher = TLS_NONE;
        serverMsgOff = 0;
        serverMsgLen = 0;

        preMasterSecret[0] = SSL_VERSION_MAJOR;
        preMasterSecret[1] = SSL_VERSION_MINOR3;

        eState = SSLSTATE_HANDSHAKE_BEGIN;
        break;

    case SSLSTATE_SERVER_HELLO:
        // Send server hello
        nNetOutSize += CreateServerHelloMsg(
            &(netoutMsg[nNetOutSize]),
            (sizeof(netoutMsg) - nNetOutSize)
            );
        break;

    case SSLSTATE_DISCONNECT:
        //We were told by the App to initiate disconnect sequence.
        //This is done by sending a Close Alert to the server, then
        //notify the App to disconnect the TCP.
        CreateAlertMsg(ALERT_WARNING, ALERT_NOTIFY_CLOSE);
        eState = SSLSTATE_DISCONNECTING;
        break;

    case SSLSTATE_DISCONNECTED:
        //Do some cleanup and prepare for next connection.
        eState = SSLSTATE_UNCONNECTED;
        break;

    default:
        break;
    }

    //Third do we have anything from the network?
    int nParsed = 0, nNetIn = 0;
    uchar netBuff[1024];
    nNetIn = m_sock.Recv(netBuff, sizeof(netBuff));
    if (nNetIn < 0)
    {
        // Socket error happened.
        eState = SSLSTATE_ABORT; //Bail out.
        return eState;
    }
    while (nParsed < nNetIn)
    {
        nParsed += ParseNetMsg(netBuff + nParsed, nNetIn - nParsed);
    }

    return eState;
}

#include <stdlib.h>

//typedef unsigned int(*SSL_RANDOM)();
//SSL_RANDOM  gfRandom = (SSL_RANDOM)rand;

void BaseTls::SetRandFunc(SSL_RANDOM fRand)
{
    gfRandom = fRand;
}

// Don't use this unless there is nothing else to use, if user gives us no PRNG.
static uint myBadPRNG() {
    static uint nRandSeed = 0x12345679;
    uint r = nRandSeed ^ rand();
    nRandSeed ^= (nRandSeed << ((r & 15) + 1)) | (nRandSeed >> (31 - (r & 15)));
    nRandSeed ^= (r<<29) | (r>>13);
    return nRandSeed;
}

BaseTls::SSL_RANDOM BaseTls::gfRandom = (SSL_RANDOM)myBadPRNG;

uint TinyTls::CreateServerHelloMsg
(
    uchar*  pMsgBuff,
    uint    nBuffSize
)
{
    uchar*  pMsg = pMsgBuff;
    Handshake handshake(*this, pMsg);
    uchar*  pExtSize = nullptr;
    uint    nExtSize = 0;
    TlsCBData cbData;

    nTemp2 = 0; //No client certificate request by default.

    //Generate a ServerRandom
    for (int i = 0; i < sizeof(serverRandom);)
    {
        uint   nRand = gfRandom();
        *((uint*)&(serverRandom[i])) = nRand;
        i += sizeof(uint);
    }
    serverRandom[0] = (uchar)((nCurrentTime) >> 24);
    serverRandom[1] = (uchar)((nCurrentTime) >> 16);
    serverRandom[2] = (uchar)((nCurrentTime) >> 8);
    serverRandom[3] = (uchar)((nCurrentTime) >> 0);
    // Give application a chance to peek at or change the server random
    cbData.cbType = TlsCBData::CB_RANDOM;
    cbData.data.ptrs[0] = serverRandom; cbData.data.ptrs[1] = nullptr;
    m_userCallBack(m_userContext, &cbData);

    //See if we need to generate a new Session ID, or reuse previous one.
    if (nSessionIDLen == 0 || isTls13())
    {
        //This is a new connection session. Create a SessionID.
        // Do not generate session ID in TLS 1.2

        //We will send server certificate next.
        eState = SSLSTATE_SERVER_CERTIFICATE;
    }
    else
    {
        //Resuming an existing connection session.
        //We will directly send ChangeCipherSpec and ServerFinish.
        eState = SSLSTATE_SERVER_FINISH1;
    }

    //Now fill in the Server Hello Message
    *pMsg++ = MSG_SERVER_HELLO;
    *pMsg++ = 0x00; *pMsg++ = 0x00; *pMsg++ = 0x00; //Msg Size. Come back to set.

    //First two bytes of SSL version.
    *pMsg++ = SSL_VERSION_MAJOR;
    *pMsg++ = SSL_VERSION_MINOR3;

    //Then a fixed 32 bytes Server Random.
    memcpy(pMsg, serverRandom, sizeof(serverRandom));
    pMsg += sizeof(serverRandom);

    //Then the Session ID length and the Session ID.
    *pMsg++ = (uchar)nSessionIDLen;
    if (nSessionIDLen) memcpy(pMsg, &(sessionID[sizeof(sessionID) - nSessionIDLen]), nSessionIDLen);
    pMsg += nSessionIDLen;

    //Set PendingCipherSuite
    *pMsg++ = (uchar)(ePendingCipher >> 8);
    *pMsg++ = (uchar)(ePendingCipher >> 0);

    //Set Compression
    *pMsg++ = 0x00;

    // Set the extensions one by one
    pExtSize = pMsg;
    *pMsg++ = 0x00; *pMsg++ = 0x00; // Come back to set total extension length.

    if (!isTls13()) {
        // Extension: extended_master_secret (len=0)
        if (m_attrs & ATT_extended_master_secret) {
            *pMsg++ = EXT_EXTENDED_MASTER_SECRET >> 8; *pMsg++ = EXT_EXTENDED_MASTER_SECRET;
            *pMsg++ = 0x00; *pMsg++ = 0x00; // Length: 0
        }
    }

    if (!isTls13()) {
        // Extension: renegotiation_info (len=1)
        *pMsg++ = EXT_RENEGOTIATION_INFO >> 8; *pMsg++ = uchar(EXT_RENEGOTIATION_INFO);
        *pMsg++ = 0x00; *pMsg++ = 0x01; // Length: 1
        *pMsg++ = 0x00;                 // Renegotiation info extension length: 0
    }

    // Extension: server_name (len=0)
    if (0) {
    *pMsg++ = EXT_SERVER_NAME >> 8; *pMsg++ = EXT_SERVER_NAME;
    *pMsg++ = 0x00; *pMsg++ = 0x00; // Length: 0
    }

    // Extension: ec_point_formats (len=4)
    if (needServerKE(ePendingCipher)) {
        *pMsg++ = EXT_EC_POINT_FORMATS >> 8; *pMsg++ = EXT_EC_POINT_FORMATS;
        *pMsg++ = 0x00; *pMsg++ = 0x04; // Length: 4
        *pMsg++ = 0x03;                 // EC point formats Length: 3
        *pMsg++ = 0x00;                 // EC point format: uncompressed (0)
        *pMsg++ = 0x01;                 // EC point format: ansiX962_compressed_prime (1)
        *pMsg++ = 0x02;                 // EC point format: ansiX962_compressed_char2 (2)
    }

    // Extension: SessionTicket TLS (len=0)
    cbData.cbType = TlsCBData::CB_SESSIONTICKET_TLS; cbData.data.ptrs[0] = nullptr;
    uint slen = m_userCallBack(m_userContext, &cbData);
    if (slen && cbData.data.ptrs[0]) {
        if (slen > 32) slen = 32; // Prevent buffer overflow bug.
        *pMsg++ = EXT_SESSIONTICKET_TLS >> 8; *pMsg++ = EXT_SESSIONTICKET_TLS;
        *pMsg++ = slen >> 8; *pMsg++ = slen;

        // Put in the session ticke TLS
        memcpy(pMsg, cbData.data.ptrs[0], slen);
        pMsg += slen;
    }

    // Some more extensions if doing TLS1.3. TODO: If we cannot send key share. Do a hello request.
    if (isTls13()) {
        // Should not send this unless client sent it first
        if (0) {
            *pMsg++ = EXT_PSK_KEY_EXCHANGE_MODES >> 8; *pMsg++ = EXT_PSK_KEY_EXCHANGE_MODES;
            *pMsg++ = 0x00; *pMsg++ = 0x02; // Length 2
            *pMsg++ = 0x01; *pMsg++ = 0x01; // enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
                                            // 01 = psk_dhe_ke:  PSK with(EC)DHE key establishment.In this mode, the client and server MUST
                                            // supply "key_share" values as described in RFC8446 Section 4.2.8.
        }

        // Do we have a PSK given?
        cbData.cbType = TlsCBData::CB_PSK_INFO;  cbData.data.ptrs[0] = nullptr; cbData.data.rawSize[1] = 0;
        uint nPskLen = m_userCallBack(m_userContext, &cbData);
        const uchar* pPsk = (const uchar*)cbData.data.ptrs[0];
        if ((nPskLen == 0) || (cbData.data.rawSize[1] == 0) || (pPsk == nullptr)) nPskLen = 0;
        else {
            // TODO. PSK extension.
        }

        // The key share extension must be the last extension?
        *pMsg++ = EXT_KEY_SHARE >> 8; *pMsg++ = EXT_KEY_SHARE;
        *pMsg++ = 0x00; *pMsg++ = sizeof(m_eccClient) + 4; // Extension Length 0x24
        *pMsg++ = m_eccGroup >> 8; *pMsg++ = m_eccGroup;
        *pMsg++ = 0x00; *pMsg++ = sizeof(m_eccClient);
        // Give application a change to peek or modify the ephemeral ECC private key.
        cbData.cbType = TlsCBData::CB_ECDHE_PRIVATEKEY;
        cbData.data.ptrs[0] = m_eccServer;
        cbData.data.rawSize[1] = static_cast<size_t>(m_eccGroup);
        cbData.data.rawSize[2] = 0;
        uint eccGroup = m_userCallBack(m_userContext, &cbData);
        m_eccServer[0] &= 0xF8; m_eccServer[31] |= 0x40; m_eccServer[31] &= 0x7F;
        if (eccGroup == 0) eccGroup = m_eccGroup;
        pMsg += PubEccKey(pMsg, eccGroup);

        // Extensions related to TLS1.3. Extension supported version
        *pMsg++ = EXT_SUPPORTED_VERSION >> 8; *pMsg++ = EXT_SUPPORTED_VERSION;
        *pMsg++ = 0x00; *pMsg++ = 0x02; // Length: 2. Always just one entry.
        *pMsg++ = 0x03; *pMsg++ = 0x04; // Supports V3.4 (TLS1.3)

        if (eState == SSLSTATE_SERVER_CERTIFICATE) {
            eState = SSLSTATE_HANDSHAKE_SECRET;
        }
    }

    // Go back to correct extension size
    nExtSize = pMsg - pExtSize - 2;
    pExtSize[0] = nExtSize >> 8;
    pExtSize[1] = nExtSize;

    //Go back to correct Server Hello Message Size
    size_t nMsgSize = handshake.size() - 4;
    pu8 pMsgData = handshake.data();
    pMsgData[2] = u8(nMsgSize >> 8); pMsgData[3] = u8(nMsgSize);

    handshake.digestEncryptMac();
    return (pMsg - pMsgBuff);
}

/******************************************************************************
* Function:     CreateEncryptedExtensions
*
* Description:  Create the server encrypted extensions message. (TLS1.3)
*
* Returns:      Bytes of message constructed.
******************************************************************************/
uint TinyTls::CreateEncryptedExtensions
(
    uchar*  pMsgBuff,
    uint    nBuffSize
)
{
    uint    i, nLen = 22;
    uchar*  pMsg = pMsgBuff;
    Handshake handshake(*this, pMsg);
    TlsCBData cbData;

    uchar* p0 = pMsg;
    *pMsg++ = MSG_ENCRYPTED_EXTENSIONS;
    // Length of the whole message
    *pMsg++ = uchar(nLen >> 16);
    *pMsg++ = uchar(nLen >> 8);
    *pMsg++ = uchar(nLen >> 0);

    nLen -= 2; *pMsg++ = nLen>>8; *pMsg++ = nLen;
    
    // Some how Chrome does not like any of these included?
    if (1) {
    *pMsg++ = EXT_SUPPORTED_GROUPS >> 8; *pMsg++ = EXT_SUPPORTED_GROUPS;
    uint nGroups = (sizeof(gSupportedGroup) / sizeof(gSupportedGroup[0])) - 1;
    *pMsg++ = 0x00; *pMsg++ = (nGroups << 1) + 2;
    *pMsg++ = 0x00; *pMsg++ = (nGroups << 1);
    for (i = 0; i < nGroups; i++) {
        *pMsg++ = gSupportedGroup[i] >> 8; *pMsg++ = gSupportedGroup[i];
        cbData.data.rawInt[i] = gSupportedGroup[i];
    }
    cbData.data.rawInt[i] = 0;
    cbData.cbType = TlsCBData::CB_SUPPORTED_GROUPS;
    int nEccGroups = m_userCallBack(m_userContext, &cbData);
    if (nEccGroups) {
        pMsg -= (i << 1) + 4;
        *pMsg++ = 0x00; *pMsg++ = (nEccGroups << 1) + 2;
        *pMsg++ = 0x00; *pMsg++ = (nEccGroups << 1);
        for (i = 0; i< nEccGroups; i++) {
            *pMsg++ = cbData.data.rawInt[i] >> 8; *pMsg++ = cbData.data.rawInt[i];
        }
    }

    *pMsg++ = EXT_RECORD_SIZE_LIMIT >> 8; *pMsg++ = EXT_RECORD_SIZE_LIMIT;
    *pMsg++ = 0x00; *pMsg++ = 0x02;
    *pMsg++ = 0x40; *pMsg++ = 0x01;  // Record size limit 0x4001 bytes

    *pMsg++ = EXT_SERVER_NAME >> 8; *pMsg++ = EXT_SERVER_NAME;
    *pMsg++ = 0x00; *pMsg++ = 0x00;
    }

    // Go back to fix message length
    nLen = pMsg - p0 - 4;
    p0[1] = uchar(nLen >> 16); p0[2] = uchar(nLen >> 8); p0[3] = uchar(nLen);
    nLen -= 2; p0[4] = uchar(nLen >> 8); p0[5] = uchar(nLen);

    handshake.digestEncryptMac();
    return (pMsg - pMsgBuff);
}

/******************************************************************************
* Function:     CreateCertificateMsg
*
* Description:  Create the server certificate message.
*
* Returns:      Bytes of message constructed.
******************************************************************************/
uint TinyTls::CreateCertificateMsg
(
    uchar*  pMsgBuff,
    uint    nBuffSize
)
{
    uint    i, nLen = 0, nMacSize = 0, nExtSize = 0;
    uchar*  pMsg = pMsgBuff;
    TlsCBData cbData;
    const uchar* pCert;
    Handshake handshake(*this, pMsg);

    // Get the server certificates info from the user
    cbData.cbType = TlsCBData::CB_SERVER_CERTS;
    cbData.data.ptrs[0] = nullptr;
    m_userCallBack(m_userContext, &cbData);

    //First let's figure out how many certificates to be included in the message
    nLen = 3;
    for (i=0; (pCert = (const uchar*)cbData.data.ptrs[i++]); )
    {
        nLen += CERT_SIZE(pCert);
        nLen += 3; //3 bytes for the length
        if (isTls13()) nLen += 2 + nExtSize;
    }

    if (isTls13()) nLen++;

    //Now having the total length we can start construct the certificate message
    //The very first byte of course is MSG_CERTIFICATE
    *pMsg++ = MSG_CERTIFICATE;

    // Length of the whole message
    *pMsg++ = uchar(nLen >> 16);
    *pMsg++ = uchar(nLen >> 8);
    *pMsg++ = uchar(nLen >> 0);
    nLen -= 3;

    if (isTls13()) {
        // See https://tools.ietf.org/html/rfc8446#section-4.4.2
        nLen--; *pMsg++ = 0x00; // 0 bytes for certificate request context.
    }

    //Total certificate list size.
    *pMsg++ = uchar(nLen >> 16);
    *pMsg++ = uchar(nLen >> 8);
    *pMsg++ = uchar(nLen >> 0);

    //Now for each certificate. We do it in reverse order.
    for (i = 0; (pCert = (const uchar*)cbData.data.ptrs[i++]); ) {
        nLen = CERT_SIZE(pCert);

        //This one certificate size.
        *pMsg++ = (uchar)(nLen >> 16);
        *pMsg++ = (uchar)(nLen >> 8);
        *pMsg++ = (uchar)(nLen >> 0);

        //The certificate itself
        memcpy(pMsg, pCert, nLen);
        pMsg += nLen;

        // Extension entry for TLS1.3
        if (!isTls13()) continue;
        *pMsg++ = uchar(nExtSize>>8); *pMsg++ = uchar(nExtSize);
        if (nExtSize) {
            // TODO: add any extension to message payload.
            assert(0);
        }
    }

    handshake.digestEncryptMac();
    return (pMsg - pMsgBuff);
}

/******************************************************************************
* Function:     CreateCertVerifyMsg
*
* Description:  Create a certificate verify message.
*
* Returns:      Number of bytes of constructed message.
******************************************************************************/
uint TinyTls::CreateCertVerifyMsg(uchar* pMsgBuff, uint nBuffSize)
{
    uint    nKeyLen = 0, nMacSize = 0, slen=0;
    uchar*  pMsg = pMsgBuff;
    const uchar* pPubKey = nullptr;
    const uchar* pPriKey = nullptr;
    TlsCBData cbData;
    const uchar* pCert = nullptr;
    Handshake handshake(*this, pMsg);

    if (!isTls13()) {
        // TODO: Do it the TLS1.2 way
        assert(0);
        return 0;
    }

    // Do it in the new TLS1.3 way

    //Now having the total length we can start construct the certificate message
    //The very first byte of course is MSG_CERTIFICATE
    *pMsg++ = MSG_CERTIFICATE_VERIFY;
    *pMsg++ = 0x00; *pMsg++ = 0x00; *pMsg++ = 0x00;

    // Get the server certificates info from the user
    cbData.cbType = TlsCBData::CB_SERVER_KEYPAIR;
    cbData.data.ptrs[0] = nullptr; cbData.data.ptrs[1] = nullptr;
    cbData.data.ptrs[2] = nullptr; cbData.data.rawSize[3] = 0;
    nKeyLen = m_userCallBack(m_userContext, &cbData);
    pPubKey = (const uchar*)cbData.data.ptrs[0];
    pPriKey = (const uchar*)cbData.data.ptrs[1];
    pCert = (const uchar*)cbData.data.ptrs[2];
    uint nSigAlg = static_cast<uint>(cbData.data.rawSize[3]); // Pub key ECC_GROUP. 0 for RSA

    if ((nSigAlg >= 0x100) || (nSigAlg == 0)) {
        nSigAlg = rsa_pss_rsae_sha256;
    } else {
        // TODO: This is ECDSA signatures. Make sure nSigAlg is a supported kind.
        if (nSigAlg == ECC_x25519) nSigAlg = ed25519;
        else if (nSigAlg == ECC_secp256r1) {
            nSigAlg = ecdsa_secp256r1_sha256;
        } else {
            assert(0);
            nSigAlg = ecdsa_secp256r1_sha256;
        }
    }

    uchar certContext[256];
    uint nCtxLen = CreateCertContext(m_bIsClient, pCert, certContext);

    if (nKeyLen >= 256 || (nKeyLen == 128)) {
        // It is an RSA signature. 1024 bits allowed for testing RFC8448.
        *pMsg++ = uchar(nSigAlg >> 8); *pMsg++ = uchar(nSigAlg); // Signature algorithm
        *pMsg++ = uchar(nKeyLen >> 8); *pMsg++ = uchar(nKeyLen); // Signature length

        const CIPHER* c = nullptr;
        switch (nSigAlg) {
        case rsa_pss_rsae_sha256:   // Signature Algorithm: rsa_pss_rsae_sha256 (0x0804)
            c = &(m_cipherSet.sha256); break;
        case rsa_pss_rsae_sha384:   // Signature Algorithm: rsa_pss_rsae_sha384 (0x0805)
            c = &(m_cipherSet.sha384); break;
        case rsa_pss_rsae_sha512:   // Signature Algorithm: rsa_pss_rsae_sha512 (0x0806)
            c = &(m_cipherSet.sha512); break;
        default:
            c = &(m_cipherSet.sha256); break;
            break;
        }

        SsaSign(*c, pMsg, nKeyLen, certContext, nCtxLen);
        m_cipherSet.rsa.RsaDecrypt(pMsg, pPubKey, pPriKey, nKeyLen);
        pMsg += nKeyLen;
    } else {
        // It is an ECC signature. Put down signature algorithm, ecdsa_secp256r1_sha256 (0x0403)
        *pMsg++ = uchar(nSigAlg >>8); *pMsg++ = uchar(nSigAlg); // Signature algorithm

        *pMsg++ = uchar(nKeyLen >> 8); *pMsg++ = uchar(nKeyLen); // Signature length

        // Then the actual signature.
        uchar* pSign = pMsg;
        switch (nSigAlg) {
        //case ecdsa_secp384r1_sha384: // Signature Algorithm: ecdsa_secp384r1_sha384 (0x0503)
        //case ecdsa_secp521r1_sha512: // Signature Algorithm: ecdsa_secp521r1_sha512 (0x0603)
        case ed25519:                // Signature Algorithm: ed25519(0x0807)
        {
            X25519::ECDSign sig(m_cipherSet.sha512);
            uchar nc[32], md[32];
            {
                const CIPHER& sha(m_cipherSet.sha256);
                CTX  ctx;
                sha.Hash(certContext, nCtxLen, md);
                sha.Init(&ctx, NULL);
                sha.Input(&ctx, pPriKey, 32);
                sha.Input(&ctx, md, 32);
                sha.Digest(&ctx, nc);
            }
            // Use pMsg as temp buffer to contain keypair. It will be flushed a moment later.
            memcpy(pMsg, pPriKey, 32);
            memcpy(pMsg+32, pPubKey, 32);
            sig.Sign(pMsg, md, sizeof(md));

            // Encode an ASN1 sequence.
            *pMsg++ = 0x30; *pMsg++ = 0x44;
            // Encode Integer which is the r
            *pMsg++ = 0x02; *pMsg++ = 0x20;
            if (sig.r.n7 & 0x80000000) {
                pMsg[-1]++; *pMsg++ = 0x00;
            }
            sig.OutR(pMsg); pMsg += 0x20;
            // Encode Integer which is the s
            *pMsg++ = 0x02; *pMsg++ = 0x20;
            if (sig.s.n7 & 0x80000000) {
                pMsg[-1]++; *pMsg++ = 0x00;
            }
            sig.OutS(pMsg); pMsg += 0x20;
            slen = pMsg - pSign; pMsg = pSign;
            // Fix signature length.
            pMsg[-2] = slen >> 8; pMsg[-1] = slen;
            pMsg[1] = slen - 2; // Fix sequence lenth;
            pMsg += slen;
        }
        break;

        case ecdsa_secp256r1_sha256: // Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
        {
            P256::ECDSign sig;
            NN secKey; secKey.bytesIn(pPriKey);
            {
                //uchar tmpPub[64];
                //P256::G gBase;
                //gBase.PointMult(tmpPub, secKey);
                //tmpPub[0] |= 0x00;
            }
            uchar nc[32], md[32];
            {
                const CIPHER& sha(m_cipherSet.sha256);
                CTX  ctx;
                sha.Hash(certContext, nCtxLen, md);
                sha.Init(&ctx, NULL);
                sha.Input(&ctx, pPriKey, 32);
                sha.Input(&ctx, md, 32);
                sha.Digest(&ctx, nc);
            }
            sig.Sign(md, nc, secKey);
            // Encode an ASN1 sequence.
            *pMsg++ = 0x30; *pMsg++ = 0x44;
            // Encode Integer which is the r
            *pMsg++ = 0x02; *pMsg++ = 0x20;
            if (sig.r.n7 & 0x80000000) {
                pMsg[-1]++; *pMsg++ = 0x00;
            }
            sig.OutR(pMsg); pMsg += 0x20;
            // Encode Integer which is the s
            *pMsg++ = 0x02; *pMsg++ = 0x20;
            if (sig.s.n7 & 0x80000000) {
                pMsg[-1]++; *pMsg++ = 0x00;
            }
            sig.OutS(pMsg); pMsg += 0x20;
            slen = pMsg - pSign; pMsg = pSign;
            // Fix signature length.
            pMsg[-2] = slen >> 8; pMsg[-1] = slen;
            pMsg[1] = slen - 2; // Fix sequence lenth;
            pMsg += slen;
        }
        break;
        case rsa_pkcs1_sha256:
        case rsa_pkcs1_sha512:
        default:
            assert(0);
            break;
        }
        //slen = pMsg - pSign;
        //pSign[-2] = uchar(slen>>8); pSign[-1] = uchar(slen);
    }

    //Now set the correct total message size
    size_t nMsgSize = handshake.size() - 4;
    pu8 pMsgData = handshake.data();
    pMsgData[1] = u8(nMsgSize >> 16);
    pMsgData[2] = u8(nMsgSize >> 8);
    pMsgData[3] = u8(nMsgSize);

    handshake.digestEncryptMac();
    return (pMsg - pMsgBuff);
}


/******************************************************************************
* Function:     CreateCertificateRequestMsg
*
* Description:  Create a certificate request message.
*
* Returns:      Number of bytes of constructed message.
******************************************************************************/
uint TinyTls::CreateCertificateRequestMsg
(
    uchar*  pMsgBuff,
    uint    nBuffSize
)
{
    uint    nLen = 0;
    uchar*  pMsg = pMsgBuff;
    uchar*  pHashData;
    uint    nHashSize;

    //The content to be hashed in handshake hash starts here.
    pHashData = pMsg;

    *pMsg++ = MSG_CERTIFICATE_REQUEST;

    //We will come back to fill in the correct numbers later
    nLen = 0;
    //nLen = sizeof(gCAName);
    nLen += 7;
    *pMsg++ = (uchar)(nLen >> 16);
    *pMsg++ = (uchar)(nLen >> 8);
    *pMsg++ = (uchar)(nLen >> 0);

    *pMsg++ = 0x02;
    *pMsg++ = 0x01;
    *pMsg++ = 0x02;

    nLen -= 5;
    //Total certificate authority name size.
    *pMsg++ = (uchar)(nLen >> 8);
    *pMsg++ = (uchar)(nLen >> 0);

    nLen -= 2;

    {
        pTemp = pMsg;
        nTemp2 = nBuffSize - (pMsg - pMsgBuff);

        //Construct the CA list from root certificates.
        //EnumCerts(CreateCertificateRequestHelper, (void*)this);
        nLen = pTemp - pMsg;

        nLen += 5;
        pMsg -= 8;

        //We now come back to fill in the correct size numbers.
        *pMsg++ = (uchar)(nLen >> 16);
        *pMsg++ = (uchar)(nLen >> 8);
        *pMsg++ = (uchar)(nLen >> 0);

        *pMsg++ = 0x02;
        *pMsg++ = 0x01;
        *pMsg++ = 0x02;

        nLen -= 5;
        //Total certificate authority name size.
        *pMsg++ = (uchar)(nLen >> 8);
        *pMsg++ = (uchar)(nLen >> 0);

        pMsg += nLen;
    }

    nHashSize = (pMsg - pHashData);

    //Hash the handshake content of just ServerHello
    DigestMsg(pHashData, nHashSize);

    nTemp2 = MSG_CERTIFICATE_REQUEST; //This flags that we requested client certificate

    return (nLen = pMsg - pMsgBuff);
}


uint TinyTls::EccParamSignBlock(uchar* pMsg, uint nMsgLen, const uchar* pEccParam, uint nEccParamSize)
{
    CTX ctx;
    const uchar* p0 = pMsg;
    const CIPHER* pCipher = NULL;
    bool isRsa = true;
    switch (m_sigAlg) {
    //case ecdsa_secp384r1_sha384: // Signature Algorithm: ecdsa_secp384r1_sha384 (0x0503)
    //    isRsa = false;
    //    pCipher = &(m_cipherSet.sha384);
    //    break;
    case ecdsa_secp521r1_sha512: // Signature Algorithm: ecdsa_secp521r1_sha512 (0x0603)
        // Intentional fall through to ed25519
    case ed25519:                // Signature Algorithm: ed25519(0x0807)
        isRsa = false;
        // Then intentionally fall through to all sha512 cases
    case rsa_pkcs1_sha512:
        pCipher = &(m_cipherSet.sha512);
        break;
    case ecdsa_secp256r1_sha256: // Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
        isRsa = false;
        // Then intentionally fall through to sha256 cases
    case rsa_pkcs1_sha256:
        // Intentionally fall through to sha256 cases
    default:
        pCipher = &(m_cipherSet.sha256);
        break;
    }
    if (isRsa) {
        memset(pMsg, 0xFF, nMsgLen - 32);
        pMsg[0] = 0x00; pMsg[1] = 0x01;
        uchar* pOID = pMsg + nMsgLen - pCipher->dSize - 20;
        *pOID++ = 0x00; *pOID++ = 0x30; *pOID++ = 0x11 + pCipher->dSize; *pOID++ = 0x30;
        static const uchar cOID[]{ 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
            0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };
        memcpy(pOID, cOID, sizeof(cOID)); pOID += sizeof(cOID);
        switch (pCipher->eCipher) {
        case CIPHER_SHA256: pOID[-5] = 0x01; break;
        case CIPHER_SHA384: pOID[-5] = 0x02; break;
        case CIPHER_SHA512: pOID[-5] = 0x03; break;
        }
        pOID[-1] = pCipher->dSize;
        pMsg += 256 - pCipher->dSize;
    }

    // Calculate the digest: clientRandom + serverRandom + eccParam
    pCipher->Init(&ctx, pCipher->pIData);
    pCipher->Input(&ctx, clientRandom, sizeof(clientRandom));
    pCipher->Input(&ctx, serverRandom, sizeof(serverRandom));
    pCipher->Input(&ctx, pEccParam, nEccParamSize);
    pCipher->Digest(&ctx, pMsg);
    pMsg += pCipher->dSize;

    return (pMsg - p0);
}


/******************************************************************************
* Function:     CreateServerKeyExchangeMsg
*
* Description:  Create the server key exchange message.
*
* Returns:      Number of bytes of constructed message.
******************************************************************************/
uint TinyTls::CreateServerKeyExchangeMsg
(
    uchar*  pMsgBuff,
    uint    nBuffSize
)
{
    uint    nKeyLen = 0, nMacSize = 0;
    uchar*  pMsg = pMsgBuff;
    uint    slen = 0;
    uint    nUsed = 0;
    uint    nRand = 0;
    const uchar* pPubKey = NULL;
    const uchar* pPriKey = NULL;
    TlsCBData cbData;
    Handshake handshake(*this, pMsg);

    // TODO: Exam m_sigAlg to decide whether to use RSA or ECC signature.
    m_sigAlg;

    cbData.cbType = TlsCBData::CB_SERVER_KEYPAIR;
    cbData.data.ptrs[0] = nullptr; cbData.data.ptrs[1] = nullptr;
    cbData.data.ptrs[2] = nullptr; cbData.data.rawSize[3] = 0;
    nKeyLen = m_userCallBack(m_userContext, &cbData);
    pPubKey = (const uchar*)cbData.data.ptrs[0];
    pPriKey = (const uchar*)cbData.data.ptrs[1];
    const uchar* pCert = (const uchar*)cbData.data.ptrs[2];
    uint nSigAlg = static_cast<uint>(cbData.data.rawSize[3]); // Pub key ECC_GROUP. 0 for RSA

    // Server Key Exchange message starts with a type, and size to be set later.
    *pMsg++ = MSG_SERVER_KEY_EXCHANGE;
    *pMsg++ = (uchar)(nKeyLen >> 16);
    *pMsg++ = (uchar)(nKeyLen >> 8);
    *pMsg++ = (uchar)(nKeyLen >> 0);

    //EC Diffie - Hellman Server Params
    const uchar* pEccParam = pMsg;
    *pMsg++ = 0x03;             // Curve Type : named_curve(0x03)
    *pMsg++ = m_eccGroup >> 8;  // Named Curve: x25519 (0x001d)
    *pMsg++ = m_eccGroup;
    *pMsg++ = 0x20;             // Pubkey Length: 32

    // Obtain the ECC Public key and signature.
    {
        // Private ECC Key Already created upon OnTcpConnect().
        slen = sizeof(m_eccServer);

        // Give App a chance to obtain or modify the ECC private key.
        cbData.cbType = TlsCBData::CB_ECDHE_PRIVATEKEY;
        cbData.data.ptrs[0] = m_eccServer;
        cbData.data.rawInt[1] = m_eccGroup;
        m_userCallBack(m_userContext, &cbData);
        m_eccServer[0] &= 0xF8; m_eccServer[31] |= 0x40; m_eccServer[31] &= 0x7F;

        // Generate ECC public key, directly copy into pMsg
        if (m_eccGroup == ECC_x25519) {            
            NN secretKey; secretKey.bytesIn(m_eccServer);

            // Directly output client ECC public key to ClientKeyExchangeMsg.
            X25519::G gBase(9); gBase.PointMult(pMsg, secretKey);
        } else if (m_eccGroup == ECC_secp256r1) {
            NN secretKey; secretKey.bytesIn(m_eccServer);

            // Directly output client ECC public key to ClientKeyExchangeMsg.
            P256::G gBase; gBase.PointMult(pMsg, secretKey);
        } else {
            assert(0); // Error not supported ECC group.
        }

        // Give App a chance to obtain or even modify the ephemeral ECC public key.
        cbData.cbType = TlsCBData::CB_ECDHE_PUBLICKEY;
        cbData.data.ptrs[0] = pMsg;
        cbData.data.rawSize[1] = static_cast<size_t>(m_eccGroup);
        m_userCallBack(m_userContext, &cbData);

        pMsg += slen;
        uint nEccParamSize = pMsg - pEccParam;

        // Obtain the signature.
        *pMsg++ = m_sigAlg >> 8; *pMsg++ = m_sigAlg;
        *pMsg++ = uchar(nKeyLen>>8); *pMsg++ = uchar(nKeyLen); // Signature Length: 256

        uchar* pSign = pMsg;
        uint nSLen = 0;
        if ((nSLen = EccParamSignBlock(pSign, nKeyLen, pEccParam, nEccParamSize)) >= 256) {
            // RSA signature
            if (pPubKey && pPriKey) {
                m_cipherSet.rsa.RsaDecrypt(pSign, pPubKey, pPriKey, nKeyLen);
                slen = nKeyLen;
            }
        } else {
            // ECC signature
            uchar* pSeq = pMsg;
            switch (m_sigAlg) {
            case ecdsa_secp521r1_sha512: // Signature Algorithm: ecdsa_secp521r1_sha512 (0x0603)
            {
                // TODO: Implement it.
                assert(0);
            }
            break;
            case ed25519:                // Signature Algorithm: ed25519(0x0807)
            {
                X25519::ECDSign sig(m_cipherSet.sha512);
                uchar nc[32];
                {
                    const CIPHER& sha(m_cipherSet.sha256);
                    CTX  ctx;
                    sha.Init(&ctx, NULL);
                    sha.Input(&ctx, pPriKey, 32);
                    sha.Input(&ctx, pSign, nSLen);
                    sha.Digest(&ctx, nc);
                }
                // Use pMsg as temp buffer to contain keypair. It will be flushed a moment later.
                memcpy(pMsg, pPriKey, 32);
                memcpy(pMsg + 32, pPubKey, 32);
                sig.Sign(pMsg, pSign, nSLen);

                // Encode an ASN1 sequence.
                *pMsg++ = 0x30; *pMsg++ = 0x44;
                // Encode Integer which is the r
                *pMsg++ = 0x02; *pMsg++ = 0x20;
                if (sig.r.n7 & 0x80000000) {
                    pMsg[-1]++; *pMsg++ = 0x00;
                }
                sig.OutR(pMsg); pMsg += 0x20;
                // Encode Integer which is the s
                *pMsg++ = 0x02; *pMsg++ = 0x20;
                if (sig.s.n7 & 0x80000000) {
                    pMsg[-1]++; *pMsg++ = 0x00;
                }
                sig.OutS(pMsg); pMsg += 0x20;
                slen = pMsg - pSign; pMsg = pSign;
                // Fix signature length.
                pMsg[-2] = slen >> 8; pMsg[-1] = slen;
                pMsg[1] = slen - 2; // Fix sequence lenth;
                pMsg += slen;
            }
            break;
            case ecdsa_secp256r1_sha256: // Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
            {
                P256::ECDSign sig;
                NN secKey; secKey.bytesIn(pPriKey);
                {
                    uchar tmpPub[64];
                    P256::G gBase;
                    gBase.PointMult(tmpPub, secKey);
                    tmpPub[0] |= 0x00;
                }
                uchar nc[32];
                {
                    const CIPHER& sha(m_cipherSet.sha256);
                    CTX  ctx;
                    sha.Init(&ctx, NULL);
                    sha.Input(&ctx, pPriKey, 32);
                    sha.Input(&ctx, pSign, nSLen);
                    sha.Digest(&ctx, nc);
                }
                P256::G gBase;
                //gBase.PointMult(gPubEcc, secKey);
                sig.Sign(pSign, nc, secKey);
                // Encode an ASN1 sequence.
                *pMsg++ = 0x30; *pMsg++ = 0x44;
                // Encode Integer which is the r
                *pMsg++ = 0x02; *pMsg++ = 0x20;
                if (sig.r.n7 >= 0x80000000) {
                    pMsg[-1]++; *pMsg++ = 0x00;
                }
                sig.OutR(pMsg); pMsg += 0x20;
                // Encode Integer which is the s
                *pMsg++ = 0x02; *pMsg++ = 0x20;
                if (sig.s.n7 >= 0x80000000) {
                    pMsg[-1]++; *pMsg++ = 0x00;
                }
                sig.OutS(pMsg); pMsg += 0x20;
                slen = pMsg - pSign; pMsg = pSign;
                // Fix signature length.
                pMsg[-2] = slen >> 8; pMsg[-1] = slen;
                pMsg[1] = slen-2; // Fix sequence lenth;
            }
            break;
            default:
                assert(0);
                break;
            }
        }

        if (slen == 0) {
            // TODO: Needs to encrypt the signature using RSA private key.
            if (pPubKey && pPriKey) slen = nKeyLen;
        }

        pMsg += slen;
    }

    //Now set the correct total message size
    size_t nMsgSize = handshake.size() - 4;
    pu8 pMsgData = handshake.data();
    pMsgData[1] = u8(nMsgSize >> 16);
    pMsgData[2] = u8(nMsgSize >> 8);
    pMsgData[3] = u8(nMsgSize);

    handshake.digestEncryptMac();
    return (pMsg - pMsgBuff);
}


/******************************************************************************
* Function:     CreateClientKeyExchangeMsg
*
* Description:  Create the client key exchange message.
*
* Returns:      Number of bytes of constructed message.
******************************************************************************/
uint TinyTls::CreateClientKeyExchangeMsg
(
    uchar*  pMsgBuf,
    uint    nBuffSize
)
{
    uint    nKeyLen, nMacSize = 0;
    uchar*  pMsg = pMsgBuf;
    uint    slen = 0;
    Handshake handshake(*this, pMsg);

    nKeyLen = sizeof(m_eccClient);

    // The Client Key Exchange message. The size will be set later.
    *pMsg++ = MSG_CLIENT_KEY_EXCHANGE;
    *pMsg++ = (uchar)(nKeyLen >> 16);
    *pMsg++ = (uchar)(nKeyLen >> 8);
    *pMsg++ = (uchar)(nKeyLen >> 0);

    // This really depends on ePendingCipher. Either ECC DH, or RSA
    if (needServerKE(ePendingCipher)) {

        //EC Diffie - Hellman Server Params
        *pMsg++ = slen = sizeof(m_eccClient); // Pubkey Length: 32

        // Generate an EEC epitheral client key.
        TlsCBData cbData;
        //uchar eccPriKey[32];

        // Private ECC Key Already created upon OnTcpCOnnect().
        // Give app a change to obtain or modify the ECC private key.
        cbData.cbType = TlsCBData::CB_ECDHE_PRIVATEKEY;
        cbData.data.ptrs[0] = (void*)m_eccClient; cbData.data.rawSize[1] = m_eccGroup;
        slen = m_userCallBack(m_userContext, &cbData);
        m_eccClient[0] &= 0xF8; m_eccClient[31] |= 0x40; m_eccClient[31] &= 0x7F;

        if (slen != sizeof(m_eccClient)) {
            // TODO: Needs to encrypt the signature using RSA private key.
            slen = sizeof(m_eccClient);
        }

        // Do ECC computation
        pMsg += PubEccKey(pMsg, m_eccGroup); // Supply ECC Pubkey to Peer
        DoECDH(preMasterSecret); // Then do the local ECC Diffie Hellman.
        nPreMasterSize = sizeof(m_eccServer);
    } else if (pServerCert && (nKeyLen = GetPubKeyLen(pServerCert))) {
        // Not having ServerKeyExchange. But received server certificate & OK.

        //Here starts the data that needs to be encrypted.
        uchar* pEncryptData = pMsg;

        //First fill the pre padding with all none-zero random bytes
        for (int i = nKeyLen; i>0; )
        {
            uchar byteRand;
            while (0x00 == (byteRand = (uchar)gfRandom())) {}
            pMsg[--i] = byteRand;
        }
        pEncryptData[0] = 0x00;
        pEncryptData[1] = 0x02; //Block type 2, See PKCS#1
        pMsg += nKeyLen - SSL_SECRET_LEN;
        pMsg[-1] = 0x00;
        pMsg[0] = preMasterSecret[0];
        pMsg[1] = preMasterSecret[1];

        //Now add in the PreMasterSecret. Making the total nKeyLen.
        nPreMasterSize = SSL_SECRET_LEN;
        memcpy(preMasterSecret, pMsg, nPreMasterSize);
        pMsg += nPreMasterSize;

        //Now Encrypt it using server public key.
        EncryptByCert(pServerCert, pEncryptData, nKeyLen);
    }

    //Now calculate total message size and set it
    size_t nMsgSize = handshake.size() - 4;
    pu8 pMsgData = handshake.data();
    pMsgData[1] = u8(nMsgSize >> 16);
    pMsgData[2] = u8(nMsgSize >> 8);
    pMsgData[3] = u8(nMsgSize);

    handshake.digestEncryptMac();

    return (pMsg - pMsgBuf);
}


/******************************************************************************
* Function:     CreateServerHelloDoneMsg
*
* Description:  Create the server hello done message.
*
* Returns:      Number of bytes of constructed message.
******************************************************************************/
uint TinyTls::CreateServerHelloDoneMsg
(
    uchar*  pMsgBuff,
    uint    nBuffSize
)
{
    uchar*  pMsg = pMsgBuff;
    Handshake handshake(*this, pMsg);

    //The ServerHelloDone message size is just 0.
    *pMsg++ = MSG_SERVER_HELLO_DONE;
    *pMsg++ = 0x00; *pMsg++ = 0x00; *pMsg++ = 0x00;

    handshake.digestEncryptMac();

    return (pMsg - pMsgBuff);
}


/******************************************************************************
* Function:     CreateAlertMsg
*
* Description:  Create a CONTENT_ALERT message.
*
* Returns:      Bytes of constructed message.
******************************************************************************/
uint TinyTls::CreateAlertMsg(uchar cCategory, uchar cType)
{
    uchar       msg[2]{ cCategory, cType };

    return CreateNetMsg(CONTENT_ALERT, msg, sizeof(msg));
}

/******************************************************************************
* Function:     EncryptWithMAC
*
* Description:  Calculate the MAC, attach to message and then encrypt.
*
* Returns:      Bytes of the MAC block attached before encryption.
******************************************************************************/
uint TinyTls::EncryptWithMAC(
    uchar   cContentType,
    uchar*  pMsg,
    uint    nMsgSize
    )
{
    uint    nMacSize = 0;
    const uchar* pKey;
    uchar* pIV;
    uchar* pAAD;

    if (m_bIsClient) {
        pKey = clientWriteKey; pIV = clientIV; pAAD = clientAAD;
    } else {
        pKey = serverWriteKey; pIV = serverIV; pAAD = serverAAD;
    }

    ChachaNounce nc(*(const ChachaNounce*)pIV);

    switch(m_bIsClient? eClientCipher : eServerCipher) {
    case TLS_NONE: return 0;
    case TLS_RSA_EXPORT_WITH_RC4_40_MD5:    // 0x00, 0x03   N[RFC4346][RFC6347]
    case TLS_RSA_WITH_RC4_128_MD5:          // 0x00, 0x04   N[RFC5246][RFC6347]
    case TLS_RSA_WITH_RC4_128_SHA:          // 0x00, 0x05   N[RFC5246][RFC6347]
        assert(0);
        break;
    case TLS_AES_128_GCM_SHA256:            //0x13,0x01		Y[RFC8446]
    {
        nc ^= (const uint32_t*)pAAD;
        Aes128Gcm aes(pKey, nc);

        uchar* pRealAAD = pMsg - 5; uchar expIV[8];
        pMsg[nMsgSize] = cContentType; // Append one byte content type
        pRealAAD[0] = CONTENT_APPLICATION_DATA;
        pRealAAD[3] = uchar((nMsgSize+16+1)>>8); pRealAAD[4] = uchar(nMsgSize+16+1);
        aes.Encrypt(pMsg, nMsgSize+1, expIV, pMsg + nMsgSize+1, pRealAAD, 5);

        nMacSize = 1 + 16;
    }
    break;

    case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: //0xC0,0x2B		Y[RFC5289]
    case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: // 0xC0,0x2F		Y[RFC5289]
    case TLS_RSA_WITH_AES_128_GCM_SHA256:       // 0x00, 0x9C		Y[RFC5288]
    {
        Aes128Gcm aes(pKey, pIV);

        memmove(pMsg + 8, pMsg, nMsgSize);
        memcpy(pMsg, pIV + 4, 8);
        pAAD[8] = cContentType; pAAD[11] = nMsgSize >> 8; pAAD[12] = nMsgSize;
        aes.Encrypt(pMsg+8, nMsgSize, pMsg, pMsg+nMsgSize+8, pAAD, 13);

        for (int i = 12; i-->4; ) if (++pIV[i]) break;  // Increment explicit IV
        nMacSize = 8 + 16;
    }
    break;

    case TLS_CHACHA20_POLY1305_SHA256:          // 0x13, 0x03 RFC8446 Appendix-B.4
    case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: //0xCC, 0xA9  Y[RFC7905]
    case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: //0xCC,0xA8 Y[RFC7905]
    {
        pAAD[8] = cContentType; pAAD[11] = nMsgSize >> 8; pAAD[12] = nMsgSize;
        nc ^= (const uint32_t*)pAAD;

        Chacha20 cc; cc.Init(*(const ChachaKey*)pKey, nc);
        Poly1305 ply(cc);
        ++cc;
        ply.add(pAAD, 13);
        //The ChaCha20 encryption goes by whole blocks so will overshot
        //the last block. But it is OK, as overshot happens over valid
        //but still unused buffer space at the end of payload message.
        for (uint i = 0; i < nMsgSize; i+=sizeof(ChachaBlock)) {
            cc.Block(*(ChachaBlock*)(pMsg + i));
        }
        ply.add(pMsg, nMsgSize);
        uint32_t lstBlock[4]{ 13, 0, nMsgSize, 0 };
        ply.add((const uint8_t*)lstBlock, 16);
        ply.final(pMsg + nMsgSize);
        nMacSize = 16;
    }
    break;

    default:
        assert(0);
        break;
    }

    for (int i = 8; i--; ) if (++pAAD[i]) break;  // Increment AAD counter.

    return nMacSize;
}

/******************************************************************************
* Function:     DigestInit
*
* Description:  Initialize the SSL message digests.
*
* Returns:      None
******************************************************************************/
void TinyTls::DigestInit()
{
    m_cipherSet.sha256.Init(&sha256Ctx, m_cipherSet.sha256.pIData);
    hsCount_ = 0;
}

/******************************************************************************
* Function:     DigestOut
*
* Description:  Output a sha256 digest of all TLS handshake traffic so far.
*
* Returns:      Length of sha256 digest (32 bytes)
******************************************************************************/
uint TinyTls::DigestOut(uchar* digest) {
    m_cipherSet.sha256.Digest(&sha256Ctx, digest);
    return m_cipherSet.sha256.dSize;
}

/******************************************************************************
* Function:     DigestMsg
*
* Description:  Calculate accumulated SSL message digest
*
* Returns:      None
******************************************************************************/
void TinyTls::DigestMsg(const uchar* pMsg, uint cbLen)
{
    m_cipherSet.sha256.Input(&sha256Ctx, pMsg, cbLen);
    hsCount_ += cbLen;
}

/******************************************************************************
* Function:     CreateNetMsg
*
* Description:  Package and encrypt an out-going network data package.
*
* Returns:      Total size of the package when properly encrypted and packaged.
*               ZERO if not enough space to put the package in.
******************************************************************************/
uint TinyTls::CreateNetMsg(
    uchar       cContentType,
    const uchar* pData,
    uint        nDataSize
    )
{
    uint       nLen, nMacSize = MD5_SIZE, nEncryptSize;
    uchar*      pMsgBuff = &(netoutMsg[nNetOutSize]);
    uchar*      pMsg = pMsgBuff;
    uchar*      pEncryptData;

    //Do we have enough space to contain the package?
    nLen = 5 + nMacSize + nDataSize;
    if ((nLen + nNetOutSize) > sizeof(netoutMsg))
    {
        return 0; //Not enough space. No package is added, so return 0.
    }

    *pMsg++ = cContentType;

    *pMsg++ = SSL_VERSION_MAJOR;
    *pMsg++ = SSL_VERSION_MINOR3;

    nEncryptSize = nDataSize + nMacSize;

    //This content size may not be correct. Will come back to fill in again.
    *pMsg++ = (uchar)(nEncryptSize >> 8);
    *pMsg++ = (uchar)(nEncryptSize >> 0);

    //Starting here is data that needs to be encrypted.
    pEncryptData = pMsg;

    memcpy(pMsg, pData, nDataSize);
    pMsg += nDataSize;

    //Now calculate the MAC of the message and encrypt.
    pMsg += nMacSize = EncryptWithMAC(
        (*pMsgBuff),
        pEncryptData,
        nDataSize
        );

    nEncryptSize = nDataSize + nMacSize;   //Now we added the size of MAC

    pEncryptData[-2] = (uchar)(nEncryptSize >> 8);
    pEncryptData[-1] = (uchar)(nEncryptSize >> 0);

    nLen = uint(pMsg - pMsgBuff);

    nNetOutSize += nLen;

    return nLen;
}


/******************************************************************************
* Function:     ParseNetMsg
*
* Description:  Parse a generic client message
*
* Returns:      Bytes of message parsed.
******************************************************************************/
uint TinyTls::ParseNetMsg
(
    const uchar*    pNetMsg,
    uint            cbLen
    )
{
    uint nCopied = 0;
    uint nParsed = 0;
    uchar*  pMsg;

    while ((cbLen > 0) || (nParsed > 0)) {
        uint    nCopySize = 0;
        uchar   cContentType, verMajor, verMinor;
        uint    nContentSize = 0, nMsgSize;

        // First re-align any remainder server message to the beginning
        // of buffer pSSL->serverMsg, if there is unaligned message
        // data from previous parsing. But do it only when we are ready
        // to copy more data from input.
        if ((serverMsgOff > 0) && (cbLen > 0)) {
            if (serverMsgLen > 0) {
                memmove(serverMsg, serverMsg + serverMsgOff, serverMsgLen);
            }
            serverMsgOff = 0;
        }

        // Second copy what we can from input buffer into serverMsg buffer.
        nCopySize = sizeof(serverMsg) - serverMsgLen - serverMsgOff;
        if (nCopySize > cbLen) {
            nCopySize = cbLen;
        }

        if (nCopySize > 0) {
            memcpy(serverMsg + serverMsgOff + serverMsgLen, pNetMsg, nCopySize);
            serverMsgLen += nCopySize;
            pNetMsg += nCopySize;
            nCopied += nCopySize;
            cbLen -= nCopySize;
        } else if (nParsed == 0) {
            // The buffer is totally full or we have nothing more to copy.
            // So do not process any more, unless in the last round we have
            // just parsed portion of the message.
            break;
        }

        // Third parse the message in pSSL->serverMsg. One at a time.
        nParsed = 0;
        pMsg = serverMsg + serverMsgOff;

        // The CONTENT_HEADER_LEN = 5 bytes goes like this:
        // 1 content type 1 major version 1 minor version
        // 2 content length (MSB LSB)
        if (serverMsgLen < CONTENT_HEADER_LEN) {
            continue;
        }

        cContentType = *pMsg++;
        verMajor = *pMsg++;
        verMinor = *pMsg++;
        nContentSize = *pMsg++;
        nContentSize <<= 8;
        nContentSize += *pMsg++;

        if (serverMsgLen < CONTENT_HEADER_LEN + nContentSize) {
            // We do not have the complete message yet.
            continue;
        }

        nMsgSize = nContentSize;    //nMsgSize is nContentSize minus the MAC

        if ((cContentType != CONTENT_CHANGECIPHERSPEC) &&
            (TLS_NONE != (m_bIsClient ? eServerCipher : eClientCipher))) {
            //If the cipher is on already, we need to decrypt using peer key.
            const uchar* pKey;
            uchar* pIV;
            uchar* pAAD;

            if (m_bIsClient) {
                pKey = serverWriteKey; pIV = serverIV; pAAD = serverAAD;
            }
            else {
                pKey = clientWriteKey; pIV = clientIV; pAAD = clientAAD;
            }

            ChachaNounce nc(*(const ChachaNounce*)pIV);

            switch (m_bIsClient ? eServerCipher : eClientCipher)
            {
            case TLS_RSA_EXPORT_WITH_RC4_40_MD5:
            case TLS_RSA_WITH_RC4_128_MD5:
            case TLS_RSA_WITH_RC4_128_SHA:
                assert(0);
                break;

            case TLS_AES_128_GCM_SHA256:
            {
                // AES128_gcm decryption. The IV is 12 bytes and it is all implicit now.
                const uchar* pRealAAD = pMsg - 5;
                if (nContentSize < 16) {
                    eState = SSLSTATE_ABORT; break;
                }
                nMsgSize = nContentSize - 16;
                nc ^= (const uint32_t*)pAAD;
                Aes128Gcm cipher(pKey, nc);
                // Payload is nContextSize + 1 byte appended content type + 16 bytes security tag.
                if (cipher.Decrypt(pMsg, nMsgSize, pMsg + nMsgSize, pRealAAD, 5)) {
                    //Corrupted message. Bail out.
                    eState = SSLSTATE_ABORT;
                }
                nMsgSize--; // The extra byte encoded is real content type as last byte.
                cContentType = pMsg[nMsgSize];
            }
            break;

            case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
            case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            case TLS_RSA_WITH_AES_128_GCM_SHA256:
            {
                // AES128_gcm decryption. Make full 12 bytes IV = 4 bytes Implicit + 8 bytes Explicit
                if (nContentSize < 24) {
                    eState = SSLSTATE_ABORT; break;
                }
                memcpy(pIV + 4, pMsg, 8); nMsgSize = nContentSize - 24;
                Aes128Gcm cipher(pKey, pIV);
                pAAD[8] = cContentType;  pAAD[11] = (nContentSize - 24) >> 8; pAAD[12] = (nContentSize - 24);
                // Payload is nContextSize = 8 bytes explicit IV + encrypted data + 16 bytes security tag.
                if (cipher.Decrypt(pMsg + 8, nMsgSize, pMsg + nMsgSize + 8, pAAD, 13)) {
                    //Corrupted message. Bail out.
                    eState = SSLSTATE_ABORT;
                }
                memmove(pMsg, pMsg + 8, nMsgSize);

                for (int i = 12; i-->4; ) if (++pIV[i]) break;  // Increment explicit IV
            }
            break;

            case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            {
                if (nContentSize < 16) {
                    eState = SSLSTATE_ABORT; break;
                }
                nMsgSize = nContentSize - 16;
                pAAD[8] = cContentType; pAAD[11] = nMsgSize >> 8; pAAD[12] = nMsgSize;
                nc ^= (const uint32_t*)pAAD;

                Chacha20 cc; cc.Init(*(const ChachaKey*)pKey, nc);
                Poly1305 ply(cc);
                ++cc;
                ply.add(pAAD, 13);
                ply.add(pMsg, nMsgSize);
                uint8_t tag[16];
                memcpy(tag, pMsg + nMsgSize, 16);
                cc.Encode(pMsg, nMsgSize, 0);

                uint32_t lstBlock[4]{ 13, 0, nMsgSize, 0 };
                ply.add((const uint8_t*)lstBlock, 16);
                ply.final((uint8_t*)lstBlock);

                if (memcmp(lstBlock, pMsg + nMsgSize, 16)) {
                    //Corrupted message. Bail out.
                    eState = SSLSTATE_ABORT;
                }
            }
            break;

            default:
                //Unsupported cipher.
                assert(0);
                break;
            }

            for (int i = 8; i--; ) if (++pAAD[i]) break;  // Increment AAD counter.
        }

        if (eState != SSLSTATE_ABORT) switch (cContentType)
        {
        case CONTENT_CHANGECIPHERSPEC:
            if (isTls13()) {
                eState = eState;
            } else {
                ParseClientChangeCipherSpec(pMsg, nMsgSize);
            }
            break;
        case CONTENT_ALERT:
            ParseAlertMsg(pMsg, nMsgSize);
            break;
        case CONTENT_HANDSHAKE:
            ParseHandshake(pMsg, nMsgSize);
            break;
        case CONTENT_APPLICATION_DATA:
            ParseAppData(pMsg, nMsgSize);
            break;
        default:
            assert(0);  // Unknown content type
            break;
        }

        nParsed = CONTENT_HEADER_LEN + nContentSize;
        serverMsgOff += nParsed;
        serverMsgLen -= nParsed;
    }

    if (serverMsgLen >= sizeof(serverMsg))
    {
        // Need to increase serverMsg.
        assert(0);
    }

    return nCopied;
}

/******************************************************************************
* Function:     CreateClientHelloMsg
*
* Description:  Create a ClientHello message. We also initialize the SHA1 and
*               MD5 handshake hash context, and hash the ClientHello message.
*               Depends on whether we already have a session ID, we generate
*               either a Version 2.0 or Version 3.0 ClientHello message.
*
* Returns:      Number of bytes of generated ClientHello Message.
******************************************************************************/
uint TinyTls::CreateClientHelloMsg
(
    uchar*  pMsgBuff,
    uint    nBuffSize
)
{
    uint    i;
    uchar*  pMsg = pMsgBuff;
    Handshake handshake(*this, pMsg);
    TlsCBData cbData;
    bool hasTls13 = false;

    DigestInit();

    uchar*  p = &(clientRandom[0]);
    uchar*  pEnd = &(clientRandom[sizeof(clientRandom)]);

    //First construct the ClientRandom
    *p++ = (uchar)(nCurrentTime >> 24);
    *p++ = (uchar)(nCurrentTime >> 16);
    *p++ = (uchar)(nCurrentTime >> 8);
    *p++ = (uchar)(nCurrentTime >> 0);
    for (; p < pEnd; )
    {
        uint   nRand = 0;
        nRand ^= gfRandom();

        *p++ = (uchar)nRand; nRand >>= 8;
        *p++ = (uchar)nRand; nRand >>= 8;
        *p++ = (uchar)nRand; nRand >>= 8;
        *p++ = (uchar)nRand; nRand >>= 8;
    }

    //The start of the actual ClientHello Message = handshake.data()
    *pMsg++ = MSG_CLIENT_HELLO;

    //These 3 bytes are message size. We will come back to fill out.
    *pMsg++ = 0x00; *pMsg++ = 0x00; *pMsg++ = 0x00;

    //Next two bytes are version
    *pMsg++ = SSL_VERSION_MAJOR; *pMsg++ = SSL_VERSION_MINOR3;

    //Next 32 bytes are the ClientRandom bytes
    cbData.cbType = TlsCBData::CB_RANDOM;
    cbData.data.ptrs[0] = clientRandom; cbData.data.ptrs[1] = nullptr;
    m_userCallBack(m_userContext, &cbData);
    memcpy(pMsg, clientRandom, sizeof(clientRandom));
    pMsg += sizeof(clientRandom);

    //Next one byte is the session ID length, and the sessionID.
    *pMsg++ = (uchar)nSessionIDLen;
    memcpy(
        pMsg,
        &(sessionID[sizeof(sessionID) - nSessionIDLen]),
        nSessionIDLen
    );
    pMsg += nSessionIDLen;

    // Supported ciphers list
    uint nCipherSpecs = (sizeof(gSupportedCipher) / sizeof(gSupportedCipher[0])) - 1;
    *pMsg++ = (nCipherSpecs >> 7); *pMsg++ = nCipherSpecs << 1;
    for (i = 0; i < nCipherSpecs; i++) {
        hasTls13 |= ((*pMsg++ = gSupportedCipher[i] >> 8) == 0x13);
        *pMsg++ = gSupportedCipher[i];
        cbData.data.rawInt[i] = gSupportedCipher[i];
    }
    cbData.data.rawInt[i] = 0;

    cbData.cbType = TlsCBData::CB_CLIENT_CIPHER;
    int nCustomCiphers = m_userCallBack(m_userContext, &cbData);
    if (nCustomCiphers) {
        hasTls13 = false;
        pMsg -= (nCipherSpecs << 1) + 2;
        nCipherSpecs = nCustomCiphers;
        *pMsg++ = (nCipherSpecs >> 7); *pMsg++ = nCipherSpecs << 1;
        for (i = 0; i < nCipherSpecs; i++) {
            hasTls13 |= ((*pMsg++ = uchar(cbData.data.rawInt[i] >> 8)) == 0x13);
            *pMsg++ = uchar(cbData.data.rawInt[i] >> 0);
        }
    }

    //Then Compression Methods List length. And a one byte list 0x00 (=NULL compresion)
    *pMsg++ = 0x01; *pMsg++ = 0x00; //0x00 = NULL Compression. None.

    // Two bytes of size of extension. Come back to fill it.
    uchar* pExtSize = pMsg; *pMsg++ = 0x00; *pMsg++ = 0x00;

    // All available TLS extensions are listed here:
    // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml

    // Server name extension
    //EXT_SERVER_NAME
    cbData.cbType = TlsCBData::CB_SERVER_NAME;
    cbData.data.ptrs[0] = nullptr; cbData.data.rawSize[1] = 0;
    int slen = m_userCallBack(m_userContext, &cbData);
    if ((slen == 0) || (cbData.data.rawSize[1] == 0) || (cbData.data.ptrs[0] == nullptr)) slen = 0;
    if (slen) {
        *pMsg++ = EXT_SERVER_NAME >> 8; *pMsg++ = EXT_SERVER_NAME;
        slen += 5; *pMsg++ = slen >> 8; *pMsg++ = slen;
        slen -= 2; *pMsg++ = slen >> 8; *pMsg++ = slen;
        *pMsg++ = 0x00; // Server name type: host_name (0)
        slen -= 3; *pMsg++ = slen >> 8; *pMsg++ = slen;
        memcpy(pMsg, (const char*)cbData.data.ptrs[0], slen);
        pMsg += slen;
    }

    //extension: renegotiation_info(65281)
    *pMsg++ = EXT_RENEGOTIATION_INFO >> 8; *pMsg++ = EXT_RENEGOTIATION_INFO;
    *pMsg++ = 0x00; *pMsg++ = 0x01; *pMsg++ = 0x00;

    if (!hasTls13) { // Supported point format not used in TLS1.3 any more.
    //Extension: ec_point_formats(len = 4)
    *pMsg++ = EXT_EC_POINT_FORMATS >> 8; *pMsg++ = EXT_EC_POINT_FORMATS;
    *pMsg++ = 0x00; *pMsg++ = 0x04; // Length 4
    *pMsg++ = 0x03; // EC Point format length 3
    *pMsg++ = 0x00; // EC point format : uncompressed(0)
    *pMsg++ = 0x01; // EC point format : ansiX962_compressed_prime(1)
    *pMsg++ = 0x02; // EC point format : ansiX962_compressed_char2(2)
    }

    // Extension: supported_groups (len=10)
    *pMsg++ = EXT_SUPPORTED_GROUPS >> 8; *pMsg++ = EXT_SUPPORTED_GROUPS;
    uint nGroups = (sizeof(gSupportedGroup) / sizeof(gSupportedGroup[0])) - 1;
    *pMsg++ = 0x00; *pMsg++ = (nGroups<<1)+2;
    *pMsg++ = 0x00; *pMsg++ = (nGroups << 1);
    for (i = 0; i< nGroups; i++) {
        *pMsg++ = gSupportedGroup[i]>>8; *pMsg++ = gSupportedGroup[i];
        cbData.data.rawInt[i] = gSupportedGroup[i];
    }
    cbData.data.rawInt[i] = 0;
    cbData.cbType = TlsCBData::CB_SUPPORTED_GROUPS;
    int nEccGroups = m_userCallBack(m_userContext, &cbData);
    if (nEccGroups) {
        pMsg -= (i << 1) + 4;
        *pMsg++ = 0x00; *pMsg++ = (nEccGroups << 1) + 2;
        *pMsg++ = 0x00; *pMsg++ = (nEccGroups << 1);
        for (i = 0; i< nEccGroups; i++) {
            *pMsg++ = cbData.data.rawInt[i] >> 8; *pMsg++ = cbData.data.rawInt[i];
        }
    }

    // Extension: SessionTicket TLS (len=0). Always have it even size 0.
    cbData.cbType = TlsCBData::CB_SESSIONTICKET_TLS;  cbData.data.ptrs[0] = nullptr;
    uint nSTicketLen = m_userCallBack(m_userContext, &cbData);
    if ((nSTicketLen == 0) || cbData.data.rawSize[1] || (cbData.data.ptrs[0] == nullptr)) nSTicketLen = 0;
    *pMsg++ = EXT_SESSIONTICKET_TLS >> 8; *pMsg++ = EXT_SESSIONTICKET_TLS; // SessionTicket TLS(35)
    *pMsg++ = 0x00; *pMsg++ = 0x00; // Length: default 0. Indicates we can receive one from server.
    if (nSTicketLen) {
        pMsg[-2] = (nSTicketLen+2)>>8; pMsg[-1] = (nSTicketLen+2);
        *pMsg++ = nSTicketLen>>8; *pMsg++ = nSTicketLen;
        memcpy(pMsg, cbData.data.ptrs[0], nSTicketLen);
        pMsg += nSTicketLen;
    }

    // Extensions related to TLS1.3. Extension supported version
    if (hasTls13) {
        // The key share extension must be the last extension?
        *pMsg++ = EXT_KEY_SHARE >> 8; *pMsg++ = EXT_KEY_SHARE;
        *pMsg++ = 0x00; *pMsg++ = (sizeof(m_eccClient) << 1) + 10; // Extension Length 0x4A
        *pMsg++ = 0x00; *pMsg++ = (sizeof(m_eccClient) << 1) + 8; // List Length 0x48

        cbData.cbType = TlsCBData::CB_ECDHE_PRIVATEKEY;
        cbData.data.ptrs[0] = m_eccClient; cbData.data.rawSize[1] = 0; // ECC_GROUP. 0 means includes both X25519 and secp256r1
        uint nCurve = m_userCallBack(m_userContext, &cbData);
        m_eccClient[0] &= 0xF8; m_eccClient[31] |= 0x40; m_eccClient[31] &= 0x7F;
        if (nCurve) {
            pMsg[-3] -= 0x24; pMsg[-1] -= 0x24; // Readjust message size.
        }
        if (nCurve == 0 || nCurve == ECC_x25519) {
            // We include an ECC_x25519 (0x001d) and an ECC_secp256r1 (0x0017) key shares.
            *pMsg++ = ECC_x25519 >> 8; *pMsg++ = ECC_x25519;
            *pMsg++ = 0x00; *pMsg++ = sizeof(m_eccClient);
            pMsg += PubEccKey(pMsg, ECC_x25519);
        }
        if (nCurve == 0 || nCurve != ECC_x25519 || nCurve == ECC_secp256r1) {
            *pMsg++ = ECC_secp256r1 >> 8; *pMsg++ = ECC_secp256r1;
            *pMsg++ = 0x00; *pMsg++ = sizeof(m_eccClient);
            pMsg += PubEccKey(pMsg, ECC_secp256r1);
        }

        // The supported version extension.
        *pMsg++ = EXT_SUPPORTED_VERSION >> 8; *pMsg++ = EXT_SUPPORTED_VERSION;
        *pMsg++ = 0x00; *pMsg++ = 0x03; // Length: 3
        *pMsg++ = 0x02; *pMsg++ = 0x03; *pMsg++ = 0x04; // Supports V3.4 (TLS1.3)
    }  else {
        // Extension: encrypt_then_mac (len=0)
        *pMsg++ = EXT_ENCRYPT_THEN_MAC >> 8; *pMsg++ = EXT_ENCRYPT_THEN_MAC;
        *pMsg++ = 0x00; *pMsg++ = 0x00; // Length: 0

        // Extension: extended_master_secret (len=0)
        *pMsg++ = EXT_EXTENDED_MASTER_SECRET >> 8; *pMsg++ = EXT_EXTENDED_MASTER_SECRET;
        *pMsg++ = 0x00; *pMsg++ = 0x00; // Length: 0
    }

    // Extension: signature_algorithms (len=32)
    *pMsg++ = EXT_SIGNATURE_ALGORITHMS >> 8; *pMsg++ = EXT_SIGNATURE_ALGORITHMS;
    cbData.cbType = TlsCBData::CB_SIGNATURE_ALGORITHM;
    slen = (sizeof(gSigAlgs) / sizeof(gSigAlgs[0])) << 1;
    *pMsg++ = slen >> 8; *pMsg++ = slen;
    slen -= 2; *pMsg++ = slen >> 8; *pMsg++ = slen;
    for (i = 0; gSigAlgs[i]; i++) {
        *pMsg++ = gSigAlgs[i] >> 8; *pMsg++ = gSigAlgs[i];
        cbData.data.rawInt[i] = gSigAlgs[i];
    }
    cbData.data.rawInt[i] = 0;
    uint nSigs = m_userCallBack(m_userContext, &cbData);
    if (nSigs) {
        pMsg -= (i << 1) + 4;
        *pMsg++ = (nSigs+1) >> 7; *pMsg++ = (nSigs + nSigs + 2);
        *pMsg++ = nSigs >> 7; *pMsg++ = (nSigs + nSigs);
        for (i = 0; i < nSigs; i++) {
            *pMsg++ = cbData.data.rawInt[i] >> 8; *pMsg++ = cbData.data.rawInt[i];
        }
    }

    *pMsg++ = EXT_PSK_KEY_EXCHANGE_MODES >> 8; *pMsg++ = EXT_PSK_KEY_EXCHANGE_MODES;
    *pMsg++ = 0x00; *pMsg++ = 0x02; // Length 2
    *pMsg++ = 0x01; *pMsg++ = 0x01; // enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
                                    // 01 = psk_dhe_ke:  PSK with(EC)DHE key establishment.In this mode, the client and server MUST
                                    // supply "key_share" values as described in RFC8446 Section 4.2.8.

    // Do we have a PSK given?
    cbData.cbType = TlsCBData::CB_PSK_INFO;  cbData.data.ptrs[0] = nullptr; cbData.data.rawSize[1] = 0;
    uint nPskLen = m_userCallBack(m_userContext, &cbData);
    uchar* pPsk = (uchar*)cbData.data.ptrs[0];
    if ((nPskLen == 0) || (cbData.data.rawSize[1] == 0) || (pPsk == nullptr)) nPskLen = 0;
    else {
        // TODO. PSK extension.
    }

    //00 1c 00 02 40 01
    *pMsg++ = EXT_RECORD_SIZE_LIMIT >> 8; *pMsg++ = EXT_RECORD_SIZE_LIMIT;
    *pMsg++ = 0x00; *pMsg++ = 0x02; // Length 2
    *pMsg++ = 0x40; *pMsg++ = 0x01; // Record size limit is 16KB + 1

    // Finally wrap up of everything by calculating total extension length.
    slen = pMsg - pExtSize - 2;
    pExtSize[0] = slen >> 8; pExtSize[1] = slen; // Store the final extension size.

    //That's all. Now we know the whole message length.
    size_t nMsgSize = handshake.size() - 4;
    pu8 pMsgData = handshake.data();

    pMsgData[2] = (uchar)(nMsgSize >> 8);
    pMsgData[3] = (uchar)(nMsgSize >> 0);

    handshake.digestEncryptMac();
    if (hasTls13) earlySecret(pPsk, nPskLen);

    return (pMsg - pMsgBuff);
}


/******************************************************************************
* Function:     ParseClientHello
*
* Description:  Parse ClientHello in SSL V3.0 format.
*
* Returns:      Bytes of message parsed.
******************************************************************************/
uint TinyTls::ParseClientHello(
    const uchar*    pMsg,
    uint            cbLen
    )
{
    uchar vMajor, vMinor;
    int   nCiphers = 0;
    int   sIDLen = 0, nPskLen = 0;
    int   nCompression = 0;
    int   cbExtension = 0;
    int   extType = 0;
    int   extLen = 0;
    uint  theCipher = TLS_NONE, tls13Cipher = TLS_NONE;
    const uchar* p = pMsg;
    const uchar* pPsk = nullptr;

    vMajor = *p++;
    vMinor = *p++;

    // Ignore legacy version number
    //if ((vMajor != SSL_VERSION_MAJOR) || (vMinor != SSL_VERSION_MINOR3)) eState = SSLSTATE_ABORT;

    DigestInit();

    memcpy(clientRandom, p, RANDOM_SIZE);
    p += RANDOM_SIZE;

    //Does the ClientHello contain an existing SessionID?
    sIDLen = *p++;
    if (sIDLen > 0) {
        // Server will echo back client session ID regardless. RFC8446 Sec.4.1.3 legacy_session_id_echo
        nSessionIDLen = (sIDLen > sizeof(sessionID)) ? sizeof(sessionID) : sIDLen;
        memcpy(&(sessionID[sizeof(sessionID) - nSessionIDLen]), p, nSessionIDLen);
        // Allow application a chance to peek at the session ID received from client.
        TlsCBData cbData; cbData.cbType = TlsCBData::CB_CLIENT_SESSIONID;
        cbData.data.ptrs[0] = &(sessionID[sizeof(sessionID) - nSessionIDLen]);
        cbData.data.rawSize[1] = static_cast<size_t>(sIDLen);
        if (m_userCallBack(m_userContext, &cbData)) {
            // Matching Session ID found. Resume previous session.
        } else {
            //nSessionIDLen = 0;
        }
    } else {
        //Trigger the generation of a random session ID upon sending ServerHello.
        nSessionIDLen = 0;
    }
    p += sIDLen;

    nCiphers = *p++; nCiphers <<= 8; nCiphers += *p++;
    for (; nCiphers >= 2; nCiphers -= 2)
    {
        theCipher = *p++; theCipher <<= 8; theCipher += *p++;

        TlsCBData cbData;
        cbData.cbType = TlsCBData::CB_SERVER_CIPHER;

        if (((theCipher>>8) == 0x13) && CipherRank(TLS_CIPHER(theCipher)) < CipherRank(TLS_CIPHER(tls13Cipher))) {
            tls13Cipher = theCipher; // Remember the best supported TLS1.3 cipher.
        }

        if (CipherRank(TLS_CIPHER(theCipher)) < CipherRank(ePendingCipher)) {
            cbData.data.rawInt[0] = theCipher; cbData.data.rawInt[1] = ePendingCipher;
            ePendingCipher = TLS_CIPHER(theCipher);
        } else {
            cbData.data.rawInt[0] = ePendingCipher; cbData.data.rawInt[1] = theCipher;
        }
        m_userCallBack(m_userContext, &cbData);
        ePendingCipher = TLS_CIPHER(cbData.data.rawInt[0]);
    }

    nCompression = *p++;
    // Ignore compression methods.
    assert(nCompression == 1);
    assert(*p == 0x00);
    p += nCompression;

    //Do extentions exist?
    if ((p - pMsg) <= int(cbLen + 2))
    {
        cbExtension = *p++;
        cbExtension <<= 8;
        cbExtension += *p++;
    }

    assert((p - pMsg) + cbExtension == cbLen);
    bool hasTls13 = false;

    while (cbExtension > 0)
    {
        extType = *p++;
        extType <<= 8;
        extType += *p++;

        extLen = *p++;
        extLen <<= 8;
        extLen += *p++;
        
        cbExtension -= 4;

        cbExtension -= extLen;

        switch (extType) {
        case EXT_SERVER_NAME: // Server name
        {
            TlsCBData cbData;
            cbData.cbType = TlsCBData::CB_SERVER_NAME;
            cbData.data.ptrs[0] = (void*)(p + 5); cbData.data.rawSize[1] = (uint(p[3])<<8) + p[4];
            m_userCallBack(m_userContext, &cbData);
        }
        break;

        case 0x0005: break; // Status request

        case EXT_SUPPORTED_GROUPS:  // Type: supported_groups (10)
        {
            int k, nCurv, nCurvLen;
            nCurvLen = *p++; nCurvLen <<= 8; nCurvLen += *p++;
            for (k = 0; k < nCurvLen; k += 2) {
                nCurv = *p++; nCurv <<= 8; nCurv += *p++;
                if (EccRank(ECC_GROUP(nCurv)) < EccRank(ECC_GROUP(m_eccGroup))) {
                    m_eccGroup = ECC_GROUP(nCurv);
                }
            }
            extLen = 0;
        }
        break;

        case EXT_EC_POINT_FORMATS:  // Type: ec_point_formats (11)            
        {
            int k, nFmt, nFmtLen = *p++;
            for (k = 0; k < nFmtLen; k++) {
                nFmt = *p++;
            }
            extLen = 0;
        }
        break;
        case EXT_SIGNATURE_ALGORITHMS:  // Type: signature_algorithms (13)
        {
            int k, nSigAlg, nLen;
            nLen = *p++; nLen <<= 8; nLen += *p++;
            for (k = 0; k < nLen; k += 2) {
                nSigAlg = *p++; nSigAlg <<= 8; nSigAlg += *p++;
                if (SigAlgRank(SIG_ALG(nSigAlg)) < SigAlgRank(SIG_ALG(m_sigAlg))) {
                    m_sigAlg = nSigAlg;
                }
            }
            extLen = 0;
        }
        break;

        case 0x0010: break; // Application Layer Protocol Negotiation.
        case 0x0012: break; // Signed certificate timestamp.
        case 0x0015: break; // Padding
        case EXT_ENCRYPT_THEN_MAC: // Type: encrypt_then_mac(22)
            extLen = extLen;
            break;
        case EXT_EXTENDED_MASTER_SECRET:    // Type: extended_master_secret (23)
            m_attrs |= ATT_extended_master_secret;
            break; // Extended Master secret
        case EXT_RECORD_SIZE_LIMIT:
        {
            uint nLimit = uint(p[0]) << 8; nLimit += p[1];
            p = p;
        }
        break;
        case EXT_SESSIONTICKET_TLS: // Type: SessionTicket TLS(35)
            if (extLen) {
                // Do something with extended session ticket
            }
            break;
        case EXT_SUPPORTED_VERSION:
            {
                const uchar* pV = p;
                uint nV = uint(*pV++);
                while (nV) {
                    uint v = uint(*pV++) << 8;
                    v += (*pV++); nV -= 2;
                    if (v == 0x0304) {
                        // Support TLS 1.3
                        hasTls13 = true;
                    }
                }
            }
            break;
        case EXT_PSK_KEY_EXCHANGE_MODES:
        {
            uint c = uint(*p), m;
            while (c > 0) {
                m = uint(p[c--]);
                // TODO: Handle m = 0 pr 1;
            }
        }
        break;
        case EXT_PRESHARED_KEY:
            assert(0); // TODO. Handle pre-shared key
            break;
        case EXT_KEY_SHARE:
        {
            const uchar* ks = p;
            int nksLen = int(*ks++) << 8; nksLen += (*ks++);
            assert(nksLen + 2 == extLen);
            while (nksLen > 0) {
                uint nGrp = uint(*ks++) << 8; nGrp += (*ks++);
                uint klen = uint(*ks++) << 8; klen += (*ks++);
                nksLen -= klen + 4;
                if (nGrp == m_eccGroup) {
                    assert(klen == sizeof(m_eccClient));
                    memcpy(m_eccClient, ks, sizeof(m_eccClient));
                }
                ks += klen;
            }
        }
        break;
        case 0x7550: break; // Channel ID
        case 0xaaaa: break;
        case 0xbaba: break;
        case 0xff01: break; // Renegotiation info.

        }
        p += extLen;
    }

    if (hasTls13 && (tls13Cipher != TLS_NONE)) {
        if ((ePendingCipher >> 8) != 0x13) ePendingCipher = TLS_CIPHER(tls13Cipher);
        earlySecret(pPsk, nPskLen);
    }

    assert(cbExtension == 0);

    //Send out ServerHello next.
    eState = SSLSTATE_SERVER_HELLO;

    assert((uint)(p - pMsg) == cbLen);

    return (uint)(p - pMsg);
}

/******************************************************************************
* Function:     ParseClientChangeCipherSpec
*
* Description:  Parse the client change cipher spec message. After this point
*               all messages are encrypted.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint TinyTls::ParseClientChangeCipherSpec(
    const uchar*    pMsg,
    uint            cbLen
    )
{
    //Verify the message is correct.
    assert(cbLen == 1);
    assert((*pMsg) == 0x01);

    if (!m_bIsClient) CalcMasterSecret();
    ChangeCipherSpec(!m_bIsClient);

    return cbLen;
}

/******************************************************************************
* Function:     ParseAlertMsg
*
* Description:  Parse incoming message that belongs to CONTENT_ALERT.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint TinyTls::ParseAlertMsg(
    const uchar*    pMsg,
    uint            cbLen
    )
{
    uchar   cCategory, cType;

    cCategory = *pMsg++;
    cType = *pMsg++;

    switch (cType)
    {
    case ALERT_NOTIFY_CLOSE:
        CreateAlertMsg(ALERT_WARNING, ALERT_NOTIFY_CLOSE);
        eState = SSLSTATE_DISCONNECTING;
        break;
    case ALERT_UNSUPPORTED_EXTENSION:
        eState = SSLSTATE_DISCONNECTING;
        break;
    default:
        eState = SSLSTATE_DISCONNECTING;
        break;
    }

    return cbLen;
}


/******************************************************************************
* Function:     ParseHandshake
*
* Description:  Process the client handshake message
*
* Returns:      Bytes of message parsed, or a negative error code
******************************************************************************/
uint TinyTls::ParseHandshake(
    const uchar*    pMsg,
    uint            cbLen
    )
{
    uchar   cMsgType;
    uint    nMsgLen;
    uint    nParsed = 0;

    if (cbLen < 4) {
        return SSL_ERROR_PARSE;
    }

    while (nParsed < cbLen) {
        uint        nParseSize;
        const uchar*    pHashData;

        pHashData = pMsg;
        cMsgType = *pMsg++;
        nMsgLen = *pMsg++;
        nMsgLen <<= 8;
        nMsgLen += *pMsg++;
        nMsgLen <<= 8;
        nMsgLen += *pMsg++;

        nParsed += 4;

        if ((nParsed + nMsgLen) > cbLen) {
            return SSL_ERROR_PARSE;
        }

        nParseSize = nMsgLen;
        switch (cMsgType) {
        case MSG_HELLO_REQUEST:
            break;

        case MSG_CLIENT_HELLO:
            nParseSize = ParseClientHello(pMsg, nMsgLen);
            break;

        case MSG_SERVER_HELLO:
            nParseSize = ParseServerHello(pMsg, nMsgLen);
            break;

        case MSG_CERTIFICATE:
            nParseSize = ParseCertificateMsg(pMsg, nMsgLen);
            break;

        case MSG_SERVER_KEY_EXCHANGE:
            nParseSize = ParseServerKeyExchange(pMsg, nMsgLen);
            break;

        case MSG_CERTIFICATE_REQUEST:
            break;

        case MSG_SERVER_HELLO_DONE:
            nParseSize = ParseServerHelloDone(pMsg, nMsgLen);
            break;

        case MSG_CERTIFICATE_VERIFY:
            nParseSize = isTls13()? ParseCertVerifyTls13(pMsg, nMsgLen)
                                  : ParseCertificateVerify(pMsg, nMsgLen);
            break;

        case MSG_CLIENT_KEY_EXCHANGE:
            nParseSize = ParseClientKeyExchange(pMsg, nMsgLen);
            break;

        case MSG_FINISHED:
            if (VerifyPeerFinished(pMsg, nMsgLen)) {
                //The peer's Finished message mismatch. Bail.
                eState = SSLSTATE_ABORT;
            } else {
                //ClientFinishedMessage verified OK.
                switch (eState) {
                case SSLSTATE_CLIENT_FINISH1:
                    if (!isTls13()) eState = SSLSTATE_SERVER_FINISH2;
                    break;
                case SSLSTATE_CLIENT_FINISH2:
                case SSLSTATE_SERVER_FINISH2:
                    eState = SSLSTATE_HANDSHAKE_DONE;
                    break;
                case SSLSTATE_CONNECTED:
                    break; // OK
                case SSLSTATE_SERVER_FINISH1:
                    if (isTls13()) break;
                    // Otherwise fall through below
                default:
                    //We are in the wrong state to have received
                    //the ServerFinished message. What to do?
                    assert(0);
                    eState = SSLSTATE_HANDSHAKE_DONE;
                    break;
                }
            }
            if (nTemp2 == MSG_CERTIFICATE_REQUEST) {
                //We requested client certificate but the client did not go all the way through
                eState = SSLSTATE_CERTIFICATE_REJECTED;
            }
            break;

        case MSG_ENCRYPTED_EXTENSIONS:
            nParseSize = ParseEncryptedExtensions(pMsg, nMsgLen);
            break;

        case  MSG_NEW_SESSION_TICKET:
            // TODO: Implement it;
            nMsgLen = nMsgLen;
            break;
        default:
            assert(0);
            break;
        }

        assert(nParseSize == nMsgLen);

        pMsg += nParseSize;
        nParsed += nParseSize;

        //Hash the handshake content. Hash every handshake message. NOTE
        //for the purpose of calculating FinishedMessage, the HandshakeHash
        //does not include the FinishedMessage itself. So we have to do
        //the HandshakeHash right after we parse the handshake message.
        DigestMsg(pHashData, (uint)(pMsg - pHashData));

        if (!isTls13()) continue;

        switch (cMsgType) {
        case MSG_SERVER_HELLO:
            if (eState == SSLSTATE_HANDSHAKE_SECRET) {
                handshakeSecret();
                eState = SSLSTATE_SERVER_FINISH1;
            }
            break;
        case MSG_FINISHED:
            if (m_bIsClient) {
                mainSecret(); // Calculated right after server finished message.
            } else {
                setClientKey();
            }
            if (eState == SSLSTATE_SERVER_FINISH1) {
                eState = SSLSTATE_HANDSHAKE_DONE;
            }
            break;
        default:
            break;
        }
    }

    assert(nParsed == cbLen);   // We should have parsed exactly all the bytes.

    return nParsed;
}


/******************************************************************************
* Function:     ParseServerHello
*
* Description:  Parse the server hello message.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint TinyTls::ParseServerHello(
    const uchar*    pMsgBuf,
    uint            nMsgSize
    )
{
    uint    sIDLen;
    uint    nPendingCipher;
    uint    nCompression;
    uchar   verMajor, verMinor;
    bool    hasTls13 = false;
    const uchar* pMsg = pMsgBuf;

    verMajor = *pMsg++;
    verMinor = *pMsg++;

    // First in server hello msg, two bytes of server version.
    // Do we require the server to be version 3.0, no more, no less?

    // Next 32 bytes (RANDOM_SIZE) of ServerRandom.
    memcpy(serverRandom, pMsg, RANDOM_SIZE);
    pMsg += RANDOM_SIZE;

    // Next byte tells session ID length
    sIDLen = (uint)(*pMsg++);

    if (nSessionIDLen > 0)
    {
        if ((nSessionIDLen == sIDLen) &&
            (0 == memcmp(sessionID, pMsg, sIDLen)))
        {
            //No need to do ClientKeyExchange. We re-use the old
            //Pre-Master Secret from the last connection session.
            eState = SSLSTATE_SERVER_FINISH1;
        } else {
            memcpy(sessionID, pMsg, sIDLen);
        }
        pMsg += sIDLen;
    }
    nSessionIDLen = sIDLen;

    // Next two bytes is the pending ciphers.
    nPendingCipher = *pMsg++;
    nPendingCipher <<= 8;
    nPendingCipher += *pMsg++;

    //The final byte is Compression. We support only 0, no compression.
    nCompression = *pMsg++;

    ePendingCipher = TLS_CIPHER(nPendingCipher);

    if ((pMsg-pMsgBuf) >= (int)nMsgSize) {
        // No extension. We are done
        return (pMsg - pMsgBuf);
    }

    //There are extentions to the message
    uint nExtSizes = uint(*pMsg++)<<8;
    nExtSizes += *pMsg++;

    //Parse the message extention here.
    bool    bAbort = false;
    while ((pMsg - pMsgBuf) < (int)nMsgSize) {
        uint    nExtType = *pMsg++; nExtType <<= 8; nExtType += *pMsg++;
        uint    nExtSize = *pMsg++; nExtSize <<= 8; nExtSize += *pMsg++;

        switch (nExtType) {
        case EXT_SERVER_NAME:       // Type: server_name (0)
            break;
        case EXT_SUPPORTED_GROUPS:  // Type: supported_groups (10)
            // TODO: Parse it.
            break;
        case EXT_EC_POINT_FORMATS:  // Type: ec_point_formats (11)
            nExtSize--;
            if (nExtSize != *pMsg++) {
                bAbort = true; break;
            }
            while (nExtSize) {
                m_attrs |= 1 << ((*pMsg++) & 3); nExtSize--;
            }
            break;

        case EXT_SIGNATURE_ALGORITHMS:  // Type: signature_algorithms (13)
            break;
        case EXT_ENCRYPT_THEN_MAC:      // Type: encrypt_then_mac(22)
            break;
        case EXT_EXTENDED_MASTER_SECRET:    // Type: extended_master_secret (23)
            m_attrs |= ATT_extended_master_secret;
            break;
        case EXT_SESSIONTICKET_TLS:     // Type: SessionTicket TLS(35)
            m_attrs |= ATT_SessionTicket_TLS;
            break;
        case EXT_SUPPORTED_VERSION:
        {
            const uchar* pV = pMsg;
            uint v = uint(*pV++)<<8;
            v += (*pV++);
            if (v == 0x0304) {
                // Support TLS 1.3
                hasTls13 = true;
            }
        }
        break;
        case EXT_KEY_SHARE:
        {
            m_eccGroup = (uint(pMsg[0]) << 8) + pMsg[1];
            uint nKeyLen = (uint(pMsg[2]) << 8) + pMsg[3];
            assert(nKeyLen <= sizeof(m_eccServer));
            memcpy(m_eccServer, pMsg + 4, nKeyLen);
            // By now, both sides exchanged key share. So we can calculate shared secret.
            //DoECDH(); // TODO Calculate Master Secret and change state.
        }
        break;
        case EXT_RENEGOTIATION_INFO:    // Type: renegotiation_info(65281)
            break;
        default:
            break;
        }
        pMsg += nExtSize;
        if (bAbort) {
            //Something wrong with the re-negotiation info message. Bailout.
            eState = SSLSTATE_ABORT;
        }
    }
    if (bAbort) {
        //Something not quite right here. So just bail out.
        eState = SSLSTATE_ABORT;
    }

    assert((pMsg-pMsgBuf) == nMsgSize); // We should have parsed exactly all the bytes.

    if (eState == SSLSTATE_SERVER_HELLO) {
        eState = SSLSTATE_SERVER_CERTIFICATE;
        if (isTls13()) {
            eState = SSLSTATE_HANDSHAKE_SECRET;
        }
    }

    return nMsgSize;
}


/******************************************************************************
* Function:     ParseServerHelloDone
*
* Description:  Parse the server hellow done message.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint TinyTls::ParseServerHelloDone(
    const uchar*    pMsg,
    uint            cbLen
    )
{
    // Not much to be parsed. Just carry out operations that is needed upon
    // the ServerHelloDone.

    //Make sure we are expecting a ServerHelloDone at this point.

    //Upon receiving a ServerHelloDone, we should verify Server Certificate,
    //Generate the client key exchange message and send out.
    pTemp = NULL; //We set it that we have no client certificate.
    if (eState == SSLSTATE_SERVER_CERTREQUEST) {
        eState = SSLSTATE_CERTIFICATE_REQUEST;
    } else {
        eState = SSLSTATE_CERTIFICATE_VERIFY;
    }

    return cbLen;
}


/******************************************************************************
* Function:     ParseEncryptedExtensions
*
* Description:  Parse the encrypted extensions message. (TLS1.3)
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint TinyTls::ParseEncryptedExtensions(
    const uchar*    pMsg,
    uint            cbLen
)
{
    const uchar* p0 = pMsg;
    // TODO: Implement it.
    return cbLen;
}

/******************************************************************************
* Function:     ParseCertificateMsg
*
* Description:  Parse the certificate message and extract certificate(s).
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint TinyTls::ParseCertificateMsg(
    const uchar*    pMsg,
    uint            cbLen
    )
{
    const uchar* p0 = pMsg;
    uint    nTotalSize, nCurrentSize, nExtSize=0;
    struct CERT*    pCert = NULL;

    if (isTls13()) {
        // TODO: If context is non-zero, interpret it.
        uint nContextSize = uint(*pMsg++);
        pMsg += nContextSize;
    }

    // We are parsing a possible list of N certificates. First 3 bytes is the total cert list size.
    nTotalSize = uint(*pMsg++)<<16; nTotalSize += uint(*pMsg++)<<8; nTotalSize += uint(*pMsg++);

    while ((pMsg-p0) < int(cbLen))
    {
        uint    nCertParsed;

        //Next 3 bytes tells us the size of next certificate to be parsed.
        nCurrentSize = uint(*pMsg++)<<16; nCurrentSize += uint(*pMsg++)<<8; nCurrentSize += uint(*pMsg++);

        pCert = CreateCert(CS_UNKNOWN, nCurrentTime);

        if (pCertData == nullptr) pCertData = pMsg;

        nCertParsed = ParseCert(pCert, pMsg, nCurrentSize);
        pMsg += nCurrentSize;

        if (isTls13()) {
            nExtSize = uint(*pMsg++) << 8; nExtSize += uint(*pMsg++);
            if (nExtSize) {
                // TODO: Handle any extension here.
                pMsg += nExtSize;
            }
        }

        //The very first certificate is the server certificate. Anything that follows
        //are CA certificates that need to be inserted.
        if (pServerCert == NULL) {
            pServerCert = pCert;
        } else if (NULL == InsertCert(pCert, &pMidCerts)) {
            //Can not insert certificate since it exists already as root.
            //So ignore the one coming from the network.
            DestroyCert(pCert);
        }
    }

    if (isTls13()) {
        // We will try to authenticate certificate here.
        CERT_STATUS eStatus = AuthenticateCert(pServerCert, &pMidCerts);

        //Please note here. The certificate may or may not be verified,
        //depends on eStatus. It is up to application to acccept if the
        // certificate is questionable.
        if ((eStatus & (CS_OK | CS_VERIFIED)) == (CS_OK | CS_VERIFIED)) {
            //Certificate is OK and can be trusted.
            eState = SSLSTATE_SERVER_CERT_VERIFY;
        } else {
            //Certificate questionable. Prompt the application to decide
            TlsCBData cbData;
            cbData.cbType = TlsCBData::CB_CERTIFICATE_ALERT;
            cbData.data.ptrs[0] = pServerCert;
            cbData.data.rawSize[1] = static_cast<size_t>(eStatus);
            if (m_userCallBack(m_userContext, &cbData)) {
                eState = SSLSTATE_SERVER_CERT_VERIFY;
            }  else {
                eState = SSLSTATE_ABORT; // Certificate not accepted by App.
            }
        }
    } else {
        //We received server certificate so next to come is ServerHelloDone.
        eState = SSLSTATE_SERVER_HELLO_DONE;
    }

    return (pMsg - p0);
}

/******************************************************************************
* Function:     GetClientVerifyInfo
*
* Description:  Extract the client verify info block which was generated in a
*               previous client finished message. This would only exist if there
*               was a previous successful handshake. The block is 36 bytes for
*               SSL 3.0, and 12 bytes for SSL 3.1/TLS 1.0 or later.
*
* Returns:      Bytes of the client verify info copied. Zero if there is none.
******************************************************************************/
uint TinyTls::GetClientVerifyInfo(uchar* pMsgBuff)
{
    uint   nVerifySize;

    if (eClientCipher == CIPHER_NONE) {
        //No prior handshake, so the client verify info does not exist.
        nVerifySize = 0;
    } else if ((preMasterSecret[1] < SSL_VERSION_MINOR1) ||
        (SSL_VERSION_MINOR < SSL_VERSION_MINOR1))
    {
        //For SSL 3.0. The verify info is MD5_SIZE + SHA1_SIZE = 36 bytes 
        nVerifySize = MD5_SIZE + SHA1_SIZE;
        memcpy(pMsgBuff, clientVerify, nVerifySize);
    } else {
        //For SSL 3.1. The verify info is TLS_VERIFY_LEN=12 bytes;
        nVerifySize = TLS_VERIFY_LEN;
        memcpy(pMsgBuff, clientVerify, nVerifySize);
    }

    return nVerifySize;
}

/******************************************************************************
* Function:     CalculateVerifySignature
*
* Description:  Calculate the expected certificate verify signature. TLS1.2
*
* Returns:      None.
******************************************************************************/
void TinyTls::CalculateVerifySignature(
    uchar*  pSignature,
    uint    nKeyLen
    )
{
    // TODO: Fix it for TLS1.2
    DigestOut(pSignature);
}


/******************************************************************************
* Function:     ParseCertVerifyTls13
*
* Description:  Parse the certificate verify message of TLS.3
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint TinyTls::ParseCertVerifyTls13(const uchar* pMsg, uint cbLen) {
    const uchar* p0 = pMsg;
    uchar md[196];
    uchar pkey[256];

    eState = SSLSTATE_CLIENT_FINISH1;

    uint ret = 0, sigAlg = uint(*pMsg++) << 8; sigAlg += uint(*pMsg++);
    uint nlen=0, keylen = GetPubKey(pServerCert, pkey);

    uint nctx = CreateCertContext(!m_bIsClient, pCertData, md);
    pCertData = nullptr; // This data is only used temporary.

    keylen = GetPubKey(pServerCert, pkey);

    const CIPHER* c = nullptr;

    switch (sigAlg) {
    case ed25519:
    {
        // Test to find out if the signature is authentic.
        X25519::ECDSign sig(m_cipherSet.sha512);

        ret |= ((keylen ^ 0x40) && (keylen ^ 0x20)); if (ret) break;
        nlen = uint(*pMsg++); nlen += uint(*pMsg++); ret |= nlen ^ 0x46;
        ret |= (*pMsg++) ^ 0x30; ret |= ((*pMsg++) ^ 0x44) & 0xFC;
        ret |= (*pMsg++) ^ 0x02;
        ret |= ((*pMsg++) ^ 0x20)&0xFE; if (ret) break;
        if ((pMsg[-1] & 0x01) && (*pMsg == 0x00)) pMsg++;
        sig.r.bytesIn(pMsg); pMsg += 0x20;
        ret |= (*pMsg++) ^ 0x02;
        ret |= ((*pMsg++) ^ 0x20)&0xFE; if (ret) break;
        if ((pMsg[-1] & 0x01) && (*pMsg == 0x00)) pMsg++;
        sig.s.bytesIn(pMsg); pMsg += 0x20;
        ret |= (pMsg - p0) ^ cbLen; if (ret) break;

        ret |= !sig.Test(pkey, md, nctx);
    }
    break;
    case ecdsa_secp256r1_sha256:
    {
        P256::ECDSign sig;
        m_cipherSet.sha256.Hash(md, nctx, md);
        ret |= ((keylen ^ 0x40) && (keylen ^ 0x20)); if (ret) break;
        nlen = uint(*pMsg++)<<8; nlen += uint(*pMsg++);
        ret |= (*pMsg++) ^ 0x30; ret |= ((*pMsg++) ^ 0x44) & 0xFC;
        ret |= (*pMsg++) ^ 0x02;
        ret |= ((*pMsg++) ^ 0x20)&0xFE; if (ret) break;
        if ((pMsg[-1] & 0x01) && (*pMsg == 0x00)) pMsg++;
        sig.r.netIn(pMsg); pMsg += 0x20;
        ret |= (*pMsg++) ^ 0x02;
        ret |= ((*pMsg++) ^ 0x20)&0xFE; if (ret) break;
        if ((pMsg[-1] & 0x01) && (*pMsg == 0x00)) pMsg++;
        sig.s.netIn(pMsg); pMsg += 0x20;
        ret |= (pMsg - p0) ^ cbLen; if (ret) break;

        P256::G gBase; gBase.netIn(pkey, keylen);
        ret |= !sig.Test(md, gBase);
    }
    break;

    case rsa_pss_rsae_sha256:
        c = &(m_cipherSet.sha256); break;

    case rsa_pss_rsae_sha384:
        c = &(m_cipherSet.sha384); break;

    case rsa_pss_rsae_sha512:
        c = &(m_cipherSet.sha512); break;

    default:
        assert(0);
        eState = SSLSTATE_ABORT;
        break;
    }

    if (((keylen >= 256) || (keylen == 128) ) && c) {
        // RSASSA_PSS algorithm.
        nlen = uint(*pMsg++) << 8; nlen += uint(*pMsg++);
        ret |= keylen ^ nlen;
        memcpy(pkey, pMsg, keylen); pMsg += keylen;
        EncryptByCert(pServerCert, pkey, keylen);
        ret |= SsaTest(*c, pkey, keylen, md, nctx);
    }

    if (ret) {
        eState = SSLSTATE_ABORT;
    }

    return cbLen;
}

/******************************************************************************
* Function:     ParseCertificateVerify
*
* Description:  Parse the certificate verify message of TLS1.2
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint TinyTls::ParseCertificateVerify(
    const uchar*    pMsg,
    uint            nMsgSize
    )
{
    uint    nParsed = 0;
    uint    nSize;
    uint    nCopy;
    uchar   signature[256];
    uchar   tmpMsg[256]; //MAX signature block size for 2048 bits RSA key

                         // First 2 bytes tells us the certificate verify signature size.
    nSize = *pMsg++;
    nSize <<= 8;
    nSize += *pMsg++;
    nParsed += 2;

    nCopy = nSize;
    //assert(nCopy <= sizeof(tmpMsg));
    if (nCopy > sizeof(tmpMsg)) {
        //Should never happen.
        nCopy = sizeof(tmpMsg);
    }

    memcpy(tmpMsg, pMsg, nCopy);
    pMsg += nSize;
    nParsed += nSize;

    EncryptByCert(pServerCert, tmpMsg, nSize);
    //assert(nParsed == nMsgSize);

    CalculateVerifySignature(signature, nSize);

    //Verify the signature.
    if (0 == memcmp(signature, tmpMsg, nSize)) {
        //No error. Signature matches.
        nTemp2 = 0;
    } else {
        //Signature does NOT verify.
        //The value either still remains at that value or we explicitly set it.
        //nTemp2 at MSG_CERTIFICATE_REQUEST signals client certificate failed.
        nTemp2 = MSG_CERTIFICATE_REQUEST;
    }

    return nParsed;
}


/******************************************************************************
* Function:     ParseClientKeyExchange
*
* Description:  Parse the client key exchange message. TLS 1.2 only.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint TinyTls::ParseClientKeyExchange(
    const uchar*    pMsgBuf,
    uint            cbLen
    )
{
    uint   nKeyLen = 0, eccGroup = 0;
    const uchar* pMsg = pMsgBuf;
    uchar   msgBuff[256];   //Max 2048 bits RSA key
    TlsCBData cbData;

    if (needServerKE(ePendingCipher)) {
        nKeyLen = *pMsg++;
        assert(nKeyLen == sizeof(m_eccClient));
        memcpy(m_eccClient, pMsg, sizeof(m_eccClient));
        pMsg += nKeyLen;

        // Do ECC Diffie Hellman computation
        DoECDH(preMasterSecret);
        nPreMasterSize = sizeof(m_eccServer);

        eState = ((pMsg - pMsgBuf) == cbLen) ? SSLSTATE_CLIENT_FINISH1 : SSLSTATE_ABORT;
    } else {
        cbData.cbType = TlsCBData::CB_SERVER_KEYPAIR;
        cbData.data.ptrs[0] = cbData.data.ptrs[1] = cbData.data.ptrs[2] = nullptr; cbData.data.rawSize[3] = 0;
        nKeyLen = m_userCallBack(m_userContext, &cbData);
        const uchar* pPubKey = (const uchar*)cbData.data.ptrs[0];
        const uchar* pPriKey = (const uchar*)cbData.data.ptrs[1];
        const uchar* pCert = (const uchar*)cbData.data.ptrs[2];
        eccGroup = static_cast<uint>(cbData.data.rawSize[3]); // Pub key ECC_GROUP. 0 for RSA

        if ((eccGroup == 0) && (nKeyLen != 128)) nKeyLen = 256; // Default RSA key size.
        else if (eccGroup < 128) nKeyLen = 32; // Default ECC key size.

        if (nKeyLen < 128) {
            // TODO. Handle ECC type client key exchange.
        }

        //We are OK. So copy over the message
        memcpy(msgBuff, pMsg, nKeyLen);

        m_cipherSet.rsa.RsaDecrypt(
            msgBuff,
            pPubKey,
            pPriKey,
            nKeyLen
        );

        nPreMasterSize = sizeof(preMasterSecret);

        memcpy(preMasterSecret, &(msgBuff[nKeyLen - nPreMasterSize]), nPreMasterSize);

        // If these assertions fail, we proceed as if nothing happens, so as to avoid
        // leaking side channel information. The handshake will eventually fail anyway.
        //assert(0x00 == msgBuff[0]); assert(0x02 == msgBuff[1]);
        //assert(0x00 == msgBuff[nKeyLen - nPreMasterSize - 1]);
        //assert(SSL_VERSION_MAJOR == preMasterSecret[0]);
        //assert(SSL_VERSION_MINOR3 == (preMasterSecret[1]|0x02));

        // Intentionally corrupt preMasterSecret if above bytes asserted are wrong.
        preMasterSecret[0] = SSL_VERSION_MAJOR;
        preMasterSecret[1] &= SSL_VERSION_MINOR3;
        preMasterSecret[2] += msgBuff[0] + msgBuff[nKeyLen - nPreMasterSize - 1] + msgBuff[1] - 0x02;

        eState = SSLSTATE_CLIENT_FINISH1;
    }

    return cbLen;
}


/******************************************************************************
* Function:     ParseServerKeyExchange
*
* Description:  Parse the server key exchange message.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint TinyTls::ParseServerKeyExchange(
    const uchar*    pMsgBuf,
    uint            cbLen
)
{
    uint   nSigLen = 0, err = 0;
    const uchar* pMsg = pMsgBuf;
    uchar  msgHash[256];

    // EC Diffie-Hellman Server Params
    const uchar* pEccParam = pMsg;

    uint8_t curvType = *pMsg++; // Curve Type: named_curve (0x03)
    if (curvType != 0x03) {
        // TODO: Handle not named curve cases
        assert(0);
        return cbLen;
    }

    // Named Curve: example x25519 (0x001d)
    m_eccGroup = uint(*pMsg++) << 8; m_eccGroup += (*pMsg++);
    
    uint nKeyLen = *pMsg++;      // Pubkey Length: 32
    if ((nKeyLen & 1) && (*pMsg == 0x00)) {nKeyLen--; pMsg++;}
    err |= (nKeyLen ^ sizeof(m_eccServer));
    memcpy(m_eccServer, pMsg, sizeof(m_eccServer));
    pMsg += nKeyLen;
    uint nEccParamSize = pMsg - pEccParam;

    // Signature Algorithm: example rsa_pkcs1_sha512 (0x0601)
    m_sigAlg = *pMsg++; m_sigAlg <<= 8; m_sigAlg += *pMsg++;

    // Signature Length: 256
    nSigLen = *pMsg++; nSigLen <<= 8; nSigLen += *pMsg++;

    if (nSigLen >= 256) {
        // RSA signature
        if ((nSigLen & 1) && (*pMsg == 0x00)) {
            nSigLen--; pMsg++;
        }
        nKeyLen = GetPubKeyLen(pServerCert);
        assert(nSigLen == nKeyLen);
    } else {
        // ECDSA signature

    }

    // Calculate a message hash block
    EccParamSignBlock(msgHash, nKeyLen, pEccParam, nEccParamSize);

    if (nKeyLen < 256) {
        // It is ECC signature
        uchar gPubEcc[64];

        switch (m_sigAlg) {
        case ecdsa_secp521r1_sha512: // Signature Algorithm: ecdsa_secp521r1_sha512 (0x0603)
            // TODO: Implement it.
            assert(0); err |= -1;
            pMsg += nSigLen;
            break;
        case ed25519:                // Signature Algorithm: ed25519(0x0807)
        {
            // Test to find out if the signature is authentic.
            uint nLen, nKeyLen = GetPubKey(pServerCert, gPubEcc);
            X25519::ECDSign sig(m_cipherSet.sha512);
            err |= (*pMsg) ^ 0x30; pMsg++; nLen = *pMsg++;

            err |= (*pMsg) ^ 0x02; pMsg++; nLen = *pMsg++;
            if ((nLen & 1) && (*pMsg == 0x00)) { nLen--; pMsg++; }
            err |= (nLen ^ 0x20);
            sig.r.bytesIn(pMsg); pMsg += nLen;

            err |= (*pMsg) ^ 0x02; pMsg++; nLen = *pMsg++;
            if ((nLen & 1) && (*pMsg == 0x00)) { nLen--; pMsg++; }
            err |= (nLen ^ 0x20);
            sig.s.bytesIn(pMsg); pMsg += nLen;
            err |= !sig.Test(gPubEcc, pEccParam, nEccParamSize);
        }
        break;
        case ecdsa_secp256r1_sha256: // Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
        {
            // Test to find out if the signature is authentic.
            uint nLen, nKeyLen = GetPubKey(pServerCert, gPubEcc);
            P256::ECDSign sig;
            err |= (*pMsg) ^ 0x30; pMsg++; nLen = *pMsg++;

            err |= (*pMsg) ^ 0x02; pMsg++; nLen = *pMsg++;
            if ((nLen & 1) && (*pMsg == 0x00)) { nLen--; pMsg++; }
            err |= (nLen ^ 0x20);
            sig.r.netIn(pMsg); pMsg += nLen;

            err |= (*pMsg) ^ 0x02; pMsg++; nLen = *pMsg++;
            if ((nLen & 1) && (*pMsg == 0x00)) { nLen--; pMsg++; }
            err |= (nLen ^ 0x20);
            sig.s.netIn(pMsg); pMsg += nLen;

            P256::G gBase;
            gBase.netIn(gPubEcc, nKeyLen);
            err |= !sig.Test(msgHash, gBase);
        }
        break;
        default:
            assert(0); err |= -1;
            break;
        }
    } else {
        // It is RSA signature
        uchar  msgBuff[256];    //Max 2048 bits RSA key
        memcpy(msgBuff, pMsg, nSigLen); pMsg += nSigLen;
        EncryptByCert(pServerCert, msgBuff, nKeyLen);

        // Validate the signature.
        if (memcmp(msgBuff, msgHash, nKeyLen)) {
            eState = SSLSTATE_ABORT;
        }
    }

    if ((pMsg - pMsgBuf) != cbLen || err) {
        eState = SSLSTATE_ABORT;
    }

    return cbLen;
}

/******************************************************************************
* Function:     CreateChangeCipherSpecMsg
*
* Description:  Create the change cipher spec message
*
* Returns:      Number of bytes of constructed message.
******************************************************************************/
uint TinyTls::CreateChangeCipherSpecMsg
(
    uchar*  pMsgBuff,
    uint   nBuffSize
)
{
    uchar*      pMsg = pMsgBuff;

    *pMsg++ = CONTENT_CHANGECIPHERSPEC;
    *pMsg++ = SSL_VERSION_MAJOR;
    *pMsg++ = SSL_VERSION_MINOR3;

    //The Message Body is 1 byte: That byte is 0x01.
    *pMsg++ = 0x00;
    *pMsg++ = 0x01; //The message length

    uchar* pMsgBody = pMsg;
    *pMsg++ = 0x01; //The message body

    pMsg += EncryptWithMAC(
        CONTENT_CHANGECIPHERSPEC,
        pMsgBody,
        (pMsg-pMsgBody)
        );

    pMsgBody[-2] = (uchar)((pMsg-pMsgBody) >> 8);
    pMsgBody[-1] = (uchar)((pMsg-pMsgBody) >> 0);

    return (pMsg - pMsgBuff);
}

/******************************************************************************
* Function:     FinishedBlock
*
* Description:  Create 12 bytes TLS1.2 or 32 bytes TLS1.3 Finished Block data.
*
* Returns:      12: Size of finished block which is 12 bytes.
******************************************************************************/
uint TinyTls::FinishedBlock(uchar* pMsgBuff, bool isClient)
{
    const CIPHER& sha(m_cipherSet.sha256);
    if (isTls13()) {
        Hkdf hkdf(sha, isClient? m_eccClient : m_eccServer, TLS_SECRET_LEN, nullptr, 0);
        hkdf.ExpandLabel("finished", Hkdf::null_, 0, TLS_SECRET_LEN);
        HMac hmac(sha, hkdf, TLS_SECRET_LEN);
        DigestOut(pMsgBuff);
        hmac.hash(pMsgBuff, 32);
        memcpy(pMsgBuff, hmac, 32);
        return 32;
    } else {
        uchar finishedLabel[64];
        memcpy(finishedLabel, isClient ? "client finished" : "server finished", 15);
        m_cipherSet.sha256.Digest(&sha256Ctx, finishedLabel + 15);
        PrfHash prf(
            m_cipherSet.sha256,
            masterSecret,
            sizeof(masterSecret),
            finishedLabel, 15 + m_cipherSet.sha256.dSize);
        prf.Output(pMsgBuff, 12);
        return 12;
    }
}

/******************************************************************************
* Function:     CreateFinishedMsg
*
* Description:  Create the Client Finished or Server Finished message. It can
*               be used by both the client and server, depending on the flag.
*
* Returns:      Number of bytes of constructed message.
******************************************************************************/
uint TinyTls::CreateFinishedMsg(
    uchar*  pMsgBuff,
    uint    nBuffSize
    )
{
    uchar*  pMsg = pMsgBuff;
    Handshake handshake(*this, pMsg);

    //The start of the Finished Message
    *pMsg++ = MSG_FINISHED;
    *pMsg++ = 0x00; *pMsg++ = 0x00; *pMsg++ = 0x0C; // 3 bytes size.

    pMsg += pMsg[-1] = FinishedBlock(pMsg, m_bIsClient);

    //Go back to correct Finished Message Size
    handshake.data()[3] = u8(handshake.size() - 4);

    handshake.digestEncryptMac();
    return (pMsg - pMsgBuff);
}

/******************************************************************************
* Function:     VerifyPeerFinished
*
* Description:  Verify the peer (client/server) finished message is correct
*
* Returns:      Zero if message is correct.
******************************************************************************/
uint TinyTls::VerifyPeerFinished(
    const uchar*    pMsg,
    uint            cbLen
    )
{
    uchar   nMsgLen;
    uchar   finishedData[32];

    nMsgLen = FinishedBlock(finishedData, !m_bIsClient);
    return (nMsgLen ^ cbLen) | memcmp(pMsg, finishedData, (nMsgLen | cbLen));
}

uint TinyTls::CreateNewSessionTicketMsg(
    uchar*  pMsgBuff,
    uint    nBuffSize
)
{
    uchar*  pMsg = pMsgBuff;
    uint    nLen, nLifeSpan;
    TlsCBData cbData;

    cbData.cbType = TlsCBData::CB_NEW_SESSION_TICKET;
    cbData.data.ptrs[0] = cbData.data.ptrs[1] = cbData.data.ptrs[2] = nullptr;
    nLen = m_userCallBack(this->m_userContext, &cbData);
    if ((nLen == 0) || (cbData.data.ptrs[0] == nullptr)) return 0;  // No session ticket.

    // Otherwise proceed to create a session ticket message.
    Handshake handshake(*this, pMsg);

    nLifeSpan = static_cast<uint>(cbData.data.rawSize[1]);

    //Here starts the actual New Session Ticket Message
    nLen += 6;
    *pMsg++ = MSG_NEW_SESSION_TICKET;
    *pMsg++ = nLen>>16; *pMsg++ = nLen>>8; *pMsg++ = nLen;
    nLen -= 6;

    // Lifespan in seconds.
    *pMsg++ = nLifeSpan>>24; *pMsg++ = nLifeSpan>>16; *pMsg++ = nLifeSpan>>8; *pMsg++ = nLifeSpan;

    // New session ticket length
    *pMsg++ = nLen>>8; *pMsg++ = nLen;

    // The New Session Ticket ifself
    memcpy(pMsg, cbData.data.ptrs[0], nLen);
    pMsg += nLen;

    handshake.digestEncryptMac();

    return (pMsg - pMsgBuff);
}

/******************************************************************************
* Function:     ParseAppData
*
* Description:  Parse incoming network message that is CONTENT_APPLICATION_DATA.
*               since the data is not SSL handshake but application data to be
*               interpretted by application level code, we simply copy it over.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint TinyTls::ParseAppData(
    const uchar*    pMsg,
    uint            cbLen
    )
{
    uint nParsed = 0, off, chunk;
    while (cbLen) {
        off = nAppOutSize & (sizeof(appoutMsg) - 1);
        chunk = sizeof(appoutMsg) - off;
        if (chunk > cbLen) chunk = cbLen;
        if (chunk > sizeof(appoutMsg) + nAppOutRead - nAppOutSize) {
            if (0 == (chunk = sizeof(appoutMsg) + nAppOutRead - nAppOutSize)) break;
        }
        memcpy(appoutMsg + off, pMsg, chunk);
        pMsg += chunk; cbLen -= chunk;
        nAppOutSize += chunk;  nParsed += chunk;
    }

    return nParsed;
}

// RFC 8446 Section 7.1: https://tools.ietf.org/html/rfc8446#section-7.1
static const uchar zstr[TLS_SECRET_LEN] = {0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
static const char EXTERNAL_BINDER[]   = "ext binder";
static const char RESUMPTION_BINDER[] = "res binder";
static const char CLIENT_EARLY_TRAFFIC[]="c e traffic";
static const char EARLY_EXPORTER_MASTER[]="e exp master";
static const char S_DERIVED[]         = "derived";
static const char CLIENT_HS_TRAFFIC[] = "c hs traffic";
static const char SERVER_HS_TRAFFIC[] = "s hs traffic";
static const char CLIENT_AP_TRAFFIC[] = "c ap traffic";
static const char SERVER_AP_TRAFFIC[] = "s ap traffic";
static const char EXPORTER_MASTER[]   = "exp master";
static const char RESERVED_MASTER[]   = "res master";

static void CalcTrafficKey(const Hkdf& prk, uchar* pKey, uint keyLen, uchar* pIV, uint ivLen)
{
    Hkdf hkdf2(prk, nullptr, 0);   // client_handshake_traffic_secret
    hkdf2.ExpandLabel("key", zstr, 0, keyLen);  // Todo: determine key length.
    hkdf2.Output(pKey, keyLen);
    hkdf2.ExpandLabel("iv", zstr, 0, ivLen);  // Todo: determine key length.
    hkdf2.Output(pIV, ivLen);
}

void TinyTls::earlySecret(const uchar* pPsk, uint  nPskLen)
{
    //           0
    //           |
    //           v
    //  PSK -> HKDF-Extract = Early Secret
    Hkdf hkdf(m_cipherSet.sha256, pPsk, nPskLen, zstr, sizeof(zstr));
    if (pPsk && nPskLen) {
        //       |
        //       +----->Derive - Secret(., "ext binder" | "res binder", "")
        //       |                      = binder_key
        //       |
        //       +----->Derive - Secret(., "c e traffic", ClientHello)
        //       |                      = client_early_traffic_secret
        //       |
        //       +----->Derive - Secret(., "e exp master", ClientHello)
        //       |                      = early_exporter_master_secret
    }

    //           |
    //           v
    //     Derive-Secret(., "derived", "")
    hkdf.ExpandLabel(S_DERIVED, zstr, 0);
    hkdf.Output(m_Secret, TLS_SECRET_LEN);
}

void TinyTls::handshakeSecret()
{
    uchar hsDigest[TLS_SECRET_LEN];
    if (0) {
        static const uchar sPriKey[] = {
            0xb0, 0x58, 0x0e, 0xea, 0xdf, 0x6d, 0xd5, 0x89, 0xb8, 0xef, 0x4f, 0x2d, 0x56, 0x52, 0x57, 0x8c,
            0xc8, 0x10, 0xe9, 0x98, 0x01, 0x91, 0xec, 0x8d, 0x05, 0x83, 0x08, 0xce, 0xa2, 0x16, 0xa2, 0x5e };
        memcpy(m_eccServer, sPriKey, 32);
    }

    //           |
    //           v
    // (EC)DHE->HKDF-Extract = Handshake Secret
    DoECDH(hsDigest); Hkdf hkdf(m_cipherSet.sha256, m_Secret, TLS_SECRET_LEN, hsDigest, sizeof(hsDigest));
    //           |
    // At this point we can derive "c hs traffic", "s sh traffic" etc.
    {
        int keyLen = 16, ivLen = 12;

        switch (ePendingCipher) {
        case TLS_CHACHA20_POLY1305_SHA256:
            keyLen = 32; ivLen = 12; break;
        case TLS_AES_128_GCM_SHA256:
            keyLen = 16; ivLen = 12; break;
        case TLS_AES_256_GCM_SHA384:
            keyLen = 32; ivLen = 12; break;
        default:
            keyLen = 32; ivLen = 12; break;
        }
        DigestOut(hsDigest);

        //       |
        //       +----->Derive - Secret(., "c hs traffic",
        //       |                      ClientHello...ServerHello)
        //       |                      = client_handshake_traffic_secret
        hkdf.ExpandLabel(CLIENT_HS_TRAFFIC, hsDigest, sizeof(hsDigest), TLS_SECRET_LEN);

        // Derive the client handshake key from client_handshake_traffic_secret
        CalcTrafficKey(hkdf, clientWriteKey, keyLen, clientIV, ivLen);

        // Save a copy of the client handshake traffic secret, which is base key.
        hkdf.Output(m_eccClient, sizeof(m_eccClient));

        memset(clientAAD, 0, sizeof(clientAAD));
        clientAAD[9] = SSL_VERSION_MAJOR;
        clientAAD[10] = SSL_VERSION_MINOR3;
        eClientCipher = ePendingCipher;

        //       |
        //       +----->Derive - Secret(., "s hs traffic",
        //       |                      ClientHello...ServerHello)
        //       |                      = server_handshake_traffic_secret
        hkdf.ExpandLabel(SERVER_HS_TRAFFIC, hsDigest, sizeof(hsDigest), TLS_SECRET_LEN);

        // Derive the server handshake key from server_handshake_traffic_secret
        CalcTrafficKey(hkdf, serverWriteKey, keyLen, serverIV, ivLen);

        // Save a copy of the server handshake traffic secret, which is base key.
        hkdf.Output(m_eccServer, sizeof(m_eccServer));

        memset(serverAAD, 0, sizeof(serverAAD));
        serverAAD[9] = SSL_VERSION_MAJOR;
        serverAAD[10] = SSL_VERSION_MINOR3;
        eServerCipher = ePendingCipher;
    }

    //           |
    //           v
    //     Derive-Secret(., "derived", "")
    hkdf.ExpandLabel(S_DERIVED, zstr, 0);
    hkdf.Output(m_Secret, TLS_SECRET_LEN);
}

void TinyTls::mainSecret()
{
    uchar hsDigest[TLS_SECRET_LEN]; DigestOut(hsDigest);
    //           |
    //           v
    //  0 -> HKDF-Extract = Master Secret
    Hkdf hkdf(m_cipherSet.sha256, m_Secret, TLS_SECRET_LEN, zstr, sizeof(zstr));
    hkdf.Output(m_Secret, TLS_SECRET_LEN);

    // At this point we can derive "c ap traffic", "s ap traffic" etc.
    {
        int keyLen = 16, ivLen = 12;

        switch (ePendingCipher) {
        case TLS_CHACHA20_POLY1305_SHA256:
            keyLen = 32; ivLen = 12; break;
        case TLS_AES_128_GCM_SHA256:
            keyLen = 16; ivLen = 12; break;
        case TLS_AES_256_GCM_SHA384:
            keyLen = 32; ivLen = 12; break;
        default:
            keyLen = 32; ivLen = 12; break;
        }

        //       |
        //       +----->Derive - Secret(., "c ap traffic",
        //       |                      ClientHello...server Finished)
        //       |                      = client_application_traffic_secret_0

        // Derive the client application key from client_application_traffic_secret
        hkdf.ExpandLabel(CLIENT_AP_TRAFFIC, hsDigest, sizeof(hsDigest), TLS_SECRET_LEN);
        // For both client and server, client application traffic key must be calculated
        // after the client finished message. So cannot do it here. Save secret for later.
        hkdf.Output(m_Secret, TLS_SECRET_LEN);

        //       |
        //       +----->Derive - Secret(., "s ap traffic",
        //       |                      ClientHello...server Finished)
        //       |                      = server_application_traffic_secret_0
        hkdf.ExpandLabel(SERVER_AP_TRAFFIC, hsDigest, sizeof(hsDigest), TLS_SECRET_LEN);

        // Derive the server handshake key from server_handshake_traffic_secret
        CalcTrafficKey(hkdf, serverWriteKey, keyLen, serverIV, ivLen);
        memset(serverAAD, 0, 8); // Reset sequence number
        // Save a copy of the server application traffic secret for later usage.
        hkdf.Output(m_eccServer, sizeof(m_eccServer));

        //       |
        //       +----->Derive - Secret(., "exp master",
        //       |                      ClientHello...server Finished)
        //       |                      = exporter_master_secret
        //       |
        //       +----->Derive - Secret(., "res master",
        //                              ClientHello...client Finished)
        //                              = resumption_master_secret
    }
}

// For TLS1.3 only. The client App key must be set a bit later after mainSecret.
void TinyTls::setClientKey()
{
    int keyLen = 16, ivLen = 12;

    switch (ePendingCipher) {
    case TLS_CHACHA20_POLY1305_SHA256:
        keyLen = 32; ivLen = 12; break;
    case TLS_AES_128_GCM_SHA256:
        keyLen = 16; ivLen = 12; break;
    case TLS_AES_256_GCM_SHA384:
        keyLen = 32; ivLen = 12; break;
    default:
        keyLen = 32; ivLen = 12; break;
    }
    Hkdf hkdf(m_cipherSet.sha256, m_Secret, TLS_SECRET_LEN, nullptr, 0);   // client_application_traffic_secret
    CalcTrafficKey(hkdf, clientWriteKey, keyLen, clientIV, ivLen);
    memset(clientAAD, 0, 8);
    // Save a copy of the client application traffic secret for later usage.
    hkdf.Output(m_eccClient, sizeof(m_eccClient));
}

// https://tools.ietf.org/html/rfc8446#section-4.4.3
uint TinyTls::CreateCertContext(bool isClient, const uchar* pCert, uchar* pMsg)
{
    static const char l1[]{ "TLS 1.3, " };
    static const char l2[]{ " CertificateVerify" };
    static const char ls[]{ "server" };
    static const char lc[]{ "client" };

    const uchar* p0 = pMsg;
    const char* p = l1;
    for (int i = 0; i < 64; i++) *pMsg++ = 0x20;
    for (p = l1; (*p); ) *pMsg++ = *p++;
    for (p = isClient?lc:ls; (*p); ) *pMsg++ = *p++;
    for (p = l2; (*p); ) *pMsg++ = *p++;
    *pMsg++ = 0x00;

    CIPHER sha(m_cipherSet.sha256);
    CTX ctx(sha256Ctx);

    // Some how the certificate does not need to be part of hash?
    //sha.Input(&ctx, pCert, CERT_SIZE(pCert));

    sha.Digest(&ctx, pMsg);
    pMsg += sha.dSize;

    return (pMsg - p0);
}

void TinyTls::NewEccKey()
{
    uchar* pEccKey = m_bIsClient? m_eccClient : m_eccServer;
    for (int i = 0; i < 8; i++) ((uint*)pEccKey)[i] = gfRandom();
    pEccKey[31] &= 0x7F; // Clear high bit to make good for X25519
    pEccKey[31] |= 0x40; pEccKey[0] &= 0xF8; // RFC 7748 Sec.
    // What's good for X25519 is also good for P256r1.
}

uint TinyTls::PubEccKey(uchar* pMsg, uint eccGroup) const
{
    NN secretKey; secretKey.bytesIn(m_bIsClient? m_eccClient : m_eccServer);

    if (eccGroup == ECC_x25519) {
        // Directly output client ECC public key to ClientKeyExchangeMsg.
        X25519::G gBase(9); gBase.PointMult(pMsg, secretKey);
    } else if (eccGroup == ECC_secp256r1) {
        // Directly output client ECC public key to ClientKeyExchangeMsg.
        P256::G gBase; gBase.PointMult(pMsg, secretKey);
    } else {
        assert(0); // Error not supported ECC group.
    }
    return sizeof(m_eccClient);
}

/******************************************************************************
* Function:     DoECDH
*
* Description:  Calculate PreMaster secret based on ECC Diffie Hellman.
*
* Returns:      None.
******************************************************************************/
void TinyTls::DoECDH(uchar* dhSecret) const
{
    const uchar* pSecKey = m_bIsClient? m_eccClient : m_eccServer;
    const uchar* pPeerKey = m_bIsClient ? m_eccServer : m_eccClient;
    if (m_eccGroup == ECC_x25519) {
        NN secretKey; secretKey.bytesIn(pSecKey);
        X25519::G gBase; gBase.bytesIn(pPeerKey);
        gBase.PointMult(dhSecret, secretKey);
    } else if (m_eccGroup == ECC_secp256r1) {
        NN secretKey; secretKey.bytesIn(pSecKey);
        P256::G gBase; gBase.bytesIn(pPeerKey);
        gBase.PointMult(dhSecret, secretKey);
    } else {
        assert(0);
    }
}

/******************************************************************************
* Function:     CalculateMasterSecret
*
* Description:  Calculate Master secret using TLS 1.2
*
* Returns:      None.
******************************************************************************/
void TinyTls::CalcMasterSecret()
{
    uint seedLen = 0;
    uchar seedLabel[80];
    // https://tools.ietf.org/html/rfc7627#page-6
    if (m_attrs & ATT_extended_master_secret) {
        static const uchar TLS_MD_EXTENDED_MASTER_SECRET[22] = {
            0x65, 0x78, 0x74, 0x65, 0x6E, 0x64, 0x65, 0x64, 0x20, 0x6D, 0x61,
            0x73, 0x74, 0x65, 0x72, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74 };
        uchar digest[32]; m_cipherSet.sha256.Digest(&sha256Ctx, digest);
        memcpy(seedLabel, TLS_MD_EXTENDED_MASTER_SECRET, seedLen = sizeof(TLS_MD_EXTENDED_MASTER_SECRET));
        memcpy(seedLabel + seedLen, digest, sizeof(digest));
        seedLen += sizeof(digest);
    } else {
        static const uchar TLS_MD_MASTER_SECRET[15] = {
            0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74 };
        memcpy(seedLabel, TLS_MD_MASTER_SECRET, seedLen = sizeof(TLS_MD_MASTER_SECRET));
        memcpy(seedLabel + seedLen, clientRandom, sizeof(clientRandom));
        seedLen += sizeof(clientRandom);
        memcpy(seedLabel + seedLen, serverRandom, sizeof(serverRandom));
        seedLen += sizeof(serverRandom);
    } 

    PrfHash prf(m_cipherSet.sha256, preMasterSecret, nPreMasterSize, seedLabel, seedLen);
    prf.Output(masterSecret, sizeof(masterSecret));

    clientSequenceL = 0;
    clientSequenceH = 0;
}

void TinyTls::ChangeCipherSpec(bool isForClient)
{
    // Calculate key block data from Master Secret
    int keyLen = 16, ivLen = 4;

    switch (ePendingCipher) {
    case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
    case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        keyLen = 32; ivLen = 12; break;
    case TLS_RSA_WITH_AES_128_GCM_SHA256:
    case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
    case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        keyLen = 16; ivLen = 4; break;
    default:
        keyLen = 16; ivLen = 4; break;
    }

    if (isForClient) {
        static const uchar magicLabel[13]{ 0x6B, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70, 0x61, 0x6E, 0x73, 0x69, 0x6F, 0x6E };
        uchar newLabel[80]; // magicLabel = "key expansion" https://tools.ietf.org/html/rfc5246#section-6.3
        memcpy(newLabel, magicLabel, sizeof(magicLabel));
        memcpy(newLabel + sizeof(magicLabel), serverRandom, sizeof(serverRandom));
        memcpy(newLabel + sizeof(magicLabel) + sizeof(serverRandom), clientRandom, sizeof(clientRandom));

        memset(clientIV, 0, sizeof(clientIV));
        memset(serverIV, 0, sizeof(serverIV));

        PrfHash prf(m_cipherSet.sha256, masterSecret, sizeof(masterSecret), newLabel, sizeof(magicLabel) + 64);
        prf.Output(clientWriteKey, keyLen);
        prf.Output(serverWriteKey, keyLen);
        prf.Output(clientIV, ivLen);
        prf.Output(serverIV, ivLen);

        memset(clientAAD, 0, sizeof(clientAAD));
        clientAAD[9] = SSL_VERSION_MAJOR;
        clientAAD[10] = SSL_VERSION_MINOR3;

        if (ivLen == 4) {
            // Get 8 bytes of random nounce for client IV.
            ((uint*)(clientIV + 4))[0] = gfRandom();
            ((uint*)(clientIV + 4))[1] = gfRandom();
        }

        eClientCipher = ePendingCipher;
    } else {
        memset(serverAAD, 0, sizeof(serverAAD));
        serverAAD[9] = SSL_VERSION_MAJOR;
        serverAAD[10] = SSL_VERSION_MINOR3;

        if (ivLen == 4) {
            // Get 8 bytes of random nounce for server IV.
            ((uint*)(serverIV + 4))[0] = gfRandom();
            ((uint*)(serverIV + 4))[1] = gfRandom();
        }

        eServerCipher = ePendingCipher;
    }
}
