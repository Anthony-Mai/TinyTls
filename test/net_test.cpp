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
*  File Name:       net_test.cpp
*
*  Description:     Run TLS client and server test on the real network.
*
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         10/08/2018 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef __linux__
#include <unistd.h>
#include <pthread.h>
#include <sys/select.h>
#include <errno.h>
#endif //__linux__

#include "net_test.h"


#include "TlsFactory.h"
#include "TinyTls.h"
#include "cipher.h"

#include "cert.h"
#include "certSamples.h"

#include "ecc_x25519.h"

#include "TcpSockLinux.h"

#define SOCKET_ERROR (-1)

extern uint32_t getIp(const char* hostname);

static int do_socketTest();
static int do_connectTest();

bool IsReadable(SOCKET sock)
{
    timeval timeout{ 0, 0 };
	// This is defined similar to fd_set but with only one fd element.
    struct my_fd {
        uint   fd_count;
        SOCKET fd_sock;
    } rd{ 1, sock}, wd(rd), ed(wd);

    int ret = select(1, (fd_set*)&rd, (fd_set*)&wd, (fd_set*)&ed, &timeout);

    switch (ret)
    {
    case 0:
        break;
    case SOCKET_ERROR:
        close(sock);
        break;
    default:
        if (rd.fd_count)
        {
            return true;
        }
        break;
    }

    return false;
}

class MyAppContext {
    const CIPHERSET& cset_;
public:
    const char* server_name_;

    MyAppContext(const CIPHERSET& cset) : cset_(cset), server_name_(nullptr) {}
};

static unsigned int ClientCallback(void* pUserContext, TlsCBData* pCBData)
{
    MyAppContext& appCtx(*reinterpret_cast<MyAppContext*>(pUserContext));

    unsigned int ret = 0;
    switch (pCBData->cbType) {
    case TlsCBData::CB_RANDOM:
        //memcpy(pCBData->data.ptrs[0], c_clientRandom, 32); break;
        ret = 0; break; // We could modify the 32 bytes client Random but do not.
    case TlsCBData::CB_SERVER_NAME:
        pCBData->data.ptrs[0] = (void*)appCtx.server_name_;
        ret = pCBData->data.rawSize[1] = strlen((const char*)pCBData->data.ptrs[0]);
        break;
    case TlsCBData::CB_CLIENT_CIPHER:
        pCBData->data.rawInt[0] = TLS_AES_128_GCM_SHA256;
        pCBData->data.rawInt[1] = TLS_CHACHA20_POLY1305_SHA256;
        //pCBData->data.rawInt[2] = TLS_AES_256_GCM_SHA384;
        pCBData->data.rawInt[2] = 0;
        ret = 3; // Only 3 ciphers supported.
        break;
    case TlsCBData::CB_SUPPORTED_GROUPS:
        pCBData->data.rawInt[0] = ECC_x25519; // Supported Group: x25519 (0x001d)
        pCBData->data.rawInt[1] = ECC_secp256r1; // Supported Group: secp256r1(0x0017)
        //pCBData->data.rawInt[2] = ECC_secp384r1; // Supported Group: secp384r1 (0x0018)
        //pCBData->data.rawInt[3] = ECC_secp521r1; // Supported Group: secp521r1 (0x0019)
        //pCBData->data.rawInt[4] = ECC_ffdhe2048; // Supported Group: ffdhe2048 (0x0100) RFC7919
        //pCBData->data.rawInt[5] = ECC_ffdhe3072; // Supported Group: ffdhe3072 (0x0101) RFC7919
        //pCBData->data.rawInt[6] = ECC_ffdhe4096; // Supported Group: ffdhe4096 (0x0102) RFC7919
        //pCBData->data.rawInt[7] = ECC_ffdhe6144; // Supported Group: ffdhe6144 (0x0103) RFC7919
        //pCBData->data.rawInt[8] = ECC_ffdhe8192; // Supported Group: ffdhe8192 (0x0104) RFC7919
        ret = 2; // Only 9 entries of supported ECC groups
        break;
    case TlsCBData::CB_SESSIONTICKET_TLS:
        ret = 0; break;
    case  TlsCBData::CB_PSK_INFO:
        ret = 0; break;
    case TlsCBData::CB_ECDHE_PRIVATEKEY: {
        // pCBData->data.ptrs[0] is the ephemeral ECC private key
        // pCBData->data.rawSize[1] is the ECC_GROUP which should also be returned.
        static const uchar c_privKey[32] = { // https://tools.ietf.org/html/rfc8448#section-3
            0x49, 0xaf, 0x42, 0xba, 0x7f, 0x79, 0x94, 0x85, 0x2d, 0x71, 0x3e, 0xf2, 0x78, 0x4b, 0xcb, 0xca,
            0xa7, 0x91, 0x1d, 0xe2, 0x6a, 0xdc, 0x56, 0x42, 0xcb, 0x63, 0x45, 0x40, 0xe7, 0xea, 0x50, 0x05};
        memcpy(pCBData->data.ptrs[0], c_privKey, sizeof(c_privKey));
        ret = pCBData->data.rawSize[1] = ECC_x25519;
        break; }
    case TlsCBData::CB_SIGNATURE_ALGORITHM:
        // https://tools.ietf.org/html/rfc8448#section-3
        pCBData->data.rawInt[0] = ecdsa_secp256r1_sha256; // Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
        //pCBData->data.rawInt[1] = ecdsa_secp384r1_sha384; // Signature Algorithm: ecdsa_secp384r1_sha384 (0x0503)
        //pCBData->data.rawInt[2] = ecdsa_secp521r1_sha512; // Signature Algorithm: ecdsa_secp521r1_sha512 (0x0603)
        //pCBData->data.rawInt[3] = ecdsa_sha1;             // Signature Algorithm: ecdsa_sha1 (0x0203)
        pCBData->data.rawInt[1] = rsa_pss_rsae_sha256;    // Signature Algorithm: rsa_pss_rsae_sha256 (0x0804)
        //pCBData->data.rawInt[5] = rsa_pss_rsae_sha384;    // Signature Algorithm: rsa_pss_rsae_sha384 (0x0805)
        //pCBData->data.rawInt[6] = rsa_pss_rsae_sha512;    // Signature Algorithm: rsa_pss_rsae_sha512 (0x0806)
        pCBData->data.rawInt[2] = rsa_pkcs1_sha256;       // Signature Algorithm: rsa_pkcs1_sha256 (0x0401)
        //pCBData->data.rawInt[8] = rsa_pkcs1_sha384;       // Signature Algorithm: rsa_pkcs1_sha384 (0x0501)
        //pCBData->data.rawInt[9] = rsa_pkcs1_sha512;       // Signature Algorithm: rsa_pkcs1_sha512 (0x0601)
        pCBData->data.rawInt[3] = rsa_pkcs1_sha1;        // Signature Algorithm: rsa_pkcs1_sha1 (0x0201)
        //pCBData->data.rawInt[11] = SHA256_DSA;            // Signature Algorithm: SHA256 DSA (0x0402)
        //pCBData->data.rawInt[12] = SHA384_DSA;            // Signature Algorithm: SHA384 DSA (0x0502)
        //pCBData->data.rawInt[13] = SHA512_DSA;            // Signature Algorithm: SHA512 DSA (0x0602)
        //pCBData->data.rawInt[14] = SHA1_DSA;              // Signature Algorithm: SHA1 DSA (0x0202)
        ret = 4; break;
    case TlsCBData::CB_CERTIFICATE_ALERT: { // Client receives questionable server certificate.
        const CERT* pCert = reinterpret_cast<const CERT*>(pCBData->data.ptrs[0]);
        CERT_STATUS eStatus = (CERT_STATUS)reinterpret_cast<size_t>(pCBData->data.ptrs[1]);
        // See CERT_STATUS defined in cert.h for meaning of its bits. For purpose of test
        // we accept self-signed cert. In real production self signed certificate should be rejected.
        if ((eStatus & CS_BAD) == 0 && ((eStatus & CS_OK) || ((eStatus & CS_SELF)))) {
            ret = 1; // Return 1 is accept the certificate. 0 is to reject it and abort connection.
        }
        break; }

    default:
        break;
    }

    return ret;
}

static unsigned int ServerCallback(void* pUserContext, TlsCBData* pCBData)
{
    MyAppContext& appCtx(*reinterpret_cast<MyAppContext*>(pUserContext));

    static const char MyHostName[]{"blockchain.server.com"};

    // This is ServerCallback
    unsigned int ret = 0;
    switch (pCBData->cbType) {
    case TlsCBData::CB_SERVER_NAME: {
        const uchar* p = (const uchar*)pCBData->data.ptrs[0];
        uint32_t slen = pCBData->data.rawSize[1];
        ret = 0;
        }
        break;
    case TlsCBData::CB_RANDOM:
        // We could obtain or modify 32 bytes server random from pCBData->data.ptrs[0].
        break;

    case TlsCBData::CB_SERVER_CIPHER:
        if (pCBData->data.rawInt[1] == TLS_AES_128_GCM_SHA256) {
            pCBData->data.rawInt[1] = pCBData->data.rawInt[0];
            pCBData->data.rawInt[0] = TLS_AES_128_GCM_SHA256;
        }
        break;

    case TlsCBData::CB_SUPPORTED_GROUPS:
        pCBData->data.rawInt[0] = ECC_x25519;    // Supported Group: x25519 (0x001d)
        pCBData->data.rawInt[1] = ECC_secp256r1; // Supported Group: secp256r1(0x0017)
        pCBData->data.rawInt[2] = 0; ret = 2; break; // Only 2 supported ECC groups

    case TlsCBData::CB_SERVER_CERTS:
        pCBData->data.ptrs[0] = (void*)gServerCert1;
        pCBData->data.ptrs[1] = nullptr; // After last one, the pointer is set to nullptr to end.
        break;

    case TlsCBData::CB_SERVER_KEYPAIR:
        pCBData->data.ptrs[0] = (void*)gServerPub1;
        pCBData->data.ptrs[1] = (void*)gServerPri1;
        pCBData->data.ptrs[2] = (void*)gServerCert1;
        pCBData->data.rawSize[3] = ECC_secp256r1; // The key uses ECDSA P256
        pCBData->data.ptrs[4] = nullptr;
        ret = ECC_secp256r1;
        break;
    case TlsCBData::CB_ECDHE_PUBLICKEY:
        break;

    case TlsCBData::CB_ECDHE_PRIVATEKEY: {
        // pCBData->data.ptrs[0] is the ephemeral ECC private key
        // pCBData->data.rawSize[1] is the ECC_GROUP which should also be returned.
        ret = 0; // We do not want to modify the ephemeral key generated.
        break; }

    case TlsCBData::CB_SESSIONTICKET_TLS:
        ret = 0;  break;

    case TlsCBData::CB_NEW_SESSION_TICKET:
        ret = 0; break;
    }

    return ret;
}

void* NetClientThread(void* pParam)
{
#define SERVER_NAME "www.google.com" // This works as of 06/20/2023
//#define SERVER_NAME "www.cnn.com" // This does not appear to be working
//#define SERVER_NAME "www.cloudflare.com" // This works as of 06/20/2023
    static const char httpRequestMsg[] =
        "GET / HTTP/1.1\r\n"
        "User-Agent: TinyTls\r\n"
        //"Host: www.google.com\r\n"
        //"Host: www.cnn.com\r\n"
        //"Host: cloudflare.com\r\n"
        "\r\n";

    uint ip = 0, it = 0;
    CIPHERSET cipherSet;
    MyAppContext appCtx(cipherSet);

    InitCiphers(&cipherSet);

    appCtx.server_name_ = SERVER_NAME;

    ip = getIp(appCtx.server_name_);

    printf("IP of %s is %08X\n", appCtx.server_name_, ip);

    TcpSockLinux cSock(ip, 443);

    while (!cSock.Connected()) {
        usleep(5000);
    }
    printf("Socket connected\n");

    BaseTls* mySsl = CreateTls(*((TcpSock*)&cSock), cipherSet, 0, true, ClientCallback, &appCtx);
    uchar inMsg[4096];
    uchar outMsg[4096];

    printf("Tls created %p\n", mySsl);

    SSL_STATE eLast = (SSL_STATE)0;

    while (!cSock.Connected()) {
        if (cSock.GetSock() == HSock(nullptr)) break;
        usleep(5000); continue;
    }

    for ( ; cSock.GetSock(); ) {
        uint len = 0, len1, len2, len3;
        SSL_STATE eState = mySsl->State();
        if (eState != eLast) {
            eLast = eState;
        }
        if (eState == SSLSTATE_DISCONNECTING) {
            //cSock.Close();
            eState = SSLSTATE_DISCONNECTED;
        } else if (eState == SSLSTATE_CONNECTED) {
            it ++;
        }
        if (it == 1) {
            printf("TLS connected\n");
        }
        mySsl->Work(0, eState);
        if (eState == SSLSTATE_UNCONNECTED) {
            printf("Unconnect. Breaking\n");
            break;
        }
        if (eState != SSLSTATE_CONNECTED) {
          continue;
        }

        if (++it == 1) {
            printf("TLS connected\n");
        }

        if (it == 2) {
            len = mySsl->Write((const uchar*)httpRequestMsg, strlen(httpRequestMsg));
            printf("Send %d bytes:\n", len);
        }

        if (it == 12) {
            if (eState == SSLSTATE_CONNECTED) eState = SSLSTATE_DISCONNECT;
            else eState = SSLSTATE_UNCONNECTED;
            break;
        }

        len = mySsl->Read(inMsg, sizeof(inMsg));
        inMsg[len] = 0x00;
        if (len) {
            printf("Read incoming message %d bytes:\n%s", len, inMsg);
            //len1 = strlen(sPage);
            //sprintf((char*)outMsg, "HTTP/1.0 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: %d\r\n\r\n%s", len1, sPage);
            //len2 = strlen((const char*)outMsg);
            //len3 = mySsl->Write(outMsg, len2);
            //printf("Send %d(=%d) bytes:\n%s\n", len3, len2, outMsg);
        }

        usleep(200000);
    }

    printf("NetClientThread done\n");
    *((uint*)pParam) = 1;
    return nullptr;
}

void* NetServerThread(void* pParam)
{
    static const int LISTEN_PORT = 443;
    HSock sock = TcpSockLinux::CreateListenSock(LISTEN_PORT);
    TcpSockLinux tcpListen(sock);
    int     nRecv = 0;
    CIPHERSET cipherSet;

    InitCiphers(&cipherSet);

    if (!tcpListen.GetSock()) {
        printf("Failed to create listen socket. Maybe try sudo?\n");
    }

    for (; tcpListen.GetSock();) {
        printf("TLS Server Listening on port %d\n", LISTEN_PORT);
        while (!tcpListen.Incoming())
        {
            usleep(5000);
        }

        TcpSockLinux tcpSock;

        tcpSock.Accept((const TcpSock&)tcpListen);

        BaseTls* mySsl = CreateTls(*((TcpSock*)&tcpSock), cipherSet, 0, false, ServerCallback, NULL);

        usleep(100000);

        for (;;)
        {
            uchar inMsg[4096];
            uchar outMsg[4096];
            static const char sPage[] = "<html>\r\n<body>\r\n<title>Anthony Mai Secure Web</title>\r\n<h1>Anthony Mai Secure Web</h1><br>\r\n<body>\r\n</html>\r\n";
            uint len = 0, len1, len2, len3;
            SSL_STATE eState = mySsl->State();
            if (eState == SSLSTATE_DISCONNECTING) {
                tcpSock.Closed();
                eState = SSLSTATE_DISCONNECTED;
            }
            mySsl->Work(0, eState);
            len = mySsl->Read(inMsg, sizeof(inMsg));
            inMsg[len] = 0x00;
            if (len) {
                printf("Read incoming message %d bytes:\n%s", len, inMsg);
                len1 = strlen(sPage);
                sprintf((char*)outMsg, "HTTP/1.0 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: %d\r\n\r\n%s", len1, sPage);
                len2 = strlen((const char*)outMsg);
                len3 = mySsl->Write(outMsg, len2);
                printf("Send %d(=%d) bytes:\n%s\n", len3, len2, outMsg);
            }

            if (eState == SSLSTATE_UNCONNECTED) break;

            usleep(100000);
        }
    }

    printf("NetServerThread done\n");
    *((uint*)pParam) = 1;
    return nullptr;
}

int do_clientTest()
{
    int r = 0;

    // Start a client thread
    pthread_t threadId = 0;
    uint nThreadDone = 0;
    if (pthread_create(&threadId, nullptr, NetClientThread, &nThreadDone)) {
        printf("Failed to create client pthread\n"); return -1;
    }
    while (!nThreadDone)
    {
        usleep(5000);
    }
    return 0;
}


int do_serverTest()
{
    int r = 0; //do_socketTest();
    //r |= do_clientTest(); // If we want, do another client test here.
    //r |= do_connectTest();

    printf("Now start a TLS server thread for test\n");

    pthread_t threadId = 0;
    uint nThreadDone = 0;
    if (pthread_create(&threadId, nullptr, NetServerThread, &nThreadDone)) {
        printf("Failed to create pthread\n"); return -1;
    }
    while (!nThreadDone)
    {
        usleep(5000);
    }
    return 0;
}


int do_socketTest()
{
    printf("Do basic socket test\n");
    HSock sock = TcpSockLinux::CreateListenSock(443);

    if (sock) printf("Listen socket created successfully\n");
    else printf("Listen socket created UNSUCCESSFULLY\n");

    TcpSockLinux tcpListen(sock);

    printf("Now listening\n");

    int     nRecv = 0, nSend = 0;
    uchar buff[4096];

    for (;;) {
        nRecv = 0;
        while (!tcpListen.Incoming())
        {
            printf(".");
            usleep(500000);
        }

        printf("Incming connection detected\n");

        TcpSockLinux tcpSock;

        tcpSock.Accept((const TcpSock&)tcpListen);

        for ( ;nRecv>= 0; ) {
            nRecv = tcpSock.Recv(buff, sizeof(buff));
            if (nRecv > 0) {
                printf("Received %d bytes\n", nRecv);
            } else if (nRecv < 0) {
                printf("Error happened\n"); break;
            } else {
                printf(" errno = %d ", errno);
                if (errno) break;
            }

            if (nRecv > 0) {
                nSend = tcpSock.Send(buff, nRecv);
                printf("Send %d bytes\n", nSend);
                nRecv = 0;
            }
             
            usleep(5000);

        }
        usleep(5000);

    }

    printf("Basic socket test done\n");

    return 0;
}

int do_connectTest()
{
    static const char* domainToConnect = "www.google.com";
    uint ip = getIp(domainToConnect);
    printf("IP of %s is %08X\n", domainToConnect, ip);

    TcpSockLinux mySock(ip, 443);

    printf("Successfully connected to %s\n", domainToConnect);
    return 0;
}


