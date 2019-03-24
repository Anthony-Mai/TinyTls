#ifndef _BASESSL_H_INCLUDED_10_28_2017_
#define _BASESSL_H_INCLUDED_10_28_2017_

class TcpSock;
struct CIPHERSET;

typedef enum
{
    SSLSTATE_RESET              = 0,    //Reset everything and then go to SSLSTATE_INITIALIZED.
    SSLSTATE_INITIALIZED        = 1,    //Just initialized. Nothing happened yet.
    SSLSTATE_UNCONNECTED        = 2,    //The "RESET" state after a successful or failed connection.
    SSLSTATE_TCPCONNECTED       = 3,    //Application tells us TCP connected. This triggers handshake.
    SSLSTATE_HANDSHAKE_BEGIN    = 4,    //Initialize HandShake & goto SSLSTATE_CLIENT_HELLO

    SSLSTATE_HELLO_REQUEST      = 7,    //Initiate a server hello request message
    SSLSTATE_CLIENT_HELLO       = 8,    //Send out ClientHello & goto SSLSTATE_SERVER_HELLO
    SSLSTATE_CLIENT_CERTREQUEST = 9,    //Server can set nInXData = non-zero to request client certificate.

    SSLSTATE_HANDSHAKE_SECRET   =10,    //We are ready to computer TLS1.3 handshake secret.
    SSLSTATE_ENCRYPTED_EXTENSIONS=11,   //Server sends encrypted extensions then go to SSLSTATE_SERVER_CERTIFICATE
    SSLSTATE_SERVER_CERT_VERIFY =12,    // Server to send a certificate verify message and client to verify it.

    SSLSTATE_SERVER_HELLO       =16,    //Wait ServerHello, if reuse SessionID, goto SSLSTATE_SERVER_FINISH1, else goto SSLSTATE_SERVER_HELLO_DONE
    SSLSTATE_SERVER_CERTIFICATE =17,    //Wait Server Certificate, then go to SSLSTATE_SERVER_KEYEXCHANGE or SSLSTATE_SERVER_HELLO_DONE
    SSLSTATE_SERVER_CERTREQUEST =18,    //Certificate request received from server, Wait ServerHelloDone & goto SSLSTATE_CERTIFICATE_REQUEST
    SSLSTATE_SERVER_HELLO_DONE  =19,    //Wait ServerHelloDone & goto SSLSTATE_CERTIFICATE_VERIFY.

    SSLSTATE_CERTIFICATE_REQUEST =20,   //Server asked the client to supply a certificate. Go to SSLSTATE_CERTIFICATE_REQUESTING to tell application.
    SSLSTATE_CERTIFICATE_REQUESTING=21, //Application asked to supply a client certificate and goto SSLSTATE_CERTIFICATE_SUPPLIED, or fall to SSLSTATE_CERTIFICATE_NOTGIVEN
    SSLSTATE_CERTIFICATE_NOTGIVEN=22,   //In SSLSTATE_CERTIFICATE_REQUESTING, App fails to give us certificate. Goto SSLSTATE_ABORTING.
    SSLSTATE_CERTIFICATE_SUPPLIED=23,   //In SSLSTATE_CERTIFICATE_REQUESTING, App supplied it and set SSLSTATE_CERTIFICATE_SUPPLIED. Go to SSLSTATE_CERTIFICATE_VERIFY

    SSLSTATE_CERTIFICATE_VERIFY = 24,   //Verify server certificate and goto SSLSTATE_CERTIFICATE_VERIFIED
    SSLSTATE_CERTIFICATE_VERIFIED=25,   //Certificate verified. Go to SSLSTATE_CLIENT_KEYEXCHANGE.
    SSLSTATE_CERTIFICATE_ACCEPTING=26,  //Wait for application to accept questionable certificate. nOutXData carries the HCERT. Default goes to SSLSTATE_CERTIFICATE_REJECTED
    SSLSTATE_CERTIFICATE_REJECTED=27,   //Bad certificate rejected. Goto SSLSTATE_ABORTING.
    SSLSTATE_CERTIFICATE_EXPIRED= 28,   //Certificate expired. Goto SSLSTATE_ABORTING.
    SSLSTATE_CERTIFICATE_ACCEPTED=29,   //Certificate accepted by App, goto SSLSTATE_CLIENT_KEYEXCHANGE, or SSLSTATE_CLIENT_CERTIFICATE first

    SSLSTATE_CLIENT_CERTIFICATE = 32,   //Send the client certificate message to server and go to SSLSTATE_CLIENT_KEYEXCHANGE
    SSLSTATE_CLIENT_KEYEXCHANGE = 33,   //Send ClientKeyExchange & goto SSLSTATE_CLIENT_FINISH1, or SSLSTATE_CLIENT_VALIDATE first
    SSLSTATE_CLIENT_VALIDATE    = 34,   //Send Client certificate verify message & goto SSLSTATE_CLIENT_FINISH1
    SSLSTATE_SERVER_KEYEXCHANGE = 35,   //Send ServerKeyExchange & goto SSLSTATE_SERVER_HELLO_DONE, or SSLSTATE_CLIENT_VALIDATE first

    SSLSTATE_SERVER_FINISH1     = 40,   //Wait for ServerFinish & goto SSLSTATE_CLIENT_FINISH2.
    SSLSTATE_CLIENT_FINISH1     = 41,   //Send ChangeCipher, Finish & goto SSLSTATE_SERVER_FINISH2
    SSLSTATE_CLIENT_FINISH2     = 42,   //Send ChangeCipher, Finish & goto SSLSTATE_HANDSHAKE_DONE
    SSLSTATE_SERVER_FINISH2     = 43,   //Wait for ServerFinish & goto SSLSTATE_HANDSHAKE_DONE.
    SSLSTATE_HANDSHAKE_DONE     = 48,   //Verify every thing OK & goto SSLSTATE_CONNECTED, else

    SSLSTATE_CONNECTED          = 64,   //We can now exchange application data encrypted.
    SSLSTATE_DISCONNECT         = 66,   //App tells us to initiate a disconnect sequence.
    SSLSTATE_DISCONNECTING      = 67,   //We were told by the server to disconnect. Tell App to disconnect
    SSLSTATE_DISCONNECTED       = 68,   //App tells us TCP disconnected. Cleanup and goto SSLSTATE_UNCONNECTED
    SSLSTATE_ABORT              = 70,   //We fall into a fatal error processing incoming message. So bail out.
    SSLSTATE_ABORTING           = 71,   //Notify server we are aborting a failed connection, then goto SSLSTATE_ABORTED
    SSLSTATE_ABORTED            = 72,   //Failed connection aborted. App disconnect TCP and goto SSLSTATE_DISCONNECTED
    SSLSTATE_ERROR              = -1    //Any other errors.
} SSL_STATE;


typedef enum
{
    SSL_OK                  = 0,
    SSL_RESULT_INVALID      = 1,
    SSL_RESULT_NOT_APPLY    = 2,
    SSL_ERROR_GENERIC       = -1,
    SSL_ERROR_PARSE         = -2,
    SSL_ERROR_TIMEOUT       = -3,
    SSL_ERROR_MEMORY        = -4,
    SSL_ERROR_NOTREADY      = -5,
    SSL_ERROR_CERTIFICATE_EXISTS = -6,
    SSL_ERROR_CERTIFICATE_BAD   = -7,
    SSL_ERROR_BUFFER_FULL   = -8,
    SSL_ERROR_LIMIT32       = 0xFFFF0000    //Forcing 32 bits int for enum
} SSL_RESULT;

class BaseTls
{
public:
    typedef unsigned int(*SSL_RANDOM)();
    static void SetRandFunc(SSL_RANDOM fRand);

protected:
    static SSL_RANDOM  gfRandom;

public:
    BaseTls() {}
    virtual ~BaseTls() {}

    virtual int Write(const unsigned char* pData, size_t cbSize) = 0;
    virtual int Read(unsigned char* pBuff, size_t cbSize) = 0;
    virtual SSL_STATE Work(unsigned int curTimeSec, SSL_STATE newState = SSLSTATE_RESET) = 0;
    virtual SSL_STATE State() = 0;
};

#endif //_BASESSL_H_INCLUDED_10_28_2017_
