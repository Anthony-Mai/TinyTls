#ifndef _SSLCALLBACK_H_INCLUDED_
#define _SSLCALLBACK_H_INCLUDED_

struct TlsCBData {
    static const int PAYLOAD_SIZE = 64;
    enum  CBType {
        CB_RANDOM = 0,
        CB_SERVER_NAME = 1,
        CB_SERVER_CERTS = 2,
        CB_SERVER_KEYPAIR = 3,
        CB_SERVER_CIPHER = 4,
        CB_CLIENT_CIPHER = 5,
        CB_CLIENT_SESSIONID = 6,
        CB_SUPPORTED_GROUPS = 7,
        CB_SIGNATURE_ALGORITHM = 8,
        CB_PSK_INFO = 9,
        CB_SESSIONTICKET_TLS = 10,
        CB_ECDHE_PUBLICKEY = 11,
        CB_ECDHE_PRIVATEKEY = 12,
        CB_NEW_SESSION_TICKET = 13,
        CB_CERTIFICATE_ALERT = 14,
        CB_LAST = 0x7FFFFFFF
    } cbType;
    union { // Fixed size PAYLOAD_SIZE bytes. Only rawSize can be used mixed with ptrs.
        void*   ptrs[PAYLOAD_SIZE / sizeof(void*)];
        size_t  rawSize[PAYLOAD_SIZE / sizeof(size_t)];
        unsigned int rawInt[PAYLOAD_SIZE / sizeof(unsigned int)];
        unsigned char rawByte[PAYLOAD_SIZE];
        char    rawChar[PAYLOAD_SIZE];
    } data;
};

// Content of TlsCBData.data depends on TlsCBData.cbType. Callback return value is 0 unless specified:
// CB_RANDOM:
//   ptrs[0] points to 32 bytes buffer to a client or server random, to be read or modified.
// CB_SERVER_NAME:
//  ptrs[0] is set to point to a null terminated string of server name. rawSize[1] is set to length of server name, which is also returned.
// CB_SERVER_CERTS:
//   ptrs[0..n] is set to point to chain of certificates to send, starting with server certificate. last ptrs[i] is set to nullptr.
// CB_SERVER_KEYPAIR:
//   ptrs[0] is set to server private key, ptrs[1] is public key, ptrs[2] is server certificate, ptrs[3] is ECC_GROUP, 0 for RSA. ptrs[4] is null.
//   Key size is implied from ECC Group. RSA Key size is assumed to be 2048 bits (256 bytes) only. Returns either ECC_GROUP, or RSA key size.
// CB_SERVER_CIPHER:
//   rawInt[0] is proposed server cipher like TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256. rawInt[1] is a potential replacement. When callback,
//   either do nothing, or swap the two values if rawInt[1] is a more preferable cipher to use. See SSL_CIPHERS.
// CB_CLIENT_CIPHER:
//   rawInt[o..n] is set to client supported ciphers. After last one it ends with a 0 entry. Returns the number of supported ciphers included.
// CB_CLIENT_SESSIONID:
//   ptrs[0] is legacy session ID server received from client, which will be echoed back. rawSize[1] is session ID length (default 32 bytes)
// CB_SUPPORTED_GROUPS:
//   rawInt[0..n] is set to list of supported ECC_GROUP, ends with a 0 entry. Returns number of ECC groups filled in and supported.
// CB_SIGNATURE_ALGORITHM:
//   rawInt[0..n] is set to list of supported signature algorithms SIG_ALG, ends with a 0 entry. Returns number of SIG_ALG's supported.
// CB_PSK_INFO:
//   ptrs[0] is initially nullptr. If PSK (Pre-Shared-Key) exists, ptrs[0] is set to point to PSK. and rawSize[1] is size. Returns PSK size.
// CB_SESSIONTICKET_TLS:
//   ptrs[0] is set to point to session ticket, if one exists, and rawSize[1] is set to its size, which is also the return value.
// CB_ECDHE_PUBLICKEY:
//   ptrs[0] points to the ephemeral ECC public key to examine or modify. rawSize[1] is ECC_GROUP, and also returned if key modified.
// CB_ECDHE_PRIVATEKEY = 12,
//   ptrs[0] points to the ephemeral ECC private key to examine or modify. rawSize[1] is ECC_GROUP, and also returned if key modified.
// CB_NEW_SESSION_TICKET:
//   ptrs[0] set to new session ticket if to be provided. rawSize[1] set to its lifespan in seconds. Returns size of new session ticket.
// CB_CERTIFICATE_ALERT:
//   Server certificate is questionable. ptrs[0] is CERT pointer which can be used to access cert.h features to query the cert.
//   rawSize[1] is CERT_STATUS. Returns true for handshake to continue. If deturn default 0, connection will be aborted.

typedef unsigned int(*TlsCallback)(void* pUserContext, TlsCBData* pCBData);

#endif //_SSLCALLBACK_H_INCLUDED_
