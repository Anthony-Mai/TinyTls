#pragma once

#include "TcpSock.h"

struct sockaddr;

class TcpSockWin32 : TcpSock {
public:
    static void* CreateListenSock(unsigned int port);

    TcpSockWin32();
    TcpSockWin32(uint32_t ip, uint32_t port);
    TcpSockWin32(HSock sock, sockaddr& addr, int addrLen);

    virtual ~TcpSockWin32();

    HSock GetSock() const override { return m_hSock; }

    bool Incoming() override;
    HSock Accept(const TcpSock& listenSock) override;
    bool Connected() override;
    bool Closed() override;
    int Send(const uint8_t* pData, size_t cbSize) override;
    int Recv(uint8_t* pData, size_t cbSize) override;

private:
    void Close();

    HSock m_hSock = nullptr;
    bool m_bConnected = false;

    static int m_LastError;
};
