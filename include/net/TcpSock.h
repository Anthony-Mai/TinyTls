#pragma once

typedef void* HSock;

class TcpSock {
public:
    TcpSock() {}
    virtual ~TcpSock() {}
    virtual HSock GetSock() const = 0;
    virtual bool Incoming() = 0;
    virtual HSock Accept(const TcpSock& listenSock) = 0;
    virtual bool Connected() = 0;
    virtual bool Closed() = 0;
    virtual int Send(const uint8_t* pData, size_t cbSize) = 0;
    virtual int Recv(uint8_t* pData, size_t cbSize) = 0;
};
