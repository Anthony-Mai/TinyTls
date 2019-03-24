#ifndef MOCK_SOCK_INCLUDED
#define MOCK_SOCK_INCLUDED

#include <stdint.h>

#include "TcpSock.h"

class MockSock : public TcpSock {
    friend class TestBuddy;
public:
    bool m_isClient;
	MockSock() : m_isClient(true) {}
	virtual ~MockSock() {}
	HSock GetSock() const override;
	bool Incoming() override;
	HSock Accept(const TcpSock& listenSock) override;
	bool Connected() override;
	bool Closed() override;
	int Send(const uint8_t* pData, size_t cbSize) override;
	int Recv(uint8_t* pData, size_t cbSize) override;

    static uint32_t MockRand();
    static uint32_t Validate();

private:
    static const uint32_t BUF_SIZE = 65536;
    static const uint32_t BUF_MASK = 65535;
    static uint32_t m_nCOut, m_nSIn;
    static uint32_t m_nSOut, m_nCIn;
    static uint8_t m_Client2Server[BUF_SIZE];
    static uint8_t m_Server2Client[BUF_SIZE];
    static uint32_t m_it;
public:
    static const char HostName[];
};

#endif //MOCK_SOCK_INCLUDED
