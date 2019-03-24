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
*  File Name:       TcpSockWin32.cpp
*
*  Description:     Implementation of TcpSock class on the Windows platform.
*                   TcpSock is ab abstract class for TinyTls to access network.
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         10/20/2018 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include "TcpSockWin32.h"

int TcpSockWin32::m_LastError = 0;

static const u_long Non_Blocking = 1;

HSock TcpSockWin32::CreateListenSock(unsigned int port)
{
    m_LastError = 0;

    int       ret = 0;
    SOCKET    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    for (; sock != INVALID_SOCKET;)
    {
        // Set up the sockaddr structure
        sockaddr_in  addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        // Set socket to non-blocking: 0 blocking; 1: non-blocking
        u_long iBlockingMode = Non_Blocking;
        if (ioctlsocket(sock, FIONBIO, &iBlockingMode)) break;

        // Bind the listening socket to address and port based on sockaddr.
        if (bind(sock, (sockaddr*)&addr, sizeof(addr))) break;

        if (listen(sock, 16)) break;

        return reinterpret_cast<HSock>(sock); // Only successful return.
    }

    m_LastError = WSAGetLastError();
    if (sock != INVALID_SOCKET)
    {
        closesocket(sock);
    }

    return nullptr;
}

TcpSockWin32::TcpSockWin32()
{
}

#include "ws2tcpip.h"

TcpSockWin32::TcpSockWin32(uint32_t ip, uint32_t port)
{
    int ret;
    sockaddr_in saddr;
    int         len(sizeof(sockaddr));
    addrinfo*   inf = nullptr;
    addrinfo    hints;

    memset(saddr.sin_zero, 0, sizeof(saddr.sin_zero));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.S_un.S_addr = htonl(ip);
    saddr.sin_port = htons(443);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    ret = getaddrinfo("www.cnn.com", "443", &hints, &inf);
    if (ret) {
        ret = WSAGetLastError();
    }


    m_hSock = reinterpret_cast<HSock>(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));

    // Set socket to non-blocking: 0 blocking; 1: non-blocking
    u_long iBlockingMode = Non_Blocking;
    if (ioctlsocket((SOCKET)m_hSock, FIONBIO, &iBlockingMode)) {
        assert(0);
    }

    ret = connect((SOCKET)m_hSock, (const sockaddr*)&saddr, len);
    //ret = connect((SOCKET)m_hSock, inf->ai_addr, inf->ai_addrlen);

    if (ret) {
        ret = WSAGetLastError();
    }
}

TcpSockWin32::TcpSockWin32(void* sock, sockaddr& addr, int addrLen)
{
    m_hSock = sock;
}

TcpSockWin32::~TcpSockWin32()
{
}

bool TcpSockWin32::Incoming()
{
    if (!m_hSock) return false;

    timeval timeout{ 0, 0 };
    struct my_fd {
        u_int fd_count;
        SOCKET fd_sock;
    } rd{ 1, SOCKET(m_hSock) }, wd(rd), ed(wd);

    switch (select(1, (fd_set*)&rd, (fd_set*)&wd, (fd_set*)&ed, &timeout))
    {
    case 0:
        break;
    case SOCKET_ERROR:
        m_LastError = WSAGetLastError();
        closesocket(SOCKET(m_hSock));
        m_hSock = nullptr;
        break;
    default:
        if (rd.fd_count >= 0) return true;
        break;
    }

    return false;
}

HSock TcpSockWin32::Accept(const TcpSock& listenSock)
{
    sockaddr  addr2;
    int addr2len = sizeof(addr2);
    SOCKET sock2 = accept((SOCKET)listenSock.GetSock(), &addr2, &addr2len);

    m_hSock = reinterpret_cast<HSock>(sock2);
    return m_hSock;
}

bool TcpSockWin32::Connected()
{
    if (m_bConnected || m_hSock == nullptr)
    {
        return m_bConnected;
    }
    timeval timeout{0, 0};
    struct my_fd {
        u_int fd_count;
        SOCKET fd_sock;
    } rd{ 1, (SOCKET)m_hSock }, wd(rd), ed(wd);

    int ret = select(1, (fd_set*)&rd, (fd_set*)&wd, (fd_set*)&ed, &timeout);

    switch (ret)
    {
    case 0:
        break;
    case SOCKET_ERROR:
        closesocket((SOCKET)m_hSock);
        m_hSock = nullptr;
        m_bConnected = false;
        break;
    default:
        if (!m_bConnected && (rd.fd_count || wd.fd_count)) m_bConnected = true;
        break;
    }
        
    return m_bConnected;
}

bool TcpSockWin32::Closed()
{
    return (m_hSock == nullptr);
}

void TcpSockWin32::Close()
{
    if (m_hSock)
    {
        closesocket((SOCKET)m_hSock);
        m_hSock = nullptr;
    }
    m_bConnected = false;
}

void DumpData(const char* tag, const uint8_t* p, size_t cbSize)
{
    printf("%s:", tag);
    for (int i = 0; i < cbSize; i++) {
        printf("%s%02X", (i&15)? " " : "\n    ", p[i]);
    }
    printf("\n");
}

int TcpSockWin32::Send(const uint8_t* pData, size_t cbSize)
{
    if (!Connected()) return 0;

    int nSend = 0, ret;
    DumpData("Send", pData, cbSize);
    while (cbSize)
    {
        ret = send((SOCKET)m_hSock, (const char*)pData, (int)cbSize, 0);
        if (ret >= 0)
        {
            nSend += ret;
            cbSize -= ret;
            pData += ret;
            if (cbSize) Sleep(5);
            else return nSend;
        }
        else if (ret = SOCKET_ERROR)
        {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK || err == WSAENOBUFS) Sleep(5);
            else
            {
                Close();
                break;
            }
        }
    }

    return nSend;
}

int TcpSockWin32::Recv(uint8_t* pData, size_t cbSize)
{
    if (!Connected()) return 0;
    timeval timeout{ 0, 0 };
    struct my_fd {
        u_int fd_count;
        SOCKET fd_sock;
    } rd{ 1, (SOCKET)m_hSock }, wd(rd), ed(wd);

    int ret = select(1, (fd_set*)&rd, (fd_set*)&wd, (fd_set*)&ed, &timeout);
    if (rd.fd_count == 0) return 0;

    ret = recv((SOCKET)m_hSock, (char*)pData, (int)cbSize, 0);
    if (ret > 0)
    {
        DumpData("Recv", pData, ret);
        return ret;  // received some data.
    }
    else if (ret == SOCKET_ERROR)
    {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) return 0;
    }

    // Connection lost
    Close();

    return SOCKET_ERROR;
}
