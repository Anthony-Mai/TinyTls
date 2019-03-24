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
*  File Name:       TcpSockLinux.cpp
*
*  Description:     Implementation of the TcpSock class on the Lnux platform.
*                   TcpSock is ab abstract class for TinyTls to access network.
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         10/20/2018 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef __linux__
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>
#endif //__linux__

#include "TcpSockLinux.h"

int TcpSockLinux::m_LastError = 0;

#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)

static int GetLastError() {return errno;}

static const u_long Non_Blocking = 1;

HSock TcpSockLinux::CreateListenSock(unsigned int port)
{
    int       ret = 0;
    SOCKET    sock = socket(AF_INET, SOCK_STREAM, 0);

    m_LastError = 0;
    for (; sock != INVALID_SOCKET;)
    {
        // Set up the sockaddr structure
        sockaddr_in  addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        // Set socket to non-blocking: 0 blocking; 1: non-blocking
        int flags = fcntl(sock, F_GETFL, 0) | O_NONBLOCK;
        if (fcntl(sock, F_SETFL, flags)) break;

        // Bind the listening socket to address and port based on sockaddr.
        if (bind(sock, (sockaddr*)&addr, sizeof(addr))) break;

        if (listen(sock, 16)) break;

        return reinterpret_cast<HSock>(sock); // Only successful return.
    }

    m_LastError = GetLastError();
    if (sock != INVALID_SOCKET) close(sock);

    return HSock(nullptr);
}

TcpSockLinux::TcpSockLinux() : m_hSock(HSock(nullptr))
{
}

TcpSockLinux::TcpSockLinux(uint32_t ip, uint32_t port)
{
    int       ret = 0;
    m_hSock = reinterpret_cast<HSock>(socket(AF_INET, SOCK_STREAM, 0));

    // Set up the sockaddr structure
    sockaddr_in  addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(ip);
    addr.sin_port = htons(port);

    // Set socket to non-blocking: 0 blocking; 1: non-blocking
    int flags = fcntl(reinterpret_cast<size_t>(m_hSock), F_GETFL, 0) | O_NONBLOCK;
    if (fcntl(reinterpret_cast<size_t>(m_hSock), F_SETFL, flags)) {
        m_LastError = errno;
    }

    if (connect(reinterpret_cast<size_t>(m_hSock), (const sockaddr*)&addr, sizeof(addr))
        && (errno != EINPROGRESS)) {
        m_LastError = errno;
    }
}

TcpSockLinux::TcpSockLinux(void* sock)
{
    m_hSock = sock;
}

TcpSockLinux::~TcpSockLinux()
{
}

bool TcpSockLinux::Incoming()
{
    if (!m_hSock) {
        return false;
    }

    timeval timeout{ 0, 0 };
    fd_set rfds, wfds, efds;

    FD_ZERO(&rfds); FD_ZERO(&wfds); FD_ZERO(&efds);
    FD_SET(SOCKET(reinterpret_cast<size_t>(m_hSock)), &rfds);
    FD_SET(SOCKET(reinterpret_cast<size_t>(m_hSock)), &wfds);
    FD_SET(SOCKET(reinterpret_cast<size_t>(m_hSock)), &efds);
    
    int r = select(SOCKET(reinterpret_cast<size_t>(m_hSock))+1, &rfds, &wfds, &efds, &timeout);
    switch (r)
    {
    case 0:
        break;
    case SOCKET_ERROR:
        if (errno == EINPROGRESS || errno == EAGAIN || errno == EWOULDBLOCK) {
            break; // Ignore benigh errors.
        }
        m_LastError = errno;
        close((SOCKET)reinterpret_cast<size_t>(m_hSock));
        m_hSock = nullptr; break;
    default:
        if (FD_ISSET(SOCKET(reinterpret_cast<size_t>(m_hSock)), &rfds) ||
            FD_ISSET(SOCKET(reinterpret_cast<size_t>(m_hSock)), &wfds)) {
           return true;
        }
        break;
    }

    return false;
}

HSock TcpSockLinux::Accept(const TcpSock& listenSock)
{
    sockaddr  addr2;
    socklen_t addr2len = sizeof(addr2);
    SOCKET sock2 = accept(
        (SOCKET)reinterpret_cast<size_t>(listenSock.GetSock()),
        &addr2, &addr2len);

    // Set the new socket to non-blocking.
    int flags = fcntl(sock2, F_GETFL, 0) | O_NONBLOCK;
    if (fcntl(sock2, F_SETFL, flags)) {
       //TODO: Handle rare error if happens.
    }

    m_hSock = reinterpret_cast<HSock>(sock2);
    return m_hSock;
}

bool TcpSockLinux::Connected()
{
    if (m_bConnected || m_hSock == nullptr)
    {
        return m_bConnected;
    }

    timeval timeout{0, 0};
    fd_set rfds, wfds, efds;

    FD_ZERO(&rfds); FD_ZERO(&wfds); FD_ZERO(&efds);
    FD_SET(SOCKET(reinterpret_cast<size_t>(m_hSock)), &rfds);
    FD_SET(SOCKET(reinterpret_cast<size_t>(m_hSock)), &wfds);
    FD_SET(SOCKET(reinterpret_cast<size_t>(m_hSock)), &efds);

    int ret = select(SOCKET(reinterpret_cast<size_t>(m_hSock))+1, &rfds, &wfds, &efds, &timeout);
    switch (ret)
    {
    case 0:
        break;
    case SOCKET_ERROR:
        if (errno == EINPROGRESS || errno == EAGAIN || errno == EWOULDBLOCK) {
            break; // iIgnore benigh errors.
        }
        close((SOCKET)reinterpret_cast<size_t>(m_hSock));
        m_hSock = nullptr;
        m_bConnected = false;
        m_LastError = errno;
        break;
    default:
        if (FD_ISSET(SOCKET(reinterpret_cast<size_t>(m_hSock)), &rfds) ||
            FD_ISSET(SOCKET(reinterpret_cast<size_t>(m_hSock)), &wfds)) {
            m_bConnected = true;
        }
        break;
    }

    return m_bConnected;
}

bool TcpSockLinux::Closed()
{
    return (m_hSock == nullptr);
}

void TcpSockLinux::Close()
{
    if (m_hSock)
    {
        close((SOCKET)reinterpret_cast<size_t>(m_hSock));
        m_hSock = nullptr;
    }
    m_bConnected = false;
}

static void DumpData(const char* tag, const uint8_t* p, int cbSize)
{
    printf("%s[0x%04X]:", tag, cbSize);
    for (int i = 0; i< cbSize; i++) {
        printf("%s%02X", (i&15)? " ":"\n    ", p[i]);
    }
    printf("\n");
}

int TcpSockLinux::Send(const uint8_t* pData, size_t cbSize)
{
    if (!Connected()) return 0;

    int nSend = 0, ret;

    DumpData("Send", pData, cbSize);

    while (cbSize)
    {
        ret = send((SOCKET)reinterpret_cast<size_t>(m_hSock), (const char*)pData, (int)cbSize, 0);
        if (ret >= 0)
        {
            nSend += ret;
            cbSize -= ret;
            pData += ret;
            if (cbSize) {
                usleep(5000);
            } else return nSend;
        }
        else if (ret == SOCKET_ERROR)
        {
            int err = errno;
            if (err == EWOULDBLOCK || err == ENOBUFS) {
                usleep(5000);
            } else {
                Close();
                break;
            }
        }
    }

    return nSend;
}

int TcpSockLinux::Recv(uint8_t* pData, size_t cbSize)
{
    int ret = 0;
    if (!Connected()) {
        return 0;
    }

    ret = recv((SOCKET)reinterpret_cast<size_t>(m_hSock), (char*)pData, (int)cbSize, 0);
    if (ret > 0)
    {
        DumpData("Recv", pData, ret);
        return ret;  // received some data.
    }
    else if (ret == SOCKET_ERROR)
    {
        int err = GetLastError();
        if (err == EWOULDBLOCK) return 0;
    }

    // Connection lost
    Close();

    return SOCKET_ERROR;
}

