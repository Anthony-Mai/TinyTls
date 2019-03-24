/******************************************************************************
*
* Copyright © 2018-2019 Anthony Mai Mai_Anthony@hotmail.com. All Rights Reserved.
*
* This software is written by Anthony Mai who retains full copyright of this
* work. As such any Copyright Notices contained in this code. are NOT to be
* removed or modified. If this package is used in a product, Anthony Mai
* should be given attribution as the author of the parts of the library used.
* This can be in the form of a textual message at program startup or in
* documentation (online or textual) provided with the package.
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
* The licence and distribution terms for any publically available version or derivative
* of this code cannot be changed.  i.e. this code cannot simply be copied and put under
* another distribution licence [including the GNU Public Licence.]
*
******************************************************************************/

/******************************************************************************
*
*  File Name:       MockSock.cpp
*
*  Description:     Mock socket for integrity test without hitting network.
*                   Network traffic is simulated by simple memory copying.
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

#include "MockSock.h"


static uint32_t CompFunc(const uint8_t* p1, const uint8_t* p2, uint32_t cbBytes);

uint32_t MockSock::m_nCOut = 0;
uint32_t MockSock::m_nSIn = 0;
uint32_t MockSock::m_nSOut = 0;
uint32_t MockSock::m_nCIn = 0;
uint32_t MockSock::m_it = 0;

uint8_t MockSock::m_Client2Server[BUF_SIZE];
uint8_t MockSock::m_Server2Client[BUF_SIZE];

const char MockSock::HostName[]{ "www.cnn.com" };

HSock MockSock::GetSock() const {
    return (void*)(m_isClient ? 0 : 1);
}

bool MockSock::Incoming() {
    return true;
}

HSock MockSock::Accept(const TcpSock& listenSock)
{
    m_isClient = false;
    m_nCOut = m_nCIn = m_nSOut = m_nSIn = 0;
    m_it = 0;
    return GetSock();
}

bool MockSock::Connected()
{
    return true;
}

bool MockSock::Closed()
{
    return false;
}

int MockSock::Send(const uint8_t* pData, size_t cbSize)
{
    uint32_t nSent = 0, off, chunk;
    if (m_isClient) {
        while (cbSize) {
            off = m_nCOut & BUF_MASK;
            chunk = BUF_SIZE - off;
            if (chunk > cbSize) chunk = cbSize;
            if (chunk > m_nSIn + BUF_SIZE - m_nCOut) {
                chunk = m_nSIn + BUF_SIZE - m_nCOut;
            }
            if (chunk == 0) break;
            memcpy(m_Client2Server + off, pData, chunk);
            pData += chunk; cbSize -= chunk;
            m_nCOut += chunk; nSent += chunk;
        }
    } else {
        while (cbSize) {
            off = m_nSOut & BUF_MASK;
            chunk = BUF_SIZE - off;
            if (chunk > cbSize) chunk = cbSize;
            if (chunk > m_nCIn + BUF_SIZE - m_nSOut) {
                chunk = m_nCIn + BUF_SIZE - m_nSOut;
            }
            if (chunk == 0) break;
            memcpy(m_Server2Client + off, pData, chunk);
            pData += chunk; cbSize -= chunk;
            m_nSOut += chunk; nSent += chunk;
        }
    }

    return nSent;
}

int MockSock::Recv(uint8_t* pData, size_t cbSize)
{
    uint32_t nRecv = 0, off, chunk;
    if (m_isClient) {
        while (cbSize) {
            off = m_nCIn & BUF_MASK;
            chunk = BUF_SIZE - off;
            if (chunk > cbSize) chunk = cbSize;
            if (chunk > m_nSOut - m_nCIn) {
                chunk = m_nSOut - m_nCIn;
            }
            if (chunk == 0) break;
            memcpy(pData, m_Server2Client + off, chunk);
            pData += chunk; cbSize -= chunk;
            m_nCIn += chunk; nRecv += chunk;
        }
    } else {
        while (cbSize) {
            off = m_nSIn & BUF_MASK;
            chunk = BUF_SIZE - off;
            if (chunk > cbSize) chunk = cbSize;
            if (chunk > m_nCOut - m_nSIn) {
                chunk = m_nCOut - m_nSIn;
            }
            if (chunk == 0) break;
            memcpy(pData, m_Client2Server + off, chunk);
            pData += chunk; cbSize -= chunk;
            m_nSIn += chunk; nRecv += chunk;
        }
    }

    return nRecv;
}

uint32_t MockSock::MockRand()
{
    static int it = 0;
    it += 0x79543621; it ^= (it >> 2) * 7; it ^= it * 13;

    return it;
}


uint32_t MockSock::Validate()
{
    return 0;
}

uint32_t CompFunc(const uint8_t* p1, const uint8_t* p2, uint32_t cbBytes)
{
    for (uint32_t i = 0; i < cbBytes; i++) {
        if (p1[i] ^ p2[i]) {
            printf("Error at %d\n", i);
            return i? i : -1;
        }
    }
    return 0;
}
