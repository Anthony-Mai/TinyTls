/******************************************************************************
*
* Copyright � 2019 Anthony Mai Mai_Anthony@hotmail.com. All Rights Reserved.
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
*  File Name:       certgen_test.cpp
*
*  Description:     X.509 digital certificate generation test code.
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         2/18/2019 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#ifdef _WIN32
#include <windows.h>
#endif _WIN32
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "certgen_test.h"
#include "cert_gen.h"
#include "x509.h"
#include "hmac.h"
#include "cipher.h"
#include "BN.h"
#include "ssl_ciphers.h"
#include "cert.h"
#include "ecc_p256.h"

extern const CIPHERSET* gpCipherSet;

static uint myConsistentRand()
{
    static uint it = 12345;
    static const char myKey[] = "Tiny TLS Certificate";
    static const char myLabel[] = "03/28/2019 12:00:00pm";
    static uint buff[16];
    static PrfHash prf(gpCipherSet->sha256, (const uchar*)myKey, strlen(myKey), (const uchar*)myLabel, strlen(myLabel));

    for (; it >= 16; it -= 16) {
        prf.Output((uchar*)buff, sizeof(buff));
    }

    return buff[it++];
}

uint getCurTime()
{
    uint curTime = 0x5C800000;
#ifdef _WIN32
    SYSTEMTIME stime;
    GetSystemTime((LPSYSTEMTIME)&stime);

    curTime = ((stime.wMonth + 10) * 367) / 12;
    curTime += (stime.wYear * 1461) >> 2;
    curTime -= (0 - (stime.wMonth > 2))&((8 - (stime.wYear & 3)) >> 2);
    curTime += stime.wDay;
    curTime -= 719879; // Epoch
    curTime *= 24; curTime += stime.wHour;
    curTime *= 60; curTime += stime.wMinute;
    curTime *= 60; curTime += stime.wSecond;
#endif //_WIN32
    return curTime;
}

const uchar cPrivateKey[] = {
    0xf8, 0x14, 0xa0, 0x38, 0x04, 0xdc, 0xf1, 0xb7, 0x29, 0xec, 0xd8, 0xc4, 0x11, 0x90, 0x37, 0xae,
    0xda, 0x2e, 0xe2, 0x43, 0x1c, 0x70, 0xb4, 0x9a, 0xcb, 0xb5, 0xf3, 0x11, 0xa0, 0x12, 0xcc, 0x5e
};

const uchar sPrivateEcc[] = {
    0x88, 0x16, 0x39, 0x9b, 0x2f, 0xab, 0x12, 0x93, 0xc0, 0xaf, 0x9a, 0xb9, 0x01, 0x75, 0x42, 0x7f,
    0xce, 0x77, 0xa6, 0x6b, 0x57, 0x1c, 0xaa, 0xe2, 0x8d, 0x7f, 0x35, 0x5d, 0x11, 0x25, 0x09, 0x73
};

const uchar sPrivateKey[] = {
    0xab, 0xe0, 0xef, 0xd5, 0xc2, 0x2e, 0xd0, 0x5f, 0xc5, 0xaf, 0xed, 0x7d, 0xf9, 0x2c, 0x78, 0xf0,
    0x8b, 0xc7, 0x19, 0xf4, 0x55, 0x40, 0xeb, 0xd3, 0xf6, 0x8c, 0xbb, 0x4a, 0xd4, 0xba, 0x73, 0x63,
    0xc8, 0xdc, 0xa6, 0xca, 0xea, 0x37, 0xf1, 0x87, 0x62, 0xdb, 0x73, 0x0b, 0xe7, 0xc6, 0xca, 0x1e,
    0x75, 0x1b, 0xce, 0x18, 0xd7, 0xe6, 0x61, 0x05, 0x9d, 0x8d, 0x1c, 0x8f, 0x22, 0xa0, 0xef, 0xc7,
    0x9b, 0xac, 0x57, 0xae, 0x6d, 0x0c, 0x9c, 0xba, 0xcf, 0xed, 0x00, 0xe1, 0x72, 0x0e, 0x56, 0x0e,
    0xc9, 0xa1, 0xb8, 0x63, 0xb6, 0x96, 0x5e, 0x43, 0x6f, 0x7f, 0x66, 0x99, 0x5b, 0x81, 0x26, 0x4f,
    0x06, 0x17, 0x3f, 0x22, 0xc4, 0x23, 0x88, 0x56, 0x1c, 0xcd, 0xf0, 0x54, 0x46, 0xac, 0x90, 0x76,
    0x33, 0x4f, 0x1c, 0x85, 0x9c, 0xb5, 0xe7, 0xb1, 0xe2, 0x77, 0x51, 0xb2, 0xb0, 0x60, 0x2b, 0xbb,
    0x69, 0xb4, 0x48, 0x47, 0xb8, 0x7a, 0x40, 0x87, 0xc0, 0x1f, 0xe7, 0x38, 0xa3, 0x5e, 0x8e, 0x98,
    0x18, 0x98, 0xf8, 0xb8, 0x96, 0x48, 0x2b, 0x17, 0x48, 0x85, 0xd0, 0x55, 0xe5, 0xc7, 0xd6, 0x38,
    0x63, 0xb6, 0x04, 0x89, 0x4a, 0x23, 0x28, 0x96, 0x73, 0xee, 0xe0, 0x66, 0xcf, 0xf9, 0x45, 0xe7,
    0x82, 0x1d, 0x54, 0xda, 0x5a, 0xab, 0xe3, 0x78, 0x45, 0x55, 0x44, 0x7a, 0xf6, 0xb5, 0x24, 0x0b,
    0xdd, 0x22, 0xec, 0xc3, 0x33, 0x4d, 0x1d, 0x61, 0x0d, 0x34, 0x80, 0x3d, 0x99, 0x53, 0xef, 0x9d,
    0x6e, 0x98, 0xae, 0x7a, 0xc8, 0xdd, 0x4e, 0xb2, 0x50, 0xf3, 0xeb, 0xfb, 0x27, 0xcf, 0x8f, 0xe2,
    0xd8, 0x4a, 0x59, 0xdf, 0x42, 0xa5, 0x92, 0x09, 0x32, 0xf9, 0x87, 0x5a, 0xd6, 0x7c, 0x4b, 0xbf,
    0xe6, 0x35, 0x91, 0x6e, 0xef, 0x7c, 0xff, 0x61, 0xcb, 0xa8, 0x1c, 0xab, 0x45, 0x34, 0x3f, 0x01
};

const uchar gRootCert1[] = {
    0x30, 0x82, 0x03, 0xd6, 0x30, 0x82, 0x02, 0xbe, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x81, 0x95, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
    0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13,
    0x02, 0x43, 0x41, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x08, 0x53, 0x61,
    0x6e, 0x20, 0x4a, 0x6f, 0x73, 0x65, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13,
    0x13, 0x54, 0x69, 0x6e, 0x79, 0x20, 0x54, 0x4c, 0x53, 0x20, 0x54, 0x65, 0x63, 0x68, 0x6e, 0x6f,
    0x6c, 0x6f, 0x67, 0x79, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x1c, 0x53,
    0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
    0x65, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x31, 0x21, 0x30, 0x1f, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x13, 0x18, 0x54, 0x69, 0x6e, 0x79, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20,
    0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x20, 0x56, 0x31, 0x2e, 0x30, 0x30, 0x1e,
    0x17, 0x0d, 0x31, 0x32, 0x31, 0x32, 0x32, 0x31, 0x32, 0x30, 0x31, 0x32, 0x32, 0x31, 0x5a, 0x17,
    0x0d, 0x32, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x81,
    0x95, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x02, 0x43, 0x41, 0x31, 0x11, 0x30, 0x0f, 0x06,
    0x03, 0x55, 0x04, 0x07, 0x13, 0x08, 0x53, 0x61, 0x6e, 0x20, 0x4a, 0x6f, 0x73, 0x65, 0x31, 0x1c,
    0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x13, 0x54, 0x69, 0x6e, 0x79, 0x20, 0x54, 0x4c,
    0x53, 0x20, 0x54, 0x65, 0x63, 0x68, 0x6e, 0x6f, 0x6c, 0x6f, 0x67, 0x79, 0x31, 0x25, 0x30, 0x23,
    0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x1c, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x43, 0x65,
    0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72,
    0x69, 0x74, 0x79, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x18, 0x54, 0x69,
    0x6e, 0x79, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74,
    0x79, 0x20, 0x56, 0x31, 0x2e, 0x30, 0x30, 0x82, 0x01, 0x24, 0x30, 0x82, 0x00, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xb9, 0x5a, 0xf4, 0x51, 0x4a, 0xd0, 0xd9,
    0x16, 0x73, 0xe4, 0x61, 0x2e, 0x61, 0xce, 0x92, 0x47, 0x28, 0xf5, 0xe5, 0xba, 0x8a, 0xa1, 0x0e,
    0x39, 0x9a, 0x54, 0xb1, 0xf7, 0x68, 0x1a, 0x96, 0xef, 0x04, 0x32, 0x8c, 0x52, 0xe7, 0xd5, 0x1d,
    0xb4, 0x17, 0xcd, 0xcf, 0xf1, 0x03, 0xf8, 0x98, 0x13, 0x45, 0xe2, 0xcb, 0xbc, 0x04, 0xea, 0xb8,
    0xf6, 0x00, 0x84, 0x59, 0x04, 0xd5, 0x1e, 0x0d, 0xaf, 0x33, 0xdd, 0x19, 0xe8, 0xef, 0x84, 0x4b,
    0xb8, 0x8a, 0xe0, 0x35, 0x2b, 0xf0, 0xa1, 0xca, 0xfa, 0x6b, 0xdf, 0xfe, 0x67, 0xc1, 0xd5, 0x30,
    0x25, 0xcd, 0x39, 0xf8, 0xed, 0x1e, 0xc2, 0xf5, 0xe8, 0x5c, 0x7f, 0x9b, 0xf4, 0x38, 0x09, 0x15,
    0x86, 0x32, 0x77, 0x2f, 0x12, 0x2d, 0x43, 0x24, 0xa0, 0x5b, 0xf4, 0x8a, 0x97, 0xdb, 0x2e, 0x56,
    0xbe, 0x02, 0x18, 0x2e, 0x24, 0xb5, 0x2e, 0x8a, 0x30, 0xcd, 0xd9, 0x22, 0x0e, 0xc6, 0x1c, 0xae,
    0x02, 0x95, 0x25, 0x0f, 0x73, 0x75, 0x1d, 0x96, 0x55, 0x5f, 0xdb, 0x65, 0xc2, 0x52, 0x81, 0x8b,
    0x25, 0x6c, 0x00, 0xf7, 0x73, 0xcf, 0x7e, 0x84, 0x88, 0x17, 0x2e, 0xb8, 0x39, 0x68, 0x19, 0x9f,
    0x39, 0xde, 0x4f, 0xcc, 0x65, 0xa8, 0x4d, 0x09, 0x42, 0x89, 0x9d, 0xb3, 0x91, 0xf1, 0x4a, 0xd9,
    0x4d, 0xc3, 0x1f, 0x89, 0x5e, 0x55, 0x29, 0x38, 0x6f, 0x4e, 0x91, 0x12, 0x84, 0xfd, 0x28, 0x86,
    0x72, 0x3e, 0x0a, 0x0a, 0x7c, 0xb5, 0xd0, 0xb8, 0x00, 0x32, 0xe2, 0x80, 0x18, 0xe9, 0x3a, 0xd9,
    0xb6, 0x0d, 0xf4, 0xd0, 0xf8, 0x01, 0x04, 0xa1, 0x17, 0x9a, 0xb1, 0xeb, 0x32, 0x79, 0xc1, 0x7a,
    0x3c, 0xdc, 0xed, 0xeb, 0xc5, 0xa5, 0xbc, 0xfe, 0xc0, 0x66, 0xa1, 0x6c, 0xe5, 0xce, 0x00, 0x2b,
    0xa8, 0x03, 0xc9, 0xd1, 0x7b, 0x45, 0x91, 0xa6, 0xfb, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x26,
    0x30, 0x24, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02,
    0x00, 0x86, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06,
    0x01, 0x04, 0xff, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x3a, 0xcd, 0x62, 0x63, 0xab, 0x39,
    0xcf, 0x6d, 0x7c, 0xfe, 0x3d, 0x73, 0xdc, 0x62, 0xb6, 0xbf, 0xff, 0x57, 0x53, 0x19, 0xf6, 0x51,
    0xa6, 0x25, 0x6f, 0x13, 0x12, 0xb6, 0x1b, 0x5a, 0x1f, 0xba, 0x90, 0xa9, 0x21, 0x73, 0xa3, 0x98,
    0x14, 0x14, 0x1d, 0xc8, 0x71, 0x2f, 0x38, 0x4b, 0xc2, 0x2a, 0x33, 0x94, 0x8d, 0x90, 0xf3, 0x57,
    0x45, 0x9a, 0xaa, 0x13, 0x69, 0x83, 0x76, 0x95, 0xd6, 0x1e, 0x1f, 0x28, 0x3b, 0xa0, 0x62, 0x76,
    0xe0, 0x67, 0x40, 0x71, 0x72, 0x31, 0xa4, 0xb6, 0xbb, 0xfe, 0x98, 0x95, 0x01, 0x1f, 0x81, 0xb2,
    0x01, 0x3c, 0xde, 0x27, 0x18, 0xa0, 0xd3, 0x1e, 0xb6, 0xa0, 0x54, 0xaf, 0x05, 0x46, 0x06, 0xfa,
    0x3a, 0xc4, 0x93, 0x98, 0xee, 0xe1, 0xac, 0x1b, 0xc0, 0x03, 0xc8, 0xf4, 0x2f, 0xf5, 0x61, 0x69,
    0x3b, 0x4b, 0xce, 0xcc, 0xcc, 0xfb, 0x25, 0x32, 0x1d, 0x55, 0xb7, 0x62, 0x15, 0x00, 0xfa, 0x43,
    0xdb, 0xfc, 0x98, 0x5f, 0xd1, 0xe4, 0xa3, 0xe7, 0x56, 0xef, 0x9f, 0xb5, 0xbe, 0x3c, 0xb6, 0xab,
    0xc3, 0x9e, 0xbb, 0x7f, 0x42, 0x16, 0x03, 0x29, 0x1a, 0x65, 0xbb, 0x5a, 0x43, 0x2a, 0x07, 0xeb,
    0x6b, 0x40, 0xea, 0xe9, 0x0a, 0xa1, 0x09, 0xd7, 0x6f, 0xcd, 0x87, 0x7c, 0x4d, 0x83, 0x00, 0xac,
    0x8f, 0xac, 0x09, 0xfc, 0x53, 0xc3, 0x88, 0x8d, 0x0f, 0x78, 0x65, 0x08, 0x3c, 0xec, 0x6b, 0xbc,
    0xfd, 0x30, 0x4e, 0x78, 0xbd, 0x7d, 0xae, 0xb1, 0x71, 0x05, 0x62, 0x5b, 0x35, 0x7a, 0xab, 0x3a,
    0x04, 0x48, 0xea, 0x01, 0xae, 0x00, 0x40, 0xa3, 0x2e, 0x50, 0xc3, 0x91, 0x0c, 0xb0, 0x6e, 0x72,
    0xd9, 0xe1, 0x8c, 0xff, 0x27, 0x46, 0xab, 0xd5, 0x19, 0x6f, 0xe4, 0x28, 0x68, 0x21, 0x94, 0xce,
    0xd7, 0xee, 0x2c, 0xc7, 0x0a, 0x71, 0x10, 0xab, 0xc4, 0x1e };

const uchar gServerCert1[] = {
    0x30, 0x82, 0x03, 0x33, 0x30, 0x82, 0x02, 0x1b, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x81, 0x95, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
    0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13,
    0x02, 0x43, 0x41, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x08, 0x53, 0x61,
    0x6e, 0x20, 0x4a, 0x6f, 0x73, 0x65, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13,
    0x13, 0x54, 0x69, 0x6e, 0x79, 0x20, 0x54, 0x4c, 0x53, 0x20, 0x54, 0x65, 0x63, 0x68, 0x6e, 0x6f,
    0x6c, 0x6f, 0x67, 0x79, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x1c, 0x53,
    0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
    0x65, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x31, 0x21, 0x30, 0x1f, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x13, 0x18, 0x54, 0x69, 0x6e, 0x79, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20,
    0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x20, 0x56, 0x31, 0x2e, 0x30, 0x30, 0x1e,
    0x17, 0x0d, 0x31, 0x38, 0x31, 0x32, 0x31, 0x38, 0x32, 0x30, 0x31, 0x38, 0x31, 0x38, 0x5a, 0x17,
    0x0d, 0x32, 0x38, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x81,
    0x9a, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x02, 0x43, 0x41, 0x31, 0x11, 0x30, 0x0f, 0x06,
    0x03, 0x55, 0x04, 0x07, 0x13, 0x08, 0x4d, 0x6f, 0x75, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x31, 0x27,
    0x30, 0x25, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x1e, 0x6e, 0x65, 0x77, 0x62, 0x69, 0x65, 0x20,
    0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x20, 0x53, 0x74, 0x61, 0x72, 0x74,
    0x75, 0x70, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0b,
    0x13, 0x19, 0x41, 0x6d, 0x61, 0x7a, 0x69, 0x6e, 0x67, 0x20, 0x5a, 0x4b, 0x20, 0x53, 0x74, 0x61,
    0x72, 0x6b, 0x20, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x31, 0x1e, 0x30, 0x1c, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x13, 0x15, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x63, 0x68, 0x61, 0x69, 0x6e,
    0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x5b, 0x30, 0x82, 0x00,
    0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xb9, 0x74, 0xef, 0xbe, 0xe2, 0x54, 0xca, 0xc9,
    0x8b, 0x7f, 0x96, 0x13, 0xac, 0xeb, 0x0c, 0x04, 0x24, 0x67, 0x16, 0xc7, 0xf5, 0xcf, 0x84, 0xb4,
    0xf3, 0x8d, 0x98, 0x7c, 0xeb, 0x7c, 0xb4, 0x20, 0x19, 0x37, 0xb1, 0x42, 0x79, 0x3c, 0x48, 0x23,
    0xb4, 0x7d, 0xd7, 0xf8, 0x29, 0xb3, 0xc4, 0x50, 0xf5, 0x30, 0xee, 0xda, 0xc5, 0x42, 0x31, 0xd8,
    0xc1, 0x4b, 0xe4, 0xc0, 0x65, 0xc0, 0x65, 0x01, 0xa3, 0x49, 0x30, 0x47, 0x30, 0x0e, 0x06, 0x03,
    0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x00, 0x80, 0x30, 0x12, 0x06, 0x03,
    0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x04, 0xff, 0x02, 0x01, 0x00,
    0x30, 0x21, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x01, 0x01, 0xff, 0x04, 0x17, 0x30, 0x15, 0x82, 0x09,
    0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x2a, 0x82, 0x08, 0x31, 0x30, 0x2e, 0x30, 0x2e,
    0x30, 0x2e, 0x2a, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0xa7, 0x80, 0x43, 0xfb, 0x52, 0x17, 0x9c, 0x88, 0xdb,
    0x64, 0xca, 0x56, 0xa0, 0xd8, 0x9d, 0x23, 0xe1, 0x58, 0xfc, 0xad, 0x19, 0xec, 0xe0, 0x6f, 0xbc,
    0xcb, 0x01, 0x58, 0x8e, 0x3f, 0x8f, 0xd7, 0xd8, 0xec, 0x46, 0xa2, 0xa5, 0xe4, 0x34, 0x8b, 0x47,
    0xa5, 0xd3, 0xea, 0x67, 0x03, 0x58, 0x35, 0xe4, 0xa7, 0xb3, 0x08, 0xc8, 0xba, 0x0f, 0xc3, 0xd7,
    0x9c, 0x18, 0x1a, 0xd6, 0x9a, 0x07, 0x4c, 0xdc, 0x45, 0x50, 0x77, 0xfb, 0xe7, 0x9e, 0xfe, 0x2c,
    0x3b, 0xb7, 0xa5, 0xe8, 0x7c, 0xae, 0x97, 0x83, 0x99, 0xd2, 0xbd, 0x8a, 0x86, 0x39, 0x2d, 0x3d,
    0xec, 0x7d, 0xdf, 0x0e, 0x7b, 0x30, 0xce, 0xdd, 0xb3, 0xe3, 0x32, 0x0d, 0xa1, 0x0b, 0x2d, 0x87,
    0x62, 0x9b, 0x06, 0xdc, 0x4a, 0x4b, 0x3d, 0x07, 0x97, 0x7d, 0xbc, 0xdc, 0x72, 0x2e, 0xb2, 0x67,
    0x86, 0x91, 0x5d, 0x98, 0xb0, 0xad, 0xe3, 0x71, 0x40, 0x11, 0xf3, 0xc6, 0xd6, 0x5e, 0x19, 0x72,
    0x43, 0x53, 0x81, 0xd9, 0x6f, 0x6f, 0x7b, 0xb7, 0xef, 0x73, 0x57, 0x64, 0xcf, 0x21, 0x84, 0xfc,
    0x10, 0x1a, 0x22, 0x2d, 0xb4, 0x47, 0xa0, 0x26, 0xc9, 0xf0, 0x8d, 0x3c, 0xe4, 0xb4, 0xbd, 0x52,
    0x80, 0x36, 0x2e, 0xcd, 0x2c, 0x29, 0xe4, 0x84, 0x3c, 0xd2, 0xd1, 0x33, 0x4d, 0x86, 0xab, 0x9f,
    0x8f, 0x5a, 0xc0, 0x5c, 0x6b, 0x96, 0x96, 0x1a, 0x56, 0xbe, 0x1c, 0x6d, 0xb7, 0x11, 0x25, 0xa6,
    0xd0, 0x9a, 0x44, 0xec, 0x3a, 0x46, 0x61, 0xbb, 0xe1, 0x64, 0x56, 0x14, 0x7d, 0x8c, 0x03, 0x5d,
    0x35, 0x40, 0x88, 0xf1, 0x46, 0xe3, 0xde, 0xfa, 0xac, 0x59, 0xc3, 0x75, 0xeb, 0x16, 0x38, 0x07,
    0x95, 0xf5, 0x78, 0xde, 0xe6, 0x74, 0x93, 0x06, 0x7c, 0x55, 0x06, 0x9b, 0xde, 0x25, 0xac, 0x86,
    0x54, 0xc2, 0xf8, 0x03, 0x97, 0x6d, 0xa4 };

const uchar gRootCert2[] = {
    0x30, 0x82, 0x02, 0x4d, 0x30, 0x82, 0x01, 0xf2, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x02, 0x05, 0x00, 0x30, 0x81, 0x95, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
    0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x02,
    0x43, 0x41, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x08, 0x53, 0x61, 0x6e,
    0x20, 0x4a, 0x6f, 0x73, 0x65, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x13,
    0x54, 0x69, 0x6e, 0x79, 0x20, 0x54, 0x4c, 0x53, 0x20, 0x54, 0x65, 0x63, 0x68, 0x6e, 0x6f, 0x6c,
    0x6f, 0x67, 0x79, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x1c, 0x53, 0x65,
    0x63, 0x75, 0x72, 0x65, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65,
    0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x13, 0x18, 0x54, 0x69, 0x6e, 0x79, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x41,
    0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x20, 0x56, 0x31, 0x2e, 0x31, 0x30, 0x1e, 0x17,
    0x0d, 0x31, 0x32, 0x31, 0x32, 0x32, 0x31, 0x32, 0x30, 0x31, 0x32, 0x32, 0x31, 0x5a, 0x17, 0x0d,
    0x32, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x81, 0x95,
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0b, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x02, 0x43, 0x41, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03,
    0x55, 0x04, 0x07, 0x13, 0x08, 0x53, 0x61, 0x6e, 0x20, 0x4a, 0x6f, 0x73, 0x65, 0x31, 0x1c, 0x30,
    0x1a, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x13, 0x54, 0x69, 0x6e, 0x79, 0x20, 0x54, 0x4c, 0x53,
    0x20, 0x54, 0x65, 0x63, 0x68, 0x6e, 0x6f, 0x6c, 0x6f, 0x67, 0x79, 0x31, 0x25, 0x30, 0x23, 0x06,
    0x03, 0x55, 0x04, 0x0b, 0x13, 0x1c, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x43, 0x65, 0x72,
    0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69,
    0x74, 0x79, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x18, 0x54, 0x69, 0x6e,
    0x79, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79,
    0x20, 0x56, 0x31, 0x2e, 0x31, 0x30, 0x5b, 0x30, 0x82, 0x00, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42,
    0x00, 0x04, 0x9b, 0xcc, 0xa8, 0xce, 0x0d, 0x94, 0xcc, 0x33, 0x4e, 0xad, 0x6b, 0x7d, 0x98, 0x26,
    0x10, 0xc8, 0x2c, 0x94, 0x4b, 0xc8, 0xb4, 0xc2, 0x53, 0xcf, 0xc5, 0x8a, 0xf8, 0xce, 0x1d, 0x38,
    0x33, 0xa0, 0x60, 0xc0, 0xf9, 0xc3, 0xfd, 0x23, 0x6c, 0x4d, 0xef, 0x95, 0xd8, 0xd0, 0xeb, 0x8e,
    0x47, 0x1d, 0xd4, 0x2d, 0x73, 0x36, 0x2d, 0x4e, 0xc4, 0xca, 0xe6, 0x69, 0x39, 0xdd, 0xb2, 0xb7,
    0x8c, 0x89, 0xa3, 0x26, 0x30, 0x24, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff,
    0x04, 0x04, 0x03, 0x02, 0x00, 0x86, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
    0x04, 0x08, 0x30, 0x06, 0x01, 0x04, 0xff, 0x02, 0x01, 0x00, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x05, 0x00, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x4e,
    0x43, 0x99, 0xe3, 0x65, 0xb0, 0x73, 0xf2, 0xe3, 0xd5, 0x1a, 0x1b, 0x2b, 0x56, 0xe4, 0x87, 0xb7,
    0x21, 0xc8, 0x68, 0x88, 0xeb, 0x09, 0x34, 0x76, 0x6a, 0xcb, 0x1d, 0xd8, 0x28, 0x72, 0x01, 0x02,
    0x20, 0x27, 0x80, 0xba, 0x44, 0xfb, 0x44, 0x8a, 0xf5, 0x68, 0xa5, 0xda, 0x52, 0x7c, 0x72, 0x4c,
    0x67, 0x9d, 0x17, 0x4f, 0x8e, 0x80, 0x6b, 0x47, 0x02, 0xb5, 0xbd, 0x8c, 0xd6, 0x1b, 0x5e, 0xb6,
    0x20 };

const uchar gServerCert2[] = {
    0x30, 0x82, 0x02, 0x75, 0x30, 0x82, 0x02, 0x1a, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x35, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x02, 0x05, 0x00, 0x30, 0x81, 0x95, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
    0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x02,
    0x43, 0x41, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x08, 0x53, 0x61, 0x6e,
    0x20, 0x4a, 0x6f, 0x73, 0x65, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x13,
    0x54, 0x69, 0x6e, 0x79, 0x20, 0x54, 0x4c, 0x53, 0x20, 0x54, 0x65, 0x63, 0x68, 0x6e, 0x6f, 0x6c,
    0x6f, 0x67, 0x79, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x1c, 0x53, 0x65,
    0x63, 0x75, 0x72, 0x65, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65,
    0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x13, 0x18, 0x54, 0x69, 0x6e, 0x79, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x41,
    0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x20, 0x56, 0x31, 0x2e, 0x31, 0x30, 0x1e, 0x17,
    0x0d, 0x31, 0x38, 0x31, 0x32, 0x31, 0x38, 0x32, 0x30, 0x31, 0x38, 0x31, 0x38, 0x5a, 0x17, 0x0d,
    0x32, 0x38, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x81, 0x9a,
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0b, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x02, 0x43, 0x41, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03,
    0x55, 0x04, 0x07, 0x13, 0x08, 0x4d, 0x6f, 0x75, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x31, 0x27, 0x30,
    0x25, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x1e, 0x6e, 0x65, 0x77, 0x62, 0x69, 0x65, 0x20, 0x42,
    0x6c, 0x6f, 0x63, 0x6b, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x20, 0x53, 0x74, 0x61, 0x72, 0x74, 0x75,
    0x70, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13,
    0x19, 0x41, 0x6d, 0x61, 0x7a, 0x69, 0x6e, 0x67, 0x20, 0x5a, 0x4b, 0x20, 0x53, 0x74, 0x61, 0x72,
    0x6b, 0x20, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x13, 0x15, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x2e,
    0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x5b, 0x30, 0x82, 0x00, 0x13,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xb9, 0x74, 0xef, 0xbe, 0xe2, 0x54, 0xca, 0xc9, 0x8b,
    0x7f, 0x96, 0x13, 0xac, 0xeb, 0x0c, 0x04, 0x24, 0x67, 0x16, 0xc7, 0xf5, 0xcf, 0x84, 0xb4, 0xf3,
    0x8d, 0x98, 0x7c, 0xeb, 0x7c, 0xb4, 0x20, 0x19, 0x37, 0xb1, 0x42, 0x79, 0x3c, 0x48, 0x23, 0xb4,
    0x7d, 0xd7, 0xf8, 0x29, 0xb3, 0xc4, 0x50, 0xf5, 0x30, 0xee, 0xda, 0xc5, 0x42, 0x31, 0xd8, 0xc1,
    0x4b, 0xe4, 0xc0, 0x65, 0xc0, 0x65, 0x01, 0xa3, 0x49, 0x30, 0x47, 0x30, 0x0e, 0x06, 0x03, 0x55,
    0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x00, 0x80, 0x30, 0x12, 0x06, 0x03, 0x55,
    0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x04, 0xff, 0x02, 0x01, 0x00, 0x30,
    0x21, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x01, 0x01, 0xff, 0x04, 0x17, 0x30, 0x15, 0x82, 0x09, 0x31,
    0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x2a, 0x82, 0x08, 0x31, 0x30, 0x2e, 0x30, 0x2e, 0x30,
    0x2e, 0x2a, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x05, 0x00,
    0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x3d, 0x26, 0x09, 0x5a, 0x66, 0xa2, 0x89, 0xf0, 0x8b,
    0xf5, 0xfa, 0x93, 0xf1, 0x24, 0xef, 0x3f, 0x87, 0x7d, 0xe5, 0x3f, 0xef, 0xa1, 0xb7, 0xcf, 0xa7,
    0x3a, 0xcc, 0x89, 0x63, 0x46, 0xce, 0x42, 0x02, 0x20, 0x4f, 0xe5, 0x36, 0x01, 0x6b, 0x0d, 0x54,
    0xab, 0xfb, 0x0f, 0xe2, 0x6b, 0xce, 0x15, 0x7e, 0x29, 0x77, 0x87, 0x77, 0x4f, 0x78, 0x39, 0xc0,
    0x4c, 0xb6, 0x83, 0xaf, 0xa6, 0x4c, 0x4a, 0x54, 0xef };

int do_CertGenTest(const CIPHERSET& cipherSet)
{
    X509::X509NAME issuer;
    X509::X509NAME subject;
    KEYPAIR isKeyPair, subPubKey;
    uchar cpubKey[256];
    uchar cpriKey[256];
    uchar spubKey[256];
    uchar spriKey[256];
    uchar spubEcc[64];
    uchar spriEcc[32];

    memset(cpubKey, 0, sizeof(cpubKey));
    memset(cpriKey, 0, sizeof(cpriKey));

    // First generate a root RSA keypair.
    BN_KeyGen(myConsistentRand, 65537, 256, spubKey, spriKey);

    // Second generate a root ECC keypair.
    {
        // Generate a server ECC KeyPair.
        P256::ECDKeyPair kp;

        kp.Create(myConsistentRand);
        kp.priKey.bytesOut(spriEcc);
        kp.pubKey.x.netOut(spubEcc);
        kp.pubKey.y.netOut(spubEcc + 0x20);
    }

    // Third generate a server ECC keypair.
    {
        // Generate a ECC KeyPair.
        P256::ECDKeyPair kp;

        kp.Create(myConsistentRand);
        kp.priKey.bytesOut(cpriKey);
        kp.pubKey.x.netOut(cpubKey);
        kp.pubKey.y.netOut(cpubKey + 0x20);
    }

    // Set up the root CA identity.
    issuer.country = "US";
    issuer.state = "CA";
    issuer.local = "San Jose";
    issuer.company = "Tiny TLS Technology";
    issuer.unitname = "Secure Certificate Authority";
    issuer.commonname = "Tiny Root Authority V1.0";

    // Set up serevr subject identity
    subject.country = "US";
    subject.state = "CA";
    subject.local = "Mountain View";
    subject.company = "Newbie Blockchain Startup Inc.";
    subject.unitname = "Amazing ZK Stark Security";
    subject.commonname = "blockchain.server.com";

    // This is used by the root CA which does not have alternative names.
    const char* altNames1[] = { nullptr };
    // This is used by the server certificate who needs the alt names.
    const char* altNames2[] = { "127.0.0.*", "10.0.0.*", nullptr };

    uint64_t rootSerial = 0x0100000000000001llu;
    uint64_t serverSerial = 0x0100000000001234llu;

    uint32_t nCurTime = getCurTime();

    isKeyPair.pPriKey = spriKey;
    isKeyPair.pPubKey = spubKey;
    isKeyPair.nEccGroup = ECC_NONE; // For RSA certificate.

    subPubKey.pPriKey = cpriKey;
    subPubKey.pPubKey = cpubKey;
    subPubKey.nEccGroup = ECC_secp256r1; // For ECC Using P256

    uint iTime1 = 0x50D4C2A5, eTime1 = 0x70DBD87F;
    uint iTime2 = 0x5C19560A, eTime2 = 0x6EFAA4FF;

    // First generate an RSA root certificate.
    const uint8_t* pRootCert = certGen(
        &cipherSet, &isKeyPair, &isKeyPair, &issuer, &issuer, altNames1, iTime1, eTime1, rootSerial);
    uint nCertSize = CERT_SIZE(pRootCert);
    {
        CERT* pCert = CreateCert(CS_ROOT, nCurTime);
        uint nParsed = ParseCert(pCert, pRootCert, nCertSize);
        CERT_STATUS status = AuthenticateCert(pCert, NULL);
        printf("Root Certificate Status 0x%02X %s\n", status, (status == (CS_OK | CS_VERIFIED | CS_ROOT | CS_SELF)) ? "OK" : "BAD");
        InsertCert(pCert, nullptr);
    }
    if (1) {
        FILE* fout = fopen("TinyTlsRoot001.cer", "wb");
        fwrite(pRootCert, 1, nCertSize, fout);
        fclose(fout);
        // TODO: Save spriKey some where for later use. Without you do not own the root cert.
    }

    // Second generate a ECC server certificate signed by the RSA root certificate.
    const uint8_t* pServerCert = certGen(
        &cipherSet, &isKeyPair, &subPubKey, &issuer, &subject, altNames2, iTime2, eTime2, serverSerial);
    uint nCertSize2 = CERT_SIZE(pServerCert);
    {
        CERT* pCert2 = CreateCert(CS_UNKNOWN, nCurTime);
        uint nParsed = ParseCert(pCert2, pServerCert, nCertSize2);
        CERT_STATUS status = AuthenticateCert(pCert2, NULL);
        printf("Server Certificate Status 0x%02X %s\n", status, (status == (CS_OK | CS_VERIFIED)) ? "OK" : "BAD");
        DestroyCert(pCert2);
    }
    if (1) {
        FILE* fout = fopen("TinyTlsServer001.cer", "wb");
        fwrite(pServerCert, 1, nCertSize2, fout);
        fclose(fout);
        // TODO: Save cpriKey some where for later use. Without you do not own the server cert.
    }

    // Replace RSA root keypair with ECC root keypair.
    isKeyPair.pPriKey = spriEcc;
    isKeyPair.pPubKey = spubEcc;
    isKeyPair.nEccGroup = ECC_secp256r1; // For ECC Using P256

    issuer.commonname = "Tiny Root Authority V1.1";

    // Third generate an ECC root certificate.
    pRootCert = certGen(
        &cipherSet, &isKeyPair, &isKeyPair, &issuer, &issuer, altNames1, iTime1, eTime1, rootSerial+1);
    nCertSize = CERT_SIZE(pRootCert);
    {
        CERT* pCert = CreateCert(CS_ROOT, nCurTime);
        uint nParsed = ParseCert(pCert, pRootCert, nCertSize);
        CERT_STATUS status = AuthenticateCert(pCert, NULL);
        printf("ECC Root Certificate Status 0x%02X %s\n", status, (status == (CS_OK | CS_VERIFIED | CS_ROOT | CS_SELF)) ? "OK" : "BAD");
        InsertCert(pCert, nullptr);
    }
    if (1) {
        FILE* fout = fopen("TinyTlsRoot002.cer", "wb");
        fwrite(pRootCert, 1, nCertSize, fout);
        fclose(fout);
        // TODO: Save spriKey some where for later use. Without you do not own the root cert.
    }

    // Fourth generate an ECC server certificate signed by a ECC root certificate.
    pServerCert = certGen(
        &cipherSet, &isKeyPair, &subPubKey, &issuer, &subject, altNames2, iTime2, eTime2, serverSerial+1);
    nCertSize2 = CERT_SIZE(pServerCert);
    {
        CERT* pCert2 = CreateCert(CS_UNKNOWN, nCurTime);
        uint nParsed = ParseCert(pCert2, pServerCert, nCertSize2);
        CERT_STATUS status = AuthenticateCert(pCert2, NULL);
        printf("ECC Server Certificate Status 0x%02X %s\n", status, (status == (CS_OK | CS_VERIFIED)) ? "OK" : "BAD");
        DestroyCert(pCert2);
    }
    if (1) {
        FILE* fout = fopen("TinyTlsServer002.cer", "wb");
        fwrite(pServerCert, 1, nCertSize2, fout);
        fclose(fout);
        // TODO: Save cpriKey some where for later use. Without you do not own the server cert.
    }

    return 0;
}