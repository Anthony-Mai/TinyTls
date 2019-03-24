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

#include <stdint.h>

#include "ecc_x25519.h"

const BLIND edp_blinding =
{
    {0x891D027C,0x443AFFB7,0x19E25BFE,0xEA60187C,0x969C5735,0xDB09205D,0xF3D36C39,0x0EF49BB8},
    {0xDAF2F8BD,0x6BF86785,0xBF65538F,0x01A6BB93,0x3ECDD092,0x1AF401D6,0x8AAAA6D5,0x68C845EB},
    {
        {0xDD128CD6,0x901DB76E,0x45C2C8AC,0x24AAB8F5,0x6BAE8649,0xDE046039,0x2333E3A4,0xF55D8DAE},
        {0xABA90510,0x33E8A450,0x35F0FE9C,0x4D6F4DD9,0xA27B9F2F,0x31B6552D,0xD5CC86FE,0x1E76BD54},
        {0xDD085A32,0x01AE712B,0x0284A982,0xFE36BE10,0x12C19914,0x0186BCCE,0x644E97C1,0x973B6BC7},
        {0x59A24586,0xB794C4E1,0xAF0A9971,0xCAA44DC7,0x0C3BF87A,0x751A3235,0xF27D8638,0x8D01185B}
    }
};

using X25519::G;

// Return P = P + Q, Q = 2Q
void G::MontXY(XZ_PT& P, XZ_PT& Q) const
{
    // x3 = ((x1-z1)(x2+z2) + (x1+z1)(x2-z2))^2*zb     zb=1
    // z3 = ((x1-z1)(x2+z2) - (x1+z1)(x2-z2))^2*xb     xb=Base
    P.X.reduce(); P.Z.reduce();
    Q.X.reduce(); Q.Z.reduce();

    NN A; A.subr(P.X, P.Z);     // A = x1-z1
    NN B; B.addr(P.X, P.Z);     // B = x1+z1
    NN C; C.subr(Q.X, Q.Z);     // C = x2-z2
    NN D; D.addr(Q.X, Q.Z);     // D = x2+z2

    A = A ^ D;              // A = (x1-z1)(x2+z2)
    B = B ^ C;              // B = (x1+z1)(x2-z2)

    NN E; E.addr(A, B);     // E = (x1-z1)(x2+z2) + (x1+z1)(x2-z2)

    B = (A >= B) ? A - B : A + (NN::P_ - B);  // B = (x1-z1)(x2+z2) - (x1+z1)(x2-z2)

    P.X = E ^ E;        // x3 = ((x1-z1)(x2+z2) + (x1+z1)(x2-z2))^2

    A = B ^ B;          // A = ((x1-z1)(x2+z2) - (x1+z1)(x2-z2))^2
    P.Z = A ^ *(NN*)this;    // z3 = ((x1-z1)(x2+z2) - (x1+z1)(x2-z2))^2*Base

                        // x4 = (x2+z2)^2 * (x2-z2)^2
                        // z4 = ((x2+z2)^2 - (x2-z2)^2)*((x2+z2)^2 + 121665((x2+z2)^2 - (x2-z2)^2))
                        // C = (x2-z2)
                        // D = (x2+z2)

    A = D ^ D;          // A = (x2+z2)^2
    B = C ^ C;          // B = (x2-z2)^2

    Q.X = A ^ B;        // x4 = (x2+z2)^2 * (x2-z2)^2

    B = (A >= B) ? A - B : A + (NN::P_ - B); // B = (x2+z2)^2 - (x2-z2)^2
    (A += (NN(121665) ^ B)).reduce();

    Q.Z = A ^ B;        // z4 = B*((x2+z2)^2 + 121665*B)
}

// Y = X + X
void G::MontX2(XZ_PT& Y, const XZ_PT& X)
{
    //  x2 = (x+z)^2 * (x-z)^2
    //  z2 = ((x+z)^2 - (x-z)^2)*((x+z)^2 + ((A-2)/4)((x+z)^2 - (x-z)^2))

    NN A((X.X + X.Z).reduce()); // A = (x+z)
    NN B((X.X >= X.Z) ? X.X - X.Z : X.X + (NN::P_ - X.Z)); // B = (x-z)

    A = A ^ A;                  // A = (x+z)^2
    B = B ^ B;                  // B = (x-z)^2

    Y.X = A ^ B;                // x2 = (x+z)^2 * (x-z)^2
    B = (A >= B) ? A - B : A + (NN::P_ - B); // B = (x+z)^2 - (x-z)^2
    (A += (NN(121665) ^ B)).reduce();    // (486662-2)/4 = 121665

    Y.Z = A ^ B;                // z2 = (B)*((x+z)^2 + ((A-2)/4)(B))
}

// Return point Q = k*P. K in a little-endian byte array
void G::PointMult(uint8_t* PublicKey, const NN& SecretKey) const
{
    int i, j, len = 8;
    uint32_t k;
    const uint32_t* pSecret = SecretKey.n_;
    XZ_PT P, Q, *PP[2], *QP[2];

    const G& X(*this);

    // 1: P = (2k+1)G, Q = (2k+2)G
    // 0: Q = (2k+1)G, P = (2k)G

    // Search for first non-zero bit
    while (len-- > 0) {
        k = pSecret[len];
        for (i = 0; i < 32; i++, k <<= 1) {
            if (k & 0x80000000) break;
        }
        if (i < 32) break;
    }
    if (len < 0) {
        NN(0).bytesOut(PublicKey);
        return; // No set bit found
    }

    // P = kG, Q = (k+1)G

    // First we found first non-zero bit. Should be bit 254 for keys
    // created according to the spec. Start with randomized base point

    P.Z = (X + edp_blinding.zr).reduce();  // P.Z = random
    P.X = X ^ P.Z;

    G::MontX2(Q, P);

    PP[1] = &P; PP[0] = &Q;
    QP[1] = &Q; QP[0] = &P;

    // Everything we reference in the below loop are on
    // the stack and already touched (cached)
    i++; k <<= 1;

    for (;;) {
        while (i++ < 32) {
            j = k >> 31;

            // Depends on bit31:
            // 1: X.MontXY(P, Q);
            // 0: X.MontXY(Q, P);
            X.MontXY(*PP[j], *QP[j]);

            k <<= 1;
        }
        if (len <= 0) break;
        i = 0;  k = pSecret[--len];
    }

    Q.Z = P.Z.inverse();
    (P.X ^ Q.Z).bytesOut(PublicKey);
}
