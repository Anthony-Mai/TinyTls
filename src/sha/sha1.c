/******************************************************************************
*
* Copyright © 2014-2019 Anthony Mai Mai_Anthony@hotmail.com. All Rights Reserved.
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
*  File Name:       SHA1.c
*
*  Description:     SHA-1 hash algorithm. From http://www.di-mgt.com.au/src/sha1.c.txt
*
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         6/27/2014 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "cipher.h"

#define SHA     CTX
#define DSIZE   SHA1_SIZE

#include "sha1.h"
#include "endian.h"


// SHA1 initial values
#define H0  0x67452301L
#define H1  0xEFCDAB89L
#define H2  0x98BADCFEL
#define H3  0x10325476L
#define H4  0xC3D2E1F0L


//The SHS f()-functions.  The f1 and f3 functions can be optimized to
//save one boolean operation each - thanks to Rich Schroeppel,
//rcs@cs.arizona.edu for discovering this

//#define f1(x,y,z)   ( z ^ ( x & ( y ^ z ) ) )           // Rounds  0-19
//#define f2(x,y,z)   ( x ^ y ^ z )                       // Rounds 20-39
//#define f3(x,y,z)   ( ( x & y ) | ( z & ( x | y ) ) )   // Rounds 40-59
//#define f4(x,y,z)   ( x ^ y ^ z )                       // Rounds 60-79

// The SHS Mysterious Constants

#define K1  0x5A827999L                                 // Rounds  0-19
#define K2  0x6ED9EBA1L                                 // Rounds 20-39
#define K3  0x8F1BBCDCL                                 // Rounds 40-59
#define K4  0xCA62C1D6L                                 // Rounds 60-79


//Note that it may be necessary to add parentheses to these macros if they
//are to be called with expressions as arguments
//32-bit rotate left - kludged with shifts

#define ROTL(n,X)  ( ( ( X ) << n ) | ( ( X ) >> ( 32 - n ) ) )

//The initial expanding function.  The hash function is defined over an
//80-UINT2 expanded input array W, where the first 16 are copies of the input
//data, and the remaining 64 are defined by
//
//    W[ i ] = W[ i - 16 ] ^ W[ i - 14 ] ^ W[ i - 8 ] ^ W[ i - 3 ]
//
//This implementation generates these values on the fly in a circular
//buffer - thanks to Colin Plumb, colin@nyx10.cs.du.edu for this
//optimization.
//
//The updated SHS changes the expanding function by adding a rotate of 1
//bit.  Thanks to Jim Gillogly, jim@rand.org, and an anonymous contributor
//for this information

#define expand(W,i) ( W[ i & 15 ] = ROTL( 1, ( W[ i & 15 ] ^ W[ (i - 14) & 15 ] ^ \
                                                 W[ (i - 8) & 15 ] ^ W[ (i - 3) & 15 ] ) ) )


//The prototype SHS sub-round.  The fundamental sub-round is:
//
//    a' = e + ROTL( 5, a ) + f( b, c, d ) + k + data;
//    b' = a;
//    c' = ROTL( 30, b );
//    d' = c;
//    e' = d;
//
//but this is implemented by unrolling the loop 5 times and renaming the
//variables ( e, a, b, c, d ) = ( a', b', c', d', e' ) each iteration.
//This code is then replicated 20 times for each of the 4 functions, using
//the next 20 values from the W[] array each time

#define subRound(a, b, c, d, e, f, k, data) \
    ( e += ROTL( 5, a ) + f( b, c, d ) + k + data, b = ROTL( 30, b ) )


//Perform the SHS transformation.  Note that this code, like MD5, seems to
//break some optimizing compilers due to the complexity of the expressions
//and the size of the basic block.  It may be necessary to split it into
//sections, e.g. based on the four subrounds
//
//Note that this corrupts the pSha->data area
void Sha1Round
(
	struct SHA* pShaCtx
)
{
    uint i;
    uint A, B, C, D, E;     // Local vars
#define eData   (pShaCtx->ints)
#define state   (pShaCtx->state)

    A = state[0]; B = state[1]; C = state[2]; D = state[3]; E = state[4];

    E += ROTL(5, A) + (D ^ (B & (C ^ D))) + K1 + eData[ 0]; B = ROTL( 30, B);
    D += ROTL(5, E) + (C ^ (A & (B ^ C))) + K1 + eData[ 1]; A = ROTL( 30, A);
    C += ROTL(5, D) + (B ^ (E & (A ^ B))) + K1 + eData[ 2]; E = ROTL( 30, E);
    B += ROTL(5, C) + (A ^ (D & (E ^ A))) + K1 + eData[ 3]; D = ROTL( 30, D);
    A += ROTL(5, B) + (E ^ (C & (D ^ E))) + K1 + eData[ 4]; C = ROTL( 30, C);
    E += ROTL(5, A) + (D ^ (B & (C ^ D))) + K1 + eData[ 5]; B = ROTL( 30, B);
    D += ROTL(5, E) + (C ^ (A & (B ^ C))) + K1 + eData[ 6]; A = ROTL( 30, A);
    C += ROTL(5, D) + (B ^ (E & (A ^ B))) + K1 + eData[ 7]; E = ROTL( 30, E);
    B += ROTL(5, C) + (A ^ (D & (E ^ A))) + K1 + eData[ 8]; D = ROTL( 30, D);
    A += ROTL(5, B) + (E ^ (C & (D ^ E))) + K1 + eData[ 9]; C = ROTL( 30, C);
    E += ROTL(5, A) + (D ^ (B & (C ^ D))) + K1 + eData[10]; B = ROTL( 30, B);
    D += ROTL(5, E) + (C ^ (A & (B ^ C))) + K1 + eData[11]; A = ROTL( 30, A);
    C += ROTL(5, D) + (B ^ (E & (A ^ B))) + K1 + eData[12]; E = ROTL( 30, E);
    B += ROTL(5, C) + (A ^ (D & (E ^ A))) + K1 + eData[13]; D = ROTL( 30, D);
    A += ROTL(5, B) + (E ^ (C & (D ^ E))) + K1 + eData[14]; C = ROTL( 30, C);
    E += ROTL(5, A) + (D ^ (B & (C ^ D))) + K1 + eData[15]; B = ROTL( 30, B);
    
    for (i=0; i<16; i++) {expand(eData, i);}
    D += ROTL(5, E) + (C ^ (A & (B ^ C))) + K1 + eData[ 0]; A = ROTL( 30, A);
    C += ROTL(5, D) + (B ^ (E & (A ^ B))) + K1 + eData[ 1]; E = ROTL( 30, E);
    B += ROTL(5, C) + (A ^ (D & (E ^ A))) + K1 + eData[ 2]; D = ROTL( 30, D);
    A += ROTL(5, B) + (E ^ (C & (D ^ E))) + K1 + eData[ 3]; C = ROTL( 30, C);
    E += ROTL(5, A) + (B ^ C ^ D) + K2 + eData[ 4]; B = ROTL( 30, B);
    D += ROTL(5, E) + (A ^ B ^ C) + K2 + eData[ 5]; A = ROTL( 30, A);
    C += ROTL(5, D) + (E ^ A ^ B) + K2 + eData[ 6]; E = ROTL( 30, E);
    B += ROTL(5, C) + (D ^ E ^ A) + K2 + eData[ 7]; D = ROTL( 30, D);
    A += ROTL(5, B) + (C ^ D ^ E) + K2 + eData[ 8]; C = ROTL( 30, C);
    E += ROTL(5, A) + (B ^ C ^ D) + K2 + eData[ 9]; B = ROTL( 30, B);
    D += ROTL(5, E) + (A ^ B ^ C) + K2 + eData[10]; A = ROTL( 30, A);
    C += ROTL(5, D) + (E ^ A ^ B) + K2 + eData[11]; E = ROTL( 30, E);
    B += ROTL(5, C) + (D ^ E ^ A) + K2 + eData[12]; D = ROTL( 30, D);
    A += ROTL(5, B) + (C ^ D ^ E) + K2 + eData[13]; C = ROTL( 30, C);
    E += ROTL(5, A) + (B ^ C ^ D) + K2 + eData[14]; B = ROTL( 30, B);
    D += ROTL(5, E) + (A ^ B ^ C) + K2 + eData[15]; A = ROTL( 30, A);
    
    
    for (i=0; i<16; i++) {expand(eData, i);}
    C += ROTL(5, D) + (E ^ A ^ B) + K2 + eData[ 0]; E = ROTL( 30, E);
    B += ROTL(5, C) + (D ^ E ^ A) + K2 + eData[ 1]; D = ROTL( 30, D);
    A += ROTL(5, B) + (C ^ D ^ E) + K2 + eData[ 2]; C = ROTL( 30, C);
    E += ROTL(5, A) + (B ^ C ^ D) + K2 + eData[ 3]; B = ROTL( 30, B);
    D += ROTL(5, E) + (A ^ B ^ C) + K2 + eData[ 4]; A = ROTL( 30, A);
    C += ROTL(5, D) + (E ^ A ^ B) + K2 + eData[ 5]; E = ROTL( 30, E);
    B += ROTL(5, C) + (D ^ E ^ A) + K2 + eData[ 6]; D = ROTL( 30, D);
    A += ROTL(5, B) + (C ^ D ^ E) + K2 + eData[ 7]; C = ROTL( 30, C);
    E += ROTL(5, A) + ((B & C) | (D & (B | C))) + K3 + eData[ 8]; B = ROTL( 30, B);
    D += ROTL(5, E) + ((A & B) | (C & (A | B))) + K3 + eData[ 9]; A = ROTL( 30, A);
    C += ROTL(5, D) + ((E & A) | (B & (E | A))) + K3 + eData[10]; E = ROTL( 30, E);
    B += ROTL(5, C) + ((D & E) | (A & (D | E))) + K3 + eData[11]; D = ROTL( 30, D);
    A += ROTL(5, B) + ((C & D) | (E & (C | D))) + K3 + eData[12]; C = ROTL( 30, C);
    E += ROTL(5, A) + ((B & C) | (D & (B | C))) + K3 + eData[13]; B = ROTL( 30, B);
    D += ROTL(5, E) + ((A & B) | (C & (A | B))) + K3 + eData[14]; A = ROTL( 30, A);
    C += ROTL(5, D) + ((E & A) | (B & (E | A))) + K3 + eData[15]; E = ROTL( 30, E);
    
    for (i=0; i<16; i++) {expand(eData, i);}
    B += ROTL(5, C) + ((D & E) | (A & (D | E))) + K3 + eData[ 0]; D = ROTL( 30, D);
    A += ROTL(5, B) + ((C & D) | (E & (C | D))) + K3 + eData[ 1]; C = ROTL( 30, C);
    E += ROTL(5, A) + ((B & C) | (D & (B | C))) + K3 + eData[ 2]; B = ROTL( 30, B);
    D += ROTL(5, E) + ((A & B) | (C & (A | B))) + K3 + eData[ 3]; A = ROTL( 30, A);
    C += ROTL(5, D) + ((E & A) | (B & (E | A))) + K3 + eData[ 4]; E = ROTL( 30, E);
    B += ROTL(5, C) + ((D & E) | (A & (D | E))) + K3 + eData[ 5]; D = ROTL( 30, D);
    A += ROTL(5, B) + ((C & D) | (E & (C | D))) + K3 + eData[ 6]; C = ROTL( 30, C);
    E += ROTL(5, A) + ((B & C) | (D & (B | C))) + K3 + eData[ 7]; B = ROTL( 30, B);
    D += ROTL(5, E) + ((A & B) | (C & (A | B))) + K3 + eData[ 8]; A = ROTL( 30, A);
    C += ROTL(5, D) + ((E & A) | (B & (E | A))) + K3 + eData[ 9]; E = ROTL( 30, E);
    B += ROTL(5, C) + ((D & E) | (A & (D | E))) + K3 + eData[10]; D = ROTL( 30, D);
    A += ROTL(5, B) + ((C & D) | (E & (C | D))) + K3 + eData[11]; C = ROTL( 30, C);
    E += ROTL(5, A) + (B ^ C ^ D) + K4 + eData[12]; B = ROTL( 30, B);
    D += ROTL(5, E) + (A ^ B ^ C) + K4 + eData[13]; A = ROTL( 30, A);
    C += ROTL(5, D) + (E ^ A ^ B) + K4 + eData[14]; E = ROTL( 30, E);
    B += ROTL(5, C) + (D ^ E ^ A) + K4 + eData[15]; D = ROTL( 30, D);
    
    for (i=0; i<16; i++) {expand(eData, i);}
    A += ROTL(5, B) + (C ^ D ^ E) + K4 + eData[ 0]; C = ROTL( 30, C);
    E += ROTL(5, A) + (B ^ C ^ D) + K4 + eData[ 1]; B = ROTL( 30, B);
    D += ROTL(5, E) + (A ^ B ^ C) + K4 + eData[ 2]; A = ROTL( 30, A);
    C += ROTL(5, D) + (E ^ A ^ B) + K4 + eData[ 3]; E = ROTL( 30, E);
    B += ROTL(5, C) + (D ^ E ^ A) + K4 + eData[ 4]; D = ROTL( 30, D);
    A += ROTL(5, B) + (C ^ D ^ E) + K4 + eData[ 5]; C = ROTL( 30, C);
    E += ROTL(5, A) + (B ^ C ^ D) + K4 + eData[ 6]; B = ROTL( 30, B);
    D += ROTL(5, E) + (A ^ B ^ C) + K4 + eData[ 7]; A = ROTL( 30, A);
    C += ROTL(5, D) + (E ^ A ^ B) + K4 + eData[ 8]; E = ROTL( 30, E);
    B += ROTL(5, C) + (D ^ E ^ A) + K4 + eData[ 9]; D = ROTL( 30, D);
    A += ROTL(5, B) + (C ^ D ^ E) + K4 + eData[10]; C = ROTL( 30, C);
    E += ROTL(5, A) + (B ^ C ^ D) + K4 + eData[11]; B = ROTL( 30, B);
    D += ROTL(5, E) + (A ^ B ^ C) + K4 + eData[12]; A = ROTL( 30, A);
    C += ROTL(5, D) + (E ^ A ^ B) + K4 + eData[13]; E = ROTL( 30, E);
    B += ROTL(5, C) + (D ^ E ^ A) + K4 + eData[14]; D = ROTL( 30, D);
    A += ROTL(5, B) + (C ^ D ^ E) + K4 + eData[15]; C = ROTL( 30, C);

    // Build message digest
    state[0] += A; state[1] += B; state[2] += C; state[3] += D; state[4] += E;
#undef state
#undef edata
}


typedef struct CDAT
{
    uint    state[5];
    uint    Lo,Hi;
} CDAT;

const CDAT* Sha1Cd()
{
    static const CDAT  cSha1Cd = {
        {H0, H1, H2, H3, H4},
        0, 0
    };

    return &cSha1Cd;
}


/******************************************************************************
* Function:     SetSha1
*
* Description:  Set the SHA1 cipher
*
* Returns:      None.
******************************************************************************/
void SetSha1(CIPHER* pCipher)
{
    pCipher->eCipher = CIPHER_SHA1;
    pCipher->cSize = sizeof(CTX);
    pCipher->dSize = DSIZE;
    pCipher->pIData = Sha1Cd();

    pCipher->Init  = Sha1Init;
    pCipher->Input = Sha1Input;
    pCipher->Digest= Sha1Digest;
    pCipher->Hash  = Sha1Hash;
}


/******************************************************************************
* Function:     Sha1Init
*
* Description:  Initialize the SHS values
*
* Returns:      None
******************************************************************************/
void Sha1Init
(
    SHA*        pSha,
    const CDAT* pIData  //SHA1 init data
)
{
//    static const SHA    SHAInitState = {
//        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
//        {H0, H1, H2, H3, H4},
//        0, 0
//    };
    if (pIData == NULL) pIData = Sha1Cd();

    pSha->state[0] = pIData->state[0];
    pSha->state[1] = pIData->state[1];
    pSha->state[2] = pIData->state[2];
    pSha->state[3] = pIData->state[3];
    pSha->state[4] = pIData->state[4];
    pSha->countLo = pIData->Lo;
    pSha->countHi = pIData->Hi;
}


/******************************************************************************
* Function:     Sha1Input
*
* Description:  Update SHS for a block of 64 bytes data
*
* Returns:      None
******************************************************************************/
void Sha1Input
(
    SHA*            pSha,
    const uchar*    pBuffer,
    uint            nCount
)
{
    uint   dataCount, chunk;

    // Get count of bytes already in data
    dataCount = (pSha->countLo) & 0x3F;

    // Update byte count
    pSha->countLo += nCount;
    pSha->countHi += (pSha->countLo < nCount)&1;

    // Handle any leading odd-sized chunks
    for ( ; (dataCount&3) && nCount; dataCount++, nCount--)
    {
        pSha->ints[(dataCount)>>2] = (pSha->ints[(dataCount)>>2]<<8) + (*pBuffer++);
    }

    if (dataCount >= SHA1_DATA)
    {
        Sha1Round(pSha); dataCount &= 0x3F;
    }

    for ( ; nCount > 3; )
    {
        chunk = SHA1_DATA - dataCount;
        if (chunk > nCount)
        {
            chunk = nCount & (-4);
            Byte2Int(pBuffer, &(pSha->ints[(dataCount>>2)&0x3F]), chunk>>2);
            dataCount += chunk; pBuffer += chunk; nCount -= chunk;
            break;
        }
        else if (chunk)
        {
            Byte2Int(pBuffer, &(pSha->ints[(dataCount>>2)&0x3F]), chunk>>2);
            dataCount += chunk; pBuffer += chunk; nCount -= chunk;
        }
        Sha1Round(pSha); dataCount &= 0x3F;
    }

    for ( ; nCount; dataCount++, nCount--)
    {
        pSha->ints[(dataCount>>2)&0x3F] = (pSha->ints[(dataCount>>2)&0x3F]<<8) + (*pBuffer++);
    }
}


/******************************************************************************
* Function:     Sha1Digest
*
* Description:  Digest wrapup - pad to SHA1_DATA - byte boundary with the bit
*               pattern 1 0* (64 - bit count of bits processed, MSB - first).
*               The context can continue to take inputs.
*
* Returns:      None
******************************************************************************/
void Sha1Digest
(
    const SHA*  pSha,
    uchar*      pDigest
)
{
    uint    count;
    SHA     sha = *pSha;

    // Compute number of bytes mod 64
    count = sha.countLo & 0x3F;

    // Set the first char of padding to 0x80.  This is safe since there is
    // always at least one byte free
    sha.ints[(count)>>2] = (sha.ints[(count)>>2]<<8) + (0x80); count++;

    for ( ; (count&3); count++)
    {
        sha.ints[(count)>>2] = (sha.ints[(count)>>2]<<8);
    }

    // Pad out to 56 mod 64
    memset(&(sha.ints[count>>2]), 0, SHA1_DATA - count);
    if (SHA1_DATA - count < 8)
    {
        // Two lots of padding:  Pad the first block to 64 bytes
        Sha1Round(&sha);

        // Now fill the next block with 56 bytes
        memset(sha.ints, 0, SHA1_DATA);
    }

    // Append length in bits and transform
    sha.ints[14] = (sha.countHi << 3) + (sha.countLo >> 29);
    sha.ints[15] = (sha.countLo << 3);

    Sha1Round(&sha);

    Int2Byte(sha.state, pDigest, SHA1_SIZE>>2);
}



/******************************************************************************
* Function:     Sha1Hash
*
* Description:  Calculate the SHA1 hash of a block of message
*
* Returns:      None
******************************************************************************/
void Sha1Hash
(
    const uchar*    pData,
    uint            nSize,
    uchar           pDigest[SHA1_SIZE]
)
{
    SHA     sha;

    Sha1Init(&sha, Sha1Cd());
    Sha1Input(&sha, pData, nSize);
    Sha1Digest(&sha, pDigest);
}


#ifdef TEST_SHA1

#include <stdio.h>
#include <string.h>

typedef struct SHA1TEST
{
    const char* pTestString;
    char        result[40];
} SHA1TEST;

//Do NOT modify this. This is the official SHA1 test suite. http://www.di-mgt.com.au/sha_testvectors.html
SHA1TEST gSHA1Tests[] = 
{
    // These are correct solutions from FIPS PUB 180-1
    {"",    "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"},
    {"abc", "A9993E364706816ABA3E25717850C26C9CD0D89D"},
    {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "84983E441C3BD26EBAAE4AA1F95129E5E54670F1"},
    {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "A49B2446A02C645BF419F995B67091253A04A259"},
    {0, ""}
};

int sha1Test()
{
    int         i, j=0;
    SHA     sha1;
    SHA1TEST*   pTest = gSHA1Tests;
    uchar   digest[SHA1_SIZE];
    uchar   digestMsg[(SHA1_SIZE<<1)+2];

    while (pTest->pTestString && (j == 0))
    {
        Sha1Init(&sha1, Sha1Cd());
        Sha1Input(&sha1, (uchar*)pTest->pTestString, strlen(pTest->pTestString));
        Sha1Digest(&sha1, digest);

        for (i=0; i<SHA1_SIZE; i++)
        {
            sprintf((char*)&(digestMsg[i+i]), "%02X", digest[i]);
        }
        j |= memcmp(digestMsg, pTest->result, sizeof(pTest->result));

        pTest++;
    }

    return j;
}

#endif //TEST_SHA1
