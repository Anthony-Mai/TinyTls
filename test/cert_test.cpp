/******************************************************************************
*
* Copyright © 2014-2019 Anthony Mai Mai_Anthony@hotmail.com. All Rights Reserved.
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
*  File Name:       cert_test.c
*
*  Description:     Test code for X.509 certificate parsing and processing.
*
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         6/27/2014 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <stdint.h>
#include <malloc.h>

#include "cert.h"
#include "oid.h"
#include "cipher.h"
#include "certSamples.h"

int DoCertTest()
{
    int         len = 0, ret = 0;
    CERT*       pRoot = NULL;
    CERT*       pCert = NULL;
    CERT_STATUS eStatus = CS_UNKNOWN;
    const CIPHERSET* pMyCiphers = NULL;

    pMyCiphers = InitCiphers(&gCipherSet, NULL);

    StartCerts(malloc, free, pMyCiphers);
    pRoot = CreateCert(CS_ROOT, 0);
    len = ParseCert(pRoot, gGeoTrustRoot, sizeof(gGeoTrustRoot));
    ret |= len - sizeof(gGeoTrustRoot);
    eStatus = AuthenticateCert(pRoot, NULL);
    ret |= eStatus ^ (CS_ROOT|CS_SELF|CS_OK|CS_VERIFIED);
    InsertCert(pRoot, NULL);

    pCert = CreateCert(CS_ROOT, 0);
    len = ParseCert(pCert, gGlobalSignR2, sizeof(gGlobalSignR2));
    ret |= len - sizeof(gGlobalSignR2);
    eStatus = AuthenticateCert(pCert, NULL);
    ret |= eStatus ^ (CS_OK|CS_VERIFIED);
    InsertCert(pCert, NULL);

    CleanupCerts(NULL);

    return ret;
}

