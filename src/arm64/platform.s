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

.text

.globl  rd_clk
.type   rd_clk,@function
.align  16
rd_clk:
    isb
    mrs     x0, cntvct_el0
    ret
.size   rd_clk,.-rd_clk

// Count leading 0 bits. Usage: uint32_t leadz32(uint32_t v);
.globl  leadz32
.type   leadz32,@function
.align  16
leadz32:
    clz     x0, x0
    ret
.size   leadz32,.-leadz32

// Count leading 0 bits. Usage: uint32_t leadz64(uint64_t v);
.globl  leadz64
.type   leadz64,@function
.align  16
leadz64:
    clz     x0, x0
    ret
.size   leadz64,.-leadz64

.globl  armv7_neon_probe
.align  16
armv7_neon_probe:
    //.inst   0x4eaf1def
    mov     v15.16b, v15.16b
    ret
.size armv7_neon_probe,.-armv7_neon_probe

.globl  armv8_aes_probe
armv8_aes_probe:
    //.inst 0x4e284800
    aese    v0.16b, v0.16b
    ret
.size armv8_aes_probe,.-armv8_aes_probe

.globl  armv8_sha1_probe
armv8_sha1_probe:
    //.inst 0x5e280800
    sha1h   s0, s0
    ret
.size armv8_sha1_probe,.-armv8_sha1_probe

.globl  armv8_sha256_probe
armv8_sha256_probe:
    //.inst 0x5e282800
    sha256su0 v0.4s, v0.4s
    ret
.size armv8_sha256_probe,.-armv8_sha256_probe

.globl  armv8_pmull_probe
armv8_pmull_probe:
    //.inst 0x0ee0e000
    pmull   v0.1q, v0.1d, v0.1d
    ret
.size armv8_pmull_probe,.-armv8_pmull_probe

// Polynomial product of 64 bits x 64 bits produce 128 bits, in Aarch64.
// See https://conradoplg.cryptoland.net/files/2010/12/mocrysen13.pdf
// and https://conradoplg.cryptoland.net/software/ecc-and-ae-for-arm-neon/
// The above discusses implementation using pmull.p8 in armv7. Since pmull
// and pmull1 is available on armv8 and later, it can be done much faster.
// Usage: uint64_t PMull8x8(uint64_t a, uint64_t b, uint64_t r[2]);
.globl  PMull8x8
PMull8x8:
    eor     v0.16b, v0.16b, v0.16b
    eor     v1.16b, v1.16b, v1.16b
    mov     v0.d[0], x0
    mov     v1.d[0], x1
    pmull   v0.1q, v0.1d, v1.1d
    mov     x0, v0.d[0]
    mov     x1, v0.d[1]
    str     x0, [x2]
    str     x1, [x2, #8]
    ret
.size PMull8x8,.-PMull8x8

// Polynomial product of 64 bits x 64 bits & reduce by 65 bits p, in Aarch64.
// See https://conradoplg.cryptoland.net/files/2010/12/mocrysen13.pdf
// and https://conradoplg.cryptoland.net/software/ecc-and-ae-for-arm-neon/
// The above discusses implementation using pmull.p8 in armv7. Since pmull
// and pmull1 is available on armv8 and later, it can be done much faster.
// Usage: uint64_t PMull8x8(uint64_t a, uint64_t b, uint64_t p);
.globl  PMull8x8r
PMull8x8r:
    eor     v0.16b, v0.16b, v0.16b
    eor     v1.16b, v1.16b, v1.16b
    mov     v0.d[0], x0
    eor     x0, x0, x0
    mov     v1.d[0], x1

rep1:
    pmull   v0.1q, v0.1d, v1.1d
    mov     x1, v0.d[0]
    mov     v1.d[0], x2
    eor     x0, x0, x1
    mov     x1, v0.d[1]
    mov     v0.d[0], v0.d[1]
    ands    x1, x1, x1
    bne     rep1

    ret
.size PMull8x8r,.-PMull8x8r

// Usage: void PMull64s(uint64_t* pData, uint32_t n, uint64_t p)
.globl  PMull64s
.type   PMull64s,@function
PMull64s:
    eor     v0.16b, v0.16b, v0.16b
    eor     v1.16b, v1.16b, v1.16b
    eor     x3, x3, x3
    mov     v1.d[0], x2

rep2:
    ldr     x2, [x0]
    mov     v0.d[0], x2
    pmull   v0.1q, v0.1d, v1.1d
    mov     x2, v0.d[0]
    eor     x2, x2, x3
    mov     x3, v0.d[1]
    str     x2, [x0]
    add     x0, x0, 8
    subs    x1, x1, 1
    bne     rep2

    ands    x3, x3, x3
    beq     done2
    str     x3, [x0]

done2:
    ret
.size PMull64s,.-PMull64s

// Usage: u128 PMull16x16(u128 a, u128 b, u128 r[2])
.globl  PMull16x16
.type   PMull16x16,@function
PMull16x16:
    mov     v1.d[0], x0
    mov     v1.d[1], x1
    eor     x1, x1, x0
    mov     v0.d[0], x2
    mov     v2.d[0], x3
    eor     x2, x2, x3

    pmull   v0.1q, v0.1d, v1.1d
    mov     x0, v0.d[0]
    str     x0, [x4]

    mov     v1.d[0], v1.d[1]
    pmull   v2.1q, v2.1d, v1.1d
    mov     x3, v2.d[1]
    str     x3, [x4,#24]

    mov     v1.d[0], x1
    mov     v3.d[0], x2
    pmull   v1.1q, v1.1d, v3.1d
    eor     v1.16b, v1.16b, v0.16b
    eor     v1.16b, v1.16b, v2.16b
    mov     x2, v1.d[0]
    mov     x1, v0.d[1]
    eor     x1, x1, x2
    str     x1, [x4,#8]

    mov     x2, v1.d[1]
    mov     x3, v2.d[0]
    eor     x2, x2, x3
    str     x2, [x4,#16]

    mov     x3, v2.d[1]
    ret
.size PMull16x16,.-PMull16x16

// Usage: u128 PMull16x16r(u128 a, u128 b, u128* p)
.globl  PMull16x16r
.type   PMull16x16r,@function
PMull16x16r:
    eor     v0.16b, v0.16b, v0.16b

    mov     v1.d[0], x0
    mov     v1.d[1], x1
    eor     x1, x1, x0

    mov     v3.d[0], x2
    mov     v2.d[0], x3

rep_2:
    eor     x2, x2, x3
    pmull   v3.1q, v3.1d, v1.1d

    mov     v1.d[0], v1.d[1]
    pmull   v2.1q, v2.1d, v1.1d

    mov     x0, v3.d[0]
    mov     v1.d[0], x1
    mov     v3.d[0], x2
    pmull   v1.1q, v1.1d, v3.1d
    mov     v3.d[0], x0
    eor     v1.16b, v1.16b, v3.16b
    eor     v1.16b, v1.16b, v2.16b

    ldr     x0, [x4]
    mov     x2, v1.d[0]
    mov     x1, v3.d[1]
    eor     x2, x2, x1
    mov     v3.d[1], x2
    ldr     x1, [x4,#8]
    eor     v0.16b, v0.16b, v3.16b

    mov     x2, v1.d[1]
    mov     x3, v2.d[0]
    mov     v1.d[0], x0
    eor     x2, x2, x3
    mov     v1.d[1], x1
    mov     v3.d[0], x2
    eor     x1, x1, x0

    mov     x3, v2.d[1]
    mov     v2.d[0], x3

    ands    x2, x2, x2
    bne     rep_2
    ands    x3, x3, x3
    bne     rep_2

    mov     x0, v0.d[0]
    mov     x1, v0.d[1]
    ret
.size PMull16x16r,.-PMull16x16r

// Usage: void PMull128s(u128* pData, uint32_t n, u128 p)
.globl  PMull128s
.type   PMull128s,@function
PMull128s:
    eor     v0.16b, v0.16b, v0.16b
    eor     v1.16b, v1.16b, v1.16b
    eor     v2.16b, v2.16b, v2.16b
    mov     v2.d[1], x3
    mov     v2.d[0], x2
    eor     x2, x2, x2
    eor     x3, x3, x3

rep3:
    ldr     x4, [x0]
    mov     v0.d[0], x4
    mov     v1.d[0], x4
    pmull   v0.1q, v0.1d, v2.1d
    mov     x4, v0.d[0]
    eor     x2, x2, x4
    str     x2, [x0]
    mov     x2, v0.d[1]
    add     x0, x0, 8
    eor     x2, x2, x3

    mov     v0.d[0], v2.d[1]
    pmull   v0.1q, v0.1d, v1.1d

    ldr     x4, [x0]
    mov     v1.d[0], x4
    pmull   v1.1q, v1.1d, v2.1d
    eor     v0.16b, v0.16b, v1.16b
    mov     x3, v0.d[0]
    eor     x2, x2, x3
    str     x2, [x0]
    mov     x2, v0.d[1]
    add     x0, x0, 8

    mov     v0.d[0], v2.d[1]
    mov     v1.d[0], x4
    pmull   v0.1q, v0.1d, v1.1d
    mov     x3, v0.d[0]
    eor     x2, x2, x3
    mov     x3, v0.d[1]

    subs    x1, x1, 1
    bne     rep3

    orr     x4, x2, x3
    ands    x4, x4, x4
    beq     done3
    eor     x4, x4, x4

    str     x2, [x0]
    str     x3, [x0,8]

done3:
    ret
.size PMull128s,.-PMull128s

