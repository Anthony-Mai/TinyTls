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
.align  16
rd_clk:
    mrrc    15, 1, r0, r1, cr14
    bx      lr
.size   rd_clk,.-rd_clk

// Count leading 0 bits. Usage: uint32_t leadz32(uint32_t v);
.globl  leadz32
.align  16
leadz32:
    clz     r0, r0
    bx      lr
.size   leadz32,.-leadz32

// Count leading 0 bits. Usage: uint32_t leadz64(uint64_t v);
.globl  leadz64
.align  16
leadz64:
    clz     r1, r1
    cmp     r1, #0x20
    beq     isb32
    mov     r0, r1
    eor     r1, r1
    bx      lr
isb32:
    clz     r0, r0
    add     r0, r1
    eor     r1, r1
    bx      lr
.size   leadz64,.-leadz64

.globl  armv7_neon_probe
.align  16
armv7_neon_probe:
    ;.inst 0xf2200150 @ vorr    q0, q0, q0
    vorr    q0, q0, q0
    bx      lr
.size armv7_neon_probe,.-armv7_neon_probe

.globl  armv8_aes_probe
armv8_aes_probe:
    .inst 0xf3b00300 @ aese.8  q0, q0
    bx      lr
.size armv8_aes_probe,.-armv8_aes_probe

.globl  armv8_sha1_probe
armv8_sha1_probe:
    .inst 0xf2000c40 @ sha1c.32 q0, q0, q0
    bx      lr
.size armv8_sha1_probe,.-armv8_sha1_probe

.globl  armv8_sha256_probe
armv8_sha256_probe:
    .inst 0xf3000c40 @ sha256h.32 q0, q0, q0
    bx      lr
.size armv8_sha256_probe,.-armv8_sha256_probe

.globl  armv8_pmull_probe
armv8_pmull_probe:
    .inst 0xf2a00e00 @ vmull.p64 q0, d0, d0
    bx      lr
.size armv8_pmull_probe,.-armv8_pmull_probe

// Polynomial product of 64 bits x 64 bits produce 128 bits.
// See https://conradoplg.cryptoland.net/files/2010/12/mocrysen13.pdf
// and https://conradoplg.cryptoland.net/software/ecc-and-ae-for-arm-neon/
// I think my code is better than the one from Conrado P. L. Gouvea et al.
// Usage: uint64_t PMull8x8(uint64_t a, uint64_t b, uint64_t r[2]);
.globl  PMull8x8
PMull8x8:
    vpush       {q0 - q3}       @ Preserve registers q0-q3
    vmov        d0, r0, r1      @ First 64 bits argument a
    vmov        d1, r2, r3      @ Second 64 bit argument b
    vmull.p8    q1, d0, d1      @ b0-15

    vext.8      d1, d1, d1, #1
    vmull.p8    q2, d0, d1      @ b1-14,b7-8
    vext.8      d1, d1, d1, #6
    vext.8      q2, q2, q2, #14 @ b7-8,b1-14
    vmull.p8    q3, d0, d1      @ b7-8,b1-14
    veor        q2, q2, q3      @ b7-8,b1-14
    veor        q3, q3, q3      @ 0000000000000000
    vext.8      q3, q3, q2, #2  @ 00000000000000,b7-8
    vext.8      q2, q2, q2, #1  @ b8,b1-14,b7
    vext.8      q3, q3, q3, #7  @ 0000000,b7-8,0000000
    veor        q2, q2, q3      @ b8,b1-14,b7
    vext.8      q3, q3, q3, #8  @ b8,00000000000000,b7
    veor        q2, q2, q3      @ 0,b1-b14,0
    veor        q1, q1, q2

    vext.8      d1, d1, d1, #3
    vmull.p8    q2, d0, d1      @ b2-13,b6-9
    vext.8      d1, d1, d1, #4
    vext.8      q2, q2, q2, #12 @ b6-9,b2-13
    vmull.p8    q3, d0, d1      @ b6-9,b2-13
    veor        q2, q2, q3      @ b6-9,b2-13
    veor        q3, q3, q3      @ 0000000000000000
    vext.8      q3, q3, q2, #4  @ 000000000000,b6-9
    vext.8      q2, q2, q2, #2  @ b8-9,b2-13,b6-7
    vext.8      q3, q3, q3, #6  @ 000000,b6-9,000000
    veor        q2, q2, q3
    vext.8      q3, q3, q3, #8  @ b8-9,000000000000,b6-7
    veor        q2, q2, q3      @ 00,b2-13,00
    veor        q1, q1, q2

    vext.8      d1, d1, d1, #5
    vmull.p8    q2, d0, d1      @ b3-12,b5-10
    vext.8      d1, d1, d1, #2
    vext.8      q2, q2, q2, #10 @ b5-10,b3-12
    vmull.p8    q3, d0, d1      @ b5-10,b3-12
    veor        q2, q2, q3      @ b5-10,b3-12
    veor        q3, q3, q3      @ 0000000000000000
    vext.8      q3, q3, q2, #6  @ 0000000000,b5-10
    vext.8      q2, q2, q2, #3  @ b8-10,b3-12,b5-7
    vext.8      q3, q3, q3, #5  @ 00000,b5-10,00000
    veor        q2, q2, q3
    vext.8      q3, q3, q3, #8  @ b8-10,0000000000,b5-7
    veor        q2, q2, q3      @ 000,b3-12,000
    veor        q1, q1, q2

    vext.8      d1, d1, d1, #7
    vmull.p8    q2, d0, d1      @ b4-11,b4-11
    vext.8      q3, q2, q2, #8
    veor        q3, q2, q3      @ b4-11,b4-11
    veor        q2, q2, q2
    vext.8      q2, q2, q3, #8  @ 00000000,b4-11
    vext.8      q2, q2, q2, #4  @ 0000,b4-11,0000
    veor        q1, q1, q2      @ Final 128 bits result

    ldr         r3, [sp, #64]   @ 64 is space to preserve q0-q3
    vst1.64     {d2-d3}, [r3]   @ Store 128 bits result in r[2]

    vmov        r0, r1, d2      @ Directly return 128 bits result
    vmov        r2, r3, d3      @ for callers who can access it.

    vpop        {q0 - q3}       @ restore registers q0-q3
    bx          lr
.size PMull8x8,.-PMull8x8

