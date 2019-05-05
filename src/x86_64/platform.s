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

.globl   rd_clk
.type    rd_clk,@function
.align   16
rd_clk:
  rdtsc
  shl    $32, %rdx
  or     %rdx, %rax
  ret
.size    rd_clk,.-rd_clk

// Count leading 0 bits. Usage: uint32_t leadz32(uint32_t v);
.globl   leadz32
.type    leadz32,@function
.align   16
leadz32:
  lzcnt  %rdi, %rax
  ret
.size    leadz32,.-leadz32

// Count leading 0 bits. Usage: uint32_t leadz64(uint64_t v);
.globl   leadz64
.type    leadz64,@function
.align   16
leadz64:
  lzcnt  %rdi, %rax
  ret
.size    leadz64,.-leadz64

// Polynomial product of 64 bits x 64 bits produce 128 bits.
// Usage: uint64_t PMull8x8(uint64_t a, uint64_t b, uint64_t r[2]);
.globl   PMull8x8
.type    PMull8x8,@function
.align   16
PMull8x8:
  movd   %rdi, %xmm0
  movd   %rsi, %xmm1
  pclmullqlqdq %xmm1, %xmm0
  movd   %xmm0, %rax
  movups %xmm0, (%rdx)
  pshufd $0x4e, %xmm0, %xmm0
  movd   %xmm0, %rdx
  emms
  ret
.size    PMull8x8,.-PMull8x8

// Polynomial product of 64 bits x 64 bits then reduced by 65 bits p.
// Usage: uint64_t PMull8x8r(uint64_t a, uint64_t b, uint64_t p);
.globl   PMull8x8r
.type    PMull8x8r,@function
.align   16
PMull8x8r:
  movd   %rdi, %xmm0
  movd   %rsi, %xmm1
  pclmullqlqdq %xmm1, %xmm0
  movd   %rdx, %xmm1
  movd   %xmm0, %rax
  psrldq $8, %xmm0

rep1:
  pshufd $0x44, %xmm0, %xmm0
  movd   %xmm0, %rdx
  psrldq $8, %xmm0
  or     %rdx, %rdx
  jz     done1

  pclmullqlqdq %xmm1, %xmm0
  movd   %xmm0, %rdx
  psrldq $8, %xmm0
  xor    %rdx, %rax
  jmp    rep1

done1:
  emms
  ret
.size    PMull8x8r,.-PMull8x8r

// Usage: void PMull64s(uint64_t* pData, uint32_t n, uint64_t p)
.globl   PMull64s
.type    PMull64s,@function
.align   16
PMull64s:
  movd   %rdx, %xmm0
  mov    %rdi, %rdx
  mov    %rsi, %rcx

rep_1:
  movups (%rdx),%xmm1
  movups %xmm1,%xmm2
  pshufd $0x4E,%xmm0,%xmm0
  psrldq $8,   %xmm2
  pshufd $0x4E,%xmm2,%xmm2
  psrldq $8, %xmm0
  por    %xmm2,%xmm0

  pclmullqlqdq %xmm0,%xmm1
  pxor   %xmm3,%xmm1
  movd   %xmm1,%rax
  mov    %rax, (%rdx)
  psrldq $8,   %xmm1
  add    $8,   %rdx
  dec    %rcx
  jz     rep_done

  movups %xmm0,%xmm2
  pclmulhqlqdq %xmm2,%xmm2
  pxor   %xmm2,%xmm1
  movd   %xmm1,%rax
  mov    %rax, (%rdx)
  psrldq $8,   %xmm1
  movups %xmm1,%xmm3
  add    $8,   %rdx
  loop   rep_1

rep_done:
  movd   %xmm1,%rax
  mov    %rax,(%rdx)
  psrldq $8,   %xmm1
  add    $8,   %rdx

  emms
  ret
.size    PMull64s,.-PMull64s

// Polynomial product of 128 x 128 bits for 256 bits.
// Usage: u128 PMull16x16(u128 a, u128 b, u128 r[2]);
.globl   PMull16x16
.type    PMull16x16,@function
.align   16
PMull16x16:
  push   %rbp
  mov    %rsp, %rbp

  movd   %rsi, %xmm0
  movd   %rcx, %xmm2
  pclmullqlqdq %xmm2,%xmm0
  movups %xmm0,0x10(%r8)
  movd   %rdi, %xmm0
  movd   %rdx, %xmm2
  pclmullqlqdq %xmm2,%xmm0
  movups %xmm0,(%r8)
  xor    %rsi, %rdi
  xor    %rcx, %rdx
  movd   %rdi, %xmm1
  movd   %rdx, %xmm2
  pclmullqlqdq %xmm2, %xmm1
  movups 0x10(%r8), %xmm2
  pxor   %xmm0, %xmm1
  movups 0x8(%r8), %xmm0
  pxor   %xmm2, %xmm1
  pxor   %xmm1, %xmm0
  movups %xmm0, 0x8(%r8)
  movups (%r8), %xmm0
  movd   %xmm0, %rax
  pshufd $0x4e, %xmm0, %xmm0
  movd   %xmm0, %rdx
  pshufd $0x4e, %xmm0, %xmm0

  emms
  pop    %rbp
  ret
.size    PMull16x16,.-PMull16x16

// Polynomial product of 128 x 128 bits & reduce by p.
// Usage: u128 PMull16x16(u128 a, u128 b, u128* p);
.globl   PMull16x16r
.type    PMull16x16r,@function
.align   16
PMull16x16r:
  push   %rbp
  mov    %rsp, %rbp

  pxor   %xmm5,%xmm5

  movd   %rsi, %xmm1
  movd   %rdi, %xmm0
  pslldq $0x8, %xmm1
  por    %xmm0,%xmm1
  movd   %rcx, %xmm2
  movd   %rdx, %xmm3
  pslldq $0x8, %xmm2
  por    %xmm3,%xmm2

rep_2:
  movdqa %xmm1,%xmm0
  pclmulhqhqdq %xmm2,%xmm0
  movdqa %xmm0,%xmm3
  movdqa %xmm1,%xmm0
  pclmullqlqdq %xmm2,%xmm0
  movdqa %xmm0,%xmm4
  movq   %xmm1,%xmm0
  psrldq $0x8, %xmm1
  pxor   %xmm0,%xmm1
  movq   %xmm2,%xmm0
  psrldq $0x8, %xmm2
  pxor   %xmm0,%xmm2
  pclmullqlqdq %xmm2,%xmm1
  pxor   %xmm4,%xmm1
  pxor   %xmm3,%xmm1
  movdqa %xmm1,%xmm0
  pslldq $0x8, %xmm1
  pxor   %xmm1,%xmm4
  psrldq $0x8, %xmm0
  pxor   %xmm0,%xmm3

  pxor   %xmm4,%xmm5

  movdqa %xmm3,%xmm1
  pshufd $0x4E,%xmm3,%xmm0
  por    %xmm3,%xmm0
  movups (%r8),%xmm2
  movd   %xmm0,%rax
  or     %rax,%rax
  jnz    rep_2

  movd   %xmm5,%rax
  psrldq $0x8,%xmm5
  movd   %xmm5,%rdx
  emms
  pop    %rbp
  ret
.size    PMull16x16r,.-PMull16x16r

// Usage: void PMull128s(u128* pData, uint32 n, u128 p)
.globl   PMull128s
.type    PMull128s,@function
.align   16
PMull128s:
  push   %rbp
  mov    %rsp, %rbp
  movd   %rcx, %xmm2
  pslldq $8, %xmm2
  movd   %rdx, %xmm0
  por    %xmm0, %xmm2
  mov    %rdi, %rdx
  mov    %rsi, %rcx
  pxor   %xmm3,%xmm3

rep_3:
  movups (%rdx),%xmm0
  movups %xmm0, %xmm1
  pclmullqlqdq %xmm2,%xmm0
  pxor   %xmm0,%xmm3
  movups %xmm1,%xmm0

  movd   %xmm3,%rax
  psrldq $8,   %xmm3
  mov    %rax, (%rdx)
  add    $8,   %rdx

  pclmullqhqdq %xmm2,%xmm0
  pxor   %xmm0,%xmm3
  movups %xmm1,%xmm0
  pclmulhqlqdq %xmm2,%xmm0
  pxor   %xmm0,%xmm3

  movd   %xmm3,%rax
  psrldq $8, %xmm3
  mov    %rax, (%rdx)
  add    $8, %rdx

  pclmulhqhqdq %xmm2,%xmm1
  pxor   %xmm1,%xmm3
  loop   rep_3

rep3_done:
  movups %xmm3, (%rdx)
  add    $16, %rdx

  emms
  pop    %rbp
  ret
.size    PMull128s,.-PMull128s

// Usage: u128 PShl128c(u128 data, uint32_t n)
.globl    PShl128c
.type     PShl128c,@function
.align    16
PShl128c:
  mov    %rdx, %rcx
  mov    %rsi, %rdx
  mov    %rdi, %rax

sh_0:
  cmp    $64,  %cx
  jb     sh_1
  mov    %rax, %rdx
  xor    %rax, %rax
  sub    $64,  %cx
  jmp    sh_0

sh_1:
  shld   %cl,  %rax, %rdx
  shl    %cl,  %rax

  ret
.size     PShl128c,.-PShl128c

// Usage: u128* PShl128r(u128* pData, uint32_t n)
.globl    PShl128r
.type     PShl128r,@function
.align    16
PShl128r:
  push   %rcx

  mov    %rsi, %rcx
  mov    (%rdi), %rax
  mov    8(%rdi), %rsi

sh_2:
  cmp    $64,  %cx
  jb     sh_3
  mov    %rax, %rsi
  xor    %rax, %rax
  sub    $64,  %cx
  jmp    sh_2

sh_3:
  shld   %cl,  %rax, %rsi
  shl    %cl,  %rax
  mov    %rsi, 8(%rdi)
  mov    %rax, (%rdi)

  mov    %rdi, %rax

  pop    %rcx
  ret
.size     PShl128r,.-PShl128r

