;******************************************************************************
;
; Copyright © 2018-2019 Anthony Mai Mai_Anthony@hotmail.com. All Rights Reserved.
;
; This file is a part of the software package TinyTls, originally known as TinySsl.
; This software is written by Anthony Mai and is provided under the terms and
; conditions of the GNU General Public License Version 3.0 (GPL V3.0). For the
; specific GPL V3.0 license terms please refer to:
;         https://www.gnu.org/licenses/gpl.html.
;
; This Copyright Notices contained in this code. are NOT to be removed or modified.
; If this package is used in a product, Anthony Mai should be given attribution as
; the author of the parts of the library used. This can be in the form of a textual
; message at program startup or in documentation provided with the package.
;
; This library is free for commercial and non-commercial use as long as the
; following conditions are aheared to. The following conditions apply to
; all code found in this distribution:
;
; 1. Redistributions of source code must retain the copyright notice, this
;    list of conditions and the following disclaimer.
;
; 2. Redistributions in binary form must reproduce the above copyright
;    notice, this list of conditions and the following disclaimer in the
;    documentation and/or other materials provided with the distribution.
;
; 3. All advertising materials mentioning features or use of this software
;    must display the following acknowledgement:
;
;    "This product contains software written by Anthony Mai (Mai_Anthony@hotmail.com)
;     The original source code can obtained from such and such internet sites or by
;     contacting the author directly."
;
; 4. This software may or may not contain patented technology owned by a third party.
;    Obtaining a copy of this software, with or without explicit authorization from
;    the author, does NOT imply that applicable patents have been licensed. It is up
;    to you to make sure that utilization of this software package does not infringe
;    on any third party's patents or other intellectual proerty rights.
;
; THIS SOFTWARE IS PROVIDED BY ANTHONY MAI "AS IS". ANY EXPRESS OR IMPLIED WARRANTIES,
; INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
; FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
; BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
; THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
; NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
; IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;
; The license and distribution terms for any publically available version or derivative
; of this code cannot be changed.  i.e. this code cannot simply be copied and put under
; another distribution license [including the GNU Public License.]
;
;*******************************************************************************

.686P
.XMM
.model	flat

_DATA SEGMENT
_DATA ENDS

_TEXT SEGMENT

; Usage: uint64_t rd_clk();
PUBLIC _rd_clk
_rd_clk PROC
  rdtsc
  ret
_rd_clk ENDP

; Usage: uint32_t leadz32(uint32_t v);
PUBLIC _leadz32
_leadz32 PROC
  mov   eax, [esp+4]
  lzcnt eax, eax
  ret
_leadz32 ENDP

; Usage: uint32_t leadz64(uint64_t v)
PUBLIC _leadz64
_leadz64 PROC
  mov   eax, [esp+8]
  or    eax, eax
  jz    ld2
  lzcnt eax, eax
  ret
ld2:
  mov   eax, [esp+4]
  lzcnt eax, eax
  add   eax, 32
  ret
_leadz64 ENDP

; Usage: uint64_t PMull8x8r(uint64_t a, uint64_t b, uint64_t p);
PUBLIC _PMull8x8r
_PMull8x8r PROC
  movups xmm0, [esp+4]
  movups xmm1, [esp+12]
  push ecx
  push ebx
  pclmulhqlqdq xmm0, xmm0
  psrldq xmm1, 8
  movd eax, xmm0
  psrldq xmm0, 4
  movd edx, xmm0
  psrldq xmm0, 4

rep1:
  pshufd xmm0, xmm0, 44h
  movd ebx, xmm0
  psrldq xmm0, 4
  movd ecx, xmm0
  psrldq xmm0, 4
  or  ebx, ecx
  jz  done1
  pclmullqlqdq xmm0, xmm1
  movd ebx, xmm0
  psrldq xmm0, 4
  xor  eax, ebx
  movd ecx, xmm0
  psrldq xmm0, 4
  xor  edx, ecx
  jmp short rep1

done1:
  pop  ebx
  pop  ecx
  emms
  ret
_PMull8x8r ENDP

; Usage: uint64_t PMull8x8(uint64_t a, uint64_t b, uint64_t r[2])
PUBLIC _PMull8x8
_PMull8x8 PROC
  movups xmm0, [esp+4]
  pclmulhqlqdq xmm0, xmm0
  mov  edx, [esp+20]
  movd eax, xmm0
  movups [edx], xmm0
  psrldq xmm0, 4
  movd edx, xmm0
  emms
  ret
_PMull8x8 ENDP

; Usage: void PMull64s(uint64_t* pData, uint32 n, uint64_t p)
PUBLIC _PMull64s
_PMull64s PROC
  push   ebp
  mov    ebp, esp
  movups xmm0, [ebp+8]
  movd edx, xmm0
  psrldq xmm0, 4
  movd ecx, xmm0
  psrldq xmm0, 4
  pxor xmm3, xmm3

rep_1:
  movups xmm1, [edx]
  movups xmm2, xmm1
  pshufd xmm0, xmm0, 4eh
  psrldq xmm2, 8
  pshufd xmm2, xmm2, 4eh
  psrldq xmm0, 8
  por    xmm0, xmm2

  pclmullqlqdq xmm1, xmm0
  pxor xmm1, xmm3
  movd eax, xmm1
  mov [edx], eax
  psrldq xmm1, 4
  movd eax, xmm1
  mov [edx+4], eax
  psrldq xmm1, 4

  add edx, 8
  dec ecx
  jz  rep_done

  movups xmm2, xmm0
  pclmulhqlqdq xmm2, xmm2
  pxor xmm1, xmm2
  movd eax, xmm1
  mov [edx], eax
  psrldq xmm1, 4
  movd eax, xmm1
  mov [edx+4], eax
  psrldq xmm1, 4
  movups xmm3, xmm1

  add  edx, 8
  loop rep_1

rep_done:
  movd eax, xmm1
  mov [edx], eax
  psrldq xmm1, 4
  movd eax, xmm1
  mov [edx+4], eax
  psrldq xmm1, 4

  emms
  pop    ebp
  ret
_PMull64s ENDP

; Usage: u128 PMull16x16(u128 a, u128 b, u128 r[2]);
PUBLIC _PMull16x16
_PMull16x16 PROC
  push ebp
  mov ebp, esp

  movups xmm1, [ebp+12] ; Parameter a
  movups xmm2, [ebp+28] ; Parameter b

  movdqa xmm0, xmm1
  pclmulhqhqdq xmm0, xmm2
  movdqa xmm3, xmm0
  movdqa xmm0, xmm1
  pclmullqlqdq xmm0, xmm2
  movdqa xmm4, xmm0
  movq xmm0, xmm1
  psrldq xmm1, 8
  pxor xmm1, xmm0
  movq xmm0, xmm2
  psrldq xmm2, 8
  pxor xmm2, xmm0
  pclmullqlqdq xmm1, xmm2
  pxor xmm1, xmm4
  pxor xmm1, xmm3
  mov eax, [ebp+44]
  movdqa xmm0, xmm1
  pslldq xmm1, 8
  pxor xmm4, xmm1
  movups [eax], xmm4
  psrldq xmm0, 8
  pxor xmm3, xmm0
  movups [eax+16], xmm3

  mov eax, [ebp+8]
  movups [eax], xmm4

  emms
  pop ebp
  ret
_PMull16x16 ENDP

; Usage: u128 PMull16x16r(u128 a, u128 b, u128* p);
PUBLIC _PMull16x16r
_PMull16x16r PROC
  push ebp
  mov ebp, esp

  pxor xmm0, xmm0
  mov eax, [ebp+8]
  movups [eax], xmm0

  movups xmm1, [ebp+12] ; Parameter a
  movups xmm2, [ebp+28] ; Parameter b

rep_2:
  movdqa xmm0, xmm1
  pclmulhqhqdq xmm0, xmm2
  movdqa xmm3, xmm0
  movdqa xmm0, xmm1
  pclmullqlqdq xmm0, xmm2
  movdqa xmm4, xmm0
  movq xmm0, xmm1
  psrldq xmm1, 8
  pxor xmm1, xmm0
  movq xmm0, xmm2
  psrldq xmm2, 8
  pxor xmm2, xmm0
  pclmullqlqdq xmm1, xmm2
  pxor xmm1, xmm4
  pxor xmm1, xmm3
  movdqa xmm0, xmm1
  pslldq xmm1, 8
  pxor xmm4, xmm1
  psrldq xmm0, 8
  pxor xmm3, xmm0

  mov eax, [ebp+8]
  movups xmm0, [eax]
  pxor xmm4, xmm0
  movups [eax], xmm4

  movdqa xmm1, xmm3
  pshufd xmm0, xmm3, 4eh
  mov eax, [ebp+44] ;; Parameter p
  por xmm0, xmm3
  movups xmm2, [eax]
  movdqa xmm3, xmm0
  pshufd xmm0, xmm0, 0b1h
  por xmm0, xmm3
  movd eax, xmm0
  or eax, eax
  jnz rep_2

  mov eax, [ebp+8]
  emms
  pop ebp
  ret
_PMull16x16r ENDP

_TEXT ENDS
END
