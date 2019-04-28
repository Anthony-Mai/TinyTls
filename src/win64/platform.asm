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

_DATA SEGMENT
_DATA ENDS

_TEXT SEGMENT

; Usage: uint64_t rd_clk();
PUBLIC rd_clk
rd_clk PROC
  rdtsc
  shl rdx, 32
  or rax, rdx
  ret
rd_clk ENDP

; Usage: uint32_t leadz32(uint32_t v);
PUBLIC leadz32
leadz32 PROC  
  lzcnt eax, ecx
  ret
leadz32 ENDP

; Usage: uint32_t leadz64(uint64_t v);
PUBLIC leadz64
leadz64 PROC
  lzcnt rax, rcx
  ret
leadz64 ENDP

; Usage: uint64_t PMull8x8r(uint64_t a, uint64_t b, uint64_t p);
PUBLIC PMull8x8r
PMull8x8r PROC
  movd xmm0, rcx
  movd xmm1, rdx
  pclmullqlqdq xmm0, xmm1
  movd xmm1, r8
  movd rax, xmm0
  psrldq xmm0, 8

rep1:
  pshufd xmm0, xmm0, 44h
  movd rcx, xmm0
  psrldq xmm0, 8
  or rcx, rcx
  jz  done1

  pclmullqlqdq xmm0, xmm1
  movd rcx, xmm0
  psrldq xmm0, 8
  xor  rax, rcx
  jmp short rep1

done1:
  emms
  ret
PMull8x8r ENDP

; Usage: uint64_t PMull8x8(uint64_t a, uint64_t b, uint64_t r[2])
PUBLIC PMull8x8
PMull8x8 PROC
  sub  rsp, 32
  movups [rsp], xmm0
  movups [rsp+16], xmm1
  movd xmm0, rcx
  movd xmm1, rdx
  pclmullqlqdq xmm0, xmm1
  movd rax, xmm0
  movups [r8], xmm0
  ;;psrldq xmm0, 8
  pshufd xmm0, xmm0, 4eh
  movd rdx, xmm0
  movups xmm1, [rsp+16]
  movups xmm0, [rsp]
  add rsp, 32
  emms
  ret
PMull8x8 ENDP

; Usage: void PMull64s(uint64_t* pData, uint32 n, uint64_t p);
PUBLIC PMull64s
PMull64s PROC
  xor rdx, rcx
  xor rcx, rdx
  xor rdx, rcx
  movd xmm0, r8

rep001:
  movups xmm1, [rdx]
  movups xmm2, xmm1
  pshufd xmm0, xmm0, 4eh
  psrldq xmm2, 8
  pshufd xmm2, xmm2, 4eh
  psrldq xmm0, 8
  por    xmm0, xmm2

  pclmullqlqdq xmm1, xmm0
  pxor xmm1, xmm3
  movd rax, xmm1
  mov [rdx], rax
  psrldq xmm1, 8
  add rdx, 8
  dec rcx
  jz  rep_done

  movups xmm2, xmm0
  pclmulhqlqdq xmm2, xmm2
  pxor xmm1, xmm2
  movd rax, xmm1
  mov [rdx], rax
  psrldq xmm1, 8
  movups xmm3, xmm1
  add  rdx, 8
  loop rep001

rep_done:
  movd rax, xmm1
  mov [rdx], rax
  psrldq xmm1, 8
  add rdx, 8

  emms
  ret
PMull64s ENDP

; Usage: u128 PMull16x16(u128 a, u128 b, u128 r[2]);
PUBLIC PMull16x16
PMull16x16 PROC
  push rbp
  mov rbp, rsp

  ;; Upon entry into the Win32 function:
  ;;   [esp+0] is return address. [esp+4] is pointer to return value.
  ;;   [esp+8] is first parameter of 16 bytes.
  ;;   [esp+24] is second parameter of 16 bytes.
  ;;   [esp+40] is third parameter of 4 bytes
  movups xmm1, [rdx] ; Parameter a
  movups xmm2, [r8] ; Parameter b
  ;;;; Parameter r is r9
  movdqa xmm0, xmm1
  pclmulhqhqdq xmm0, xmm2
  movups [r9+16], xmm0
  movdqa xmm0, xmm1
  pclmullqlqdq xmm0, xmm2
  movups [r9+0], xmm0
  movq xmm0, xmm1
  psrldq xmm1, 8
  pxor xmm1, xmm0
  movq xmm0, xmm2
  psrldq xmm2, 8
  pxor xmm2, xmm0
  movups xmm0, [r9+0]
  pclmullqlqdq xmm1, xmm2
  movups xmm2, [r9+16]
  pxor xmm1, xmm0
  movups xmm0, [r9+8]
  pxor xmm1, xmm2
  pxor xmm1, xmm0
  movups [r9+8], xmm1
  movups xmm0, [r9+0]
  mov rax, rcx
  movups [rax], xmm0

  emms
  pop rbp
  ret
PMull16x16 ENDP

; Usage: PMull16x16r(u128 a, u128 b, u128* p);
PUBLIC PMull16x16r
PMull16x16r PROC
  push rbp
  mov rbp, rsp

  ;; Upon entry into the Win64 function:
  ;;   rcx is pointer to the return value.
  ;;   rdx is pointer to 1st parameter of 16 bytes.
  ;;   r8 is pointer to 2nd parameter of 16 bytes.
  ;;   r9 is 3rd parameter which is pointer to p
  pxor xmm0, xmm0
  movups [rcx], xmm0

  movups xmm1, [rdx] ; Parameter a
  movups xmm2, [r8]  ; Parameter b

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

  movups xmm0, [rcx]
  pxor xmm4, xmm0
  movups [rcx], xmm4

  ;; If xmm3 is zero we are done.
  movdqa xmm1, xmm3
  pshufd xmm0, xmm3, 4eh
  por xmm0, xmm3
  movups xmm2, [r9] ; Parameter p
  movd rax, xmm0
  or rax, rax
  jnz rep_2

  mov rax, rcx
  emms
  pop rbp
  ret
PMull16x16r ENDP

_TEXT ENDS
END
