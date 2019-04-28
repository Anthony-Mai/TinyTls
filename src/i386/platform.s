.text	

.globl  rd_clk
.type   rd_clk,@function
.align  16
rd_clk:
    rdtsc
    ret
.size   rd_clk,.-rd_clk

// Count leading 0 bits. Usage: uint32_t leadz32(uint32_t v);
.globl  leadz32
.type   leadz32,@function
.align  16
leadz32:
    mov  0x04(%esp), %eax
    lzcnt %eax, %eax
    ret
.size   leadz32,.-leadz32

// Count leading 0 bits. Usage: uint32_t leadz64(uint64_t v);
.globl  leadz64
.type   leadz64,@function
.align  16
leadz64:
    mov  0x08(%esp), %eax
    lzcnt %eax, %eax
    cmp  $0x20, %eax
    je   isb32
    ret
isb32:
    mov  0x04(%esp), %eax
    lzcnt %eax, %eax
    add  $0x20, %eax
    ret
.size   leadz64,.-leadz64

// Polynomial product of 64 bits x 64 bits produce 128 bits.
// Usage: uint64_t PMull8x8(uint64_t a, uint64_t b, uint64_t r[2]);
.globl  PMull8x8
.type   PMull8x8,@function
.align  16
PMull8x8:
    movups 0x04(%esp), %xmm0
    pclmulqdq $1, %xmm0, %xmm0
    mov  0x14(%esp), %edx
    movd %xmm0, %eax
    movups %xmm0, (%edx)
    psrldq $4, %xmm0
    movd %xmm0, %edx
    emms
    ret
.size   PMull8x8,.-PMull8x8


// Polynomial product of 64 bits x 64 bits then reduced by 65 bits p.
// Usage: uint64_t PMull8x8r(uint64_t a, uint64_t b, uint64_t p);
.globl  PMull8x8r
.type   PMull8x8r,@function
.align  16
PMull8x8r:
    movups 0x04(%esp), %xmm0
    movups 0x0c(%esp), %xmm1
    push %ecx
    push %ebx
    pclmulhqlqdq %xmm0, %xmm0
    psrldq $8, %xmm1
    movd %xmm0, %eax
    psrldq $4, %xmm0
    movd %xmm0, %edx
    psrldq $4, %xmm0

rep1:
    pshufd $0x44, %xmm0, %xmm0
    movd %xmm0, %ebx
    psrldq $4, %xmm0
    movd %xmm0, %ecx
    psrldq $4, %xmm0
    or %ecx, %ebx
    jz done1

    pclmullqlqdq %xmm1, %xmm0
    movd %xmm0, %ebx
    psrldq $4, %xmm0
    xor %ebx, %eax
    movd %xmm0, %ecx
    psrldq $4, %xmm0
    xor %ecx, %edx
    jmp rep1

done1:
    pop %ebx
    pop %ecx
    emms
    ret
.size   PMull8x8r,.-PMull8x8r

// Usage: void PMull64s(uint64_t* pData, uint32_t n, uint64_t p)
.globl  PMull64s
.type   PMull64s,@function
.align  16
PMull64s:
    push   %ebp
    mov    %esp, %ebp
    movups 0x08(%ebp),%xmm0
    movd   %xmm0,%edx
    psrldq $4, %xmm0
    movd   %xmm0,%ecx
    psrldq $4, %xmm0
    pxor   %xmm3,%xmm3

rep_1:
    movups (%edx),%xmm1
    movups %xmm1,%xmm2
    pshufd $0x4E,%xmm0,%xmm0
    psrldq $8,%xmm2
    pshufd $0x4E,%xmm2,%xmm2
    psrldq $8,%xmm0
    por    %xmm2,%xmm0

    pclmullqlqdq %xmm0,%xmm1
    por    %xmm3,%xmm1
    movd   %xmm1,%eax
    mov    %eax,(%edx)
    psrldq $4, %xmm1
    movd   %xmm1,%eax
    mov    %eax,0x4(%edx)
    psrldq $4, %xmm1

    add    $8, %edx
    dec    %ecx
    jz     rep_done

    movups %xmm0,%xmm2
    pclmulhqlqdq %xmm2,%xmm2
    por    %xmm2,%xmm1
    movd   %xmm1,%eax
    mov    %eax, (%edx)
    psrldq $4, %xmm1
    movd   %xmm1,%eax
    mov    %eax, 0x4(%edx)
    psrldq $4, %xmm1
    movups %xmm1,%xmm3

    add    $8, %edx
    loop   rep_1

rep_done:
    movd   %xmm1,%eax
    mov    %eax, (%edx)
    psrldq $4, %xmm1
    movd   %xmm1,%eax
    mov    %eax, 0x4(%edx)
    psrldq $4, %xmm1

    emms
    pop    %ebp
    ret
.size   PMull64s,.-PMull64s

// Polynomial product of 128 x 128 bits for 256 bits.
// Usage: u128 PMull16x16(u128 a, u128 b, u128 r[2]);
.globl  PMull16x16
.type   PMull16x16,@function
.align  16
PMull16x16:
    push   %ebp
    mov    %esp, %ebp
    movups 0x0C(%ebp),%xmm1
    movups 0x1C(%ebp),%xmm2

    movdqa %xmm1,%xmm0
    pclmulhqhqdq %xmm2,%xmm0
    movdqa %xmm0,%xmm3
    movdqa %xmm1,%xmm0
    pclmullqlqdq %xmm2,%xmm0
    movdqa %xmm0,%xmm4
    movdqa %xmm1,%xmm0
    psrldq $0x8,%xmm1
    pxor   %xmm0,%xmm1
    movdqa %xmm2,%xmm0
    psrldq $0x8,%xmm2
    pxor   %xmm0,%xmm2
    pclmullqlqdq %xmm2,%xmm1
    pxor   %xmm4,%xmm1
    pxor   %xmm3,%xmm1
    mov    0x2C(%ebp),%eax
    movdqa %xmm1,%xmm0
    pslldq $0x8,%xmm1
    pxor   %xmm1,%xmm4
    movups %xmm4,(%eax)
    psrldq $0x8,%xmm0
    pxor   %xmm0,%xmm3
    movups %xmm3,0x10(%eax)

    mov    0x8(%ebp),%eax
    movups %xmm4,(%eax)

    emms
    pop    %ebp
    ret    $4
.size   PMull16x16,.-PMull16x16

// Polynomial product of 128 x 128 bits & reduce by 128 bits p.
// Usage: u128 PMull16x16(u128 a, u128 b, u128* p);
.globl  PMull16x16r
.type   PMull16x16r,@function
.align  16
PMull16x16r:
    push   %ebp
    mov    %esp, %ebp

    pxor   %xmm0,%xmm0
    mov    0x08(%ebp),%eax
    movups %xmm0,(%eax)

    movups 0x0C(%ebp),%xmm1
    movups 0x1C(%ebp),%xmm2

rep_2:
    movdqa %xmm1,%xmm0
    pclmulhqhqdq %xmm2,%xmm0
    movdqa %xmm0,%xmm3
    movdqa %xmm1,%xmm0
    pclmullqlqdq %xmm2,%xmm0
    movdqa %xmm0,%xmm4
    movdqa %xmm1,%xmm0
    psrldq $0x8,%xmm1
    pxor   %xmm0,%xmm1
    movdqa %xmm2,%xmm0
    psrldq $0x8,%xmm2
    pxor   %xmm0,%xmm2
    pclmullqlqdq %xmm2,%xmm1
    pxor   %xmm4,%xmm1
    pxor   %xmm3,%xmm1
    movdqa %xmm1,%xmm0
    pslldq $0x8,%xmm1
    pxor   %xmm1,%xmm4
    psrldq $0x8,%xmm0
    pxor   %xmm0,%xmm3

    mov    0x8(%ebp),%eax
    movups (%eax),%xmm0
    pxor   %xmm0,%xmm4
    movups %xmm4,(%eax)

    movdqa %xmm3,%xmm1
    pshufd $0x4E,%xmm3,%xmm0
    mov    0x2C(%ebp),%eax
    por    %xmm3,%xmm0
    movups (%eax),%xmm2
    movdqa %xmm0,%xmm3
    pshufd $0xB1,%xmm0,%xmm0
    por    %xmm3,%xmm0
    movd   %xmm0,%eax
    or     %eax,%eax
    jnz    rep_2

    mov    0x08(%ebp),%eax
    emms
    pop    %ebp
    ret    $4
.size   PMull16x16r,.-PMull16x16r

