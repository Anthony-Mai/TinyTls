.text	

.globl  rd_clk
.type   rd_clk,@function
.align  16
rd_clk:
    rdtsc
    shl $32, %rdx
    or  %rdx, %rax
    ret
.size   rd_clk,.-rd_clk

// Count leading 0 bits. Usage: uint32_t leadz32(uint32_t v);
.globl  leadz32
.type   leadz32,@function
.align  16
leadz32:
    lzcnt %rdi, %rax
    ret
.size   leadz32,.-leadz32

// Count leading 0 bits. Usage: uint32_t leadz64(uint64_t v);
.globl  leadz64
.type   leadz64,@function
.align  16
leadz64:
    lzcnt %rdi, %rax
    ret
.size   leadz64,.-leadz64

// Polynomial product of 64 bits x 64 bits produce 128 bits.
// Usage: uint64_t PMull8x8(uint64_t a, uint64_t b, uint64_t r[2]);
.globl  PMull8x8
.type   PMull8x8,@function
.align  16
PMull8x8:
    movd %rdi, %xmm0
    movd %rsi, %xmm1
    pclmullqlqdq %xmm1, %xmm0
    movd %xmm0, %rax
    movups %xmm0, (%rdx)
    pshufd $0x4e, %xmm0, %xmm0
    movd %xmm0, %rdx
    emms
    ret
.size   PMull8x8,.-PMull8x8


// Polynomial product of 64 bits x 64 bits then reduced by 65 bits p.
// Usage: uint64_t PMull8x8r(uint64_t a, uint64_t b, uint64_t p);
.globl  PMull8x8r
.type   PMull8x8r,@function
.align  16
PMull8x8r:
    movd %rdi, %xmm0
    movd %rsi, %xmm1
    pclmullqlqdq %xmm1, %xmm0
    movd %rdx, %xmm1
    movd %xmm0, %rax
    psrldq $8, %xmm0

rep1:
    pshufd $0x44, %xmm0, %xmm0
    movd %xmm0, %rdx
    psrldq $8, %xmm0
    or %rdx, %rdx
    jz done1

    pclmullqlqdq %xmm1, %xmm0
    movd %xmm0, %rdx
    psrldq $8, %xmm0
    xor %rdx, %rax
    jmp rep1

done1:
    emms
    ret
.size   PMull8x8r,.-PMull8x8r

// Polynomial product of 128 x 128 bits for 256 bits.
// Usage: u128 PMull16x16(u128 a, u128 b, u128 r[2]);
.globl  PMull16x16
.type   PMull16x16,@function
.align  16
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
.size   PMull16x16,.-PMull16x16

// Polynomial product of 128 x 128 bits & reduce by p.
// Usage: u128 PMull16x16(u128 a, u128 b, u128* p);
.globl  PMull16x16r
.type   PMull16x16r,@function
.align  16
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
.size   PMull16x16r,.-PMull16x16r

