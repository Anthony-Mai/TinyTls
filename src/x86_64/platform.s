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

.globl	rd_clk2
.type	rd_clk2,@function
.align	16
rd_clk2:
    push %rdx
    rdtsc
    rol $32, %rdx
    or  %rdx, %rax
    pop %rdx
    ret
.size	rd_clk2,.-rd_clk2

// Count leading 0 bits. Usage: uint32_t lead0(uint32_t v);
.globl  lead0
.type   lead0,@function
.align  16
lead0:
    lzcnt %rdi, %rax
    ret
.size   lead0,.-lead0

// Count leading 0 bits. Usage: uint32_t lead0(uint64_t v);
.globl  lead0u8
.type   lead0u8,@function
.align  16
lead0u8:
    lzcnt %rdi, %rax
    ret
.size   lead0u8,.-lead0u8

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

// Polynomial product of 128 x 128 bits producing 256 bits result.
// Usage: uint128 PMull16x16(uint128 a, uint128 b, uint128 r[2]);
.globl  PMull16x16
.type   PMull16x16,@function
.align  16
PMull16x16:
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
    ret
.size   PMull16x16,.-PMull16x16

