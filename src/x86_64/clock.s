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
    sub  $0x20, %rsp
    movups %xmm0, (%rsp)
    movups %xmm1, 0x10(%rsp)
    movd %rdi, %xmm0
    movd %rsi, %xmm1
    pclmullqlqdq %xmm1, %xmm0
    movd %xmm0, %rax
    movups %xmm0, (%rdx)
    pshufd $0x4e, %xmm0, %xmm0
    movd %xmm0, %rdx
    movups 0x10(%rsp), %xmm1
    movups (%rsp), %xmm0
    add $0x20, %rsp
    emms
    ret
.size   PMull8x8,.-PMull8x8

