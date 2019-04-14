.text	

.globl  rd_clk
.type   rd_clk,@function
.align  16
rd_clk:
    rdtsc
    or $0, %edx
    ret
.size   rd_clk,.-rd_clk

.globl	rd_clk2
.type	rd_clk2,@function
.align	16
rd_clk2:
    rdtsc
    or $0, %edx
    ret
.size	rd_clk2,.-rd_clk2

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

