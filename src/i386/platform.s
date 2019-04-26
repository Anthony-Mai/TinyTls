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

// Count leading 0 bits. Usage: uint32_t lead0(uint32_t v);
.globl  lead0
.type   lead0,@function
.align  16
lead0:
    mov  0x04(%esp), %eax
    lzcnt %eax, %eax
    ret
.size   lead0,.-lead0

// Count leading 0 bits. Usage: uint32_t lead0(uint64_t v);
.globl  lead0u8
.type   lead0u8,@function
.align  16
lead0u8:
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
.size   lead0u8,.-lead0u8

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

