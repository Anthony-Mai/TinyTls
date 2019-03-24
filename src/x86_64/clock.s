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


