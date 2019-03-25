.text	

.globl  rd_clk
.align  16
rd_clk:
    mrrc    15, 1, r0, r1, cr14
    bx      lr
.size   rd_clk,.-rd_clk

.globl	rd_clk2
.align	16
rd_clk2:
    mrrc    15, 1, r0, r1, cr14
    bx      lr
.size	rd_clk2,.-rd_clk2


