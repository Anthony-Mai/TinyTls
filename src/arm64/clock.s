.text	

.globl  rd_clk
.type   rd_clk,@function
.align  16
rd_clk:
    ret
.size   rd_clk,.-rd_clk

.globl	rd_clk2
.type	rd_clk2,@function
.align	16
rd_clk2:
    ret
.size	rd_clk2,.-rd_clk2

// Count leading 0 bits. Usage: uint32_t lead0(uint32_t v);
.globl  lead0
.type   lead0,@function
.align  16
lead0:
    clz     x0, x0
    ret
.size   lead0,.-lead0

// Count leading 0 bits. Usage: uint32_t lead0(uint64_t v);
.globl  lead0u8
.type   lead0u8,@function
.align  16
lead0u8:
    clz     x0, x0
    ret
.size   lead0u8,.-lead0u8

.globl  armv7_neon_probe
.align  16
armv7_neon_probe:
    //.inst   0x4eaf1def
    mov     v15.16b, v15.16b
    ret
.size armv7_neon_probe,.-armv7_neon_probe

.globl  armv8_aes_probe
armv8_aes_probe:
    //.inst 0x4e284800
    aese    v0.16b, v0.16b
    ret
.size armv8_aes_probe,.-armv8_aes_probe

.globl  armv8_sha1_probe
armv8_sha1_probe:
    //.inst 0x5e280800
    sha1h   s0, s0
    ret
.size armv8_sha1_probe,.-armv8_sha1_probe

.globl  armv8_sha256_probe
armv8_sha256_probe:
    //.inst 0x5e282800
    sha256su0 v0.4s, v0.4s
    ret
.size armv8_sha256_probe,.-armv8_sha256_probe

.globl  armv8_pmull_probe
armv8_pmull_probe:
    //.inst 0x0ee0e000
    pmull   v0.1q, v0.1d, v0.1d
    ret
.size armv8_pmull_probe,.-armv8_pmull_probe

// Polynomial product of 64 bits x 64 bits produce 128 bits, in Aarch64.
// See https://conradoplg.cryptoland.net/files/2010/12/mocrysen13.pdf
// and https://conradoplg.cryptoland.net/software/ecc-and-ae-for-arm-neon/
// The above discusses implementation using pmull.p8 in armv7. Since pmull
// and pmull1 is available on armv8 and later, it can be done much faster.
// Usage: uint64_t PMull8x8(uint64_t a, uint64_t b, uint64_t r[2]);
.globl  PMull8x8
PMull8x8:
    eor     v0.16b, v0.16b, v0.16b
    eor     v1.16b, v1.16b, v1.16b
    mov     v0.d[0], x0
    mov     v1.d[0], x1
    pmull   v0.1q, v0.1d, v1.1d
    mov     x0, v0.d[0]
    mov     x1, v0.d[1]
    str     x0, [x2]
    str     x1, [x2, #8]
    ret
.size PMull8x8,.-PMull8x8

