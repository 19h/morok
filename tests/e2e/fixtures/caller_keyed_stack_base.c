// SPDX-License-Identifier: MIT
// A dynamic, aligned stack frame and enough live arguments to force reloads
// during dispatch setup. AArch64 uses x19 as the frame base for this layout.
#include <stdint.h>

static volatile unsigned calls;

__attribute__((noinline)) uint64_t consume(
    uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
    uint64_t a8, uint64_t a9, uint64_t a10, uint64_t a11,
    uint64_t a12, uint64_t a13, uint64_t a14, uint64_t a15,
    uint64_t a16, uint64_t a17, uint64_t a18, uint64_t a19,
    uint64_t a20, uint64_t a21, uint64_t a22, uint64_t a23,
    uint64_t a24, uint64_t a25, uint64_t a26, uint64_t a27,
    uint64_t a28, uint64_t a29, uint64_t a30, uint64_t a31) {
    ++calls;
    return a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 +
           a8 + a9 + a10 + a11 + a12 + a13 + a14 + a15 +
           a16 + a17 + a18 + a19 + a20 + a21 + a22 + a23 +
           a24 + a25 + a26 + a27 + a28 + a29 + a30 + a31;
}

int main(int argc, char **argv) {
    (void)argv;
    _Alignas(64) volatile uint64_t fixed[32];
    volatile unsigned char dynamic[(unsigned)argc + 37];
    dynamic[0] = 43;
    __asm__ volatile("" : : "r"(dynamic) : "memory");

    uint64_t expected = 0;
    for (unsigned i = 0; i < 32; ++i) {
        fixed[i] = (uint64_t)i * 17 + (unsigned)argc;
        expected += fixed[i];
    }
    uint64_t actual = consume(
        fixed[0], fixed[1], fixed[2], fixed[3],
        fixed[4], fixed[5], fixed[6], fixed[7],
        fixed[8], fixed[9], fixed[10], fixed[11],
        fixed[12], fixed[13], fixed[14], fixed[15],
        fixed[16], fixed[17], fixed[18], fixed[19],
        fixed[20], fixed[21], fixed[22], fixed[23],
        fixed[24], fixed[25], fixed[26], fixed[27],
        fixed[28], fixed[29], fixed[30], fixed[31]);
    return actual != expected || calls != 1 || dynamic[0] != 43 ||
           fixed[31] != 31 * 17 + (unsigned)argc;
}
