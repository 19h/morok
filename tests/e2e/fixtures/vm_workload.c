// SPDX-License-Identifier: MIT
//
// VM differential workload: call-free leaf functions that the bytecode
// virtualizer can lift end to end — counted loops, memory loads/stores through
// pointer arguments, getelementptr indexing, a switch, and multi-way branches.
// Each is `noinline` and explicitly annotated `vm`, so it survives the inliner,
// receives priority, and cannot silently fall back to native code under the
// called-hot-loop heuristic. `main` exercises them with fixed inputs and prints
// a deterministic transcript, so a clean build and a VM-obfuscated build must
// produce byte-identical output.

#include <stdint.h>
#include <stdio.h>

#define VM_TARGET __attribute__((noinline, annotate("vm")))

// Loop + getelementptr + load + wrapping integer arithmetic.
VM_TARGET int sum_weighted(const int *a, int n) {
    int s = 0;
    for (int i = 0; i < n; i++)
        s += a[i] * (i + 1);
    return s;
}

// Loop + i8 load + 64-bit multiply/xor (FNV-1a style); exercises narrow loads
// and wide arithmetic in one function.
VM_TARGET uint64_t fnv1a(const unsigned char *p, int n) {
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < n; i++) {
        h ^= (uint64_t)p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

// Switch lowered to a comparison/branch cascade in bytecode.
VM_TARGET int route(int v) {
    switch (v & 7) {
    case 0:
        return 100;
    case 1:
    case 2:
        return v * 3 - 1;
    case 5:
        return -v;
    case 6:
        return v ^ 0x55;
    default:
        return v + 7;
    }
}

// Multi-way branches + store through a pointer arena; counts in-range elements
// and records the running parity into the caller's buffer.
VM_TARGET int range_count(const int *a, int n, int lo, int hi,
                          int *parity_out) {
    int count = 0;
    int parity = 0;
    for (int i = 0; i < n; i++) {
        int x = a[i];
        if (x >= lo) {
            if (x <= hi) {
                count++;
                parity ^= (x & 1);
            }
        }
    }
    *parity_out = parity;
    return count;
}

int main(void) {
    int a[] = {3, 1, 4, 1, 5, 9, 2, 6, -7, 13, 8, 0, 11, -2, 7};
    int n = (int)(sizeof(a) / sizeof(a[0]));

    printf("sum=%d\n", sum_weighted(a, n));
    printf("fnv=%llu\n", (unsigned long long)fnv1a(
                             (const unsigned char *)"morok bytecode vm", 17));
    int acc = 0;
    for (int i = 0; i < 16; i++)
        acc = acc * 31 + route(i);
    printf("route=%d\n", acc);

    int parity = 0;
    int c = range_count(a, n, 0, 9, &parity);
    printf("rc=%d parity=%d\n", c, parity);
    return 0;
}
