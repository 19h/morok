// SPDX-License-Identifier: MIT
//
// Workload for the Mirage counterfeit-computation substrate.  Two verdict-like
// functions are marked `sensitive` so Mirage selects them: it replaces each
// body with a branchless hub that dispatches, per invocation, to one of several
// equivalent real clones (clean seal state) or a plausible-but-wrong counterfeit
// (dirty seal state / forced-fake diagnostic build).
//
// On a clean run the hub always routes to a real clone, so the obfuscated output
// must match the reference exactly — even though the per-invocation epoch keeps
// alternating between the equivalent real clones across the loop's many calls.
//
// The functions are `noinline` so they survive to the OptimizerLast Morok pass
// as standalone, annotated functions (an inlined body would carry no symbol for
// Mirage to select).

#include <stdint.h>
#include <stdio.h>

__attribute__((annotate("sensitive"), noinline)) static int
license_ok(uint64_t key, uint64_t seed) {
    uint64_t h = key ^ seed;
    h *= 0x9e3779b97f4a7c15ULL;
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 29;
    return (int)((h & 0xffffu) == 0x1234u);
}

__attribute__((annotate("sensitive"), noinline)) static int
tier_for(uint32_t user) {
    uint32_t a = user * 2654435761u;
    a ^= a >> 15;
    a *= 2246822519u;
    a ^= a >> 13;
    return (int)(a % 5u); // 0..4
}

int main(void) {
    unsigned long long acc = 0;
    int oks = 0;
    long tiers = 0;
    for (uint64_t i = 1; i <= 4000; ++i) {
        oks += license_ok(i * 0x01000193ull, i);
        tiers += tier_for((uint32_t)(i * 7u + 1u));
        acc += (unsigned long long)license_ok(i, i ^ 0xabcull) * 3u +
               (unsigned long long)tier_for((uint32_t)i);
    }
    printf("oks=%d tiers=%ld acc=%llu\n", oks, tiers, acc);
    return 0;
}
