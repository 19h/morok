// SPDX-License-Identifier: MIT
//
// End-to-end correctness workload.  Exercises every integer binary operator,
// constant and variable shifts, loops, branches and a switch — i.e. everything
// the substitution and MBA passes transform — then prints a checksum over many
// invocations.  Built twice (clean vs obfuscated); the checksums must match.

#include <stdint.h>
#include <stdio.h>

__attribute__((noinline)) static uint32_t mixer(uint32_t a, uint32_t b) {
  uint32_t r = a + b;
  r ^= a * b;
  r -= (a & b);
  r |= (a ^ b);
  r += (b << 3);
  r ^= (a >> 2);
  r += (uint32_t)((int32_t)r >> 1);
  return r;
}

__attribute__((noinline)) static uint64_t dispatch(uint32_t cmd, uint64_t v) {
  switch (cmd & 7u) {
  case 0: return v + 0x1111u;
  case 1: return v - 0x2222u;
  case 2: return v ^ 0x3333u;
  case 3: return v * 0x44445u;
  case 4: return v << 3;
  case 5: return v >> 5;
  case 6: return ~v;
  default: return (v << 13) | (v >> 51);
  }
}

// Straight-line, single-block, integer in/out: a prime virtualization target,
// exercising unsigned and signed division and remainder inside the VM.  The
// caller guarantees a non-zero, positive divisor so no operation is undefined.
__attribute__((noinline)) static uint32_t divmix(uint32_t a, uint32_t b) {
  uint32_t uq = a / b;
  uint32_t ur = a % b;
  int32_t sq = (int32_t)a / (int32_t)b;
  int32_t sr = (int32_t)a % (int32_t)b;
  return (uq * 31u) ^ (ur << 3) ^ (uint32_t)(sq * 7) ^ (uint32_t)(sr << 1);
}

__attribute__((noinline)) static uint32_t collatz(uint32_t n) {
  uint32_t steps = 0;
  while (n != 1u) {
    n = (n & 1u) ? (3u * n + 1u) : (n >> 1);
    ++steps;
    if (steps > 1000u) break;
  }
  return steps;
}

int main(void) {
  uint64_t checksum = 1469598103934665603ULL; // FNV offset basis
  for (uint32_t a = 1; a < 600; ++a) {
    uint32_t m = mixer(a * 2654435761u + 1u, a * 40503u + 7u);
    uint64_t d = dispatch(a, (uint64_t)m * 0x9E3779B97F4A7C15ULL);
    uint32_t c = collatz((a % 255u) + 1u);
    uint32_t dm = divmix(m, (a % 251u) + 1u);
    checksum ^= m;
    checksum *= 1099511628211ULL; // FNV prime
    checksum ^= d;
    checksum *= 1099511628211ULL;
    checksum ^= c;
    checksum *= 1099511628211ULL;
    checksum ^= dm;
    checksum *= 1099511628211ULL;
  }
  printf("%llu\n", (unsigned long long)checksum);
  return 0;
}
