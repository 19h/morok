// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/core/Entropy.cpp — host-specific entropy collection.
//
// Only the collection of raw sources is platform-dependent; the diffusion of
// each source and the combination into seed words live in the header so they
// stay testable.  Each raw address/counter is passed through a multiplicative
// hash before being handed back, so low-entropy low bits are spread out.

#include "morok/core/Entropy.hpp"

#include <chrono>
#include <cstdint>
#include <cstdlib>

#if defined(_MSC_VER)
#include <intrin.h>
#define MOROK_HAS_RDTSC 1
#elif defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#define MOROK_HAS_RDTSC 1
#else
#define MOROK_HAS_RDTSC 0
#endif

#if defined(_WIN32)
#include <process.h>
#define MOROK_GETPID() (static_cast<std::uint64_t>(_getpid()))
#elif defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#define MOROK_GETPID() (static_cast<std::uint64_t>(::getpid()))
#else
#define MOROK_GETPID() (std::uint64_t{0xDEADBEEFCAFEBABEULL})
#endif

namespace morok::core {

namespace {

// Knuth multiplicative hash — spreads the entropy of address low bits.
constexpr std::uint64_t diffuse(std::uint64_t x) noexcept {
    x = x * 6364136223846793005ULL + 1442695040888963407ULL;
    x ^= x >> 32;
    return x;
}

#if defined(__aarch64__) || defined(_M_ARM64)
// Virtual count register: a free-running timer readable from EL0 on all modern
// AArch64 platforms (incl. Apple Silicon).  Reading it twice yields a few-tick
// delta that adds real-time jitter.
std::uint64_t readVirtualTimer() noexcept {
#if defined(_WIN32)
    return 0; // QueryPerformanceCounter path intentionally omitted here
#else
    std::uint64_t v1 = 0, v2 = 0;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v1));
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v2));
    return v1 ^ (v2 * 6364136223846793005ULL + v1);
#endif
}
#endif

} // namespace

EntropySources collectEntropy() noexcept {
    EntropySources s;

    using clock = std::chrono::high_resolution_clock;
    s.wallClockNs =
        static_cast<std::uint64_t>(clock::now().time_since_epoch().count());

    volatile std::uint64_t stackProbe = 0xABADCAFEABADCAFEULL;
    s.stackHash = diffuse(reinterpret_cast<std::uintptr_t>(&stackProbe));

    void *heap = std::malloc(1);
    s.heapHash = diffuse(reinterpret_cast<std::uintptr_t>(heap));
    std::free(heap);

#if MOROK_HAS_RDTSC
    s.cycleCounter = static_cast<std::uint64_t>(__rdtsc());
#endif

    s.pid = diffuse(MOROK_GETPID());

#if defined(__aarch64__) || defined(_M_ARM64)
    s.hwA = readVirtualTimer();
    s.hwC = readVirtualTimer();
#endif

    return s;
}

Xoshiro256pp makeSeededEngine() noexcept {
    return makeEngine(collectEntropy());
}

} // namespace morok::core
