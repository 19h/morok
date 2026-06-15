// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/core/Random.hpp — bounded sampling and value scrambling.
//
// Sampling helpers that operate on *any* `std::uniform_random_bit_generator`
// (the Morok engines, std engines, or a deterministic test stub).  Keeping
// these as free functions over a generator concept means the distribution
// logic is tested once, independently of which engine supplies the bits.

#ifndef MOROK_CORE_RANDOM_HPP
#define MOROK_CORE_RANDOM_HPP

#include <concepts>
#include <cstdint>
#include <random>
#include <unordered_map>

namespace morok::core {

/// Any 64-bit uniform random bit generator usable with the helpers below.
template <class G>
concept BitGenerator = std::uniform_random_bit_generator<G> &&
                       std::same_as<typename G::result_type, std::uint64_t>;

/// Uniform integer in the half-open range [0, bound).
///
/// Returns 0 when `bound == 0`.  Uses rejection sampling on the high 32 bits of
/// each draw to eliminate the modulo bias that `next() % bound` would
/// introduce; the rejection threshold discards exactly the `2^32 mod bound` low
/// residues that would otherwise be over-represented.
template <BitGenerator G>
std::uint32_t boundedU32(G &gen, std::uint32_t bound) noexcept {
    if (bound == 0)
        return 0;
    // 2^32 mod bound, computed without 64-bit division of 2^32:
    const std::uint32_t threshold =
        static_cast<std::uint32_t>(-static_cast<std::int32_t>(bound)) % bound;
    for (;;) {
        const std::uint32_t v = static_cast<std::uint32_t>(gen() >> 32);
        if (v >= threshold)
            return v % bound;
    }
}

/// Uniform integer in the half-open range [min, max).
///
/// Returns `min` when `max <= min` (empty or inverted range).
template <BitGenerator G>
std::uint32_t rangeU32(G &gen, std::uint32_t min, std::uint32_t max) noexcept {
    if (max <= min)
        return min;
    return min + boundedU32(gen, max - min);
}

/// Fair coin biased by an integer percentage in [0, 100].
///
/// `percent <= 0` is always false; `percent >= 100` is always true.
template <BitGenerator G> bool chance(G &gen, std::uint32_t percent) noexcept {
    if (percent == 0)
        return false;
    if (percent >= 100)
        return true;
    return boundedU32(gen, 100) < percent;
}

/// A stable, memoised 32-bit value scrambler.
///
/// The first time a value is seen it is mapped to a fresh random 32-bit image;
/// subsequent lookups of the same value return the same image.  Used to give
/// obfuscation passes a consistent-yet-opaque renaming of integer keys within
/// a single run.
class Scrambler {
public:
    template <BitGenerator G>
    std::uint32_t operator()(G &gen, std::uint32_t value) {
        auto [it, inserted] = map_.try_emplace(value, 0);
        if (inserted)
            it->second = static_cast<std::uint32_t>(gen());
        return it->second;
    }

    std::size_t size() const noexcept { return map_.size(); }
    void clear() noexcept { map_.clear(); }

private:
    std::unordered_map<std::uint32_t, std::uint32_t> map_;
};

} // namespace morok::core

#endif // MOROK_CORE_RANDOM_HPP
