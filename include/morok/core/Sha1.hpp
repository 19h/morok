// SPDX-License-Identifier: MIT

#ifndef MOROK_CORE_SHA1_HPP
#define MOROK_CORE_SHA1_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace morok::core {

using Sha1Digest = std::array<std::uint8_t, 20>;

namespace detail {

constexpr std::uint32_t sha1Rotl(std::uint32_t V, unsigned N) noexcept {
    return (V << N) | (V >> (32u - N));
}

inline void sha1Block(std::array<std::uint32_t, 5> &H,
                      const std::uint8_t Block[64]) noexcept {
    std::array<std::uint32_t, 80> W{};
    for (unsigned I = 0; I < 16; ++I)
        W[I] = (static_cast<std::uint32_t>(Block[I * 4]) << 24) |
               (static_cast<std::uint32_t>(Block[I * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(Block[I * 4 + 2]) << 8) |
               static_cast<std::uint32_t>(Block[I * 4 + 3]);
    for (unsigned I = 16; I < 80; ++I)
        W[I] = sha1Rotl(W[I - 3] ^ W[I - 8] ^ W[I - 14] ^ W[I - 16], 1);

    std::uint32_t A = H[0], B = H[1], C = H[2], D = H[3], E = H[4];
    for (unsigned I = 0; I < 80; ++I) {
        std::uint32_t F = 0, K = 0;
        if (I < 20) {
            F = (B & C) | ((~B) & D);
            K = 0x5a827999u;
        } else if (I < 40) {
            F = B ^ C ^ D;
            K = 0x6ed9eba1u;
        } else if (I < 60) {
            F = (B & C) | (B & D) | (C & D);
            K = 0x8f1bbcdcu;
        } else {
            F = B ^ C ^ D;
            K = 0xca62c1d6u;
        }
        const std::uint32_t T = sha1Rotl(A, 5) + F + E + K + W[I];
        E = D;
        D = C;
        C = sha1Rotl(B, 30);
        B = A;
        A = T;
    }
    H[0] += A;
    H[1] += B;
    H[2] += C;
    H[3] += D;
    H[4] += E;
}

} // namespace detail

inline Sha1Digest sha1(std::span<const std::uint8_t> Input) noexcept {
    std::array<std::uint32_t, 5> H{
        0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u,
    };
    std::size_t Offset = 0;
    while (Input.size() - Offset >= 64) {
        detail::sha1Block(H, Input.data() + Offset);
        Offset += 64;
    }
    std::array<std::uint8_t, 128> Tail{};
    const std::size_t Remain = Input.size() - Offset;
    for (std::size_t I = 0; I < Remain; ++I)
        Tail[I] = Input[Offset + I];
    Tail[Remain] = 0x80;
    const std::size_t TailBytes = Remain < 56 ? 64 : 128;
    const std::uint64_t Bits = static_cast<std::uint64_t>(Input.size()) * 8;
    for (unsigned I = 0; I < 8; ++I)
        Tail[TailBytes - 1 - I] = static_cast<std::uint8_t>(Bits >> (I * 8));
    detail::sha1Block(H, Tail.data());
    if (TailBytes == 128)
        detail::sha1Block(H, Tail.data() + 64);

    Sha1Digest Out{};
    for (unsigned I = 0; I < 5; ++I) {
        Out[I * 4] = static_cast<std::uint8_t>(H[I] >> 24);
        Out[I * 4 + 1] = static_cast<std::uint8_t>(H[I] >> 16);
        Out[I * 4 + 2] = static_cast<std::uint8_t>(H[I] >> 8);
        Out[I * 4 + 3] = static_cast<std::uint8_t>(H[I]);
    }
    return Out;
}

} // namespace morok::core

#endif // MOROK_CORE_SHA1_HPP
