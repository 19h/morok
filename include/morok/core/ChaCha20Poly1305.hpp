// SPDX-License-Identifier: MIT
//
// RFC 8439 ChaCha20-Poly1305.  The implementation is allocation-free and uses
// the 26-bit-limb Poly1305 formulation so the same arithmetic can be mirrored
// by the freestanding Linux loader without compiler runtime helpers.

#ifndef MOROK_CORE_CHACHA20_POLY1305_HPP
#define MOROK_CORE_CHACHA20_POLY1305_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace morok::core {

using ChaCha20Key = std::array<std::uint8_t, 32>;
using ChaCha20Nonce = std::array<std::uint8_t, 12>;
using Poly1305Tag = std::array<std::uint8_t, 16>;

namespace detail {

constexpr std::uint32_t load32(const std::uint8_t *P) noexcept {
    return static_cast<std::uint32_t>(P[0]) |
           (static_cast<std::uint32_t>(P[1]) << 8) |
           (static_cast<std::uint32_t>(P[2]) << 16) |
           (static_cast<std::uint32_t>(P[3]) << 24);
}

constexpr void store32(std::uint8_t *P, std::uint32_t V) noexcept {
    P[0] = static_cast<std::uint8_t>(V);
    P[1] = static_cast<std::uint8_t>(V >> 8);
    P[2] = static_cast<std::uint8_t>(V >> 16);
    P[3] = static_cast<std::uint8_t>(V >> 24);
}

constexpr void store64(std::uint8_t *P, std::uint64_t V) noexcept {
    for (unsigned I = 0; I < 8; ++I)
        P[I] = static_cast<std::uint8_t>(V >> (I * 8));
}

constexpr std::uint32_t rotl(std::uint32_t V, unsigned N) noexcept {
    return (V << N) | (V >> (32u - N));
}

constexpr void quarterRound(std::uint32_t &A, std::uint32_t &B,
                            std::uint32_t &C, std::uint32_t &D) noexcept {
    A += B;
    D ^= A;
    D = rotl(D, 16);
    C += D;
    B ^= C;
    B = rotl(B, 12);
    A += B;
    D ^= A;
    D = rotl(D, 8);
    C += D;
    B ^= C;
    B = rotl(B, 7);
}

inline std::array<std::uint8_t, 64>
chachaBlock(const ChaCha20Key &Key, const ChaCha20Nonce &Nonce,
            std::uint32_t Counter) noexcept {
    std::array<std::uint32_t, 16> State{
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u,
    };
    for (unsigned I = 0; I < 8; ++I)
        State[4 + I] = load32(Key.data() + I * 4);
    State[12] = Counter;
    State[13] = load32(Nonce.data());
    State[14] = load32(Nonce.data() + 4);
    State[15] = load32(Nonce.data() + 8);

    auto Working = State;
    for (unsigned I = 0; I < 10; ++I) {
        quarterRound(Working[0], Working[4], Working[8], Working[12]);
        quarterRound(Working[1], Working[5], Working[9], Working[13]);
        quarterRound(Working[2], Working[6], Working[10], Working[14]);
        quarterRound(Working[3], Working[7], Working[11], Working[15]);
        quarterRound(Working[0], Working[5], Working[10], Working[15]);
        quarterRound(Working[1], Working[6], Working[11], Working[12]);
        quarterRound(Working[2], Working[7], Working[8], Working[13]);
        quarterRound(Working[3], Working[4], Working[9], Working[14]);
    }

    std::array<std::uint8_t, 64> Out{};
    for (unsigned I = 0; I < 16; ++I)
        store32(Out.data() + I * 4, Working[I] + State[I]);
    return Out;
}

class Poly1305 {
public:
    explicit Poly1305(const std::array<std::uint8_t, 32> &Key) noexcept {
        const std::uint32_t T0 = load32(Key.data());
        const std::uint32_t T1 = load32(Key.data() + 4);
        const std::uint32_t T2 = load32(Key.data() + 8);
        const std::uint32_t T3 = load32(Key.data() + 12);
        R_[0] = T0 & 0x3ffffffu;
        R_[1] = ((T0 >> 26) | (T1 << 6)) & 0x3ffff03u;
        R_[2] = ((T1 >> 20) | (T2 << 12)) & 0x3ffc0ffu;
        R_[3] = ((T2 >> 14) | (T3 << 18)) & 0x3f03fffu;
        R_[4] = (T3 >> 8) & 0x00fffffu;
        Pad_[0] = load32(Key.data() + 16);
        Pad_[1] = load32(Key.data() + 20);
        Pad_[2] = load32(Key.data() + 24);
        Pad_[3] = load32(Key.data() + 28);
    }

    void update(std::span<const std::uint8_t> Input) noexcept {
        if (Leftover_ != 0) {
            const std::size_t Want = std::min<std::size_t>(
                16 - Leftover_, Input.size());
            std::copy_n(Input.data(), Want, Buffer_.data() + Leftover_);
            Leftover_ += Want;
            Input = Input.subspan(Want);
            if (Leftover_ < 16)
                return;
            blocks(Buffer_.data(), 16, 1u << 24);
            Leftover_ = 0;
        }
        const std::size_t Full = Input.size() & ~std::size_t{15};
        if (Full != 0) {
            blocks(Input.data(), Full, 1u << 24);
            Input = Input.subspan(Full);
        }
        if (!Input.empty()) {
            std::copy(Input.begin(), Input.end(), Buffer_.begin());
            Leftover_ = Input.size();
        }
    }

    Poly1305Tag finish() noexcept {
        if (Leftover_ != 0) {
            Buffer_[Leftover_] = 1;
            std::fill(Buffer_.begin() + static_cast<std::ptrdiff_t>(Leftover_ + 1),
                      Buffer_.end(), 0);
            blocks(Buffer_.data(), 16, 0);
        }

        std::uint64_t C = H_[1] >> 26;
        H_[1] &= 0x3ffffffu;
        H_[2] += C;
        C = H_[2] >> 26;
        H_[2] &= 0x3ffffffu;
        H_[3] += C;
        C = H_[3] >> 26;
        H_[3] &= 0x3ffffffu;
        H_[4] += C;
        C = H_[4] >> 26;
        H_[4] &= 0x3ffffffu;
        H_[0] += C * 5;
        C = H_[0] >> 26;
        H_[0] &= 0x3ffffffu;
        H_[1] += C;

        std::array<std::uint64_t, 5> G{};
        G[0] = H_[0] + 5;
        C = G[0] >> 26;
        G[0] &= 0x3ffffffu;
        for (unsigned I = 1; I < 4; ++I) {
            G[I] = H_[I] + C;
            C = G[I] >> 26;
            G[I] &= 0x3ffffffu;
        }
        G[4] = H_[4] + C - (std::uint64_t{1} << 26);
        std::uint64_t Mask = (G[4] >> 63) - 1;
        const std::uint64_t NotMask = ~Mask;
        for (unsigned I = 0; I < 5; ++I)
            H_[I] = (H_[I] & NotMask) | (G[I] & Mask);

        std::uint64_t F0 = (H_[0] | (H_[1] << 26)) & 0xffffffffu;
        std::uint64_t F1 =
            ((H_[1] >> 6) | (H_[2] << 20)) & 0xffffffffu;
        std::uint64_t F2 =
            ((H_[2] >> 12) | (H_[3] << 14)) & 0xffffffffu;
        std::uint64_t F3 =
            ((H_[3] >> 18) | (H_[4] << 8)) & 0xffffffffu;
        F0 += Pad_[0];
        F1 += Pad_[1] + (F0 >> 32);
        F0 &= 0xffffffffu;
        F2 += Pad_[2] + (F1 >> 32);
        F1 &= 0xffffffffu;
        F3 += Pad_[3] + (F2 >> 32);

        Poly1305Tag Tag{};
        store32(Tag.data(), static_cast<std::uint32_t>(F0));
        store32(Tag.data() + 4, static_cast<std::uint32_t>(F1));
        store32(Tag.data() + 8, static_cast<std::uint32_t>(F2));
        store32(Tag.data() + 12, static_cast<std::uint32_t>(F3));
        return Tag;
    }

private:
    void blocks(const std::uint8_t *Input, std::size_t Bytes,
                std::uint64_t HiBit) noexcept {
        const std::uint64_t S1 = R_[1] * 5;
        const std::uint64_t S2 = R_[2] * 5;
        const std::uint64_t S3 = R_[3] * 5;
        const std::uint64_t S4 = R_[4] * 5;
        while (Bytes >= 16) {
            const std::uint32_t T0 = load32(Input);
            const std::uint32_t T1 = load32(Input + 4);
            const std::uint32_t T2 = load32(Input + 8);
            const std::uint32_t T3 = load32(Input + 12);
            H_[0] += T0 & 0x3ffffffu;
            H_[1] += ((T0 >> 26) | (T1 << 6)) & 0x3ffffffu;
            H_[2] += ((T1 >> 20) | (T2 << 12)) & 0x3ffffffu;
            H_[3] += ((T2 >> 14) | (T3 << 18)) & 0x3ffffffu;
            H_[4] += (T3 >> 8) | HiBit;

            const std::uint64_t D0 = H_[0] * R_[0] + H_[1] * S4 +
                                     H_[2] * S3 + H_[3] * S2 + H_[4] * S1;
            const std::uint64_t D1 = H_[0] * R_[1] + H_[1] * R_[0] +
                                     H_[2] * S4 + H_[3] * S3 + H_[4] * S2;
            const std::uint64_t D2 = H_[0] * R_[2] + H_[1] * R_[1] +
                                     H_[2] * R_[0] + H_[3] * S4 + H_[4] * S3;
            const std::uint64_t D3 = H_[0] * R_[3] + H_[1] * R_[2] +
                                     H_[2] * R_[1] + H_[3] * R_[0] + H_[4] * S4;
            const std::uint64_t D4 = H_[0] * R_[4] + H_[1] * R_[3] +
                                     H_[2] * R_[2] + H_[3] * R_[1] + H_[4] * R_[0];

            std::uint64_t C = D0 >> 26;
            H_[0] = D0 & 0x3ffffffu;
            std::uint64_t V = D1 + C;
            C = V >> 26;
            H_[1] = V & 0x3ffffffu;
            V = D2 + C;
            C = V >> 26;
            H_[2] = V & 0x3ffffffu;
            V = D3 + C;
            C = V >> 26;
            H_[3] = V & 0x3ffffffu;
            V = D4 + C;
            C = V >> 26;
            H_[4] = V & 0x3ffffffu;
            H_[0] += C * 5;
            C = H_[0] >> 26;
            H_[0] &= 0x3ffffffu;
            H_[1] += C;

            Input += 16;
            Bytes -= 16;
        }
    }

    std::array<std::uint64_t, 5> R_{};
    std::array<std::uint64_t, 5> H_{};
    std::array<std::uint32_t, 4> Pad_{};
    std::array<std::uint8_t, 16> Buffer_{};
    std::size_t Leftover_ = 0;
};

inline Poly1305Tag aeadTag(std::span<const std::uint8_t> Ciphertext,
                           std::span<const std::uint8_t> Aad,
                           const ChaCha20Key &Key,
                           const ChaCha20Nonce &Nonce) noexcept {
    const auto Block = chachaBlock(Key, Nonce, 0);
    std::array<std::uint8_t, 32> PolyKey{};
    std::copy_n(Block.begin(), PolyKey.size(), PolyKey.begin());
    Poly1305 Poly(PolyKey);
    constexpr std::array<std::uint8_t, 16> Zero{};
    Poly.update(Aad);
    if ((Aad.size() & 15u) != 0)
        Poly.update(std::span(Zero).first(16 - (Aad.size() & 15u)));
    Poly.update(Ciphertext);
    if ((Ciphertext.size() & 15u) != 0)
        Poly.update(std::span(Zero).first(16 - (Ciphertext.size() & 15u)));
    std::array<std::uint8_t, 16> Lengths{};
    store64(Lengths.data(), static_cast<std::uint64_t>(Aad.size()));
    store64(Lengths.data() + 8, static_cast<std::uint64_t>(Ciphertext.size()));
    Poly.update(Lengths);
    return Poly.finish();
}

} // namespace detail

inline void chacha20Xor(std::span<std::uint8_t> Bytes,
                        const ChaCha20Key &Key,
                        const ChaCha20Nonce &Nonce,
                        std::uint32_t Counter = 1) noexcept {
    std::size_t Offset = 0;
    while (Offset < Bytes.size()) {
        const auto Block = detail::chachaBlock(Key, Nonce, Counter++);
        const std::size_t Count = std::min<std::size_t>(64, Bytes.size() - Offset);
        for (std::size_t I = 0; I < Count; ++I)
            Bytes[Offset + I] ^= Block[I];
        Offset += Count;
    }
}

inline Poly1305Tag chacha20Poly1305Encrypt(
    std::span<std::uint8_t> Plaintext, std::span<const std::uint8_t> Aad,
    const ChaCha20Key &Key, const ChaCha20Nonce &Nonce) noexcept {
    chacha20Xor(Plaintext, Key, Nonce, 1);
    return detail::aeadTag(Plaintext, Aad, Key, Nonce);
}

inline bool constantTimeEqual(const Poly1305Tag &A,
                              const Poly1305Tag &B) noexcept {
    std::uint32_t Diff = 0;
    for (std::size_t I = 0; I < A.size(); ++I)
        Diff |= static_cast<std::uint32_t>(A[I] ^ B[I]);
    return Diff == 0;
}

inline bool chacha20Poly1305Decrypt(
    std::span<std::uint8_t> Ciphertext, std::span<const std::uint8_t> Aad,
    const ChaCha20Key &Key, const ChaCha20Nonce &Nonce,
    const Poly1305Tag &Expected) noexcept {
    const Poly1305Tag Actual = detail::aeadTag(Ciphertext, Aad, Key, Nonce);
    if (!constantTimeEqual(Actual, Expected))
        return false;
    chacha20Xor(Ciphertext, Key, Nonce, 1);
    return true;
}

} // namespace morok::core

#endif // MOROK_CORE_CHACHA20_POLY1305_HPP
