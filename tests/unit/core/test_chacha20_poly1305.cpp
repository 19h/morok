// SPDX-License-Identifier: MIT

#include "doctest.h"

#include "morok/core/ChaCha20Poly1305.hpp"

#include <array>
#include <cstdint>
#include <string_view>
#include <vector>

using namespace morok::core;

namespace {

std::vector<std::uint8_t> hex(std::string_view S) {
    auto Nibble = [](char C) -> std::uint8_t {
        if (C >= '0' && C <= '9')
            return static_cast<std::uint8_t>(C - '0');
        if (C >= 'a' && C <= 'f')
            return static_cast<std::uint8_t>(C - 'a' + 10);
        return static_cast<std::uint8_t>(C - 'A' + 10);
    };
    std::vector<std::uint8_t> Out;
    for (std::size_t I = 0; I < S.size(); I += 2)
        Out.push_back(static_cast<std::uint8_t>((Nibble(S[I]) << 4) |
                                                Nibble(S[I + 1])));
    return Out;
}

template <std::size_t N>
std::array<std::uint8_t, N> asArray(std::string_view S) {
    const auto V = hex(S);
    REQUIRE(V.size() == N);
    std::array<std::uint8_t, N> Out{};
    std::copy(V.begin(), V.end(), Out.begin());
    return Out;
}

} // namespace

TEST_CASE("RFC 8439 ChaCha20-Poly1305 AEAD vector") {
    const ChaCha20Key Key = asArray<32>(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f");
    const ChaCha20Nonce Nonce =
        asArray<12>("070000004041424344454647");
    const auto Aad = hex("50515253c0c1c2c3c4c5c6c7");
    const std::string_view Text =
        "Ladies and Gentlemen of the class of '99: If I could offer you only "
        "one tip for the future, sunscreen would be it.";
    std::vector<std::uint8_t> Bytes(Text.begin(), Text.end());
    const auto ExpectedCipher = hex(
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1"
        "a71de0a9e060b2905d6a5b67ecd3b369"
        "2ddbd7f2d778b8c9803aee328091b58f"
        "ab324e4fad675945585808b4831d7bc3"
        "ff4def08e4b7a9de576d26586cec64b61"
        "16");
    const Poly1305Tag ExpectedTag =
        asArray<16>("1ae10b594f09e26a7e902ecbd0600691");

    const Poly1305Tag Tag = chacha20Poly1305Encrypt(Bytes, Aad, Key, Nonce);
    CHECK(Bytes == ExpectedCipher);
    CHECK(Tag == ExpectedTag);
    CHECK(chacha20Poly1305Decrypt(Bytes, Aad, Key, Nonce, Tag));
    CHECK(std::equal(Bytes.begin(), Bytes.end(), Text.begin(), Text.end()));
}

TEST_CASE("ChaCha20-Poly1305 rejects a corrupted tag without decrypting") {
    ChaCha20Key Key{};
    ChaCha20Nonce Nonce{};
    std::vector<std::uint8_t> Bytes{1, 2, 3, 4, 5};
    const std::array<std::uint8_t, 3> Aad{7, 8, 9};
    Poly1305Tag Tag = chacha20Poly1305Encrypt(Bytes, Aad, Key, Nonce);
    const auto Cipher = Bytes;
    Tag[4] ^= 0x80;
    CHECK_FALSE(chacha20Poly1305Decrypt(Bytes, Aad, Key, Nonce, Tag));
    CHECK(Bytes == Cipher);
}
