// SPDX-License-Identifier: MIT

#include "doctest.h"

#include "morok/core/Sha1.hpp"

#include <cstdint>
#include <string>
#include <string_view>

using namespace morok::core;

namespace {

std::string digestHex(const Sha1Digest &Digest) {
    constexpr char Digits[] = "0123456789abcdef";
    std::string Out;
    for (std::uint8_t B : Digest) {
        Out.push_back(Digits[B >> 4]);
        Out.push_back(Digits[B & 15]);
    }
    return Out;
}

} // namespace

TEST_CASE("SHA-1 standard vectors") {
    const std::string_view Empty;
    CHECK(digestHex(sha1(std::span(
              reinterpret_cast<const std::uint8_t *>(Empty.data()),
              Empty.size()))) ==
          "da39a3ee5e6b4b0d3255bfef95601890afd80709");

    const std::string_view Abc = "abc";
    CHECK(digestHex(sha1(std::span(
              reinterpret_cast<const std::uint8_t *>(Abc.data()),
              Abc.size()))) ==
          "a9993e364706816aba3e25717850c26c9cd0d89d");
}
