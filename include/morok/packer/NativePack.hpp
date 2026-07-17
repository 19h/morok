// SPDX-License-Identifier: MIT

#ifndef MOROK_PACKER_NATIVE_PACK_HPP
#define MOROK_PACKER_NATIVE_PACK_HPP

#include <cstdint>
#include <filesystem>
#include <string>

namespace morok::packer {

struct NativePackResult {
    bool ok = false;
    std::string error;
    std::uint64_t protected_bytes = 0;
};

NativePackResult prepareNativePack(const std::filesystem::path &Directory,
                                   std::uint64_t Seed);
NativePackResult finalizeNativePack(const std::filesystem::path &Binary,
                                    const std::filesystem::path &KeyFile,
                                    bool ConsumeKey);
NativePackResult verifyNativePack(const std::filesystem::path &Binary);

} // namespace morok::packer

#endif // MOROK_PACKER_NATIVE_PACK_HPP
