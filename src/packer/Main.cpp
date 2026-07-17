// SPDX-License-Identifier: MIT

#include "morok/packer/NativePack.hpp"

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string_view>

namespace {

void usage() {
    std::cerr
        << "usage:\n"
        << "  morok-native-pack prepare DIR [--seed N]\n"
        << "  morok-native-pack finalize ELF --key FILE [--consume-key]\n"
        << "  morok-native-pack verify ELF\n";
}

} // namespace

int main(int argc, char **argv) {
    using namespace morok::packer;
    if (argc < 3) {
        usage();
        return 2;
    }
    const std::string_view Command(argv[1]);
    NativePackResult Result;
    if (Command == "prepare") {
        std::uint64_t Seed = 0;
        for (int I = 3; I < argc; ++I) {
            if (std::string_view(argv[I]) == "--seed" && I + 1 < argc) {
                Seed = std::strtoull(argv[++I], nullptr, 0);
                continue;
            }
            usage();
            return 2;
        }
        Result = prepareNativePack(std::filesystem::path(argv[2]), Seed);
    } else if (Command == "finalize") {
        std::filesystem::path Key;
        bool Consume = false;
        for (int I = 3; I < argc; ++I) {
            const std::string_view Arg(argv[I]);
            if (Arg == "--key" && I + 1 < argc) {
                Key = argv[++I];
                continue;
            }
            if (Arg == "--consume-key") {
                Consume = true;
                continue;
            }
            usage();
            return 2;
        }
        if (Key.empty()) {
            usage();
            return 2;
        }
        Result = finalizeNativePack(std::filesystem::path(argv[2]), Key,
                                    Consume);
    } else if (Command == "verify") {
        if (argc != 3) {
            usage();
            return 2;
        }
        Result = verifyNativePack(std::filesystem::path(argv[2]));
    } else {
        usage();
        return 2;
    }

    if (!Result.ok) {
        std::cerr << "morok-native-pack: " << Result.error << '\n';
        return 1;
    }
    if (Command == "prepare")
        std::cout << "native-pack: prepared\n";
    else
        std::cout << "native-pack: protected_bytes=" << Result.protected_bytes
                  << '\n';
    return 0;
}
