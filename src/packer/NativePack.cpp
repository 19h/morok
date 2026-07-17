// SPDX-License-Identifier: MIT

#include "morok/packer/NativePack.hpp"

#include "morok/core/ChaCha20Poly1305.hpp"
#include "morok/core/Entropy.hpp"
#include "morok/core/Sha1.hpp"
#include "morok/core/Xoshiro256.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace morok::packer {

namespace {

constexpr std::size_t kMetaSize = 128;
constexpr std::size_t kVersionOff = 16;
constexpr std::size_t kFlagsOff = 20;
constexpr std::size_t kDeltaOff = 24;
constexpr std::size_t kLengthOff = 32;
constexpr std::size_t kNonceOff = 40;
constexpr std::size_t kTagOff = 56;
constexpr std::size_t kCookieOff = 72;
constexpr std::size_t kKeyShareOff = 80;
constexpr std::size_t kSaltOff = 112;
constexpr std::uint64_t kCookieDomain = 0x9f4a7c15d3e26b81ULL;
constexpr std::uint64_t kIsolation = 65536;

constexpr std::uint32_t PT_LOAD = 1;
constexpr std::uint32_t PF_X = 1;
constexpr std::uint32_t SHT_SYMTAB = 2;
constexpr std::uint32_t SHT_RELA = 4;
constexpr std::uint32_t SHT_DYNAMIC = 6;
constexpr std::uint32_t SHT_NOTE = 7;
constexpr std::uint32_t SHT_REL = 9;
constexpr std::uint32_t SHT_DYNSYM = 11;
constexpr std::uint32_t SHT_RELR = 19;
constexpr std::uint64_t DT_NULL = 0;
constexpr std::uint64_t DT_INIT = 12;
constexpr std::uint64_t DT_TEXTREL = 22;

struct ProgramHeader {
    std::uint32_t type = 0;
    std::uint32_t flags = 0;
    std::uint64_t offset = 0;
    std::uint64_t vaddr = 0;
    std::uint64_t file_size = 0;
    std::uint64_t memory_size = 0;
};

struct SectionHeader {
    std::uint32_t name_offset = 0;
    std::uint32_t type = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint64_t entry_size = 0;
};

struct ElfImage {
    std::uint16_t type = 0;
    std::uint16_t machine = 0;
    std::vector<ProgramHeader> programs;
    std::vector<SectionHeader> sections;
    std::uint64_t shstr_offset = 0;
    std::uint64_t shstr_size = 0;
};

struct Secrets {
    core::ChaCha20Key key{};
    std::array<std::uint8_t, 32> share_b{};
    std::array<std::uint8_t, 16> marker{};
    core::ChaCha20Nonce nonce{};
    std::array<std::uint8_t, 16> salt{};
};

NativePackResult failure(std::string Message) {
    return {false, std::move(Message), 0};
}

bool rangeValid(std::size_t Size, std::uint64_t Offset,
                std::uint64_t Bytes) {
    return Offset <= Size && Bytes <= Size - static_cast<std::size_t>(Offset);
}

std::uint16_t load16(const std::vector<std::uint8_t> &B, std::size_t O) {
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(B[O]) |
        (static_cast<std::uint16_t>(B[O + 1]) << 8));
}

std::uint32_t load32(const std::vector<std::uint8_t> &B, std::size_t O) {
    return static_cast<std::uint32_t>(B[O]) |
           (static_cast<std::uint32_t>(B[O + 1]) << 8) |
           (static_cast<std::uint32_t>(B[O + 2]) << 16) |
           (static_cast<std::uint32_t>(B[O + 3]) << 24);
}

std::uint64_t load64(const std::vector<std::uint8_t> &B, std::size_t O) {
    std::uint64_t V = 0;
    for (unsigned I = 0; I < 8; ++I)
        V |= static_cast<std::uint64_t>(B[O + I]) << (I * 8);
    return V;
}

std::int64_t loadS64(const std::vector<std::uint8_t> &B, std::size_t O) {
    return static_cast<std::int64_t>(load64(B, O));
}

void store64(std::vector<std::uint8_t> &B, std::size_t O, std::uint64_t V) {
    for (unsigned I = 0; I < 8; ++I)
        B[O + I] = static_cast<std::uint8_t>(V >> (I * 8));
}

std::optional<std::vector<std::uint8_t>> readFile(
    const std::filesystem::path &Path, std::string &Error) {
    std::ifstream In(Path, std::ios::binary);
    if (!In) {
        Error = "cannot open " + Path.string();
        return std::nullopt;
    }
    In.seekg(0, std::ios::end);
    const std::streamoff End = In.tellg();
    if (End < 0) {
        Error = "cannot size " + Path.string();
        return std::nullopt;
    }
    In.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> Bytes(static_cast<std::size_t>(End));
    if (!Bytes.empty())
        In.read(reinterpret_cast<char *>(Bytes.data()), End);
    if (!In) {
        Error = "cannot read " + Path.string();
        return std::nullopt;
    }
    return Bytes;
}

bool writeAtomic(const std::filesystem::path &Path,
                 const std::vector<std::uint8_t> &Bytes,
                 std::string &Error) {
    const std::filesystem::path Temp = Path.string() + ".morok-npack.tmp";
    std::ofstream Out(Temp, std::ios::binary | std::ios::trunc);
    if (!Out) {
        Error = "cannot create temporary output " + Temp.string();
        return false;
    }
    Out.write(reinterpret_cast<const char *>(Bytes.data()),
              static_cast<std::streamsize>(Bytes.size()));
    Out.close();
    if (!Out) {
        Error = "cannot write temporary output " + Temp.string();
        return false;
    }
    std::error_code Ec;
    const auto Perms = std::filesystem::status(Path, Ec).permissions();
    if (!Ec)
        std::filesystem::permissions(Temp, Perms, Ec);
    Ec.clear();
    std::filesystem::rename(Temp, Path, Ec);
    if (Ec) {
        std::filesystem::remove(Temp);
        Error = "cannot replace " + Path.string() + ": " + Ec.message();
        return false;
    }
    return true;
}

std::optional<ElfImage> parseElf(const std::vector<std::uint8_t> &B,
                                 std::string &Error) {
    if (B.size() < 64 || B[0] != 0x7f || B[1] != 'E' || B[2] != 'L' ||
        B[3] != 'F' || B[4] != 2 || B[5] != 1) {
        Error = "input is not little-endian ELF64";
        return std::nullopt;
    }
    ElfImage E;
    E.type = load16(B, 16);
    E.machine = load16(B, 18);
    if ((E.type != 2 && E.type != 3) ||
        (E.machine != 62 && E.machine != 183)) {
        Error = "native packing requires x86-64/AArch64 ET_EXEC or ET_DYN";
        return std::nullopt;
    }
    const std::uint64_t Phoff = load64(B, 32);
    const std::uint64_t Shoff = load64(B, 40);
    const std::uint16_t Phentsize = load16(B, 54);
    const std::uint16_t Phnum = load16(B, 56);
    const std::uint16_t Shentsize = load16(B, 58);
    const std::uint16_t Shnum = load16(B, 60);
    const std::uint16_t Shstrndx = load16(B, 62);
    if (Phentsize < 56 || Phnum == 0 ||
        !rangeValid(B.size(), Phoff,
                    static_cast<std::uint64_t>(Phentsize) * Phnum)) {
        Error = "invalid ELF program-header table";
        return std::nullopt;
    }
    for (std::uint16_t I = 0; I < Phnum; ++I) {
        const std::size_t O =
            static_cast<std::size_t>(Phoff + static_cast<std::uint64_t>(I) *
                                                 Phentsize);
        E.programs.push_back({load32(B, O), load32(B, O + 4),
                              load64(B, O + 8), load64(B, O + 16),
                              load64(B, O + 32), load64(B, O + 40)});
    }
    if (Shoff == 0 || Shnum == 0 || Shentsize < 64 ||
        !rangeValid(B.size(), Shoff,
                    static_cast<std::uint64_t>(Shentsize) * Shnum)) {
        Error = "section headers are required for relocation auditing";
        return std::nullopt;
    }
    for (std::uint16_t I = 0; I < Shnum; ++I) {
        const std::size_t O =
            static_cast<std::size_t>(Shoff + static_cast<std::uint64_t>(I) *
                                                 Shentsize);
        E.sections.push_back({load32(B, O), load32(B, O + 4), load64(B, O + 24),
                              load64(B, O + 32), load64(B, O + 56)});
    }
    if (Shstrndx >= E.sections.size()) {
        Error = "invalid ELF section-name string table index";
        return std::nullopt;
    }
    E.shstr_offset = E.sections[Shstrndx].offset;
    E.shstr_size = E.sections[Shstrndx].size;
    if (!rangeValid(B.size(), E.shstr_offset, E.shstr_size)) {
        Error = "ELF section-name string table extends beyond the file";
        return std::nullopt;
    }
    return E;
}

std::string_view sectionName(const std::vector<std::uint8_t> &B,
                             const ElfImage &E, const SectionHeader &S) {
    if (S.name_offset >= E.shstr_size)
        return {};
    const std::size_t O = static_cast<std::size_t>(E.shstr_offset + S.name_offset);
    const std::size_t Limit =
        static_cast<std::size_t>(E.shstr_offset + E.shstr_size);
    std::size_t End = O;
    while (End < Limit && B[End] != 0)
        ++End;
    if (End == Limit)
        return {};
    return {reinterpret_cast<const char *>(B.data() + O), End - O};
}

void scrubNativeSectionNames(std::vector<std::uint8_t> &B, const ElfImage &E,
                             const std::array<std::uint8_t, 16> &Marker) {
    constexpr std::array<std::string_view, 2> Names{
        ".morok_npack_rx", ".morok_npack_ro"};
    constexpr char Alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    unsigned Domain = 0;
    for (const SectionHeader &S : E.sections) {
        const std::string_view Name = sectionName(B, E, S);
        if (std::find(Names.begin(), Names.end(), Name) == Names.end())
            continue;
        const std::size_t O =
            static_cast<std::size_t>(E.shstr_offset + S.name_offset);
        B[O] = '.';
        for (std::size_t I = 1; I < Name.size(); ++I)
            B[O + I] = static_cast<std::uint8_t>(
                Alphabet[(Marker[(I + Domain) & 15u] + I * 11u) % 36u]);
        ++Domain;
    }
}

std::optional<std::size_t> findBuildId(const std::vector<std::uint8_t> &B,
                                       const ElfImage &E,
                                       std::string &Error) {
    std::optional<std::size_t> Found;
    for (const SectionHeader &S : E.sections) {
        if (S.type != SHT_NOTE)
            continue;
        if (!rangeValid(B.size(), S.offset, S.size)) {
            Error = "ELF note section extends beyond the file";
            return std::nullopt;
        }
        std::uint64_t O = S.offset;
        const std::uint64_t End = S.offset + S.size;
        while (O + 12 <= End) {
            const std::uint32_t NameSize = load32(B, static_cast<std::size_t>(O));
            const std::uint32_t DescSize = load32(B, static_cast<std::size_t>(O + 4));
            const std::uint32_t Type = load32(B, static_cast<std::size_t>(O + 8));
            const std::uint64_t NameOff = O + 12;
            const std::uint64_t DescOff =
                NameOff + ((static_cast<std::uint64_t>(NameSize) + 3) & ~3ULL);
            const std::uint64_t Next =
                DescOff + ((static_cast<std::uint64_t>(DescSize) + 3) & ~3ULL);
            if (Next > End) {
                Error = "malformed ELF note";
                return std::nullopt;
            }
            const bool GnuName = NameSize == 4 &&
                B[static_cast<std::size_t>(NameOff)] == 'G' &&
                B[static_cast<std::size_t>(NameOff + 1)] == 'N' &&
                B[static_cast<std::size_t>(NameOff + 2)] == 'U' &&
                B[static_cast<std::size_t>(NameOff + 3)] == 0;
            if (GnuName && Type == 3) {
                if (DescSize != 20) {
                    Error = "native packing requires a 20-byte SHA-1 build ID";
                    return std::nullopt;
                }
                if (Found) {
                    Error = "multiple GNU build IDs found";
                    return std::nullopt;
                }
                Found = static_cast<std::size_t>(DescOff);
            }
            O = Next;
        }
    }
    if (!Found)
        Error = "GNU SHA-1 build ID is required for native packing";
    return Found;
}

bool refreshBuildId(std::vector<std::uint8_t> &B, const ElfImage &E,
                    std::string &Error) {
    const auto Off = findBuildId(B, E, Error);
    if (!Off)
        return false;
    std::fill_n(B.begin() + static_cast<std::ptrdiff_t>(*Off), 20, 0);
    const core::Sha1Digest Digest = core::sha1(B);
    std::copy(Digest.begin(), Digest.end(),
              B.begin() + static_cast<std::ptrdiff_t>(*Off));
    return true;
}

bool verifyBuildId(const std::vector<std::uint8_t> &B, const ElfImage &E,
                   std::string &Error) {
    const auto Off = findBuildId(B, E, Error);
    if (!Off)
        return false;
    core::Sha1Digest Expected{};
    std::copy_n(B.begin() + static_cast<std::ptrdiff_t>(*Off), 20,
                Expected.begin());
    std::vector<std::uint8_t> Copy = B;
    std::fill_n(Copy.begin() + static_cast<std::ptrdiff_t>(*Off), 20, 0);
    if (core::sha1(Copy) != Expected) {
        Error = "GNU build ID does not describe the finalized artifact";
        return false;
    }
    return true;
}

std::optional<std::uint64_t> fileToVaddr(const ElfImage &E,
                                         std::uint64_t Offset,
                                         std::uint64_t Bytes) {
    for (const ProgramHeader &P : E.programs)
        if (P.type == PT_LOAD && Offset >= P.offset &&
            Bytes <= P.file_size && Offset - P.offset <= P.file_size - Bytes)
            return P.vaddr + (Offset - P.offset);
    return std::nullopt;
}

std::optional<std::uint64_t> vaddrToFile(const ElfImage &E,
                                         std::uint64_t Address,
                                         std::uint64_t Bytes,
                                         bool RequireExecute) {
    for (const ProgramHeader &P : E.programs) {
        if (P.type != PT_LOAD || (RequireExecute && (P.flags & PF_X) == 0) ||
            Address < P.vaddr || Bytes > P.file_size)
            continue;
        const std::uint64_t Delta = Address - P.vaddr;
        if (Delta <= P.file_size - Bytes)
            return P.offset + Delta;
    }
    return std::nullopt;
}

std::optional<std::uint64_t> addSignedDelta(std::uint64_t Base,
                                            std::int64_t Delta) {
    if (Delta < 0) {
        const std::uint64_t Magnitude =
            static_cast<std::uint64_t>(-(Delta + 1)) + 1;
        if (Magnitude > Base)
            return std::nullopt;
        return Base - Magnitude;
    }
    if (static_cast<std::uint64_t>(Delta) >
        std::numeric_limits<std::uint64_t>::max() - Base)
        return std::nullopt;
    return Base + static_cast<std::uint64_t>(Delta);
}

bool inProtected(std::uint64_t V, std::uint64_t Begin, std::uint64_t Length) {
    return V >= Begin && V - Begin < Length;
}

std::optional<std::string> auditRelocations(const std::vector<std::uint8_t> &B,
                                            const ElfImage &E,
                                            std::uint64_t Begin,
    std::uint64_t Length) {
    for (const SectionHeader &S : E.sections) {
        if (S.type == SHT_RELA || S.type == SHT_REL) {
            if (!rangeValid(B.size(), S.offset, S.size))
                return "relocation section extends beyond the ELF file";
            const std::uint64_t Default = S.type == SHT_RELA ? 24 : 16;
            const std::uint64_t Ent = S.entry_size == 0 ? Default : S.entry_size;
            if (Ent < Default || S.size % Ent != 0)
                return "invalid ELF relocation section";
            for (std::uint64_t O = S.offset; O < S.offset + S.size; O += Ent) {
                const std::uint64_t Target = load64(B, static_cast<std::size_t>(O));
                const std::uint64_t Info = load64(B, static_cast<std::size_t>(O + 8));
                const std::uint32_t Type = static_cast<std::uint32_t>(Info);
                if (inProtected(Target, Begin, Length))
                    return "dynamic relocation targets protected ciphertext";
                if ((E.machine == 62 && Type == 37) ||
                    (E.machine == 183 && Type == 1032))
                    return "IRELATIVE relocations are unsupported by native packing";
            }
        } else if (S.type == SHT_RELR) {
            if (!rangeValid(B.size(), S.offset, S.size))
                return "RELR section extends beyond the ELF file";
            const std::uint64_t Ent = S.entry_size == 0 ? 8 : S.entry_size;
            if (Ent != 8 || S.size % 8 != 0)
                return "invalid ELF RELR section";
            std::uint64_t Where = 0;
            for (std::uint64_t O = S.offset; O < S.offset + S.size; O += 8) {
                const std::uint64_t V = load64(B, static_cast<std::size_t>(O));
                if ((V & 1) == 0) {
                    if (inProtected(V, Begin, Length))
                        return "RELR relocation targets protected ciphertext";
                    Where = V + 8;
                } else {
                    const std::uint64_t Bitmap = V >> 1;
                    for (unsigned Bit = 0; Bit < 63; ++Bit)
                        if (((Bitmap >> Bit) & 1) != 0 &&
                            inProtected(Where + static_cast<std::uint64_t>(Bit) * 8,
                                        Begin, Length))
                            return "RELR relocation targets protected ciphertext";
                    Where += 63 * 8;
                }
            }
        } else if (S.type == SHT_SYMTAB || S.type == SHT_DYNSYM) {
            if (!rangeValid(B.size(), S.offset, S.size))
                return "symbol table extends beyond the ELF file";
            const std::uint64_t Ent = S.entry_size == 0 ? 24 : S.entry_size;
            if (Ent < 24 || S.size % Ent != 0)
                return "invalid ELF symbol table";
            for (std::uint64_t O = S.offset; O < S.offset + S.size; O += Ent)
                if ((B[static_cast<std::size_t>(O + 4)] & 0x0f) == 10)
                    return "GNU IFUNC symbols are unsupported by native packing";
        } else if (S.type == SHT_DYNAMIC) {
            if (!rangeValid(B.size(), S.offset, S.size))
                return "dynamic section extends beyond the ELF file";
            const std::uint64_t Ent = S.entry_size == 0 ? 16 : S.entry_size;
            if (Ent < 16 || S.size % Ent != 0)
                return "invalid ELF dynamic section";
            for (std::uint64_t O = S.offset; O < S.offset + S.size; O += Ent) {
                const std::uint64_t Tag = load64(B, static_cast<std::size_t>(O));
                const std::uint64_t Value = load64(B, static_cast<std::size_t>(O + 8));
                if (Tag == DT_NULL)
                    break;
                if (Tag == DT_TEXTREL)
                    return "DT_TEXTREL is unsupported by native packing";
                if (Tag == DT_INIT && inProtected(Value, Begin, Length))
                    return "DT_INIT points into protected ciphertext";
            }
        }
    }
    return std::nullopt;
}

std::string hex(std::span<const std::uint8_t> Bytes) {
    std::ostringstream Out;
    Out << std::hex << std::setfill('0');
    for (std::uint8_t B : Bytes)
        Out << std::setw(2) << static_cast<unsigned>(B);
    return Out.str();
}

std::optional<std::vector<std::uint8_t>> unhex(std::string_view Text) {
    if ((Text.size() & 1u) != 0)
        return std::nullopt;
    auto Nibble = [](char C) -> int {
        if (C >= '0' && C <= '9') return C - '0';
        if (C >= 'a' && C <= 'f') return C - 'a' + 10;
        if (C >= 'A' && C <= 'F') return C - 'A' + 10;
        return -1;
    };
    std::vector<std::uint8_t> Out;
    Out.reserve(Text.size() / 2);
    for (std::size_t I = 0; I < Text.size(); I += 2) {
        const int H = Nibble(Text[I]), L = Nibble(Text[I + 1]);
        if (H < 0 || L < 0)
            return std::nullopt;
        Out.push_back(static_cast<std::uint8_t>((H << 4) | L));
    }
    return Out;
}

template <std::size_t N>
bool parseField(std::string_view Value, std::array<std::uint8_t, N> &Out) {
    auto Bytes = unhex(Value);
    if (!Bytes || Bytes->size() != N)
        return false;
    std::copy(Bytes->begin(), Bytes->end(), Out.begin());
    return true;
}

std::optional<Secrets> readSecrets(const std::filesystem::path &Path,
                                   std::string &Error) {
    std::ifstream In(Path);
    if (!In) {
        Error = "cannot open native-pack key file " + Path.string();
        return std::nullopt;
    }
    std::string Line;
    if (!std::getline(In, Line) || Line != "MOROK_NATIVE_PACK_KEY_V1") {
        Error = "invalid native-pack key header";
        return std::nullopt;
    }
    Secrets S;
    unsigned Seen = 0;
    while (std::getline(In, Line)) {
        const std::size_t Eq = Line.find('=');
        if (Eq == std::string::npos)
            continue;
        const std::string_view Name(Line.data(), Eq);
        const std::string_view Value(Line.data() + Eq + 1, Line.size() - Eq - 1);
        if (Name == "key" && parseField(Value, S.key)) Seen |= 1;
        else if (Name == "share_b" && parseField(Value, S.share_b)) Seen |= 2;
        else if (Name == "marker" && parseField(Value, S.marker)) Seen |= 4;
        else if (Name == "nonce" && parseField(Value, S.nonce)) Seen |= 8;
        else if (Name == "salt" && parseField(Value, S.salt)) Seen |= 16;
    }
    if (Seen != 31) {
        Error = "native-pack key file is incomplete";
        return std::nullopt;
    }
    return S;
}

template <std::size_t N>
void fill(std::array<std::uint8_t, N> &Out, core::Xoshiro256pp &Engine) {
    for (std::size_t I = 0; I < N; I += 8) {
        const std::uint64_t V = Engine();
        for (std::size_t J = 0; J < 8 && I + J < N; ++J)
            Out[I + J] = static_cast<std::uint8_t>(V >> (J * 8));
    }
}

std::string byteMacro(std::span<const std::uint8_t> Bytes) {
    std::ostringstream Out;
    Out << std::hex << std::setfill('0');
    for (std::size_t I = 0; I < Bytes.size(); ++I) {
        if (I != 0) Out << ',';
        Out << "0x" << std::setw(2) << static_cast<unsigned>(Bytes[I]);
    }
    return Out.str();
}

std::optional<std::size_t> findMarker(const std::vector<std::uint8_t> &B,
                                      const std::array<std::uint8_t, 16> &M,
                                      std::string &Error) {
    std::optional<std::size_t> Found;
    auto It = B.begin();
    while ((It = std::search(It, B.end(), M.begin(), M.end())) != B.end()) {
        const std::size_t O = static_cast<std::size_t>(It - B.begin());
        if (rangeValid(B.size(), O, kMetaSize)) {
            if (Found) {
                Error = "native-pack metadata marker is not unique";
                return std::nullopt;
            }
            Found = O;
        }
        ++It;
    }
    if (!Found)
        Error = "native-pack metadata marker was not found";
    return Found;
}

std::optional<std::size_t> findFinalizedMeta(const std::vector<std::uint8_t> &B,
                                             const ElfImage &E,
                                             std::string &Error) {
    std::optional<std::size_t> Found;
    for (std::size_t O = 0; O + kMetaSize <= B.size(); O += 8) {
        if (load32(B, O + kVersionOff) != 1 ||
            load32(B, O + kFlagsOff) != 1)
            continue;
        const std::uint64_t Length = load64(B, O + kLengthOff);
        const std::uint64_t Cookie = load64(B, O + kCookieOff);
        const std::uint64_t Expected = load64(B, O + kTagOff) ^ Length ^
                                       load64(B, O + kSaltOff) ^ kCookieDomain;
        if (Length == 0 || (Length & (kIsolation - 1)) != 0 ||
            Cookie != Expected)
            continue;
        const auto MetaVa = fileToVaddr(E, O, kMetaSize);
        if (!MetaVa)
            continue;
        const auto BeginValue =
            addSignedDelta(*MetaVa, loadS64(B, O + kDeltaOff));
        if (!BeginValue)
            continue;
        const std::uint64_t Begin = *BeginValue;
        if ((Begin & (kIsolation - 1)) != 0 || Begin > *MetaVa ||
            *MetaVa - Begin != Length ||
            !vaddrToFile(E, Begin, Length, true))
            continue;
        if (Found) {
            Error = "multiple finalized native-pack manifests found";
            return std::nullopt;
        }
        Found = O;
    }
    if (!Found)
        Error = "no finalized native-pack manifest found";
    return Found;
}

} // namespace

NativePackResult prepareNativePack(const std::filesystem::path &Directory,
                                   std::uint64_t Seed) {
    std::error_code Ec;
    std::filesystem::create_directories(Directory, Ec);
    if (Ec)
        return failure("cannot create " + Directory.string() + ": " +
                       Ec.message());

    core::Xoshiro256pp Engine =
        Seed == 0 ? core::makeSeededEngine() : core::Xoshiro256pp::fromSeed(Seed);
    Secrets S;
    std::array<std::uint8_t, 32> ShareA{};
    fill(S.key, Engine);
    fill(ShareA, Engine);
    fill(S.marker, Engine);
    fill(S.nonce, Engine);
    fill(S.salt, Engine);
    for (std::size_t I = 0; I < S.share_b.size(); ++I)
        S.share_b[I] = S.key[I] ^ ShareA[I];

    const auto Header = Directory / "morok_native_pack_config.h";
    std::ofstream H(Header, std::ios::trunc);
    if (!H)
        return failure("cannot create " + Header.string());
    H << "#ifndef MOROK_NATIVE_PACK_CONFIG_H\n"
      << "#define MOROK_NATIVE_PACK_CONFIG_H\n"
      << "#define MOROK_NPACK_MARKER_BYTES " << byteMacro(S.marker) << "\n"
      << "#define MOROK_NPACK_KEY_A_BYTES " << byteMacro(ShareA) << "\n"
      << "#define MOROK_NPACK_SALT_BYTES " << byteMacro(S.salt) << "\n"
      << "#endif\n";
    H.close();
    if (!H)
        return failure("cannot write " + Header.string());

    const auto KeyPath = Directory / "morok_native_pack.key";
    std::ofstream K(KeyPath, std::ios::trunc);
    if (!K)
        return failure("cannot create " + KeyPath.string());
    K << "MOROK_NATIVE_PACK_KEY_V1\n"
      << "key=" << hex(S.key) << "\n"
      << "share_b=" << hex(S.share_b) << "\n"
      << "marker=" << hex(S.marker) << "\n"
      << "nonce=" << hex(S.nonce) << "\n"
      << "salt=" << hex(S.salt) << "\n";
    K.close();
    if (!K)
        return failure("cannot write " + KeyPath.string());
    std::filesystem::permissions(
        KeyPath, std::filesystem::perms::owner_read |
                     std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, Ec);
    if (Ec)
        return failure("cannot restrict permissions on " + KeyPath.string());
    return {true, {}, 0};
}

NativePackResult finalizeNativePack(const std::filesystem::path &Binary,
                                    const std::filesystem::path &KeyFile,
                                    bool ConsumeKey) {
    std::string Error;
    auto BytesOpt = readFile(Binary, Error);
    if (!BytesOpt)
        return failure(Error);
    std::vector<std::uint8_t> Bytes = std::move(*BytesOpt);
    auto Elf = parseElf(Bytes, Error);
    if (!Elf)
        return failure(Error);
    auto SecretsOpt = readSecrets(KeyFile, Error);
    if (!SecretsOpt)
        return failure(Error);
    const Secrets &S = *SecretsOpt;
    auto MetaOff = findMarker(Bytes, S.marker, Error);
    if (!MetaOff)
        return failure(Error);
    const std::size_t M = *MetaOff;
    if (load32(Bytes, M + kVersionOff) != 1 ||
        load32(Bytes, M + kFlagsOff) != 1 ||
        load64(Bytes, M + kCookieOff) != 0)
        return failure("native-pack metadata is incompatible or already finalized");
    if (!std::equal(S.salt.begin(), S.salt.end(), Bytes.begin() +
                                                     static_cast<std::ptrdiff_t>(M + kSaltOff)))
        return failure("native-pack salt does not match the loader object");

    const auto MetaVa = fileToVaddr(*Elf, M, kMetaSize);
    if (!MetaVa)
        return failure("native-pack metadata is not file-backed by PT_LOAD");
    const auto BeginValue =
        addSignedDelta(*MetaVa, loadS64(Bytes, M + kDeltaOff));
    const auto EndValue =
        addSignedDelta(*MetaVa, loadS64(Bytes, M + kLengthOff));
    if (!BeginValue || !EndValue || *EndValue <= *BeginValue)
        return failure("protected-range self-relative bounds are invalid");
    const std::uint64_t Begin = *BeginValue;
    const std::uint64_t Length = *EndValue - Begin;
    if (Length == 0 || Length > 0x40000000ULL || *EndValue != *MetaVa ||
        (Begin & (kIsolation - 1)) != 0 ||
        (Length & (kIsolation - 1)) != 0)
        return failure("protected range is empty, excessive, or not 64 KiB isolated");
    store64(Bytes, M + kLengthOff, Length);
    const auto FileOff = vaddrToFile(*Elf, Begin, Length, true);
    if (!FileOff || !rangeValid(Bytes.size(), *FileOff, Length))
        return failure("protected range is not wholly file-backed and executable");
    if (M >= *FileOff && M - *FileOff < Length)
        return failure("loader metadata overlaps protected ciphertext");
    if (auto RelocError = auditRelocations(Bytes, *Elf, Begin, Length))
        return failure(*RelocError);

    std::copy(S.nonce.begin(), S.nonce.end(),
              Bytes.begin() + static_cast<std::ptrdiff_t>(M + kNonceOff));
    std::copy(S.share_b.begin(), S.share_b.end(),
              Bytes.begin() + static_cast<std::ptrdiff_t>(M + kKeyShareOff));
    std::array<std::uint8_t, 40> Aad{};
    std::copy_n(Bytes.begin() + static_cast<std::ptrdiff_t>(M + kVersionOff),
                24, Aad.begin());
    std::copy(S.salt.begin(), S.salt.end(), Aad.begin() + 24);
    std::span<std::uint8_t> Protected(
        Bytes.data() + static_cast<std::size_t>(*FileOff),
        static_cast<std::size_t>(Length));
    const core::Poly1305Tag Tag =
        core::chacha20Poly1305Encrypt(Protected, Aad, S.key, S.nonce);
    std::copy(Tag.begin(), Tag.end(),
              Bytes.begin() + static_cast<std::ptrdiff_t>(M + kTagOff));
    const std::uint64_t Cookie = load64(Bytes, M + kTagOff) ^ Length ^
                                 load64(Bytes, M + kSaltOff) ^ kCookieDomain;
    store64(Bytes, M + kCookieOff, Cookie);
    scrubNativeSectionNames(Bytes, *Elf, S.marker);
    if (!refreshBuildId(Bytes, *Elf, Error))
        return failure(Error);

    if (!writeAtomic(Binary, Bytes, Error))
        return failure(Error);
    NativePackResult Verified = verifyNativePack(Binary);
    if (!Verified.ok)
        return failure("post-write verification failed: " + Verified.error);
    if (ConsumeKey) {
        std::error_code Ec;
        if (!std::filesystem::remove(KeyFile, Ec) || Ec)
            return failure("finalized binary but could not consume key file " +
                           KeyFile.string());
    }
    return {true, {}, Length};
}

NativePackResult verifyNativePack(const std::filesystem::path &Binary) {
    std::string Error;
    auto Bytes = readFile(Binary, Error);
    if (!Bytes)
        return failure(Error);
    auto Elf = parseElf(*Bytes, Error);
    if (!Elf)
        return failure(Error);
    if (!verifyBuildId(*Bytes, *Elf, Error))
        return failure(Error);
    auto Meta = findFinalizedMeta(*Bytes, *Elf, Error);
    if (!Meta)
        return failure(Error);
    const std::uint64_t Length = load64(*Bytes, *Meta + kLengthOff);
    return {true, {}, Length};
}

} // namespace morok::packer
