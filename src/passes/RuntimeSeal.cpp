// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// Shared runtime seal / KDF support for dataflow-bound detector consumers.

#include "morok/passes/RuntimeSeal.hpp"

#include "llvm/ADT/SmallString.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <cctype>

using namespace llvm;

namespace morok::passes::runtime_seal {
namespace {

std::string rootName(StringRef Channel) {
    SmallString<64> Name("morok.seal.root.");
    for (char C : Channel) {
        const auto UC = static_cast<unsigned char>(C);
        Name.push_back((std::isalnum(UC) || C == '_' || C == '.') ? C : '_');
    }
    return std::string(Name);
}

Value *toI64(IRBuilderBase &B, Value *V) {
    auto *I64 = B.getInt64Ty();
    if (V->getType()->isIntegerTy(64))
        return V;
    if (V->getType()->isIntegerTy())
        return B.CreateZExtOrTrunc(V, I64);
    return B.CreatePtrToInt(V, I64);
}

Value *mix64(IRBuilderBase &B, Value *X, std::uint64_t Salt,
             const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    X = B.CreateAdd(X, ConstantInt::get(I64, Salt), Name + ".add");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 33)),
                    Name + ".fold33");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xff51afd7ed558ccdULL),
                    Name + ".mul0");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 29)),
                    Name + ".fold29");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xc4ceb9fe1a85ec53ULL),
                    Name + ".mul1");
    return B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 32)),
                       Name + ".fold32");
}

} // namespace

GlobalVariable *findChannel(Module &M, StringRef Channel) {
    return M.getGlobalVariable(rootName(Channel), /*AllowInternal=*/true);
}

GlobalVariable *getChannel(Module &M, StringRef Channel, ir::IRRandom &Rng) {
    if (auto *Existing = findChannel(M, Channel))
        return Existing;
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(M, I64, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantInt::get(I64, Rng.next()),
                                  rootName(Channel));
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    GV->setAlignment(Align(8));
    return GV;
}

std::uint64_t initialValue(const GlobalVariable *Seal) {
    if (!Seal || !Seal->hasInitializer())
        return 0;
    if (auto *CI = dyn_cast<ConstantInt>(Seal->getInitializer()))
        return CI->getZExtValue();
    return 0;
}

Value *emitDelta(IRBuilderBase &B, GlobalVariable *Seal,
                 std::uint64_t Initial, const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    if (!Seal)
        return ConstantInt::get(I64, 0);
    auto *Loaded = B.CreateLoad(I64, Seal, Name + ".load");
    Loaded->setVolatile(true);
    Loaded->setAlignment(Align(8));
    return B.CreateXor(Loaded, ConstantInt::get(I64, Initial),
                       Name + ".delta");
}

Value *emitChannelDelta(IRBuilderBase &B, StringRef Channel,
                        const Twine &Name) {
    Module *M = B.GetInsertBlock() ? B.GetInsertBlock()->getModule() : nullptr;
    if (!M)
        return ConstantInt::get(B.getInt64Ty(), 0);
    GlobalVariable *Seal = findChannel(*M, Channel);
    return emitDelta(B, Seal, initialValue(Seal), Name);
}

Value *emitKdf64(IRBuilderBase &B, Value *Delta, std::uint64_t Domain,
                 const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    Delta = toI64(B, Delta);
    Value *Dirty = B.CreateICmpNE(Delta, ConstantInt::get(I64, 0),
                                  Name + ".dirty");
    Value *Seed =
        B.CreateXor(Delta, ConstantInt::get(I64, Domain),
                    Name + ".domain");
    Value *Mixed = mix64(B, Seed, Domain ^ 0x9E3779B97F4A7C15ULL, Name);
    return B.CreateSelect(Dirty, Mixed, ConstantInt::get(I64, 0),
                          Name + ".key");
}

void foldFlag(IRBuilderBase &B, StringRef Channel, Value *Flag,
              std::uint64_t Salt, const Twine &Name) {
    Module *M = B.GetInsertBlock() ? B.GetInsertBlock()->getModule() : nullptr;
    if (!M)
        return;
    GlobalVariable *Seal = findChannel(*M, Channel);
    if (!Seal)
        return;

    auto *I64 = B.getInt64Ty();
    Value *Tripped = B.CreateICmpNE(toI64(B, Flag), ConstantInt::get(I64, 0),
                                    Name + ".trip");
    auto *Cur = B.CreateLoad(I64, Seal, Name + ".cur");
    Cur->setVolatile(true);
    Cur->setAlignment(Align(8));
    Value *Rot = B.CreateOr(B.CreateShl(Cur, ConstantInt::get(I64, 17)),
                            B.CreateLShr(Cur, ConstantInt::get(I64, 47)),
                            Name + ".rot");
    Value *Mixed =
        B.CreateXor(Rot, ConstantInt::get(I64, Salt ^ 0xD6E8FEB86659FD93ULL),
                    Name + ".salt");
    Mixed = B.CreateMul(
        Mixed, ConstantInt::get(I64, (Salt ^ 0x9E3779B97F4A7C15ULL) | 1ULL),
        Name + ".mul");
    Mixed = B.CreateAdd(
        Mixed, ConstantInt::get(I64, (Salt + 0xA0761D6478BD642FULL) | 1ULL),
        Name + ".mix");
    Value *Next = B.CreateSelect(Tripped, Mixed, Cur, Name + ".next");
    auto *Store = B.CreateStore(Next, Seal);
    Store->setVolatile(true);
    Store->setAlignment(Align(8));
}

void foldWord(IRBuilderBase &B, StringRef Channel, Value *Word,
              std::uint64_t Salt, const Twine &Name) {
    Module *M = B.GetInsertBlock() ? B.GetInsertBlock()->getModule() : nullptr;
    if (!M)
        return;
    GlobalVariable *Seal = findChannel(*M, Channel);
    if (!Seal)
        return;

    auto *I64 = B.getInt64Ty();
    Value *Word64 = toI64(B, Word);
    Value *Active = B.CreateICmpNE(Word64, ConstantInt::get(I64, 0),
                                   Name + ".active");
    auto *Cur = B.CreateLoad(I64, Seal, Name + ".cur");
    Cur->setVolatile(true);
    Cur->setAlignment(Align(8));
    Value *Input = B.CreateXor(Cur, Word64, Name + ".word");
    Value *Mixed = mix64(B, Input, Salt ^ 0xA0761D6478BD642FULL, Name);
    Value *Next = B.CreateSelect(Active, Mixed, Cur, Name + ".next");
    auto *Store = B.CreateStore(Next, Seal);
    Store->setVolatile(true);
    Store->setAlignment(Align(8));
}

} // namespace morok::passes::runtime_seal
