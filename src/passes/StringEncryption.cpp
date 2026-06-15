// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/StringEncryption.cpp

#include "morok/passes/StringEncryption.hpp"

#include "morok/core/Galois8.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <cstdint>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace gf8 = core::gf8;

namespace {

constexpr std::uint64_t kMaxEncryptedStrings = 64;
constexpr std::uint64_t kMaxEncryptedStringBytes = 1024;
constexpr std::uint64_t kMaxEncryptedTotalBytes = 4096;

// Emit (once) an internal GF(2^8) multiply mirroring morok::core::gf8::mul:
// shift-and-add over xtime with the AES reduction polynomial, unrolled 8×.
Function *getOrCreateGf8Mul(Module &M) {
    if (Function *existing = M.getFunction("morok.gf8mul"))
        return existing;
    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *ft = FunctionType::get(i8, {i8, i8}, false);
    auto *f =
        Function::Create(ft, GlobalValue::InternalLinkage, "morok.gf8mul", &M);
    f->addFnAttr(Attribute::AlwaysInline);

    BasicBlock *bb = BasicBlock::Create(ctx, "entry", f);
    IRBuilder<> B(bb);
    Value *a = f->getArg(0);
    Value *b = f->getArg(1);
    Value *zero = ConstantInt::get(i8, 0);
    Value *r = zero;
    for (int i = 0; i < 8; ++i) {
        Value *bitSet =
            B.CreateICmpNE(B.CreateAnd(b, ConstantInt::get(i8, 1)), zero);
        r = B.CreateXor(r, B.CreateSelect(bitSet, a, zero));
        Value *hiSet =
            B.CreateICmpNE(B.CreateAnd(a, ConstantInt::get(i8, 0x80)), zero);
        Value *shifted = B.CreateShl(a, ConstantInt::get(i8, 1));
        a = B.CreateXor(
            shifted,
            B.CreateSelect(hiSet, ConstantInt::get(i8, gf8::kReductionPoly),
                           zero));
        b = B.CreateLShr(b, ConstantInt::get(i8, 1));
    }
    B.CreateRet(r);
    return f;
}

bool eligible(const GlobalVariable &gv) {
    if (!gv.hasInitializer() || !gv.hasLocalLinkage())
        return false;
    if (gv.getName().starts_with("llvm.") || gv.getName().starts_with("morok."))
        return false;
    if (gv.getSection() == "llvm.metadata")
        return false;
    const auto *cda = dyn_cast<ConstantDataArray>(gv.getInitializer());
    return cda && cda->getElementType()->isIntegerTy(8) &&
           cda->getNumElements() > 0;
}

struct Encrypted {
    GlobalVariable *data; // now-mutable ciphertext (decrypted in place)
    GlobalVariable *pads; // k1 one-time pads
    GlobalVariable *invs; // k2^{-1} multipliers
    std::uint64_t length;
};

} // namespace

bool stringEncryptModule(Module &M, const StrEncParams &params,
                         ir::IRRandom &rng) {
    if (params.probability == 0)
        return false;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);

    std::vector<GlobalVariable *> targets;
    targets.reserve(kMaxEncryptedStrings);
    std::uint64_t selectedBytes = 0;
    for (GlobalVariable &gv : M.globals()) {
        if (targets.size() >= kMaxEncryptedStrings ||
            selectedBytes >= kMaxEncryptedTotalBytes)
            break;
        if (!eligible(gv))
            continue;
        const auto *cda = cast<ConstantDataArray>(gv.getInitializer());
        const std::uint64_t n = cda->getNumElements();
        if (n > kMaxEncryptedStringBytes ||
            selectedBytes + n > kMaxEncryptedTotalBytes)
            continue;
        if (rng.chance(params.probability)) {
            targets.push_back(&gv);
            selectedBytes += n;
        }
    }

    std::vector<Encrypted> encrypted;
    for (GlobalVariable *gv : targets) {
        const auto *cda = cast<ConstantDataArray>(gv->getInitializer());
        StringRef raw = cda->getRawDataValues();
        const std::uint64_t n = cda->getNumElements();

        std::vector<std::uint8_t> ct(n), pads(n), invs(n);
        for (std::uint64_t i = 0; i < n; ++i) {
            auto p = static_cast<std::uint8_t>(raw[i]);
            auto k1 = static_cast<std::uint8_t>(rng.next());
            std::uint8_t k2 = 0;
            while (k2 == 0)
                k2 = static_cast<std::uint8_t>(rng.next());
            ct[i] = gf8::encryptByte(p, k1, k2);
            pads[i] = k1;
            invs[i] = gf8::inv(k2);
        }

        gv->setInitializer(
            ConstantDataArray::get(ctx, ArrayRef<std::uint8_t>(ct)));
        gv->setConstant(false); // mutated in place by the decryptor

        auto mkKey = [&](ArrayRef<std::uint8_t> bytes, const char *name) {
            Constant *init = ConstantDataArray::get(ctx, bytes);
            return new GlobalVariable(M, init->getType(), /*isConstant=*/true,
                                      GlobalValue::PrivateLinkage, init, name);
        };
        encrypted.push_back(
            {gv, mkKey(pads, "morok.k1"), mkKey(invs, "morok.k2inv"), n});
    }

    if (encrypted.empty())
        return false;

    Function *gf8mul = getOrCreateGf8Mul(M);
    auto *decFn =
        Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                         GlobalValue::InternalLinkage, "morok.strdec", &M);
    IRBuilder<> B(BasicBlock::Create(ctx, "entry", decFn));
    for (const Encrypted &e : encrypted) {
        for (std::uint64_t i = 0; i < e.length; ++i) {
            Value *dataPtr = B.CreateConstInBoundsGEP2_64(
                e.data->getValueType(), e.data, 0, i);
            Value *c = B.CreateLoad(i8, dataPtr);
            Value *inv =
                B.CreateLoad(i8, B.CreateConstInBoundsGEP2_64(
                                     e.invs->getValueType(), e.invs, 0, i));
            Value *pad =
                B.CreateLoad(i8, B.CreateConstInBoundsGEP2_64(
                                     e.pads->getValueType(), e.pads, 0, i));
            Value *plain = B.CreateXor(B.CreateCall(gf8mul, {c, inv}), pad);
            B.CreateStore(plain, dataPtr);
        }
    }
    B.CreateRetVoid();

    appendToGlobalCtors(M, decFn, /*Priority=*/0);
    return true;
}

PreservedAnalyses StringEncryptionPass::run(Module &M,
                                            ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return stringEncryptModule(M, params_, rng) ? PreservedAnalyses::none()
                                                : PreservedAnalyses::all();
}

} // namespace morok::passes
