// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/StringEncryption.cpp
//
// Every eligible private byte-array string is encrypted with its OWN cipher —
// a per-string keystream generator (one of several), XOR- or ADD-combined, with
// per-string key material keyed on a runtime-opaque module seed.  Constant
// C-strings whose uses can be rewritten are recovered into fresh stack buffers
// at each use site; strings with address-identity or mutation-sensitive uses
// fall back to their own private constructor.  Read-only C strings are length-
// padded to a random block multiple, so the stored array size no longer reveals
// the string's length.

#include "morok/passes/StringEncryption.hpp"

#include "morok/ir/SymbolCloak.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <cstdint>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

// Encrypt *every* eligible string — readable strings are toxic — so the caps
// are sized only to keep pathological inputs in check, not to leave strings in
// the clear.  Strings longer than the unroll threshold get a compact loop
// decryptor instead of a fully unrolled one, so total code size stays bounded
// regardless of how much string data a module carries.
constexpr std::uint64_t kMaxEncryptedStrings = 8192;
constexpr std::uint64_t kMaxEncryptedStringBytes = 1u << 20; // 1 MiB / string
constexpr std::uint64_t kMaxEncryptedTotalBytes = 8u << 20;  // 8 MiB / module
constexpr std::uint64_t kUnrollThreshold = 64; // ≤ this ⇒ unrolled, else loop

bool eligible(const GlobalVariable &gv) {
    if (!gv.hasInitializer() || !gv.hasLocalLinkage())
        return false;
    // A single global constructor only decrypts the init-time TLS instance;
    // other threads would observe ciphertext.  Leave thread-locals alone.
    if (gv.isThreadLocal())
        return false;
    if (gv.getName().starts_with("llvm.") || gv.getName().starts_with("morok."))
        return false;
    if (gv.getSection() == "llvm.metadata")
        return false;
    const auto *cda = dyn_cast<ConstantDataArray>(gv.getInitializer());
    return cda && cda->getElementType()->isIntegerTy(8) &&
           cda->getNumElements() > 0;
}

// The per-string cipher recipe; chosen independently for every string.
struct Cipher {
    unsigned variant = 0;  // keystream generator
    bool add = false;      // ADD vs XOR combine
    std::uint64_t key = 0; // per-string xor into the module seed
    std::uint64_t mul = 1; // per-string odd multiplier
};

struct UseSite {
    Instruction *inst = nullptr;
    unsigned operand = 0;
};

bool isZeroConstant(Value *V) {
    if (auto *CI = dyn_cast<ConstantInt>(V))
        return CI->isZero();
    return false;
}

bool isStartPointerTo(const GlobalVariable *GV, Value *V) {
    if (V == GV)
        return true;

    auto *CE = dyn_cast<ConstantExpr>(V);
    if (!CE)
        return false;

    if (CE->isCast())
        return isStartPointerTo(GV, CE->getOperand(0));

    if (CE->getOpcode() != Instruction::GetElementPtr ||
        CE->getNumOperands() < 2 || CE->getOperand(0) != GV)
        return false;
    for (unsigned I = 1; I != CE->getNumOperands(); ++I)
        if (!isZeroConstant(CE->getOperand(I)))
            return false;
    return true;
}

bool collectStackUseSites(Value *V, const GlobalVariable *GV,
                          SmallVectorImpl<UseSite> &Sites,
                          SmallPtrSetImpl<Value *> &Seen) {
    if (!Seen.insert(V).second)
        return true;

    for (Use &U : V->uses()) {
        User *Usr = U.getUser();
        if (auto *I = dyn_cast<Instruction>(Usr)) {
            auto *CB = dyn_cast<CallBase>(I);
            if (!CB || !CB->isArgOperand(&U))
                return false;
            const unsigned ArgNo = CB->getArgOperandNo(&U);
            if (!CB->doesNotCapture(ArgNo))
                return false;
            if (!isStartPointerTo(GV, I->getOperand(U.getOperandNo())))
                return false;
            Sites.push_back({I, U.getOperandNo()});
            continue;
        }
        if (auto *CE = dyn_cast<ConstantExpr>(Usr)) {
            if (!isStartPointerTo(GV, CE))
                return false;
            if (!collectStackUseSites(CE, GV, Sites, Seen))
                return false;
            continue;
        }
        return false;
    }
    return true;
}

// Emit, unrolled, the decryption of `n` bytes read from `src[i]` and written to
// `dst[i]` (both base pointers to `arrTy` == [n x i8]) at B's insertion point.
void emitDecryptUnrolled(IRBuilder<> &B, const Cipher &c, GlobalVariable *seed,
                         Value *src, Value *dst, ArrayType *arrTy,
                         std::uint64_t n) {
    auto *i8 = Type::getInt8Ty(B.getContext());
    auto *i64 = Type::getInt64Ty(B.getContext());
    Value *rtKey = B.CreateXor(B.CreateLoad(i64, seed, /*isVolatile=*/true),
                               ConstantInt::get(i64, c.key));
    for (std::uint64_t i = 0; i < n; ++i) {
        Value *ks = ir::emitKeystream(B, c.variant, rtKey,
                                      static_cast<std::uint32_t>(i), c.mul);
        Value *ksByte = B.CreateTrunc(ks, i8);
        Value *sp = B.CreateInBoundsGEP(
            arrTy, src, {ConstantInt::get(i64, 0), ConstantInt::get(i64, i)});
        Value *dp = B.CreateInBoundsGEP(
            arrTy, dst, {ConstantInt::get(i64, 0), ConstantInt::get(i64, i)});
        Value *cipher = B.CreateLoad(i8, sp);
        Value *plain =
            c.add ? B.CreateSub(cipher, ksByte) : B.CreateXor(cipher, ksByte);
        B.CreateStore(plain, dp);
    }
}

Function *createStackDecryptHelper(Module &M, const Cipher &C,
                                   GlobalVariable *Seed,
                                   GlobalVariable *CipherText, ArrayType *ArrTy,
                                   std::uint64_t Len) {
    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *VoidTy = Type::getVoidTy(Ctx);
    auto *PtrTy = PointerType::get(Ctx, 0);
    auto *FTy = FunctionType::get(VoidTy, {PtrTy}, false);
    auto *Fn =
        Function::Create(FTy, GlobalValue::InternalLinkage, "morok.strsite", M);
    Fn->setDSOLocal(true);
    Fn->addFnAttr(Attribute::NoInline);
    Fn->addFnAttr(Attribute::OptimizeNone);
    Argument *DstArg = Fn->getArg(0);
    DstArg->setName("dst");

    if (Len <= kUnrollThreshold) {
        IRBuilder<> B(BasicBlock::Create(Ctx, "entry", Fn));
        emitDecryptUnrolled(B, C, Seed, CipherText, DstArg, ArrTy, Len);
        B.CreateRetVoid();
        return Fn;
    }

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    BasicBlock *Loop = BasicBlock::Create(Ctx, "morok.str.stack.loop", Fn);
    BasicBlock *Done = BasicBlock::Create(Ctx, "morok.str.stack.done", Fn);

    IRBuilder<> EB(Entry);
    LoadInst *SeedLoad =
        EB.CreateLoad(I64, Seed, /*isVolatile=*/true, "morok.str.stack.k");
    Value *RtKey = EB.CreateXor(SeedLoad, ConstantInt::get(I64, C.key),
                                "morok.str.stack.k0");
    EB.CreateBr(Loop);

    IRBuilder<> LB(Loop);
    PHINode *I = LB.CreatePHI(I64, 2, "morok.str.stack.i");
    I->addIncoming(ConstantInt::get(I64, 0), Entry);
    Value *Ks = ir::emitKeystreamDynamic(LB, C.variant, RtKey, I, C.mul);
    Value *KsByte = LB.CreateTrunc(Ks, I8);
    Value *Src =
        LB.CreateInBoundsGEP(ArrTy, CipherText, {ConstantInt::get(I64, 0), I},
                             "morok.str.stack.src");
    Value *Dst = LB.CreateInBoundsGEP(
        ArrTy, DstArg, {ConstantInt::get(I64, 0), I}, "morok.str.stack.dst");
    Value *CipherByte = LB.CreateLoad(I8, Src);
    Value *Plain = C.add ? LB.CreateSub(CipherByte, KsByte)
                         : LB.CreateXor(CipherByte, KsByte);
    LB.CreateStore(Plain, Dst);
    Value *Next =
        LB.CreateAdd(I, ConstantInt::get(I64, 1), "morok.str.stack.next");
    I->addIncoming(Next, Loop);
    Value *More = LB.CreateICmpULT(Next, ConstantInt::get(I64, Len),
                                   "morok.str.stack.more");
    LB.CreateCondBr(More, Loop, Done);

    IRBuilder<> DB(Done);
    DB.CreateRetVoid();
    return Fn;
}

Value *emitStackString(Instruction *InsertBefore, const Cipher &C,
                       GlobalVariable *Seed, GlobalVariable *CipherText,
                       ArrayType *ArrTy, std::uint64_t Len) {
    Module &M = *InsertBefore->getFunction()->getParent();
    Function *Helper =
        createStackDecryptHelper(M, C, Seed, CipherText, ArrTy, Len);
    IRBuilder<> B(InsertBefore);
    auto *I64 = Type::getInt64Ty(B.getContext());
    AllocaInst *Buf = B.CreateAlloca(ArrTy, nullptr, "morok.str.stack.buf");
    B.CreateCall(Helper->getFunctionType(), Helper, {Buf});
    return B.CreateInBoundsGEP(
        ArrTy, Buf, {ConstantInt::get(I64, 0), ConstantInt::get(I64, 0)},
        "morok.str.stack.ptr");
}

bool materializeStackUses(GlobalVariable *GV, const Cipher &C,
                          GlobalVariable *Seed, ArrayType *ArrTy,
                          std::uint64_t Len) {
    SmallVector<UseSite, 8> Sites;
    SmallPtrSet<Value *, 8> Seen;
    if (!collectStackUseSites(GV, GV, Sites, Seen) || Sites.empty())
        return false;

    for (UseSite Site : Sites) {
        Value *Stack = emitStackString(Site.inst, C, Seed, GV, ArrTy, Len);
        Site.inst->setOperand(Site.operand, Stack);
    }
    return true;
}

} // namespace

bool stringEncryptModule(Module &M, const StrEncParams &params,
                         ir::IRRandom &rng) {
    if (params.probability == 0)
        return false;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *voidTy = Type::getVoidTy(ctx);

    std::vector<GlobalVariable *> targets;
    targets.reserve(64);
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
    if (targets.empty())
        return false;

    // One runtime-opaque module seed underlies every per-string key; reading it
    // with a volatile load keeps the optimizer from folding ciphertext to text.
    GlobalVariable *seed = ir::cloakSeed(M, rng);
    const std::uint64_t seedVal =
        cast<ConstantInt>(seed->getInitializer())->getZExtValue();

    bool changed = false;
    for (GlobalVariable *gv : targets) {
        const auto *cda = cast<ConstantDataArray>(gv->getInitializer());
        StringRef raw = cda->getRawDataValues();
        const std::uint64_t n = cda->getNumElements();
        const bool stackCandidate = gv->isConstant() && cda->isCString();

        Cipher c;
        c.variant = rng.range(ir::kKeystreamVariants);
        c.add = rng.range(2) == 0;
        c.key = rng.next();
        c.mul = rng.next() | 1ull;
        const std::uint64_t k0 = seedVal ^ c.key;

        // Hide the length: a C string is padded to a random multiple of a block
        // size with random trailing bytes.  The runtime consumer still stops at
        // the original NUL, but the stored array size no longer reveals how
        // long the string is.  Raw (non-C-string) byte arrays keep their exact
        // size.
        std::vector<std::uint8_t> plain(n);
        for (std::uint64_t i = 0; i < n; ++i)
            plain[i] = static_cast<std::uint8_t>(raw[i]);
        // Only length-pad read-only C strings; a mutable global may be indexed
        // up to its original size by the program, so its size must not change.
        if (gv->isConstant() && cda->isCString()) {
            constexpr std::uint64_t kBlock = 16;
            const std::uint64_t blocks =
                (n + kBlock - 1) / kBlock + rng.range(3);
            const std::size_t padded =
                static_cast<std::size_t>(blocks * kBlock);
            const std::size_t old = plain.size();
            plain.resize(padded);
            for (std::size_t i = old; i < padded; ++i)
                plain[i] = static_cast<std::uint8_t>(rng.next());
        }
        const std::uint64_t storedLen = plain.size();

        std::vector<std::uint8_t> ct(storedLen);
        for (std::uint64_t i = 0; i < storedLen; ++i) {
            const auto ks = static_cast<std::uint8_t>(
                ir::keystreamValue(c.variant, k0, static_cast<std::uint32_t>(i),
                                   c.mul) &
                0xFFu);
            ct[i] = c.add ? static_cast<std::uint8_t>(plain[i] + ks)
                          : static_cast<std::uint8_t>(plain[i] ^ ks);
        }
        Constant *cipherInit =
            ConstantDataArray::get(ctx, ArrayRef<std::uint8_t>(ct));

        // A global's type is fixed at creation, so a size change means a new,
        // larger global with uses redirected to it.
        GlobalVariable *target = gv;
        if (storedLen == n) {
            gv->setInitializer(cipherInit);
        } else {
            const std::string nm = gv->getName().str();
            const auto addr = gv->getUnnamedAddr();
            const auto linkage = gv->getLinkage();
            gv->setName(""); // free the name for the replacement
            target = new GlobalVariable(M, cipherInit->getType(),
                                        /*isConstant=*/true, linkage,
                                        cipherInit, nm);
            target->setUnnamedAddr(addr);
            target->setAlignment(Align(1));
            gv->replaceAllUsesWith(target);
            gv->eraseFromParent();
        }
        auto *arrTy = cast<ArrayType>(target->getValueType());

        if (stackCandidate &&
            materializeStackUses(target, c, seed, arrTy, storedLen)) {
            changed = true;
            continue;
        }

        // Decrypt in place via this string's own constructor.  Short
        // strings unroll (maximally tangled); long ones loop so module code
        // size stays bounded.
        target->setConstant(
            false); // mutated in place by this string's decryptor
        auto *decFn =
            Function::Create(FunctionType::get(voidTy, false),
                             GlobalValue::InternalLinkage, "morok.strdec", &M);
        if (storedLen <= kUnrollThreshold) {
            IRBuilder<> B(BasicBlock::Create(ctx, "entry", decFn));
            emitDecryptUnrolled(B, c, seed, target, target, arrTy, storedLen);
            B.CreateRetVoid();
        } else {
            auto *entry = BasicBlock::Create(ctx, "entry", decFn);
            auto *loop = BasicBlock::Create(ctx, "loop", decFn);
            auto *exit = BasicBlock::Create(ctx, "exit", decFn);
            IRBuilder<> B(entry);
            Value *rtKey =
                B.CreateXor(B.CreateLoad(i64, seed, /*isVolatile=*/true),
                            ConstantInt::get(i64, c.key));
            B.CreateBr(loop);

            B.SetInsertPoint(loop);
            PHINode *iv = B.CreatePHI(i64, 2);
            iv->addIncoming(ConstantInt::get(i64, 0), entry);
            Value *ks =
                ir::emitKeystreamDynamic(B, c.variant, rtKey, iv, c.mul);
            Value *ptr = B.CreateInBoundsGEP(arrTy, target,
                                             {ConstantInt::get(i64, 0), iv});
            Value *dec =
                c.add
                    ? B.CreateSub(B.CreateLoad(i8, ptr), B.CreateTrunc(ks, i8))
                    : B.CreateXor(B.CreateLoad(i8, ptr), B.CreateTrunc(ks, i8));
            B.CreateStore(dec, ptr);
            Value *next = B.CreateAdd(iv, ConstantInt::get(i64, 1));
            iv->addIncoming(next, loop);
            B.CreateCondBr(
                B.CreateICmpULT(next, ConstantInt::get(i64, storedLen)), loop,
                exit);

            B.SetInsertPoint(exit);
            B.CreateRetVoid();
        }
        // Vary the constructor priority so the decryptors do not appear as one
        // contiguous block running back-to-back.
        appendToGlobalCtors(M, decFn, static_cast<int>(rng.range(40000)) + 1);
        changed = true;
    }
    return changed;
}

PreservedAnalyses StringEncryptionPass::run(Module &M,
                                            ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return stringEncryptModule(M, params_, rng) ? PreservedAnalyses::none()
                                                : PreservedAnalyses::all();
}

} // namespace morok::passes
