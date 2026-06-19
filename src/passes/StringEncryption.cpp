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
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/AtomicOrdering.h"
#include "llvm/TargetParser/Triple.h"
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
// Per-use stack materialization places a buffer of the whole string on the
// frame; keep it well below the 1 MiB global cap so a large constant string
// never inflates the stack frame.  Larger strings fall back to the in-place
// global decryptor instead of the stack path.
constexpr std::uint64_t kMaxStackStringBytes = 4096;

bool eligible(const GlobalVariable &gv) {
    if (!gv.hasInitializer() || !gv.hasLocalLinkage())
        return false;
    // A single global constructor only decrypts the init-time TLS instance;
    // other threads would observe ciphertext.  Leave thread-locals alone.
    if (gv.isThreadLocal())
        return false;
    if (gv.getName().starts_with("llvm."))
        return false;
    // Decoy string globals are deliberate bait: they must remain discoverable
    // by cheap triage such as `strings` while real user strings are encrypted.
    if (gv.getName().starts_with("morok."))
        return false;
    // Skip any section-pinned global.  The length-hiding path replaces the
    // global with a larger one, and re-emitting cipher bytes into a pinned
    // section (e.g. a mergeable cstring section, or llvm.metadata) changes its
    // identity/semantics; leave such globals alone rather than mis-rewrite them.
    if (!gv.getSection().empty())
        return false;
    const auto *cda = dyn_cast<ConstantDataArray>(gv.getInitializer());
    return cda && cda->getElementType()->isIntegerTy(8) &&
           cda->getNumElements() > 0;
}

// The per-string cipher recipe; chosen independently for every string.  The
// keystream finalizer is a randomized op sequence with random constants (no two
// strings share a shape), so a recovery script cannot hardcode a decoder
// template and pattern-match every string from a single signature.
struct Cipher {
    ir::KeystreamRecipe recipe; // randomized keystream generator
    bool add = false;           // ADD vs XOR combine
    std::uint64_t key = 0;      // per-string xor into the module seed
    std::uint64_t mul = 1;      // per-string odd multiplier
};

bool matchesContent(StringRef raw, const std::vector<std::string> &patterns) {
    for (const std::string &Pattern : patterns) {
        if (Pattern.empty())
            continue;
        if (raw.contains(Pattern))
            return true;
    }
    return false;
}

struct StringCandidate {
    GlobalVariable *gv = nullptr;
    std::uint64_t bytes = 0;
};

void emitStaticAnalysisBarrier(IRBuilderBase &B, const Module &M) {
    const Triple TT(M.getTargetTriple());
    StringRef Asm;
    StringRef Constraints;
    switch (TT.getArch()) {
    case Triple::aarch64:
    case Triple::aarch64_be:
        Asm = "ccmn wzr, #0, #4, eq";
        Constraints = "~{cc},~{memory}";
        break;
    case Triple::x86:
    case Triple::x86_64:
        Asm = "pause";
        Constraints = "~{dirflag},~{fpsr},~{flags},~{memory}";
        break;
    default:
        return;
    }

    auto *AsmTy = FunctionType::get(Type::getVoidTy(B.getContext()), false);
    InlineAsm *IA =
        InlineAsm::get(AsmTy, Asm, Constraints, /*hasSideEffects=*/true);
    B.CreateCall(AsmTy, IA);
}

Value *emitVolatileStableZero(IRBuilderBase &B, std::uint64_t Salt,
                              StringRef Prefix) {
    auto *I64 = B.getInt64Ty();
    AllocaInst *Slot =
        B.CreateAlloca(I64, nullptr, Twine(Prefix) + ".slot");
    B.CreateStore(ConstantInt::get(I64, Salt), Slot, /*isVolatile=*/true);
    LoadInst *A =
        B.CreateLoad(I64, Slot, /*isVolatile=*/true, Twine(Prefix) + ".a");
    LoadInst *Bv =
        B.CreateLoad(I64, Slot, /*isVolatile=*/true, Twine(Prefix) + ".b");
    return B.CreateSub(A, Bv, Twine(Prefix) + ".zero");
}

Value *emitDecodedByte(IRBuilderBase &B, Value *CipherByte, Value *KsByte,
                       Value *ByteZero, bool AddCombined,
                       StringRef Prefix) {
    Value *MaskedKs = B.CreateXor(KsByte, ByteZero, Twine(Prefix) + ".km");
    if (!AddCombined)
        return B.CreateXor(CipherByte, MaskedKs, Twine(Prefix) + ".x");

    auto *I32 = B.getInt32Ty();
    Value *Cipher32 = B.CreateZExt(CipherByte, I32, Twine(Prefix) + ".c32");
    Value *Ks32 = B.CreateZExt(MaskedKs, I32, Twine(Prefix) + ".k32");
    Value *NegKs =
        B.CreateAdd(B.CreateXor(Ks32, ConstantInt::get(I32, 0xff),
                                Twine(Prefix) + ".kn"),
                    ConstantInt::get(I32, 1), Twine(Prefix) + ".ka");
    Value *Plain32 = B.CreateAdd(Cipher32, NegKs, Twine(Prefix) + ".p32");
    return B.CreateTrunc(Plain32, CipherByte->getType(), Twine(Prefix) + ".p");
}

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
    LoadInst *seedLoad = B.CreateLoad(i64, seed, /*isVolatile=*/true);
    emitStaticAnalysisBarrier(B, *seed->getParent());
    Value *seedMix =
        B.CreateAdd(seedLoad,
                    emitVolatileStableZero(B, c.key ^ c.mul,
                                           "morok.str.mix"),
                    "morok.str.k.mix");
    Value *rtKey = B.CreateXor(seedMix, ConstantInt::get(i64, c.key));
    Value *byteZero = B.CreateTrunc(
        emitVolatileStableZero(B, c.key + c.mul, "morok.str.byte.mix"), i8,
        "morok.str.byte.zero");
    for (std::uint64_t i = 0; i < n; ++i) {
        Value *ks = ir::emitKeystream(B, c.recipe, rtKey,
                                      static_cast<std::uint32_t>(i), c.mul);
        Value *ksByte = B.CreateTrunc(ks, i8);
        Value *sp = B.CreateInBoundsGEP(
            arrTy, src, {ConstantInt::get(i64, 0), ConstantInt::get(i64, i)});
        Value *dp = B.CreateInBoundsGEP(
            arrTy, dst, {ConstantInt::get(i64, 0), ConstantInt::get(i64, i)});
        Value *cipher = B.CreateLoad(i8, sp);
        Value *plain =
            emitDecodedByte(B, cipher, ksByte, byteZero, c.add, "morok.str");
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
    emitStaticAnalysisBarrier(EB, M);
    Value *SeedMix =
        EB.CreateAdd(SeedLoad,
                     emitVolatileStableZero(EB, C.key ^ C.mul,
                                            "morok.str.stack.mix"),
                     "morok.str.stack.k.mix");
    Value *RtKey = EB.CreateXor(SeedMix, ConstantInt::get(I64, C.key),
                                "morok.str.stack.k0");
    Value *ByteZero = EB.CreateTrunc(
        emitVolatileStableZero(EB, C.key + C.mul,
                               "morok.str.stack.byte.mix"),
        I8, "morok.str.stack.byte.zero");
    EB.CreateBr(Loop);

    IRBuilder<> LB(Loop);
    PHINode *I = LB.CreatePHI(I64, 2, "morok.str.stack.i");
    I->addIncoming(ConstantInt::get(I64, 0), Entry);
    Value *Ks = ir::emitKeystreamDynamic(LB, C.recipe, RtKey, I, C.mul);
    Value *KsByte = LB.CreateTrunc(Ks, I8);
    Value *Src =
        LB.CreateInBoundsGEP(ArrTy, CipherText, {ConstantInt::get(I64, 0), I},
                             "morok.str.stack.src");
    Value *Dst = LB.CreateInBoundsGEP(
        ArrTy, DstArg, {ConstantInt::get(I64, 0), I}, "morok.str.stack.dst");
    Value *CipherByte = LB.CreateLoad(I8, Src);
    Value *Plain = emitDecodedByte(LB, CipherByte, KsByte, ByteZero, C.add,
                                   "morok.str.stack");
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
    Function *F = InsertBefore->getFunction();
    Module &M = *F->getParent();
    Function *Helper =
        createStackDecryptHelper(M, C, Seed, CipherText, ArrTy, Len);
    auto *I64 = Type::getInt64Ty(M.getContext());
    // Hoist the buffer to the entry block (a static alloca) so it is allocated
    // once per call activation, not once per loop iteration: a per-use alloca in
    // a loop body is never released until the function returns, so an
    // attacker-controlled loop count would exhaust the stack.  The decrypt call
    // and pointer materialization stay at the use site, refilling the buffer.
    IRBuilder<> EB(&*F->getEntryBlock().getFirstInsertionPt());
    AllocaInst *Buf = EB.CreateAlloca(ArrTy, nullptr, "morok.str.stack.buf");
    IRBuilder<> B(InsertBefore);
    B.CreateCall(Helper->getFunctionType(), Helper, {Buf});
    emitStaticAnalysisBarrier(B, M);
    return B.CreateInBoundsGEP(
        ArrTy, Buf, {ConstantInt::get(I64, 0), ConstantInt::get(I64, 0)},
        "morok.str.stack.ptr");
}

// Collect the functions that (transitively, through constant exprs) reference
// GV.  Sets Escapes if the address is baked into static data (another global's
// initializer) or any non-instruction, non-constant user — contexts where no
// function-entry hook can guarantee the string is decrypted before it is read.
void collectUsingFunctions(Value *V, SmallPtrSetImpl<Function *> &Funcs,
                           bool &Escapes) {
    for (User *U : V->users()) {
        if (auto *I = dyn_cast<Instruction>(U)) {
            if (Function *F = I->getFunction())
                Funcs.insert(F);
        } else if (isa<GlobalVariable>(U)) {
            Escapes = true;
        } else if (isa<Constant>(U)) {
            collectUsingFunctions(U, Funcs, Escapes);
        } else {
            Escapes = true;
        }
    }
}

// A private i8 once-state guard (0 = untouched, 1 = decrypting, 2 = done).
GlobalVariable *createGuard(Module &M) {
    auto *I8 = Type::getInt8Ty(M.getContext());
    auto *GV = new GlobalVariable(M, I8, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantInt::get(I8, 0), "morok.strg");
    GV->setAlignment(Align(1));
    return GV;
}

bool materializeStackUses(GlobalVariable *GV, const Cipher &C,
                          GlobalVariable *Seed, ArrayType *ArrTy,
                          std::uint64_t Len) {
    // Large strings would put a large buffer on the frame at each use; leave
    // those to the in-place global decryptor.
    if (Len > kMaxStackStringBytes)
        return false;

    SmallVector<UseSite, 8> Sites;
    SmallPtrSet<Value *, 8> Seen;
    if (!collectStackUseSites(GV, GV, Sites, Seen) || Sites.empty())
        return false;

    // Materialize one buffer per USE INSTRUCTION, not per operand: a call that
    // passes the same global in two arguments (e.g. check(secret, secret)) must
    // still receive the same pointer in both, or a callee comparing argument
    // identity would behave differently than with the original global.
    DenseMap<Instruction *, Value *> PerInst;
    for (UseSite Site : Sites) {
        Value *&Stack = PerInst[Site.inst];
        if (!Stack)
            Stack = emitStackString(Site.inst, C, Seed, GV, ArrTy, Len);
        Site.inst->setOperand(Site.operand, Stack);
    }
    return true;
}

} // namespace

bool stringEncryptModule(Module &M, const StrEncParams &params,
                         ir::IRRandom &rng) {
    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *voidTy = Type::getVoidTy(ctx);

    std::vector<StringCandidate> forcedCandidates;
    std::vector<StringCandidate> randomCandidates;
    forcedCandidates.reserve(16);
    randomCandidates.reserve(64);
    std::uint64_t forcedBytes = 0;
    std::uint64_t randomBytes = 0;
    auto tryQueueCandidate = [](std::vector<StringCandidate> &Candidates,
                                std::uint64_t &QueuedBytes,
                                GlobalVariable *GV, std::uint64_t Bytes) {
        if (Candidates.size() >= kMaxEncryptedStrings ||
            QueuedBytes + Bytes > kMaxEncryptedTotalBytes)
            return;
        Candidates.push_back({GV, Bytes});
        QueuedBytes += Bytes;
    };
    for (GlobalVariable &gv : M.globals()) {
        if (!eligible(gv))
            continue;
        const auto *cda = cast<ConstantDataArray>(gv.getInitializer());
        const std::uint64_t n = cda->getNumElements();
        if (n > kMaxEncryptedStringBytes)
            continue;
        StringRef raw = cda->getRawDataValues();
        if (matchesContent(raw, params.skip_content))
            continue;
        const bool forced = matchesContent(raw, params.force_content);
        if (forced) {
            tryQueueCandidate(forcedCandidates, forcedBytes, &gv, n);
        } else if (params.probability != 0 && rng.chance(params.probability)) {
            tryQueueCandidate(randomCandidates, randomBytes, &gv, n);
        }
    }

    std::uint64_t selectedBytes = 0;
    std::vector<GlobalVariable *> targets;
    targets.reserve(64);
    auto trySelect = [&](const StringCandidate &C) {
        if (targets.size() >= kMaxEncryptedStrings ||
            selectedBytes + C.bytes > kMaxEncryptedTotalBytes)
            return;
        targets.push_back(C.gv);
        selectedBytes += C.bytes;
    };
    for (const StringCandidate &C : forcedCandidates)
        trySelect(C);
    for (const StringCandidate &C : randomCandidates)
        trySelect(C);
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
        c.recipe = ir::randomKeystreamRecipe(rng);
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
                ir::keystreamValue(c.recipe, k0, static_cast<std::uint32_t>(i),
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
            // Preserve the original address space — replaceAllUsesWith requires
            // the replacement to have the identical pointer type, so a new
            // global in addrspace(0) replacing an addrspace(N) string is invalid
            // IR (a verifier/assertion failure).  Preserve the alignment too:
            // the program's existing loads/GEPs may rely on it, so forcing
            // Align(1) is undefined behavior.
            const unsigned addrSpace = gv->getAddressSpace();
            const Align align = gv->getAlign().valueOrOne();
            gv->setName(""); // free the name for the replacement
            target = new GlobalVariable(M, cipherInit->getType(),
                                        /*isConstant=*/true, linkage, cipherInit,
                                        nm, /*InsertBefore=*/nullptr,
                                        GlobalValue::NotThreadLocal, addrSpace);
            target->setUnnamedAddr(addr);
            target->setAlignment(align);
            gv->replaceAllUsesWith(target);
            gv->eraseFromParent();
        }
        auto *arrTy = cast<ArrayType>(target->getValueType());

        if (stackCandidate &&
            materializeStackUses(target, c, seed, arrTy, storedLen)) {
            changed = true;
            continue;
        }

        // Lazily decrypt in place the first time a using function runs, NOT
        // eagerly in a global constructor.  Eager init-time decryption leaves
        // plaintext sitting in writable .data for a "run the ctors, dump memory"
        // attack; a lazy first-use decryptor leaves only ciphertext until the
        // code path that needs the string actually executes.  A thread-safe
        // once-guard (cmpxchg 0->1, publish 2 with release; late threads spin on
        // an acquire load) makes it correct under concurrency — a plain flag
        // would let a second thread observe a half-decrypted (or, for XOR,
        // double-decrypted) buffer.
        target->setConstant(false); // mutated in place by its decryptor
        auto *decFn =
            Function::Create(FunctionType::get(voidTy, false),
                             GlobalValue::InternalLinkage, "morok.strdec", &M);
        decFn->addFnAttr(Attribute::NoInline);
        decFn->addFnAttr(Attribute::OptimizeNone);

        GlobalVariable *guard = createGuard(M);
        auto *entryBB = BasicBlock::Create(ctx, "entry", decFn);
        auto *waitBB = BasicBlock::Create(ctx, "morok.str.wait", decFn);
        auto *decBB = BasicBlock::Create(ctx, "morok.str.dec", decFn);
        auto *doneBB = BasicBlock::Create(ctx, "morok.str.done", decFn);

        {
            IRBuilder<> B(entryBB);
            auto *won = B.CreateAtomicCmpXchg(
                guard, ConstantInt::get(i8, 0), ConstantInt::get(i8, 1),
                MaybeAlign(1), AtomicOrdering::AcquireRelease,
                AtomicOrdering::Monotonic);
            B.CreateCondBr(B.CreateExtractValue(won, 1, "morok.str.won"), decBB,
                           waitBB);
        }
        {
            IRBuilder<> B(waitBB);
            auto *st = B.CreateLoad(i8, guard, "morok.str.state");
            st->setAtomic(AtomicOrdering::Acquire);
            st->setAlignment(Align(1));
            B.CreateCondBr(
                B.CreateICmpEQ(st, ConstantInt::get(i8, 2), "morok.str.ready"),
                doneBB, waitBB);
        }

        IRBuilder<> B(decBB);
        if (storedLen <= kUnrollThreshold) {
            emitDecryptUnrolled(B, c, seed, target, target, arrTy, storedLen);
        } else {
            auto *loop = BasicBlock::Create(ctx, "morok.str.loop", decFn);
            auto *loopExit =
                BasicBlock::Create(ctx, "morok.str.loopexit", decFn);
            LoadInst *seedLoad = B.CreateLoad(i64, seed, /*isVolatile=*/true);
            emitStaticAnalysisBarrier(B, M);
            Value *seedMix = B.CreateAdd(
                seedLoad,
                emitVolatileStableZero(B, c.key ^ c.mul, "morok.str.loop.mix"),
                "morok.str.loop.k.mix");
            Value *rtKey = B.CreateXor(seedMix, ConstantInt::get(i64, c.key));
            Value *byteZero = B.CreateTrunc(
                emitVolatileStableZero(B, c.key + c.mul,
                                       "morok.str.loop.byte.mix"),
                i8, "morok.str.loop.byte.zero");
            B.CreateBr(loop);

            B.SetInsertPoint(loop);
            PHINode *iv = B.CreatePHI(i64, 2);
            iv->addIncoming(ConstantInt::get(i64, 0), decBB);
            Value *ks = ir::emitKeystreamDynamic(B, c.recipe, rtKey, iv, c.mul);
            Value *ptr = B.CreateInBoundsGEP(arrTy, target,
                                             {ConstantInt::get(i64, 0), iv});
            Value *cipher = B.CreateLoad(i8, ptr);
            Value *ksByte = B.CreateTrunc(ks, i8);
            Value *dec = emitDecodedByte(B, cipher, ksByte, byteZero, c.add,
                                         "morok.str.loop");
            B.CreateStore(dec, ptr);
            Value *next = B.CreateAdd(iv, ConstantInt::get(i64, 1));
            iv->addIncoming(next, loop);
            B.CreateCondBr(
                B.CreateICmpULT(next, ConstantInt::get(i64, storedLen)), loop,
                loopExit);
            B.SetInsertPoint(loopExit);
        }
        // Publish the decrypted bytes (release) so a spinning thread that reads
        // state==2 with an acquire load sees the fully decrypted buffer.
        auto *publish = B.CreateStore(ConstantInt::get(i8, 2), guard);
        publish->setAtomic(AtomicOrdering::Release);
        publish->setAlignment(Align(1));
        B.CreateBr(doneBB);
        IRBuilder<>(doneBB).CreateRetVoid();

        // Trigger the decryptor lazily at the entry of every function that
        // references the string.  If the address is baked into static data
        // (no function-entry hook can run first), fall back to an init-time
        // constructor for that one string.
        SmallPtrSet<Function *, 8> users;
        bool escapes = false;
        collectUsingFunctions(target, users, escapes);
        users.erase(decFn);
        if (escapes || users.empty()) {
            appendToGlobalCtors(M, decFn,
                                static_cast<int>(rng.range(40000)) + 1);
        } else {
            for (Function *UF : users) {
                if (UF->isDeclaration())
                    continue;
                IRBuilder<> EB(&*UF->getEntryBlock().getFirstInsertionPt());
                EB.CreateCall(decFn->getFunctionType(), decFn, {});
            }
        }
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
