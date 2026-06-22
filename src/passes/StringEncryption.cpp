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
#include "morok/passes/CodeRegionKdf.hpp"
#include "morok/passes/RuntimeSeal.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringMap.h"
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
constexpr int kCtorDecryptPriority = 0;

bool hasSpecialSectionSemantics(StringRef Section) {
    if (Section.empty())
        return false;
    if (Section == "llvm.metadata")
        return true;

    // Explicit section names can carry ABI/runtime permissions and parser
    // semantics that are not visible from LLVM IR mutability alone.  Keep these
    // sections literal: encrypting them would put ciphertext where the loader,
    // Obj-C runtime, unwinder, or linker expects structured plaintext, and lazy
    // in-place decryptors may fault on read-only mappings.
    if (Section.starts_with("__TEXT,") ||
        Section.starts_with("__DATA_CONST,") ||
        Section.contains("__cstring") || Section.contains("cstring_literals") ||
        Section.contains("__objc_"))
        return true;

    if (Section.starts_with(".rodata") || Section.starts_with(".rdata") ||
        Section.starts_with(".text") || Section.starts_with(".eh_frame") ||
        Section.starts_with(".gcc_except_table") ||
        Section.starts_with(".debug") || Section.starts_with(".comment") ||
        Section.starts_with(".note") || Section.starts_with(".pdata") ||
        Section.starts_with(".xdata") || Section.starts_with(".CRT") ||
        Section.starts_with(".init_array") ||
        Section.starts_with(".fini_array") || Section.starts_with(".ctors") ||
        Section.starts_with(".dtors") || Section.starts_with(".llvm."))
        return true;

    return false;
}

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
    // Ordinary custom-section user strings are still encrypted, but sections
    // with loader/runtime/read-only semantics are left untouched.
    if (hasSpecialSectionSemantics(gv.getSection()))
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

Value *emitEncodedByte(IRBuilderBase &B, Value *PlainByte, Value *KsByte,
                       Value *ByteZero, bool AddCombined,
                       StringRef Prefix) {
    Value *MaskedKs = B.CreateXor(KsByte, ByteZero, Twine(Prefix) + ".km");
    if (!AddCombined)
        return B.CreateXor(PlainByte, MaskedKs, Twine(Prefix) + ".x");

    auto *I32 = B.getInt32Ty();
    Value *Plain32 = B.CreateZExt(PlainByte, I32, Twine(Prefix) + ".p32");
    Value *Ks32 = B.CreateZExt(MaskedKs, I32, Twine(Prefix) + ".k32");
    Value *Cipher32 = B.CreateAdd(Plain32, Ks32, Twine(Prefix) + ".c32");
    return B.CreateTrunc(Cipher32, PlainByte->getType(),
                         Twine(Prefix) + ".c");
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
void emitDecryptUnrolled(IRBuilder<> &B, const Cipher &c, Function *seedFn,
                         Value *src, Value *dst, ArrayType *arrTy,
                         std::uint64_t n) {
    auto *i8 = Type::getInt8Ty(B.getContext());
    auto *i64 = Type::getInt64Ty(B.getContext());
    Value *seedLoad = B.CreateCall(seedFn, {}, "morok.str.seed.v");
    emitStaticAnalysisBarrier(B, *seedFn->getParent());
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

void emitEncodeUnrolled(IRBuilder<> &B, const Cipher &c, Function *seedFn,
                        Value *src, Value *dst, ArrayType *arrTy,
                        std::uint64_t n) {
    auto *i8 = Type::getInt8Ty(B.getContext());
    auto *i64 = Type::getInt64Ty(B.getContext());
    Value *seedLoad = B.CreateCall(seedFn, {}, "morok.str.reseed.v");
    emitStaticAnalysisBarrier(B, *seedFn->getParent());
    Value *seedMix =
        B.CreateAdd(seedLoad,
                    emitVolatileStableZero(B, c.key ^ c.mul,
                                           "morok.str.reenc.mix"),
                    "morok.str.reenc.k.mix");
    Value *rtKey = B.CreateXor(seedMix, ConstantInt::get(i64, c.key));
    Value *byteZero = B.CreateTrunc(
        emitVolatileStableZero(B, c.key + c.mul, "morok.str.reenc.byte.mix"),
        i8, "morok.str.reenc.byte.zero");
    for (std::uint64_t i = 0; i < n; ++i) {
        Value *ks = ir::emitKeystream(B, c.recipe, rtKey,
                                      static_cast<std::uint32_t>(i), c.mul);
        Value *ksByte = B.CreateTrunc(ks, i8);
        Value *sp = B.CreateInBoundsGEP(
            arrTy, src, {ConstantInt::get(i64, 0), ConstantInt::get(i64, i)});
        Value *dp = B.CreateInBoundsGEP(
            arrTy, dst, {ConstantInt::get(i64, 0), ConstantInt::get(i64, i)});
        Value *plain = B.CreateLoad(i8, sp);
        Value *cipher = emitEncodedByte(B, plain, ksByte, byteZero, c.add,
                                        "morok.str.reenc");
        B.CreateStore(cipher, dp);
    }
}

Function *createStackDecryptHelper(Module &M, const Cipher &C,
                                   Function *SeedFn,
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
        emitDecryptUnrolled(B, C, SeedFn, CipherText, DstArg, ArrTy, Len);
        B.CreateRetVoid();
        return Fn;
    }

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    BasicBlock *Loop = BasicBlock::Create(Ctx, "morok.str.stack.loop", Fn);
    BasicBlock *Done = BasicBlock::Create(Ctx, "morok.str.stack.done", Fn);

    IRBuilder<> EB(Entry);
    Value *SeedLoad = EB.CreateCall(SeedFn, {}, "morok.str.stack.k");
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
                       Function *SeedFn, GlobalVariable *CipherText,
                       ArrayType *ArrTy, std::uint64_t Len) {
    Function *F = InsertBefore->getFunction();
    Module &M = *F->getParent();
    Function *Helper =
        createStackDecryptHelper(M, C, SeedFn, CipherText, ArrTy, Len);
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

bool collectLoadUseSites(Value *V, SmallVectorImpl<LoadInst *> &Loads,
                         SmallPtrSetImpl<Value *> &Seen) {
    if (!Seen.insert(V).second)
        return true;

    for (Use &U : V->uses()) {
        User *Usr = U.getUser();
        if (auto *LI = dyn_cast<LoadInst>(Usr)) {
            if (LI->getPointerOperand() != U.get())
                return false;
            Loads.push_back(LI);
            continue;
        }
        if (isa<GetElementPtrInst>(Usr) || isa<BitCastInst>(Usr) ||
            isa<AddrSpaceCastInst>(Usr)) {
            if (!collectLoadUseSites(Usr, Loads, Seen))
                return false;
            continue;
        }
        if (auto *CE = dyn_cast<ConstantExpr>(Usr)) {
            switch (CE->getOpcode()) {
            case Instruction::GetElementPtr:
            case Instruction::BitCast:
            case Instruction::AddrSpaceCast:
                if (!collectLoadUseSites(CE, Loads, Seen))
                    return false;
                continue;
            default:
                return false;
            }
        }
        return false;
    }
    return true;
}

bool hasMustTailReturn(const SmallPtrSetImpl<Function *> &Funcs) {
    for (Function *F : Funcs) {
        if (!F || F->isDeclaration())
            continue;
        for (const BasicBlock &BB : *F) {
            auto *Ret = dyn_cast<ReturnInst>(BB.getTerminator());
            if (!Ret)
                continue;
            auto *Prev = dyn_cast_or_null<CallInst>(Ret->getPrevNode());
            if (Prev && Prev->isMustTailCall())
                return true;
        }
    }
    return false;
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

GlobalVariable *createRefCount(Module &M) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *GV = new GlobalVariable(M, I32, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantInt::get(I32, 0), "morok.str.ref");
    GV->setAlignment(Align(4));
    return GV;
}

bool materializeStackUses(GlobalVariable *GV, const Cipher &C,
                          Function *SeedFn, ArrayType *ArrTy,
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
            Stack = emitStackString(Site.inst, C, SeedFn, GV, ArrTy, Len);
        Site.inst->setOperand(Site.operand, Stack);
    }

    // Shrink the at-rest plaintext window (#1).  collectStackUseSites accepted
    // this global only because every use is a non-capturing call argument, so
    // each per-instruction buffer is provably dead the moment its call returns;
    // zero it right afterwards with a volatile memset (volatile so DSE cannot
    // drop it as a dead store).  The cleartext is then live only across the
    // single consuming call instead of persisting in the frame until the
    // function returns — narrowing the byte-granular memory-scan window the
    // field report used to recover decrypted strings.  A using instruction that
    // is a terminator (invoke) has no in-block successor to anchor the scrub and
    // is simply left unscrubbed.
    for (const auto &KV : PerInst) {
        Instruction *Use = KV.first;
        Value *Buf = KV.second;
        if (Instruction *Next = Use->getNextNode()) {
            IRBuilder<> SB(Next);
            SB.CreateMemSet(Buf, SB.getInt8(0),
                            ConstantInt::get(SB.getInt64Ty(), Len),
                            MaybeAlign(1), /*isVolatile=*/true);
        }
    }
    return true;
}

// Tier-B keystream seed.  The per-string keys used to be keyed on a literal
// module-seed constant sitting in .data — an analyst reads that one word and
// decrypts the entire pool statically (exactly the recovered `G` constant in
// the field report).  Instead we derive the seed at runtime by hashing a fixed
// pseudo-random const blob: the hash is recomputed in-register on every call
// and never stored, so no seed word exists in the file or in live memory, and
// recovery now requires executing or re-implementing the hash over the blob.
// The byte loads are volatile and the function is optnone/noinline so the
// optimizer cannot fold the call back into the very constant we are hiding (if
// it did, the literal seed would reappear in .text).  seedVal is the
// compile-time hash the runtime reproduces, used to encrypt the pool.
struct SeedProvider {
    Function *fn = nullptr;
    std::uint64_t value = 0;
};

SeedProvider createSeedProvider(Module &M, ir::IRRandom &rng) {
    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);

    // Irregular length so the blob does not read as a dedicated 8/16-byte key.
    const unsigned blobLen = 48 + rng.range(48); // 48..95 bytes
    std::vector<std::uint8_t> blob(blobLen);
    for (unsigned i = 0; i < blobLen; ++i)
        blob[i] = static_cast<std::uint8_t>(rng.next());
    const std::uint64_t kdfSeed = rng.next();
    const std::uint64_t seedVal = code_region_kdf::hashBytes(blob, kdfSeed);

    Constant *blobInit =
        ConstantDataArray::get(ctx, ArrayRef<std::uint8_t>(blob));
    auto *blobGV = new GlobalVariable(M, blobInit->getType(),
                                      /*isConstant=*/true,
                                      GlobalValue::PrivateLinkage, blobInit,
                                      "morok.str.kdf.blob");
    blobGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    auto *arrTy = cast<ArrayType>(blobGV->getValueType());

    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::InternalLinkage, "morok.str.seed",
                                &M);
    fn->setDSOLocal(true);
    fn->addFnAttr(Attribute::NoInline);
    fn->addFnAttr(Attribute::OptimizeNone);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loop = BasicBlock::Create(ctx, "loop", fn);
    auto *exit = BasicBlock::Create(ctx, "exit", fn);

    IRBuilder<> EB(entry);
    EB.CreateBr(loop);

    IRBuilder<> LB(loop);
    PHINode *iv = LB.CreatePHI(i64, 2, "morok.str.seed.i");
    PHINode *h = LB.CreatePHI(i64, 2, "morok.str.seed.h");
    iv->addIncoming(ConstantInt::get(i64, 0), entry);
    h->addIncoming(ConstantInt::get(i64, kdfSeed), entry);
    Value *bp = LB.CreateInBoundsGEP(arrTy, blobGV,
                                     {ConstantInt::get(i64, 0), iv},
                                     "morok.str.seed.bp");
    LoadInst *byte = LB.CreateLoad(i8, bp, "morok.str.seed.byte");
    byte->setVolatile(true);
    byte->setAlignment(Align(1));
    Value *nh = code_region_kdf::emitHashStep(LB, h, byte, "morok.str.seed");
    Value *ni =
        LB.CreateAdd(iv, ConstantInt::get(i64, 1), "morok.str.seed.next");
    iv->addIncoming(ni, loop);
    h->addIncoming(nh, loop);
    Value *done = LB.CreateICmpEQ(ni, ConstantInt::get(i64, blobLen),
                                  "morok.str.seed.done");
    LB.CreateCondBr(done, exit, loop);

    IRBuilder<> XB(exit);
    XB.CreateRet(nh);

    return {fn, seedVal};
}

} // namespace

bool stringEncryptModule(Module &M, const StrEncParams &params,
                         ir::IRRandom &rng) {
    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
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

    // One runtime-opaque module seed underlies every per-string key.  It is
    // produced by a seed function that hashes a fixed const blob at runtime
    // (see createSeedProvider), so no literal seed constant sits in the file for
    // a static "read the word, decrypt the pool" recovery; seedVal is the
    // compile-time hash the runtime reproduces.
    const SeedProvider seedProv = createSeedProvider(M, rng);
    Function *seedFn = seedProv.fn;
    const std::uint64_t seedVal = seedProv.value;

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
        if (gv->isConstant() && cda->isCString() &&
            gv->getSection().empty()) {
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
            materializeStackUses(target, c, seedFn, arrTy, storedLen)) {
            changed = true;
            continue;
        }

        SmallPtrSet<Function *, 8> users;
        bool escapes = false;
        collectUsingFunctions(target, users, escapes);

        // Lazily decrypt in place only when there is no safe stack rewrite.
        // For originally-constant strings whose address does not escape through
        // static data, bound the plaintext lifetime to active user frames: the
        // first frame decrypts, nested/recursive frames share the plaintext, and
        // the last returning frame re-encrypts it.  Escaped/static-address
        // strings retain the constructor fallback because no function-scope
        // release point can prove all observers are done with the address.
        // musttail users cannot take an inserted release before ret; releasing
        // before the tail call is not generally safe because the callee may
        // receive the string pointer.
        const bool scopedPlaintext =
            stackCandidate && !escapes && !users.empty() &&
            !hasMustTailReturn(users);
        SmallVector<LoadInst *, 16> LoadScopeSites;
        SmallPtrSet<Value *, 16> SeenLoadUses;
        const bool loadScopedPlaintext =
            scopedPlaintext &&
            collectLoadUseSites(target, LoadScopeSites, SeenLoadUses) &&
            !LoadScopeSites.empty();
        target->setConstant(false); // mutated in place by its decryptor
        auto *decFn =
            Function::Create(FunctionType::get(voidTy, false),
                             GlobalValue::InternalLinkage, "morok.strdec", &M);
        decFn->addFnAttr(Attribute::NoInline);
        decFn->addFnAttr(Attribute::OptimizeNone);

        GlobalVariable *guard = createGuard(M);
        GlobalVariable *refCount =
            scopedPlaintext ? createRefCount(M) : nullptr;
        auto *entryBB = BasicBlock::Create(ctx, "entry", decFn);
        auto *waitBB = BasicBlock::Create(ctx, "morok.str.wait", decFn);
        auto *decBB = BasicBlock::Create(ctx, "morok.str.dec", decFn);
        auto *doneBB = BasicBlock::Create(ctx, "morok.str.done", decFn);

        if (scopedPlaintext) {
            auto *claimBB =
                BasicBlock::Create(ctx, "morok.str.claim", decFn, decBB);
            auto *waitCipherBB =
                BasicBlock::Create(ctx, "morok.str.wait.cipher", decFn, decBB);
            IRBuilder<> B(entryBB);
            auto *old = B.CreateAtomicRMW(AtomicRMWInst::Add, refCount,
                                          ConstantInt::get(i32, 1), Align(4),
                                          AtomicOrdering::AcquireRelease);
            old->setVolatile(true);
            old->setName("morok.str.ref.old");
            B.CreateCondBr(B.CreateICmpEQ(old, ConstantInt::get(i32, 0),
                                          "morok.str.ref.first"),
                           claimBB, waitBB);

            B.SetInsertPoint(waitBB);
            auto *st = B.CreateLoad(i8, guard, "morok.str.state");
            st->setAtomic(AtomicOrdering::Acquire);
            st->setAlignment(Align(1));
            B.CreateCondBr(
                B.CreateICmpEQ(st, ConstantInt::get(i8, 2), "morok.str.ready"),
                doneBB, waitBB);

            B.SetInsertPoint(claimBB);
            auto *won = B.CreateAtomicCmpXchg(
                guard, ConstantInt::get(i8, 0), ConstantInt::get(i8, 1),
                MaybeAlign(1), AtomicOrdering::AcquireRelease,
                AtomicOrdering::Monotonic);
            B.CreateCondBr(B.CreateExtractValue(won, 1, "morok.str.won"), decBB,
                           waitCipherBB);

            B.SetInsertPoint(waitCipherBB);
            auto *cipherState =
                B.CreateLoad(i8, guard, "morok.str.cipher.state");
            cipherState->setAtomic(AtomicOrdering::Acquire);
            cipherState->setAlignment(Align(1));
            B.CreateCondBr(B.CreateICmpEQ(cipherState, ConstantInt::get(i8, 0),
                                          "morok.str.cipher.ready"),
                           claimBB, waitCipherBB);
        } else {
            IRBuilder<> B(entryBB);
            auto *won = B.CreateAtomicCmpXchg(
                guard, ConstantInt::get(i8, 0), ConstantInt::get(i8, 1),
                MaybeAlign(1), AtomicOrdering::AcquireRelease,
                AtomicOrdering::Monotonic);
            B.CreateCondBr(B.CreateExtractValue(won, 1, "morok.str.won"), decBB,
                           waitBB);

            B.SetInsertPoint(waitBB);
            auto *st = B.CreateLoad(i8, guard, "morok.str.state");
            st->setAtomic(AtomicOrdering::Acquire);
            st->setAlignment(Align(1));
            B.CreateCondBr(
                B.CreateICmpEQ(st, ConstantInt::get(i8, 2), "morok.str.ready"),
                doneBB, waitBB);
        }

        IRBuilder<> B(decBB);
        if (storedLen <= kUnrollThreshold) {
            emitDecryptUnrolled(B, c, seedFn, target, target, arrTy, storedLen);
        } else {
            auto *loop = BasicBlock::Create(ctx, "morok.str.loop", decFn);
            auto *loopExit =
                BasicBlock::Create(ctx, "morok.str.loopexit", decFn);
            Value *seedLoad = B.CreateCall(seedFn, {}, "morok.str.loop.seed");
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

        Function *releaseFn = nullptr;
        if (scopedPlaintext) {
            releaseFn = Function::Create(FunctionType::get(voidTy, false),
                                         GlobalValue::InternalLinkage,
                                         "morok.strrel", &M);
            releaseFn->addFnAttr(Attribute::NoInline);
            releaseFn->addFnAttr(Attribute::OptimizeNone);
            auto *relEntry = BasicBlock::Create(ctx, "entry", releaseFn);
            auto *relClaim =
                BasicBlock::Create(ctx, "morok.str.release.claim", releaseFn);
            auto *relEnc =
                BasicBlock::Create(ctx, "morok.str.release.enc", releaseFn);
            auto *relDone =
                BasicBlock::Create(ctx, "morok.str.release.done", releaseFn);

            IRBuilder<> RB(relEntry);
            auto *old = RB.CreateAtomicRMW(AtomicRMWInst::Sub, refCount,
                                           ConstantInt::get(i32, 1), Align(4),
                                           AtomicOrdering::AcquireRelease);
            old->setVolatile(true);
            old->setName("morok.str.ref.release.old");
            RB.CreateCondBr(RB.CreateICmpEQ(old, ConstantInt::get(i32, 1),
                                            "morok.str.ref.last"),
                            relClaim, relDone);

            RB.SetInsertPoint(relClaim);
            auto *won = RB.CreateAtomicCmpXchg(
                guard, ConstantInt::get(i8, 2), ConstantInt::get(i8, 3),
                MaybeAlign(1), AtomicOrdering::AcquireRelease,
                AtomicOrdering::Monotonic);
            RB.CreateCondBr(
                RB.CreateExtractValue(won, 1, "morok.str.release.won"), relEnc,
                relDone);

            RB.SetInsertPoint(relEnc);
            if (storedLen <= kUnrollThreshold) {
                emitEncodeUnrolled(RB, c, seedFn, target, target, arrTy,
                                   storedLen);
            } else {
                auto *loop =
                    BasicBlock::Create(ctx, "morok.str.reloop", releaseFn);
                auto *loopExit = BasicBlock::Create(
                    ctx, "morok.str.reloopexit", releaseFn);
                Value *seedLoad =
                    RB.CreateCall(seedFn, {}, "morok.str.reloop.seed");
                emitStaticAnalysisBarrier(RB, M);
                Value *seedMix = RB.CreateAdd(
                    seedLoad,
                    emitVolatileStableZero(RB, c.key ^ c.mul,
                                           "morok.str.reloop.mix"),
                    "morok.str.reloop.k.mix");
                Value *rtKey =
                    RB.CreateXor(seedMix, ConstantInt::get(i64, c.key));
                Value *byteZero = RB.CreateTrunc(
                    emitVolatileStableZero(RB, c.key + c.mul,
                                           "morok.str.reloop.byte.mix"),
                    i8, "morok.str.reloop.byte.zero");
                RB.CreateBr(loop);

                RB.SetInsertPoint(loop);
                PHINode *iv = RB.CreatePHI(i64, 2, "morok.str.reloop.i");
                iv->addIncoming(ConstantInt::get(i64, 0), relEnc);
                Value *ks =
                    ir::emitKeystreamDynamic(RB, c.recipe, rtKey, iv, c.mul);
                Value *ptr = RB.CreateInBoundsGEP(
                    arrTy, target, {ConstantInt::get(i64, 0), iv});
                Value *plainByte = RB.CreateLoad(i8, ptr);
                Value *ksByte = RB.CreateTrunc(ks, i8);
                Value *enc = emitEncodedByte(RB, plainByte, ksByte, byteZero,
                                             c.add, "morok.str.reloop");
                RB.CreateStore(enc, ptr);
                Value *next =
                    RB.CreateAdd(iv, ConstantInt::get(i64, 1),
                                 "morok.str.reloop.next");
                iv->addIncoming(next, loop);
                RB.CreateCondBr(
                    RB.CreateICmpULT(next, ConstantInt::get(i64, storedLen)),
                    loop, loopExit);
                RB.SetInsertPoint(loopExit);
            }
            auto *clear = RB.CreateStore(ConstantInt::get(i8, 0), guard);
            clear->setAtomic(AtomicOrdering::Release);
            clear->setAlignment(Align(1));
            RB.CreateBr(relDone);
            IRBuilder<>(relDone).CreateRetVoid();
        }

        // Trigger the decryptor lazily at the entry of every function that
        // references the string.  If the address is baked into static data
        // (no function-entry hook can run first), fall back to an init-time
        // constructor for that one string.
        if (escapes || users.empty()) {
            // Fallback constructor decryption must complete before any user
            // constructor can observe ciphertext through escaped static data.
            appendToGlobalCtors(M, decFn, kCtorDecryptPriority);
        } else {
            if (releaseFn && loadScopedPlaintext) {
                SmallPtrSet<LoadInst *, 16> Emitted;
                for (LoadInst *LI : LoadScopeSites) {
                    if (!Emitted.insert(LI).second)
                        continue;
                    IRBuilder<> LB(LI);
                    LB.CreateCall(decFn->getFunctionType(), decFn, {});
                    if (Instruction *Next = LI->getNextNode()) {
                        IRBuilder<> RB(Next);
                        RB.CreateCall(releaseFn->getFunctionType(), releaseFn,
                                      {});
                    }
                }
            } else {
                for (Function *UF : users) {
                    if (UF->isDeclaration())
                        continue;
                    IRBuilder<> EB(&*UF->getEntryBlock().getFirstInsertionPt());
                    EB.CreateCall(decFn->getFunctionType(), decFn, {});
                    if (releaseFn) {
                        SmallVector<Instruction *, 8> Exits;
                        for (BasicBlock &BB : *UF)
                            if (Instruction *Term = BB.getTerminator())
                                if (isa<ReturnInst>(Term) ||
                                    isa<ResumeInst>(Term) ||
                                    isa<CleanupReturnInst>(Term))
                                    Exits.push_back(Term);
                        for (Instruction *Exit : Exits) {
                            IRBuilder<> XB(Exit);
                            XB.CreateCall(releaseFn->getFunctionType(),
                                          releaseFn, {});
                        }
                    }
                }
            }
        }
        changed = true;
    }
    return changed;
}

bool bindStringSeedToSeal(Module &M, ir::IRRandom &rng) {
    Function *Seed = M.getFunction("morok.str.seed");
    if (!Seed || Seed->isDeclaration())
        return false;
    GlobalVariable *Seal =
        runtime_seal::findChannel(M, runtime_seal::kAntiDebugChannel);
    if (!Seal || !Seal->hasInitializer())
        return false;
    const std::uint64_t S0 = runtime_seal::initialValue(Seal);

    bool changed = false;
    for (BasicBlock &BB : *Seed) {
        auto *RI = dyn_cast<ReturnInst>(BB.getTerminator());
        if (!RI || !RI->getReturnValue())
            continue;
        IRBuilder<> B(RI);
        Value *RV = RI->getReturnValue();
        // KDF(delta) is exactly 0 when the seal is clean (delta == 0), so the
        // seed — and therefore every decrypted string — is byte-identical on a
        // clean run and garbage once an analysis verdict has been folded in.
        Value *Delta =
            runtime_seal::emitDelta(B, Seal, S0, "morok.str.seed.seal");
        Value *Key = runtime_seal::emitKdf64(B, Delta, rng.next(),
                                             "morok.str.seed.seal.kdf");
        RI->setOperand(0, B.CreateXor(RV, Key, "morok.str.seed.sealed"));
        changed = true;
    }
    return changed;
}

bool inlineConstantFormatCalls(Module &M) {
    auto Decl = [&](StringRef Name) -> Function * {
        Function *F = M.getFunction(Name);
        return (F && F->isDeclaration()) ? F : nullptr;
    };

    Function *Snprintf = Decl("snprintf");
    Function *Sprintf = Decl("sprintf");
    Function *Printf = Decl("printf");
    Function *Fprintf = Decl("fprintf");
    SmallVector<Function *, 3> SscanfFns;
    StringRef SscanfNames[] = {"sscanf", "__isoc99_sscanf", "__isoc23_sscanf"};
    for (StringRef Name : SscanfNames)
        if (Function *F = Decl(Name))
            SscanfFns.push_back(F);
    if (!Snprintf && !Sprintf && !Printf && !Fprintf && SscanfFns.empty())
        return false;

    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);

    enum class SegKind { Literal, String, UnsignedDec, SignedDec, Hex, HexUpper, Char };
    struct Seg {
        SegKind kind;
        std::string lit;
    };

    auto isArg = [](SegKind K) { return K != SegKind::Literal; };

    // Parse deliberately small, hook-sensitive format strings.  Full printf
    // compatibility would require locale, width, precision, floating-point,
    // and undefined-overflow behavior.  Keep this helper exact for literals,
    // %%, %s, %c, simple signed/unsigned decimal, and simple hex, including
    // integer length modifiers that are normalized to i64 helper arguments.
    auto parse = [](StringRef Fmt, std::vector<Seg> &Segs,
                    unsigned &ArgCount) -> bool {
        std::string lit;
        auto flushLit = [&]() {
            if (!lit.empty()) {
                Segs.push_back({SegKind::Literal, lit});
                lit.clear();
            }
        };
        ArgCount = 0;
        for (std::size_t i = 0; i < Fmt.size(); ++i) {
            char c = Fmt[i];
            if (c == '%') {
                if (i + 1 >= Fmt.size())
                    return false;
                char n = Fmt[i + 1];
                if (n == '%') {
                    lit.push_back('%');
                    ++i;
                    continue;
                }

                std::size_t spec = i + 1;
                while (spec < Fmt.size()) {
                    char m = Fmt[spec];
                    if (m == 'h' || m == 'l' || m == 'j' || m == 'z' ||
                        m == 't') {
                        ++spec;
                        continue;
                    }
                    break;
                }
                if (spec >= Fmt.size())
                    return false;

                SegKind Kind = SegKind::Literal;
                switch (Fmt[spec]) {
                case 's':
                    Kind = SegKind::String;
                    break;
                case 'c':
                    Kind = SegKind::Char;
                    break;
                case 'd':
                case 'i':
                    Kind = SegKind::SignedDec;
                    break;
                case 'u':
                    Kind = SegKind::UnsignedDec;
                    break;
                case 'x':
                    Kind = SegKind::Hex;
                    break;
                case 'X':
                    Kind = SegKind::HexUpper;
                    break;
                default:
                    return false;
                }
                flushLit();
                Segs.push_back({Kind, {}});
                ++ArgCount;
                i = spec;
                continue;
            }
            lit.push_back(c);
        }
        flushLit();
        return true;
    };

    auto constFmt = [](Value *V, std::string &Out) -> bool {
        V = V->stripPointerCasts();
        auto *GV = dyn_cast<GlobalVariable>(V);
        if (!GV || !GV->isConstant() || !GV->hasInitializer())
            return false;
        auto *CDA = dyn_cast<ConstantDataArray>(GV->getInitializer());
        if (!CDA || !CDA->isCString())
            return false;
        Out = CDA->getAsCString().str();
        return true;
    };

    enum class BoundaryKind { Snprintf, Sprintf, Printf, Fprintf, Sscanf };

    StringMap<Function *> HelperCache;
    StringMap<Function *> PrintHelperCache;
    StringMap<Function *> ScanHelperCache;
    unsigned Counter = 0;

    auto getBufferHelper = [&](const std::string &Fmt,
                               const std::vector<Seg> &Segs) -> Function * {
        auto It = HelperCache.find(Fmt);
        if (It != HelperCache.end())
            return It->second;

        SmallVector<Type *, 8> Params{Ptr, I64};
        for (const Seg &S : Segs) {
            if (!isArg(S.kind))
                continue;
            if (S.kind == SegKind::String)
                Params.push_back(Ptr);
            else
                Params.push_back(I64);
        }
        auto *Fn = Function::Create(FunctionType::get(I32, Params, false),
                                    GlobalValue::InternalLinkage,
                                    "morok.fmt." + Twine(Counter++), &M);
        Fn->setDSOLocal(true);
        Fn->addFnAttr(Attribute::NoInline);
        Fn->addFnAttr(Attribute::OptimizeNone);

        Argument *Buf = Fn->getArg(0);
        Argument *Size = Fn->getArg(1);

        IRBuilder<> B(BasicBlock::Create(Ctx, "entry", Fn));
        AllocaInst *Pos = B.CreateAlloca(I64, nullptr, "morok.fmt.pos");
        AllocaInst *Cnt = B.CreateAlloca(I64, nullptr, "morok.fmt.cnt");
        AllocaInst *Scratch = B.CreateAlloca(I8, nullptr, "morok.fmt.scratch");
        B.CreateStore(ConstantInt::get(I64, 0), Pos);
        B.CreateStore(ConstantInt::get(I64, 0), Cnt);

        // Append one byte with exact snprintf-style bounds: the store always
        // executes but lands in a scratch slot when the output is full.  sprintf
        // calls pass size_t(-1), so this degenerates to unbounded sprintf
        // semantics while sharing one helper body.
        auto appendByte = [&](Value *ByteVal) {
            Value *P = B.CreateLoad(I64, Pos);
            Value *C = B.CreateLoad(I64, Cnt);
            Value *P1 = B.CreateAdd(P, ConstantInt::get(I64, 1));
            Value *CanWrite = B.CreateICmpULT(P1, Size);
            Value *DestBuf = B.CreateGEP(I8, Buf, {P});
            Value *Dest = B.CreateSelect(CanWrite, DestBuf, Scratch);
            B.CreateStore(ByteVal, Dest);
            B.CreateStore(B.CreateSelect(CanWrite, P1, P), Pos);
            B.CreateStore(B.CreateAdd(C, ConstantInt::get(I64, 1)), Cnt);
        };

        auto appendUnsigned = [&](Value *Num, unsigned Base, bool Upper,
                                  StringRef Prefix) {
            auto *TmpTy = ArrayType::get(I8, 65);
            AllocaInst *Tmp =
                B.CreateAlloca(TmpTy, nullptr, Twine(Prefix) + ".tmp");
            BasicBlock *Pre = B.GetInsertBlock();
            auto *ZeroBB = BasicBlock::Create(Ctx, Twine(Prefix) + ".zero", Fn);
            auto *LoopBB = BasicBlock::Create(Ctx, Twine(Prefix) + ".loop", Fn);
            auto *RevBB = BasicBlock::Create(Ctx, Twine(Prefix) + ".rev", Fn);
            auto *RevBodyBB =
                BasicBlock::Create(Ctx, Twine(Prefix) + ".rev.body", Fn);
            auto *DoneBB = BasicBlock::Create(Ctx, Twine(Prefix) + ".done", Fn);

            B.CreateCondBr(B.CreateICmpEQ(Num, ConstantInt::get(I64, 0)),
                           ZeroBB, LoopBB);

            B.SetInsertPoint(ZeroBB);
            appendByte(ConstantInt::get(I8, '0'));
            B.CreateBr(DoneBB);

            B.SetInsertPoint(LoopBB);
            PHINode *V = B.CreatePHI(I64, 2, Twine(Prefix) + ".v");
            PHINode *J = B.CreatePHI(I64, 2, Twine(Prefix) + ".j");
            V->addIncoming(Num, Pre);
            J->addIncoming(ConstantInt::get(I64, 0), Pre);
            Value *Rem = B.CreateURem(V, ConstantInt::get(I64, Base),
                                      Twine(Prefix) + ".rem");
            Value *Digit = B.CreateTrunc(Rem, I8, Twine(Prefix) + ".digit");
            Value *DecCh = B.CreateAdd(Digit, ConstantInt::get(I8, '0'),
                                       Twine(Prefix) + ".dec");
            Value *HexCh = B.CreateAdd(
                Digit, ConstantInt::get(I8, (Upper ? 'A' : 'a') - 10),
                Twine(Prefix) + ".hex");
            Value *Ch = B.CreateSelect(
                B.CreateICmpULT(Rem, ConstantInt::get(I64, 10)),
                DecCh, HexCh, Twine(Prefix) + ".ch");
            Value *PtrTmp = B.CreateInBoundsGEP(
                TmpTy, Tmp, {ConstantInt::get(I64, 0), J},
                Twine(Prefix) + ".tmp.ptr");
            B.CreateStore(Ch, PtrTmp);
            Value *NextV = B.CreateUDiv(V, ConstantInt::get(I64, Base),
                                        Twine(Prefix) + ".next.v");
            Value *NextJ = B.CreateAdd(J, ConstantInt::get(I64, 1),
                                       Twine(Prefix) + ".next.j");
            V->addIncoming(NextV, LoopBB);
            J->addIncoming(NextJ, LoopBB);
            B.CreateCondBr(B.CreateICmpNE(NextV, ConstantInt::get(I64, 0)),
                           LoopBB, RevBB);

            B.SetInsertPoint(RevBB);
            PHINode *R = B.CreatePHI(I64, 2, Twine(Prefix) + ".rev.i");
            R->addIncoming(NextJ, LoopBB);
            B.CreateCondBr(B.CreateICmpNE(R, ConstantInt::get(I64, 0)),
                           RevBodyBB, DoneBB);

            B.SetInsertPoint(RevBodyBB);
            Value *Rn = B.CreateSub(R, ConstantInt::get(I64, 1),
                                    Twine(Prefix) + ".rev.next");
            Value *LoadPtr = B.CreateInBoundsGEP(
                TmpTy, Tmp, {ConstantInt::get(I64, 0), Rn},
                Twine(Prefix) + ".rev.ptr");
            appendByte(B.CreateLoad(I8, LoadPtr, Twine(Prefix) + ".rev.ch"));
            B.CreateBr(RevBB);
            R->addIncoming(Rn, RevBodyBB);

            B.SetInsertPoint(DoneBB);
        };

        auto appendSigned = [&](Value *Num, StringRef Prefix) {
            auto *NegBB = BasicBlock::Create(Ctx, Twine(Prefix) + ".neg", Fn);
            auto *ContBB = BasicBlock::Create(Ctx, Twine(Prefix) + ".cont", Fn);
            Value *Neg = B.CreateICmpSLT(Num, ConstantInt::get(I64, 0),
                                         Twine(Prefix) + ".isneg");
            Value *Mag = B.CreateSelect(
                Neg, B.CreateSub(ConstantInt::get(I64, 0), Num,
                                 Twine(Prefix) + ".negmag"),
                Num, Twine(Prefix) + ".mag");
            B.CreateCondBr(Neg, NegBB, ContBB);

            B.SetInsertPoint(NegBB);
            appendByte(ConstantInt::get(I8, '-'));
            B.CreateBr(ContBB);

            B.SetInsertPoint(ContBB);
            std::string AbsPrefix = (Twine(Prefix) + ".abs").str();
            appendUnsigned(Mag, 10, false, AbsPrefix);
        };

        unsigned ArgIdx = 0;
        for (const Seg &S : Segs) {
            if (S.kind == SegKind::Literal) {
                for (char ch : S.lit)
                    appendByte(ConstantInt::get(
                        I8, static_cast<unsigned char>(ch)));
                continue;
            }

            Argument *Arg = Fn->getArg(2 + ArgIdx++);
            switch (S.kind) {
            case SegKind::String: {
                auto *Loop = BasicBlock::Create(Ctx, "morok.fmt.s.loop", Fn);
                auto *Body = BasicBlock::Create(Ctx, "morok.fmt.s.body", Fn);
                auto *Done = BasicBlock::Create(Ctx, "morok.fmt.s.done", Fn);
                BasicBlock *Pre = B.GetInsertBlock();
                B.CreateBr(Loop);
                B.SetInsertPoint(Loop);
                PHINode *J = B.CreatePHI(I64, 2, "morok.fmt.s.j");
                J->addIncoming(ConstantInt::get(I64, 0), Pre);
                Value *Ch = B.CreateLoad(I8, B.CreateGEP(I8, Arg, {J}));
                B.CreateCondBr(B.CreateICmpEQ(Ch, ConstantInt::get(I8, 0)),
                               Done, Body);
                B.SetInsertPoint(Body);
                appendByte(Ch);
                Value *Jn = B.CreateAdd(J, ConstantInt::get(I64, 1));
                J->addIncoming(Jn, Body);
                B.CreateBr(Loop);
                B.SetInsertPoint(Done);
                break;
            }
            case SegKind::UnsignedDec:
                appendUnsigned(Arg, 10, false, "morok.fmt.u");
                break;
            case SegKind::SignedDec:
                appendSigned(Arg, "morok.fmt.d");
                break;
            case SegKind::Hex:
                appendUnsigned(Arg, 16, false, "morok.fmt.x");
                break;
            case SegKind::HexUpper:
                appendUnsigned(Arg, 16, true, "morok.fmt.X");
                break;
            case SegKind::Char:
                appendByte(B.CreateTrunc(Arg, I8, "morok.fmt.c"));
                break;
            case SegKind::Literal:
                break;
            }
        }

        // NUL-terminate at min(total, size-1) when size > 0, again routing the
        // size==0 case to scratch so the buffer is never touched.
        Value *P = B.CreateLoad(I64, Pos);
        Value *C = B.CreateLoad(I64, Cnt);
        Value *SizeNZ = B.CreateICmpNE(Size, ConstantInt::get(I64, 0));
        Value *Dest =
            B.CreateSelect(SizeNZ, B.CreateGEP(I8, Buf, {P}), Scratch);
        B.CreateStore(ConstantInt::get(I8, 0), Dest);
        B.CreateRet(B.CreateTrunc(C, I32));

        HelperCache[Fmt] = Fn;
        return Fn;
    };

    auto getPrintHelper = [&](const std::string &Fmt,
                              const std::vector<Seg> &Segs,
                              bool HasStream) -> Function * {
        std::string Key = (HasStream ? "fprintf:" : "printf:") + Fmt;
        auto It = PrintHelperCache.find(Key);
        if (It != PrintHelperCache.end())
            return It->second;

        SmallVector<Type *, 8> Params;
        if (HasStream)
            Params.push_back(Ptr);
        for (const Seg &S : Segs) {
            if (!isArg(S.kind))
                continue;
            if (S.kind == SegKind::String)
                Params.push_back(Ptr);
            else
                Params.push_back(I64);
        }

        auto *Fn = Function::Create(FunctionType::get(I32, Params, false),
                                    GlobalValue::InternalLinkage,
                                    "morok.print." + Twine(Counter++), &M);
        Fn->setDSOLocal(true);
        Fn->addFnAttr(Attribute::NoInline);
        Fn->addFnAttr(Attribute::OptimizeNone);

        IRBuilder<> B(BasicBlock::Create(Ctx, "entry", Fn));
        AllocaInst *Cnt = B.CreateAlloca(I64, nullptr, "morok.print.cnt");
        B.CreateStore(ConstantInt::get(I64, 0), Cnt);

        FunctionCallee Putchar = M.getOrInsertFunction(
            "putchar", FunctionType::get(I32, {I32}, false));
        FunctionCallee Fputc = M.getOrInsertFunction(
            "fputc", FunctionType::get(I32, {I32, Ptr}, false));
        Argument *Stream = HasStream ? Fn->getArg(0) : nullptr;

        auto appendByte = [&](Value *ByteVal) {
            Value *Ch = B.CreateZExtOrTrunc(ByteVal, I32, "morok.print.ch");
            if (HasStream)
                B.CreateCall(Fputc, {Ch, Stream});
            else
                B.CreateCall(Putchar, {Ch});
            Value *C = B.CreateLoad(I64, Cnt);
            B.CreateStore(B.CreateAdd(C, ConstantInt::get(I64, 1)), Cnt);
        };

        auto appendUnsigned = [&](Value *Num, unsigned Base, bool Upper,
                                  StringRef Prefix) {
            auto *TmpTy = ArrayType::get(I8, 65);
            AllocaInst *Tmp =
                B.CreateAlloca(TmpTy, nullptr, Twine(Prefix) + ".tmp");
            BasicBlock *Pre = B.GetInsertBlock();
            auto *ZeroBB = BasicBlock::Create(Ctx, Twine(Prefix) + ".zero", Fn);
            auto *LoopBB = BasicBlock::Create(Ctx, Twine(Prefix) + ".loop", Fn);
            auto *RevBB = BasicBlock::Create(Ctx, Twine(Prefix) + ".rev", Fn);
            auto *RevBodyBB =
                BasicBlock::Create(Ctx, Twine(Prefix) + ".rev.body", Fn);
            auto *DoneBB = BasicBlock::Create(Ctx, Twine(Prefix) + ".done", Fn);

            B.CreateCondBr(B.CreateICmpEQ(Num, ConstantInt::get(I64, 0)),
                           ZeroBB, LoopBB);

            B.SetInsertPoint(ZeroBB);
            appendByte(ConstantInt::get(I8, '0'));
            B.CreateBr(DoneBB);

            B.SetInsertPoint(LoopBB);
            PHINode *V = B.CreatePHI(I64, 2, Twine(Prefix) + ".v");
            PHINode *J = B.CreatePHI(I64, 2, Twine(Prefix) + ".j");
            V->addIncoming(Num, Pre);
            J->addIncoming(ConstantInt::get(I64, 0), Pre);
            Value *Rem = B.CreateURem(V, ConstantInt::get(I64, Base),
                                      Twine(Prefix) + ".rem");
            Value *Digit = B.CreateTrunc(Rem, I8, Twine(Prefix) + ".digit");
            Value *DecCh = B.CreateAdd(Digit, ConstantInt::get(I8, '0'),
                                       Twine(Prefix) + ".dec");
            Value *HexCh = B.CreateAdd(
                Digit, ConstantInt::get(I8, (Upper ? 'A' : 'a') - 10),
                Twine(Prefix) + ".hex");
            Value *Ch = B.CreateSelect(
                B.CreateICmpULT(Rem, ConstantInt::get(I64, 10)),
                DecCh, HexCh, Twine(Prefix) + ".ch");
            Value *PtrTmp = B.CreateInBoundsGEP(
                TmpTy, Tmp, {ConstantInt::get(I64, 0), J},
                Twine(Prefix) + ".tmp.ptr");
            B.CreateStore(Ch, PtrTmp);
            Value *NextV = B.CreateUDiv(V, ConstantInt::get(I64, Base),
                                        Twine(Prefix) + ".next.v");
            Value *NextJ = B.CreateAdd(J, ConstantInt::get(I64, 1),
                                       Twine(Prefix) + ".next.j");
            V->addIncoming(NextV, LoopBB);
            J->addIncoming(NextJ, LoopBB);
            B.CreateCondBr(B.CreateICmpNE(NextV, ConstantInt::get(I64, 0)),
                           LoopBB, RevBB);

            B.SetInsertPoint(RevBB);
            PHINode *R = B.CreatePHI(I64, 2, Twine(Prefix) + ".rev.i");
            R->addIncoming(NextJ, LoopBB);
            B.CreateCondBr(B.CreateICmpNE(R, ConstantInt::get(I64, 0)),
                           RevBodyBB, DoneBB);

            B.SetInsertPoint(RevBodyBB);
            Value *Rn = B.CreateSub(R, ConstantInt::get(I64, 1),
                                    Twine(Prefix) + ".rev.next");
            Value *LoadPtr = B.CreateInBoundsGEP(
                TmpTy, Tmp, {ConstantInt::get(I64, 0), Rn},
                Twine(Prefix) + ".rev.ptr");
            appendByte(B.CreateLoad(I8, LoadPtr, Twine(Prefix) + ".rev.ch"));
            B.CreateBr(RevBB);
            R->addIncoming(Rn, RevBodyBB);

            B.SetInsertPoint(DoneBB);
        };

        auto appendSigned = [&](Value *Num, StringRef Prefix) {
            auto *NegBB = BasicBlock::Create(Ctx, Twine(Prefix) + ".neg", Fn);
            auto *ContBB = BasicBlock::Create(Ctx, Twine(Prefix) + ".cont", Fn);
            Value *Neg = B.CreateICmpSLT(Num, ConstantInt::get(I64, 0),
                                         Twine(Prefix) + ".isneg");
            Value *Mag = B.CreateSelect(
                Neg, B.CreateSub(ConstantInt::get(I64, 0), Num,
                                 Twine(Prefix) + ".negmag"),
                Num, Twine(Prefix) + ".mag");
            B.CreateCondBr(Neg, NegBB, ContBB);

            B.SetInsertPoint(NegBB);
            appendByte(ConstantInt::get(I8, '-'));
            B.CreateBr(ContBB);

            B.SetInsertPoint(ContBB);
            std::string AbsPrefix = (Twine(Prefix) + ".abs").str();
            appendUnsigned(Mag, 10, false, AbsPrefix);
        };

        unsigned ArgIdx = HasStream ? 1u : 0u;
        for (const Seg &S : Segs) {
            if (S.kind == SegKind::Literal) {
                for (char ch : S.lit)
                    appendByte(ConstantInt::get(
                        I8, static_cast<unsigned char>(ch)));
                continue;
            }

            Argument *Arg = Fn->getArg(ArgIdx++);
            switch (S.kind) {
            case SegKind::String: {
                auto *Loop = BasicBlock::Create(Ctx, "morok.print.s.loop", Fn);
                auto *Body = BasicBlock::Create(Ctx, "morok.print.s.body", Fn);
                auto *Done = BasicBlock::Create(Ctx, "morok.print.s.done", Fn);
                BasicBlock *Pre = B.GetInsertBlock();
                B.CreateBr(Loop);
                B.SetInsertPoint(Loop);
                PHINode *J = B.CreatePHI(I64, 2, "morok.print.s.j");
                J->addIncoming(ConstantInt::get(I64, 0), Pre);
                Value *Ch = B.CreateLoad(I8, B.CreateGEP(I8, Arg, {J}));
                B.CreateCondBr(B.CreateICmpEQ(Ch, ConstantInt::get(I8, 0)),
                               Done, Body);
                B.SetInsertPoint(Body);
                appendByte(Ch);
                Value *Jn = B.CreateAdd(J, ConstantInt::get(I64, 1));
                J->addIncoming(Jn, Body);
                B.CreateBr(Loop);
                B.SetInsertPoint(Done);
                break;
            }
            case SegKind::UnsignedDec:
                appendUnsigned(Arg, 10, false, "morok.print.u");
                break;
            case SegKind::SignedDec:
                appendSigned(Arg, "morok.print.d");
                break;
            case SegKind::Hex:
                appendUnsigned(Arg, 16, false, "morok.print.x");
                break;
            case SegKind::HexUpper:
                appendUnsigned(Arg, 16, true, "morok.print.X");
                break;
            case SegKind::Char:
                appendByte(B.CreateTrunc(Arg, I8, "morok.print.c"));
                break;
            case SegKind::Literal:
                break;
            }
        }

        Value *C = B.CreateLoad(I64, Cnt);
        B.CreateRet(B.CreateTrunc(C, I32));

        PrintHelperCache[Key] = Fn;
        return Fn;
    };

    auto getScanIntHelper = [&](bool Signed) -> Function * {
        StringRef Key = Signed ? "d" : "u";
        auto It = ScanHelperCache.find(Key);
        if (It != ScanHelperCache.end())
            return It->second;

        auto *Fn = Function::Create(FunctionType::get(I32, {Ptr, Ptr}, false),
                                    GlobalValue::InternalLinkage,
                                    Signed ? "morok.scan.d" : "morok.scan.u",
                                    &M);
        Fn->setDSOLocal(true);
        Fn->addFnAttr(Attribute::NoInline);
        Fn->addFnAttr(Attribute::OptimizeNone);

        Argument *Input = Fn->getArg(0);
        Argument *Out = Fn->getArg(1);

        auto *EntryBB = BasicBlock::Create(Ctx, "entry", Fn);
        auto *SkipBB = BasicBlock::Create(Ctx, "morok.scan.skip", Fn);
        auto *SkipBodyBB =
            BasicBlock::Create(Ctx, "morok.scan.skip.body", Fn);
        auto *AfterSkipBB =
            BasicBlock::Create(Ctx, "morok.scan.after.skip", Fn);
        auto *LoopBB = BasicBlock::Create(Ctx, "morok.scan.digits", Fn);
        auto *DigitBB =
            BasicBlock::Create(Ctx, "morok.scan.digit.body", Fn);
        auto *DoneBB = BasicBlock::Create(Ctx, "morok.scan.done", Fn);
        auto *StoreBB = BasicBlock::Create(Ctx, "morok.scan.store", Fn);
        auto *FailBB = BasicBlock::Create(Ctx, "morok.scan.fail", Fn);

        IRBuilder<> B(EntryBB);
        B.CreateBr(SkipBB);

        B.SetInsertPoint(SkipBB);
        PHINode *SkipIdx = B.CreatePHI(I64, 2, "morok.scan.skip.i");
        SkipIdx->addIncoming(ConstantInt::get(I64, 0), EntryBB);
        Value *SkipCh = B.CreateLoad(
            I8, B.CreateGEP(I8, Input, {SkipIdx}, "morok.scan.skip.ptr"),
            "morok.scan.skip.ch");
        auto isCh = [&](Value *Ch, unsigned char C) {
            return B.CreateICmpEQ(Ch, ConstantInt::get(I8, C));
        };
        Value *Space = isCh(SkipCh, ' ');
        Space = B.CreateOr(Space, isCh(SkipCh, '\t'));
        Space = B.CreateOr(Space, isCh(SkipCh, '\n'));
        Space = B.CreateOr(Space, isCh(SkipCh, '\r'));
        Space = B.CreateOr(Space, isCh(SkipCh, '\f'));
        Space = B.CreateOr(Space, isCh(SkipCh, '\v'));
        B.CreateCondBr(Space, SkipBodyBB, AfterSkipBB);

        B.SetInsertPoint(SkipBodyBB);
        Value *SkipNext =
            B.CreateAdd(SkipIdx, ConstantInt::get(I64, 1),
                        "morok.scan.skip.next");
        SkipIdx->addIncoming(SkipNext, SkipBodyBB);
        B.CreateBr(SkipBB);

        B.SetInsertPoint(AfterSkipBB);
        Value *FirstCh = B.CreateLoad(
            I8, B.CreateGEP(I8, Input, {SkipIdx}, "morok.scan.first.ptr"),
            "morok.scan.first.ch");
        Value *Neg = ConstantInt::getFalse(Ctx);
        Value *Start = SkipIdx;
        if (Signed) {
            Value *IsMinus = isCh(FirstCh, '-');
            Value *IsPlus = isCh(FirstCh, '+');
            Value *HasSign = B.CreateOr(IsMinus, IsPlus, "morok.scan.sign");
            Start = B.CreateSelect(
                HasSign, B.CreateAdd(SkipIdx, ConstantInt::get(I64, 1)),
                SkipIdx, "morok.scan.start");
            Neg = IsMinus;
        }
        B.CreateBr(LoopBB);

        B.SetInsertPoint(LoopBB);
        PHINode *Idx = B.CreatePHI(I64, 2, "morok.scan.i");
        PHINode *Acc = B.CreatePHI(I64, 2, "morok.scan.acc");
        PHINode *Seen = B.CreatePHI(Type::getInt1Ty(Ctx), 2,
                                    "morok.scan.seen");
        Idx->addIncoming(Start, AfterSkipBB);
        Acc->addIncoming(ConstantInt::get(I64, 0), AfterSkipBB);
        Seen->addIncoming(ConstantInt::getFalse(Ctx), AfterSkipBB);
        Value *Ch = B.CreateLoad(
            I8, B.CreateGEP(I8, Input, {Idx}, "morok.scan.ptr"),
            "morok.scan.ch");
        Value *Ch32 = B.CreateZExt(Ch, I32, "morok.scan.ch32");
        Value *Digit32 =
            B.CreateSub(Ch32, ConstantInt::get(I32, '0'),
                        "morok.scan.digit32");
        Value *IsDigit = B.CreateICmpULE(Digit32, ConstantInt::get(I32, 9),
                                         "morok.scan.isdigit");
        B.CreateCondBr(IsDigit, DigitBB, DoneBB);

        B.SetInsertPoint(DigitBB);
        Value *NextAcc = B.CreateAdd(
            B.CreateMul(Acc, ConstantInt::get(I64, 10),
                        "morok.scan.acc.scale"),
            B.CreateZExt(Digit32, I64), "morok.scan.acc.next");
        Value *NextIdx =
            B.CreateAdd(Idx, ConstantInt::get(I64, 1), "morok.scan.i.next");
        Idx->addIncoming(NextIdx, DigitBB);
        Acc->addIncoming(NextAcc, DigitBB);
        Seen->addIncoming(ConstantInt::getTrue(Ctx), DigitBB);
        B.CreateBr(LoopBB);

        B.SetInsertPoint(DoneBB);
        B.CreateCondBr(Seen, StoreBB, FailBB);

        B.SetInsertPoint(StoreBB);
        Value *Narrow = B.CreateTrunc(Acc, I32, "morok.scan.narrow");
        if (Signed) {
            Value *Negative =
                B.CreateSub(ConstantInt::get(I32, 0), Narrow,
                            "morok.scan.negative");
            Narrow = B.CreateSelect(Neg, Negative, Narrow,
                                    "morok.scan.signed");
        }
        B.CreateStore(Narrow, Out);
        B.CreateRet(ConstantInt::get(I32, 1));

        B.SetInsertPoint(FailBB);
        B.CreateRet(ConstantInt::get(I32, 0));

        ScanHelperCache[Key] = Fn;
        return Fn;
    };

    auto getScanAsmLineHelper = [&]() -> Function * {
        StringRef Key = "asm-line";
        auto It = ScanHelperCache.find(Key);
        if (It != ScanHelperCache.end())
            return It->second;

        auto *Fn = Function::Create(
            FunctionType::get(I32, {Ptr, Ptr, Ptr}, false),
            GlobalValue::InternalLinkage, "morok.scan.asmline", &M);
        Fn->setDSOLocal(true);
        Fn->addFnAttr(Attribute::NoInline);
        Fn->addFnAttr(Attribute::OptimizeNone);

        Argument *Input = Fn->getArg(0);
        Argument *WordOut = Fn->getArg(1);
        Argument *RestOut = Fn->getArg(2);

        auto *EntryBB = BasicBlock::Create(Ctx, "entry", Fn);
        auto *Skip1BB = BasicBlock::Create(Ctx, "morok.scan.skip1", Fn);
        auto *Skip1BodyBB =
            BasicBlock::Create(Ctx, "morok.scan.skip1.body", Fn);
        auto *WordBB = BasicBlock::Create(Ctx, "morok.scan.word", Fn);
        auto *WordBodyBB =
            BasicBlock::Create(Ctx, "morok.scan.word.body", Fn);
        auto *AfterWordBB =
            BasicBlock::Create(Ctx, "morok.scan.after.word", Fn);
        auto *WordFailBB =
            BasicBlock::Create(Ctx, "morok.scan.word.fail", Fn);
        auto *Skip2BB = BasicBlock::Create(Ctx, "morok.scan.skip2", Fn);
        auto *Skip2BodyBB =
            BasicBlock::Create(Ctx, "morok.scan.skip2.body", Fn);
        auto *RestBB = BasicBlock::Create(Ctx, "morok.scan.rest", Fn);
        auto *RestBodyBB =
            BasicBlock::Create(Ctx, "morok.scan.rest.body", Fn);
        auto *DoneBB = BasicBlock::Create(Ctx, "morok.scan.asm.done", Fn);

        IRBuilder<> B(EntryBB);
        auto isCh = [&](Value *Ch, unsigned char C) {
            return B.CreateICmpEQ(Ch, ConstantInt::get(I8, C));
        };
        auto isSpace = [&](Value *Ch) {
            Value *Space = isCh(Ch, ' ');
            Space = B.CreateOr(Space, isCh(Ch, '\t'));
            Space = B.CreateOr(Space, isCh(Ch, '\n'));
            Space = B.CreateOr(Space, isCh(Ch, '\r'));
            Space = B.CreateOr(Space, isCh(Ch, '\f'));
            return B.CreateOr(Space, isCh(Ch, '\v'));
        };
        B.CreateBr(Skip1BB);

        B.SetInsertPoint(Skip1BB);
        PHINode *Skip1 = B.CreatePHI(I64, 2, "morok.scan.skip1.i");
        Skip1->addIncoming(ConstantInt::get(I64, 0), EntryBB);
        Value *Skip1Ch = B.CreateLoad(
            I8, B.CreateGEP(I8, Input, {Skip1}, "morok.scan.skip1.ptr"),
            "morok.scan.skip1.ch");
        B.CreateCondBr(isSpace(Skip1Ch), Skip1BodyBB, WordBB);

        B.SetInsertPoint(Skip1BodyBB);
        Value *Skip1Next =
            B.CreateAdd(Skip1, ConstantInt::get(I64, 1),
                        "morok.scan.skip1.next");
        Skip1->addIncoming(Skip1Next, Skip1BodyBB);
        B.CreateBr(Skip1BB);

        B.SetInsertPoint(WordBB);
        PHINode *WordSrc = B.CreatePHI(I64, 2, "morok.scan.word.src");
        PHINode *WordLen = B.CreatePHI(I64, 2, "morok.scan.word.len");
        WordSrc->addIncoming(Skip1, Skip1BB);
        WordLen->addIncoming(ConstantInt::get(I64, 0), Skip1BB);
        Value *WordCh = B.CreateLoad(
            I8, B.CreateGEP(I8, Input, {WordSrc}, "morok.scan.word.in"),
            "morok.scan.word.ch");
        Value *WordDone = B.CreateOr(isCh(WordCh, '\0'), isSpace(WordCh));
        WordDone = B.CreateOr(
            WordDone, B.CreateICmpEQ(WordLen, ConstantInt::get(I64, 31)));
        B.CreateCondBr(WordDone, AfterWordBB, WordBodyBB);

        B.SetInsertPoint(WordBodyBB);
        B.CreateStore(WordCh, B.CreateGEP(I8, WordOut, {WordLen},
                                          "morok.scan.word.out"));
        Value *WordSrcNext =
            B.CreateAdd(WordSrc, ConstantInt::get(I64, 1),
                        "morok.scan.word.src.next");
        Value *WordLenNext =
            B.CreateAdd(WordLen, ConstantInt::get(I64, 1),
                        "morok.scan.word.len.next");
        WordSrc->addIncoming(WordSrcNext, WordBodyBB);
        WordLen->addIncoming(WordLenNext, WordBodyBB);
        B.CreateBr(WordBB);

        B.SetInsertPoint(AfterWordBB);
        B.CreateStore(ConstantInt::get(I8, 0),
                      B.CreateGEP(I8, WordOut, {WordLen},
                                  "morok.scan.word.nul"));
        B.CreateCondBr(B.CreateICmpEQ(WordLen, ConstantInt::get(I64, 0)),
                       WordFailBB, Skip2BB);

        B.SetInsertPoint(WordFailBB);
        B.CreateRet(ConstantInt::get(I32, 0));

        B.SetInsertPoint(Skip2BB);
        PHINode *Skip2 = B.CreatePHI(I64, 2, "morok.scan.skip2.i");
        Skip2->addIncoming(WordSrc, AfterWordBB);
        Value *Skip2Ch = B.CreateLoad(
            I8, B.CreateGEP(I8, Input, {Skip2}, "morok.scan.skip2.ptr"),
            "morok.scan.skip2.ch");
        B.CreateCondBr(isSpace(Skip2Ch), Skip2BodyBB, RestBB);

        B.SetInsertPoint(Skip2BodyBB);
        Value *Skip2Next =
            B.CreateAdd(Skip2, ConstantInt::get(I64, 1),
                        "morok.scan.skip2.next");
        Skip2->addIncoming(Skip2Next, Skip2BodyBB);
        B.CreateBr(Skip2BB);

        B.SetInsertPoint(RestBB);
        PHINode *RestSrc = B.CreatePHI(I64, 2, "morok.scan.rest.src");
        PHINode *RestLen = B.CreatePHI(I64, 2, "morok.scan.rest.len");
        RestSrc->addIncoming(Skip2, Skip2BB);
        RestLen->addIncoming(ConstantInt::get(I64, 0), Skip2BB);
        Value *RestCh = B.CreateLoad(
            I8, B.CreateGEP(I8, Input, {RestSrc}, "morok.scan.rest.in"),
            "morok.scan.rest.ch");
        Value *RestDone = B.CreateOr(isCh(RestCh, '\0'), isCh(RestCh, '\n'));
        RestDone = B.CreateOr(
            RestDone, B.CreateICmpEQ(RestLen, ConstantInt::get(I64, 255)));
        B.CreateCondBr(RestDone, DoneBB, RestBodyBB);

        B.SetInsertPoint(RestBodyBB);
        B.CreateStore(RestCh, B.CreateGEP(I8, RestOut, {RestLen},
                                          "morok.scan.rest.out"));
        Value *RestSrcNext =
            B.CreateAdd(RestSrc, ConstantInt::get(I64, 1),
                        "morok.scan.rest.src.next");
        Value *RestLenNext =
            B.CreateAdd(RestLen, ConstantInt::get(I64, 1),
                        "morok.scan.rest.len.next");
        RestSrc->addIncoming(RestSrcNext, RestBodyBB);
        RestLen->addIncoming(RestLenNext, RestBodyBB);
        B.CreateBr(RestBB);

        B.SetInsertPoint(DoneBB);
        B.CreateStore(ConstantInt::get(I8, 0),
                      B.CreateGEP(I8, RestOut, {RestLen},
                                  "morok.scan.rest.nul"));
        B.CreateRet(B.CreateSelect(
            B.CreateICmpEQ(RestLen, ConstantInt::get(I64, 0)),
            ConstantInt::get(I32, 1), ConstantInt::get(I32, 2),
            "morok.scan.assignments"));

        ScanHelperCache[Key] = Fn;
        return Fn;
    };

    struct FormatCall {
        CallInst *call;
        BoundaryKind kind;
    };
    SmallVector<FormatCall, 16> Calls;
    if (Snprintf)
        for (User *U : Snprintf->users())
            if (auto *CI = dyn_cast<CallInst>(U))
                if (CI->getCalledFunction() == Snprintf && CI->arg_size() >= 3)
                    Calls.push_back({CI, BoundaryKind::Snprintf});
    if (Sprintf)
        for (User *U : Sprintf->users())
            if (auto *CI = dyn_cast<CallInst>(U))
                if (CI->getCalledFunction() == Sprintf && CI->arg_size() >= 2)
                    Calls.push_back({CI, BoundaryKind::Sprintf});
    if (Printf)
        for (User *U : Printf->users())
            if (auto *CI = dyn_cast<CallInst>(U))
                if (CI->getCalledFunction() == Printf && CI->arg_size() >= 1)
                    Calls.push_back({CI, BoundaryKind::Printf});
    if (Fprintf)
        for (User *U : Fprintf->users())
            if (auto *CI = dyn_cast<CallInst>(U))
                if (CI->getCalledFunction() == Fprintf && CI->arg_size() >= 2)
                    Calls.push_back({CI, BoundaryKind::Fprintf});
    for (Function *Sscanf : SscanfFns)
        for (User *U : Sscanf->users())
            if (auto *CI = dyn_cast<CallInst>(U))
                if (CI->getCalledFunction() == Sscanf && CI->arg_size() >= 3)
                    Calls.push_back({CI, BoundaryKind::Sscanf});

    bool Changed = false;
    for (FormatCall FC : Calls) {
        CallInst *CI = FC.call;
        const bool IsSnprintf = FC.kind == BoundaryKind::Snprintf;
        const bool IsSprintf = FC.kind == BoundaryKind::Sprintf;
        const bool IsPrintf = FC.kind == BoundaryKind::Printf;
        const bool IsFprintf = FC.kind == BoundaryKind::Fprintf;
        const bool IsSscanf = FC.kind == BoundaryKind::Sscanf;
        const unsigned FmtArg =
            IsSnprintf ? 2u : (IsSprintf || IsFprintf || IsSscanf ? 1u : 0u);
        const unsigned FirstVarArg =
            IsSnprintf ? 3u : (IsSprintf || IsFprintf || IsSscanf ? 2u : 1u);
        std::string Fmt;
        if (!constFmt(CI->getArgOperand(FmtArg), Fmt))
            continue;
        if (IsSscanf) {
            const std::string AsmLineFmt = "%31s %255[^\n]";
            if (Fmt == AsmLineFmt) {
                if (CI->arg_size() != 4 ||
                    !CI->getArgOperand(2)->getType()->isPointerTy() ||
                    !CI->getArgOperand(3)->getType()->isPointerTy())
                    continue;
                IRBuilder<> B(CI);
                Function *Helper = getScanAsmLineHelper();
                CallInst *New = B.CreateCall(
                    Helper->getFunctionType(), Helper,
                    {CI->getArgOperand(0), CI->getArgOperand(2),
                     CI->getArgOperand(3)});
                New->setDebugLoc(CI->getDebugLoc());
                if (!CI->use_empty())
                    CI->replaceAllUsesWith(New);
                CI->eraseFromParent();
                Changed = true;
                continue;
            }
            if (CI->arg_size() != 3 ||
                (Fmt != "%d" && Fmt != "%u") ||
                !CI->getArgOperand(2)->getType()->isPointerTy())
                continue;
            IRBuilder<> B(CI);
            Function *Helper = getScanIntHelper(Fmt == "%d");
            CallInst *New = B.CreateCall(
                Helper->getFunctionType(), Helper,
                {CI->getArgOperand(0), CI->getArgOperand(2)});
            New->setDebugLoc(CI->getDebugLoc());
            if (!CI->use_empty())
                CI->replaceAllUsesWith(New);
            CI->eraseFromParent();
            Changed = true;
            continue;
        }

        std::vector<Seg> Segs;
        unsigned ArgCount = 0;
        if (!parse(Fmt, Segs, ArgCount))
            continue;
        if (ArgCount != CI->arg_size() - FirstVarArg)
            continue;

        bool ok = true;
        unsigned VarIdx = 0;
        for (const Seg &S : Segs) {
            if (!isArg(S.kind))
                continue;
            Value *Arg = CI->getArgOperand(FirstVarArg + VarIdx++);
            if (S.kind == SegKind::String) {
                if (!Arg->getType()->isPointerTy())
                    ok = false;
            } else if (!Arg->getType()->isIntegerTy()) {
                ok = false;
            }
        }
        if (!ok)
            continue;

        IRBuilder<> B(CI);
        Function *Helper = nullptr;
        SmallVector<Value *, 8> Args;
        if (IsPrintf || IsFprintf) {
            Helper = getPrintHelper(Fmt, Segs, IsFprintf);
            if (IsFprintf)
                Args.push_back(CI->getArgOperand(0));
        } else {
            Helper = getBufferHelper(Fmt, Segs);
            Args.push_back(CI->getArgOperand(0));
            if (IsSnprintf)
                Args.push_back(B.CreateZExtOrTrunc(CI->getArgOperand(1), I64));
            else
                Args.push_back(ConstantInt::get(I64, ~std::uint64_t{0}));
        }

        VarIdx = 0;
        for (const Seg &S : Segs) {
            if (!isArg(S.kind))
                continue;
            Value *Arg = CI->getArgOperand(FirstVarArg + VarIdx++);
            if (S.kind == SegKind::String) {
                Args.push_back(Arg);
            } else if (S.kind == SegKind::SignedDec) {
                Args.push_back(B.CreateSExtOrTrunc(Arg, I64));
            } else {
                Args.push_back(B.CreateZExtOrTrunc(Arg, I64));
            }
        }
        CallInst *New = B.CreateCall(Helper->getFunctionType(), Helper, Args);
        New->setDebugLoc(CI->getDebugLoc());
        if (!CI->use_empty())
            CI->replaceAllUsesWith(New);
        CI->eraseFromParent();
        Changed = true;
    }
    return Changed;
}

PreservedAnalyses StringEncryptionPass::run(Module &M,
                                            ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return stringEncryptModule(M, params_, rng) ? PreservedAnalyses::none()
                                                : PreservedAnalyses::all();
}

} // namespace morok::passes
