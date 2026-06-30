// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/FunctionCallObfuscate.cpp
//
// Each eligible direct call/invoke to an external function `f(args)` becomes a
// hash-gated runtime resolution followed by an encoded indirect call.  On
// 64-bit Linux/macOS, a small family of private resolvers walks loaded
// ELF/Mach-O export tables by per-family keyed name hash plus a per-callsite
// salt, so the call site carries no plaintext API name and imports no dlsym
// edge.  Other targets keep the cloaked dlsym fallback:
//   buf = <inline, per-site decryption of the encrypted symbol name>
//   p   = dlsym(RTLD_DEFAULT, buf); p(args)
// so the static import/call edge to `f` disappears.  The symbol name is never a
// readable string and is never recovered by a single shared routine: each site
// gets its own cloaked symbol (ir::emitCloakedSymbol), so cracking one site
// does not crack the rest.  Only declared (external) symbols are redirected —
// locally-defined functions stay direct, since dlsym would not resolve them.
// On Linux x86_64 direct calls use an exception-mediated resolver: the site
// publishes a hash-guarded per-thread pending request and deliberately faults;
// the SIGSEGV handler claims the faulting thread's request and resumes at the
// indirect-call continuation, where the manual resolver runs outside the signal
// context.

#include "morok/passes/FunctionCallObfuscate.hpp"

#include "morok/core/KnuthHash.hpp"
#include "morok/ir/SymbolCloak.hpp"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr std::uint32_t kMaxCallsPerModule = 256;
constexpr unsigned kResolverFamilyCount = 4;
constexpr std::uint64_t kFnvOffset = 0xCBF29CE484222325ULL;
constexpr std::uint64_t kFnvPrime = 0x100000001B3ULL;

// Per-build resolver-family name hash.  Textbook FNV-1a constants are a
// fingerprint: an analyst recognises them, hashes the libc namespace, and maps
// every resolver hash back to its API.  We instead emit a few resolver
// families, each with a random offset basis and odd multiplier, then perturb
// each target with a per-site salt before comparison.  The same family key must
// drive both pass-time hashName() and the runtime resolver IR, so keys are
// stored by Module* and family until this pass finishes.  The table is
// mutex-guarded because ThinLTO processes backend modules on separate threads.
struct HashKey {
    std::uint64_t offset;
    std::uint64_t prime;
};
using HashKeySet = std::array<HashKey, kResolverFamilyCount>;

std::mutex &hashKeyMutex() {
    static std::mutex M;
    return M;
}
std::unordered_map<const Module *, HashKeySet> &hashKeyTable() {
    static std::unordered_map<const Module *, HashKeySet> T;
    return T;
}
HashKey defaultHashKey(unsigned Family) {
    const std::uint64_t salt =
        0x9E3779B97F4A7C15ULL *
        static_cast<std::uint64_t>((Family % kResolverFamilyCount) + 1);
    return {kFnvOffset ^ salt, (kFnvPrime ^ salt) | 1ull};
}
void setHashKeys(const Module &M, const HashKeySet &Keys) {
    std::lock_guard<std::mutex> Lock(hashKeyMutex());
    hashKeyTable()[&M] = Keys;
}
void clearHashKey(const Module &M) {
    std::lock_guard<std::mutex> Lock(hashKeyMutex());
    hashKeyTable().erase(&M);
}
HashKey hashKeyFor(const Module &M, unsigned Family = 0) {
    std::lock_guard<std::mutex> Lock(hashKeyMutex());
    auto It = hashKeyTable().find(&M);
    if (It == hashKeyTable().end())
        return defaultHashKey(Family);
    return It->second[Family % kResolverFamilyCount];
}

struct ExceptionRuntime {
    GlobalVariable *hash = nullptr;
    GlobalVariable *name = nullptr;
    GlobalVariable *out = nullptr;
    GlobalVariable *cont = nullptr;
};

struct TargetPlan {
    CallBase *call = nullptr;
    std::string name;
    unsigned family = 0;
    std::uint64_t site_salt = 0;
    std::uint64_t dlsym_salt = 0;
    std::uint64_t dlsym_hash = 0;
    std::vector<std::uint64_t> hashes;
};

bool eligible(CallBase *cb) {
    if (!isa<CallInst>(cb) && !isa<InvokeInst>(cb))
        return false;
    if (cb->isInlineAsm() || cb->hasOperandBundles())
        return false;
    if (auto *ci = dyn_cast<CallInst>(cb))
        if (ci->isMustTailCall())
            return false;
    Function *callee = cb->getCalledFunction();
    if (!callee || !callee->isDeclaration() || callee->isIntrinsic())
        return false;
    if (callee->getName().starts_with("llvm.") ||
        callee->getName().starts_with("morok.") || callee->getName() == "dlsym")
        return false;
    return true;
}

std::vector<Value *> argsOf(CallBase &cb) {
    std::vector<Value *> args;
    args.reserve(cb.arg_size());
    for (Use &arg : cb.args())
        args.push_back(arg.get());
    return args;
}

Value *rotl64(IRBuilder<> &B, Value *V, unsigned Amount) {
    auto *I64 = Type::getInt64Ty(B.getContext());
    return B.CreateOr(B.CreateShl(V, ConstantInt::get(I64, Amount)),
                      B.CreateLShr(V, ConstantInt::get(I64, 64 - Amount)),
                      "morok.fco.ptr.rot");
}

std::uint64_t rotl64Const(std::uint64_t V, unsigned Amount) {
    return (V << Amount) | (V >> (64u - Amount));
}

std::uint64_t siteHash(std::uint64_t H, std::uint64_t Salt) {
    H ^= Salt + 0x9E3779B97F4A7C15ULL;
    H = rotl64Const(H, 23);
    H *= (Salt ^ 0xD6E8FEB86659FD93ULL) | 1ull;
    H ^= H >> 29;
    H += Salt * 0xA24BAED4963EE407ULL;
    H ^= H >> 32;
    return H ? H : ((Salt ^ 0xC2B2AE3D27D4EB4FULL) | 1ull);
}

Value *emitSiteHash(IRBuilder<> &B, Value *H, Value *Salt, const Twine &Name) {
    auto *I64 = Type::getInt64Ty(B.getContext());
    H = B.CreateXor(H,
                    B.CreateAdd(Salt,
                                ConstantInt::get(I64, 0x9E3779B97F4A7C15ULL),
                                Name + ".salt"),
                    Name + ".x");
    H = B.CreateOr(B.CreateShl(H, ConstantInt::get(I64, 23), Name + ".l"),
                   B.CreateLShr(H, ConstantInt::get(I64, 41), Name + ".r"),
                   Name + ".rot");
    Value *Odd = B.CreateOr(
        B.CreateXor(Salt, ConstantInt::get(I64, 0xD6E8FEB86659FD93ULL),
                    Name + ".odd.x"),
        ConstantInt::get(I64, 1), Name + ".odd");
    H = B.CreateMul(H, Odd, Name + ".mul");
    H = B.CreateXor(H, B.CreateLShr(H, ConstantInt::get(I64, 29)),
                    Name + ".fold0");
    H = B.CreateAdd(H,
                    B.CreateMul(Salt,
                                ConstantInt::get(I64, 0xA24BAED4963EE407ULL),
                                Name + ".salt.mul"),
                    Name + ".add");
    Value *Folded = B.CreateXor(H, B.CreateLShr(H, ConstantInt::get(I64, 32)),
                                Name + ".fold1");
    // Mirror siteHash()'s zero-guard exactly (see siteHash, the `H ? H : …`
    // tail): a site hash that folds to 0 must map to the same non-zero fallback
    // at runtime as it does at pass time.  Without this, hashName() substitutes
    // the fallback while the resolver's runtime hasher yields 0, so the symbol
    // never matches, resolution returns null, and the redirected call jumps to
    // address 0 — an unrecoverable SIGSEGV loop under the exception handler.
    Value *Fallback =
        B.CreateOr(B.CreateXor(Salt,
                               ConstantInt::get(I64, 0xC2B2AE3D27D4EB4FULL),
                               Name + ".z.x"),
                   ConstantInt::get(I64, 1), Name + ".z");
    return B.CreateSelect(
        B.CreateICmpEQ(Folded, ConstantInt::get(I64, 0), Name + ".isz"),
        Fallback, Folded, Name + ".nz");
}

std::uint64_t baseHashName(StringRef Name, const Module &M, unsigned Family) {
    const HashKey HK = hashKeyFor(M, Family);
    std::uint64_t H = HK.offset;
    for (unsigned char C : Name.bytes()) {
        H ^= C;
        H *= HK.prime;
    }
    return H ? H : HK.prime;
}

std::uint64_t hashName(StringRef Name, const Module &M, unsigned Family,
                       std::uint64_t SiteSalt) {
    return siteHash(baseHashName(Name, M, Family), SiteSalt);
}

std::vector<std::uint64_t> darwinAliasHashes(StringRef Name, const Module &M,
                                             unsigned Family,
                                             std::uint64_t SiteSalt) {
    if (Name == "strlen")
        return {hashName("_platform_strlen", M, Family, SiteSalt)};
    if (Name == "strcpy")
        return {hashName("_platform_strcpy", M, Family, SiteSalt)};
    if (Name == "strncpy")
        return {hashName("_platform_strncpy", M, Family, SiteSalt)};
    if (Name == "strcmp")
        return {hashName("_platform_strcmp", M, Family, SiteSalt)};
    if (Name == "strncmp")
        return {hashName("_platform_strncmp", M, Family, SiteSalt)};
    if (Name == "strchr")
        return {hashName("_platform_strchr", M, Family, SiteSalt)};
    if (Name == "strnlen")
        return {hashName("_platform_strnlen", M, Family, SiteSalt)};
    if (Name == "memset")
        return {hashName("_platform_memset", M, Family, SiteSalt)};
    if (Name == "memcpy" || Name == "memmove")
        return {hashName("_platform_memmove", M, Family, SiteSalt)};
    if (Name == "memcmp")
        return {hashName("_platform_memcmp", M, Family, SiteSalt)};
    if (Name == "memchr")
        return {hashName("_platform_memchr", M, Family, SiteSalt)};
    return {};
}

bool useExceptionCalls(const Triple &TT) {
    return TT.isOSLinux() && TT.getArch() == Triple::x86_64;
}

Value *constIp(Module &M, std::uint64_t V) {
    return ConstantInt::get(M.getDataLayout().getIntPtrType(M.getContext()), V);
}

std::string familyName(StringRef Base, unsigned Family) {
    return (Base + "." + Twine(Family % kResolverFamilyCount)).str();
}

Value *gepI8(IRBuilder<> &B, Module &M, Value *Base, Value *Off,
             const Twine &Name = "") {
    return B.CreateInBoundsGEP(Type::getInt8Ty(M.getContext()), Base, Off,
                               Name);
}

GlobalVariable *ptrGlobal(Module &M, StringRef Name) {
    if (auto *GV = M.getGlobalVariable(Name, /*AllowInternal=*/true))
        return GV;
    auto *Ptr = PointerType::getUnqual(M.getContext());
    auto *GV = new GlobalVariable(M, Ptr, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantPointerNull::get(Ptr), Name);
    GV->setDSOLocal(true);
    return GV;
}

GlobalVariable *i64Global(Module &M, StringRef Name) {
    if (auto *GV = M.getGlobalVariable(Name, /*AllowInternal=*/true))
        return GV;
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(M, I64, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantInt::get(I64, 0), Name);
    GV->setDSOLocal(true);
    GV->setAlignment(Align(8));
    return GV;
}

void configurePendingTls(GlobalVariable *GV) {
    GV->setThreadLocalMode(GlobalValue::InitialExecTLSModel);
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
}

GlobalVariable *pendingPtrGlobal(Module &M, StringRef Name) {
    GlobalVariable *GV = ptrGlobal(M, Name);
    configurePendingTls(GV);
    return GV;
}

GlobalVariable *pendingI64Global(Module &M, StringRef Name) {
    GlobalVariable *GV = i64Global(M, Name);
    configurePendingTls(GV);
    return GV;
}

FunctionCallee dlsymDecl(Module &M) {
    auto *Ptr = PointerType::getUnqual(M.getContext());
    return M.getOrInsertFunction("dlsym",
                                 FunctionType::get(Ptr, {Ptr, Ptr}, false));
}

FunctionCallee sigactionDecl(Module &M) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *Ptr = PointerType::getUnqual(M.getContext());
    return M.getOrInsertFunction(
        "sigaction", FunctionType::get(I32, {I32, Ptr, Ptr}, false));
}

FunctionCallee getauxvalDecl(Module &M) {
    auto *IP = M.getDataLayout().getIntPtrType(M.getContext());
    return M.getOrInsertFunction("getauxval",
                                 FunctionType::get(IP, {IP}, false));
}

Value *validAuxvPhdrPointer(IRBuilderBase &B, Module &M, Value *AtPhdr,
                            const Twine &Name) {
    auto *IP = M.getDataLayout().getIntPtrType(M.getContext());
    Value *NonNull =
        B.CreateICmpNE(AtPhdr, ConstantInt::get(IP, 0), Name + ".nonzero");
    if (IP->getBitWidth() < 64)
        return NonNull;
    Value *HighHalf = B.CreateICmpUGT(
        AtPhdr, ConstantInt::get(IP, 0x100000000ULL), Name + ".high");
    return B.CreateAnd(NonNull, HighHalf, Name);
}

FunctionCallee dlIteratePhdrDecl(Module &M) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *Ptr = PointerType::getUnqual(M.getContext());
    return M.getOrInsertFunction("dl_iterate_phdr",
                                 FunctionType::get(I32, {Ptr, Ptr}, false));
}

FunctionCallee dyldImageCountDecl(Module &M) {
    return M.getOrInsertFunction(
        "_dyld_image_count",
        FunctionType::get(Type::getInt32Ty(M.getContext()), false));
}

FunctionCallee dyldImageHeaderDecl(Module &M) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *Ptr = PointerType::getUnqual(M.getContext());
    return M.getOrInsertFunction("_dyld_get_image_header",
                                 FunctionType::get(Ptr, {I32}, false));
}

FunctionCallee dyldImageSlideDecl(Module &M) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *IP = M.getDataLayout().getIntPtrType(M.getContext());
    return M.getOrInsertFunction("_dyld_get_image_vmaddr_slide",
                                 FunctionType::get(IP, {I32}, false));
}

void zeroBytes(IRBuilder<> &B, Module &M, AllocaInst *Action,
               std::uint64_t Bytes) {
    auto *I8 = Type::getInt8Ty(M.getContext());
    for (std::uint64_t I = 0; I != Bytes; ++I)
        B.CreateStore(ConstantInt::get(I8, 0),
                      gepI8(B, M, Action, constIp(M, I)));
}

LoadInst *loadUnaligned(IRBuilder<> &B, Type *Ty, Value *Ptr,
                        const Twine &Name = "") {
    auto *LI = B.CreateLoad(Ty, Ptr, Name);
    LI->setAlignment(Align(1));
    return LI;
}

Value *loadAt(IRBuilder<> &B, Module &M, Type *Ty, Value *Base, Value *Offset,
              const Twine &Name = "") {
    return loadUnaligned(B, Ty, gepI8(B, M, Base, Offset, Name + ".ptr"), Name);
}

Value *loadAt(IRBuilder<> &B, Module &M, Type *Ty, Value *Base,
              unsigned long long Offset, const Twine &Name = "") {
    return loadAt(B, M, Ty, Base,
                  constIp(M, static_cast<std::uint64_t>(Offset)), Name);
}

Value *emitWindowsGsRead(IRBuilder<> &B, Module &M, std::uint32_t Offset,
                         const Twine &Name) {
    auto *IP = M.getDataLayout().getIntPtrType(M.getContext());
    auto *AsmTy = FunctionType::get(IP, false);
    const char *Slot = Offset == 0x30 ? "0x30" : "0x60";
    std::string AsmText = std::string("movq %gs:") + Slot + ", $0";
    InlineAsm *IA =
        InlineAsm::get(AsmTy, AsmText, "=r,~{dirflag},~{fpsr},~{flags}",
                       /*hasSideEffects=*/true);
    return B.CreateCall(AsmTy, IA, {}, Name);
}

Function *windowsPebReader(Module &M) {
    if (Function *Existing = M.getFunction("morok.win.peb"))
        return Existing;
    const Triple TT(M.getTargetTriple());
    if (!TT.isOSWindows() || TT.getArch() != Triple::x86_64)
        return nullptr;

    LLVMContext &Ctx = M.getContext();
    auto *IP = M.getDataLayout().getIntPtrType(Ctx);
    auto *Fn =
        Function::Create(FunctionType::get(IP, false),
                         GlobalValue::PrivateLinkage, "morok.win.peb", &M);
    Fn->addFnAttr(Attribute::NoInline);
    Fn->setDSOLocal(true);
    auto *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    IRBuilder<> B(Entry);
    B.CreateRet(emitWindowsGsRead(B, M, 0x60, "morok.win.peb.gs"));
    return Fn;
}

Function *windowsPeHashName(Module &M, unsigned Family) {
    const std::string FnName = familyName("morok.win.pe.hash", Family);
    if (Function *Existing = M.getFunction(FnName))
        return Existing;

    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *IP = M.getDataLayout().getIntPtrType(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    auto *Fn = Function::Create(FunctionType::get(I64, {Ptr, I64}, false),
                                GlobalValue::PrivateLinkage, FnName, &M);
    Fn->addFnAttr(Attribute::NoInline);
    Fn->setDSOLocal(true);
    Argument *Name = Fn->getArg(0);
    Name->setName("name");
    Argument *SiteSalt = Fn->getArg(1);
    SiteSalt->setName("salt");
    const HashKey HK = hashKeyFor(M, Family);

    auto *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    auto *Loop = BasicBlock::Create(Ctx, "loop", Fn);
    auto *Body = BasicBlock::Create(Ctx, "body", Fn);
    auto *Next = BasicBlock::Create(Ctx, "next", Fn);
    auto *Ret = BasicBlock::Create(Ctx, "ret", Fn);

    IRBuilder<> B(Entry);
    B.CreateBr(Loop);

    IRBuilder<> LB(Loop);
    auto *Idx = LB.CreatePHI(IP, 2, "morok.win.pe.hash.idx");
    auto *Acc = LB.CreatePHI(I64, 2, "morok.win.pe.hash.acc");
    Idx->addIncoming(ConstantInt::get(IP, 0), Entry);
    Acc->addIncoming(ConstantInt::get(I64, HK.offset), Entry);
    LB.CreateCondBr(LB.CreateICmpULT(Idx, ConstantInt::get(IP, 256)), Body,
                    Ret);

    IRBuilder<> BB(Body);
    Value *Ch =
        BB.CreateLoad(I8, gepI8(BB, M, Name, Idx, "morok.win.pe.hash.char.ptr"),
                      "morok.win.pe.hash.char");
    BB.CreateCondBr(BB.CreateICmpNE(Ch, ConstantInt::get(I8, 0)), Next, Ret);

    IRBuilder<> NB(Next);
    Value *Wide = NB.CreateZExt(Ch, I64, "morok.win.pe.hash.wide");
    Value *NextAcc =
        NB.CreateMul(NB.CreateXor(Acc, Wide, "morok.win.pe.hash.xor"),
                     ConstantInt::get(I64, HK.prime), "morok.win.pe.hash.next");
    Value *NextIdx = NB.CreateAdd(Idx, ConstantInt::get(IP, 1),
                                  "morok.win.pe.hash.idx.next");
    NB.CreateBr(Loop);
    Idx->addIncoming(NextIdx, Next);
    Acc->addIncoming(NextAcc, Next);

    IRBuilder<> RB(Ret);
    RB.CreateRet(emitSiteHash(RB, Acc, SiteSalt, "morok.win.pe.hash.site"));
    return Fn;
}

Function *windowsPeExportResolver(Module &M, unsigned Family) {
    const std::string FnName = familyName("morok.win.pe.resolve", Family);
    if (Function *Existing = M.getFunction(FnName))
        return Existing;

    LLVMContext &Ctx = M.getContext();
    auto *I16 = Type::getInt16Ty(Ctx);
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *IP = M.getDataLayout().getIntPtrType(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    auto *Fn = Function::Create(FunctionType::get(IP, {IP, I64, I64}, false),
                                GlobalValue::PrivateLinkage, FnName, &M);
    Fn->addFnAttr(Attribute::NoInline);
    Fn->setDSOLocal(true);
    Argument *Base = Fn->getArg(0);
    Base->setName("base");
    Argument *Wanted = Fn->getArg(1);
    Wanted->setName("wanted");
    Argument *SiteSalt = Fn->getArg(2);
    SiteSalt->setName("salt");

    auto *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    auto *Headers = BasicBlock::Create(Ctx, "headers", Fn);
    auto *Dir = BasicBlock::Create(Ctx, "dir", Fn);
    auto *Loop = BasicBlock::Create(Ctx, "loop", Fn);
    auto *Body = BasicBlock::Create(Ctx, "body", Fn);
    auto *Match = BasicBlock::Create(Ctx, "match", Fn);
    auto *Next = BasicBlock::Create(Ctx, "next", Fn);
    auto *Ret0 = BasicBlock::Create(Ctx, "ret0", Fn);

    IRBuilder<> B(Entry);
    Value *BasePtr = B.CreateIntToPtr(Base, Ptr, "morok.win.pe.base.ptr");
    Value *MZ = loadAt(B, M, I16, BasePtr, 0ULL, "morok.win.pe.mz");
    B.CreateCondBr(
        B.CreateAnd(B.CreateICmpNE(Base, ConstantInt::get(IP, 0)),
                    B.CreateICmpEQ(MZ, ConstantInt::get(I16, 0x5A4D)),
                    "morok.win.pe.has.dos"),
        Headers, Ret0);

    IRBuilder<> HB(Headers);
    Value *Lfanew32 = loadAt(HB, M, I32, BasePtr, 0x3c, "morok.win.pe.lfanew");
    Value *NtPtr = gepI8(HB, M, BasePtr,
                         HB.CreateZExt(Lfanew32, IP, "morok.win.pe.lfanew.ip"),
                         "morok.win.pe.nt");
    Value *Sig = loadAt(HB, M, I32, NtPtr, 0ULL, "morok.win.pe.sig");
    Value *Magic = loadAt(HB, M, I16, NtPtr, 24, "morok.win.pe.opt.magic");
    Value *ExportRva =
        loadAt(HB, M, I32, NtPtr, 24 + 112, "morok.win.pe.export.rva");
    Value *ExportSize =
        loadAt(HB, M, I32, NtPtr, 24 + 116, "morok.win.pe.export.size");
    HB.CreateCondBr(
        HB.CreateAnd(
            HB.CreateICmpEQ(Sig, ConstantInt::get(I32, 0x4550)),
            HB.CreateAnd(
                HB.CreateICmpEQ(Magic, ConstantInt::get(I16, 0x20b)),
                HB.CreateAnd(
                    HB.CreateICmpNE(ExportRva, ConstantInt::get(I32, 0)),
                    HB.CreateICmpNE(ExportSize, ConstantInt::get(I32, 0)),
                    "morok.win.pe.export.nonempty"),
                "morok.win.pe.export.present"),
            "morok.win.pe.headers.ok"),
        Dir, Ret0);

    IRBuilder<> DB(Dir);
    Value *ExportDir = gepI8(DB, M, BasePtr, DB.CreateZExt(ExportRva, IP),
                             "morok.win.pe.export.dir");
    Value *NumberNames =
        loadAt(DB, M, I32, ExportDir, 24, "morok.win.pe.number.names");
    Value *Limit = DB.CreateSelect(
        DB.CreateICmpULT(NumberNames, ConstantInt::get(I32, 4096)), NumberNames,
        ConstantInt::get(I32, 4096), "morok.win.pe.name.limit");
    DB.CreateCondBr(DB.CreateICmpNE(Limit, ConstantInt::get(I32, 0)), Loop,
                    Ret0);

    IRBuilder<> LB(Loop);
    auto *Idx = LB.CreatePHI(I32, 2, "morok.win.pe.name.idx");
    Idx->addIncoming(ConstantInt::get(I32, 0), Dir);
    LB.CreateCondBr(LB.CreateICmpULT(Idx, Limit), Body, Ret0);

    IRBuilder<> BB(Body);
    Value *Funcs = gepI8(BB, M, BasePtr,
                         BB.CreateZExt(loadAt(BB, M, I32, ExportDir, 28,
                                              "morok.win.pe.functions.rva"),
                                       IP),
                         "morok.win.pe.functions");
    Value *Names = gepI8(
        BB, M, BasePtr,
        BB.CreateZExt(
            loadAt(BB, M, I32, ExportDir, 32, "morok.win.pe.names.rva"), IP),
        "morok.win.pe.names");
    Value *Ords = gepI8(
        BB, M, BasePtr,
        BB.CreateZExt(
            loadAt(BB, M, I32, ExportDir, 36, "morok.win.pe.ordinals.rva"), IP),
        "morok.win.pe.ordinals");
    Value *IdxIp = BB.CreateZExt(Idx, IP, "morok.win.pe.name.idx.ip");
    Value *NameRva = loadAt(
        BB, M, I32, Names,
        BB.CreateMul(IdxIp, ConstantInt::get(IP, 4), "morok.win.pe.name.slot"),
        "morok.win.pe.name.rva");
    Value *NamePtr =
        gepI8(BB, M, BasePtr, BB.CreateZExt(NameRva, IP), "morok.win.pe.name");
    Value *Hash = BB.CreateCall(windowsPeHashName(M, Family),
                                {NamePtr, SiteSalt}, "morok.win.pe.name.hash");
    BB.CreateCondBr(BB.CreateICmpEQ(Hash, Wanted, "morok.win.pe.hash.match"),
                    Match, Next);

    IRBuilder<> MB(Match);
    Value *Ord = loadAt(
        MB, M, I16, Ords,
        MB.CreateMul(IdxIp, ConstantInt::get(IP, 2), "morok.win.pe.ord.slot"),
        "morok.win.pe.ordinal");
    Value *FuncRva =
        loadAt(MB, M, I32, Funcs,
               MB.CreateMul(MB.CreateZExt(Ord, IP), ConstantInt::get(IP, 4),
                            "morok.win.pe.func.slot"),
               "morok.win.pe.func.rva");
    Value *ForwarderOff =
        MB.CreateSub(FuncRva, ExportRva, "morok.win.pe.forwarder.off");
    Value *IsForwarder =
        MB.CreateICmpULT(ForwarderOff, ExportSize, "morok.win.pe.forwarder");
    Value *FuncAddr = MB.CreateAdd(Base, MB.CreateZExt(FuncRva, IP),
                                   "morok.win.pe.func.addr");
    MB.CreateRet(MB.CreateSelect(IsForwarder, ConstantInt::get(IP, 0), FuncAddr,
                                 "morok.win.pe.func.safe"));

    IRBuilder<> NB(Next);
    Value *NextIdx =
        NB.CreateAdd(Idx, ConstantInt::get(I32, 1), "morok.win.pe.name.next");
    NB.CreateBr(Loop);
    Idx->addIncoming(NextIdx, Next);

    IRBuilder<> RB(Ret0);
    RB.CreateRet(ConstantInt::get(IP, 0));
    return Fn;
}

Function *windowsHashResolver(Module &M, unsigned Family) {
    const std::string FnName = familyName("morok.fco.resolve.windows", Family);
    if (Function *Existing = M.getFunction(FnName))
        return Existing;
    if (!windowsPebReader(M))
        return nullptr;

    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *IP = M.getDataLayout().getIntPtrType(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    auto *Fn = Function::Create(FunctionType::get(Ptr, {I64, I64}, false),
                                GlobalValue::PrivateLinkage, FnName, &M);
    Fn->addFnAttr(Attribute::NoInline);
    Fn->setDSOLocal(true);
    Argument *Wanted = Fn->getArg(0);
    Wanted->setName("wanted");
    Argument *SiteSalt = Fn->getArg(1);
    SiteSalt->setName("salt");

    auto *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    auto *Loop = BasicBlock::Create(Ctx, "loop", Fn);
    auto *Body = BasicBlock::Create(Ctx, "body", Fn);
    auto *Check = BasicBlock::Create(Ctx, "check", Fn);
    auto *Next = BasicBlock::Create(Ctx, "next", Fn);
    auto *RetDone = BasicBlock::Create(Ctx, "ret.done", Fn);
    auto *RetNull = BasicBlock::Create(Ctx, "ret.null", Fn);

    IRBuilder<> B(Entry);
    Value *Peb = B.CreateCall(windowsPebReader(M), {}, "morok.fco.win.peb");
    Value *PebPtr = B.CreateIntToPtr(Peb, Ptr, "morok.fco.win.peb.ptr");
    Value *Ldr = loadAt(B, M, IP, PebPtr, 0x18, "morok.fco.win.ldr");
    Value *Head =
        B.CreateAdd(Ldr, ConstantInt::get(IP, 0x20), "morok.fco.win.ldr.head");
    Value *HeadPtr = B.CreateIntToPtr(Head, Ptr, "morok.fco.win.head.ptr");
    Value *First = loadAt(B, M, IP, HeadPtr, 0ULL, "morok.fco.win.first");
    Value *CanWalk = B.CreateAnd(
        B.CreateICmpNE(Ldr, ConstantInt::get(IP, 0)),
        B.CreateAnd(B.CreateICmpNE(First, ConstantInt::get(IP, 0)),
                    B.CreateICmpNE(First, Head), "morok.fco.win.first.valid"),
        "morok.fco.win.can.walk");
    B.CreateCondBr(CanWalk, Loop, RetNull);

    IRBuilder<> LB(Loop);
    auto *Cursor = LB.CreatePHI(IP, 2, "morok.fco.win.cursor");
    auto *Idx = LB.CreatePHI(I32, 2, "morok.fco.win.idx");
    auto *Candidate = LB.CreatePHI(IP, 2, "morok.fco.win.candidate");
    auto *Collision =
        LB.CreatePHI(Type::getInt1Ty(Ctx), 2, "morok.fco.win.collision");
    Cursor->addIncoming(First, Entry);
    Idx->addIncoming(ConstantInt::get(I32, 0), Entry);
    Candidate->addIncoming(ConstantInt::get(IP, 0), Entry);
    Collision->addIncoming(ConstantInt::getFalse(Ctx), Entry);
    LB.CreateCondBr(
        LB.CreateAnd(LB.CreateICmpULT(Idx, ConstantInt::get(I32, 64)),
                     LB.CreateICmpNE(Cursor, Head),
                     "morok.fco.win.keep.walking"),
        Body, RetDone);

    IRBuilder<> BB(Body);
    Value *EntryBase = BB.CreateSub(Cursor, ConstantInt::get(IP, 0x10),
                                    "morok.fco.win.entry.base");
    Value *EntryPtr =
        BB.CreateIntToPtr(EntryBase, Ptr, "morok.fco.win.entry.ptr");
    Value *DllBase =
        loadAt(BB, M, IP, EntryPtr, 0x30, "morok.fco.win.dll.base");
    BB.CreateCondBr(BB.CreateICmpNE(DllBase, ConstantInt::get(IP, 0)), Check,
                    Next);

    IRBuilder<> CB(Check);
    Value *ResolvedValue = CB.CreateCall(windowsPeExportResolver(M, Family),
                                         {DllBase, Wanted, SiteSalt},
                                         "morok.fco.win.resolved.int");
    CB.CreateBr(Next);

    IRBuilder<> NB(Next);
    auto *Resolved = NB.CreatePHI(IP, 2, "morok.fco.win.resolved.phi");
    Resolved->addIncoming(ConstantInt::get(IP, 0), Body);
    Resolved->addIncoming(ResolvedValue, Check);
    Value *HasResolved = NB.CreateICmpNE(Resolved, ConstantInt::get(IP, 0),
                                         "morok.fco.win.resolved.any");
    Value *HasCandidate = NB.CreateICmpNE(Candidate, ConstantInt::get(IP, 0),
                                          "morok.fco.win.candidate.any");
    Value *SameCandidate =
        NB.CreateICmpEQ(Resolved, Candidate, "morok.fco.win.candidate.same");
    Value *FirstMatch = NB.CreateAnd(HasResolved, NB.CreateNot(HasCandidate),
                                     "morok.fco.win.candidate.first");
    Value *CollisionHit = NB.CreateAnd(
        HasResolved, NB.CreateAnd(HasCandidate, NB.CreateNot(SameCandidate)),
        "morok.fco.win.collision.hit");
    Value *NextCandidate = NB.CreateSelect(FirstMatch, Resolved, Candidate,
                                           "morok.fco.win.candidate.next");
    Value *NextCollision =
        NB.CreateOr(Collision, CollisionHit, "morok.fco.win.collision.next");
    Value *CursorPtr =
        NB.CreateIntToPtr(Cursor, Ptr, "morok.fco.win.cursor.ptr");
    Value *NextCursor =
        loadAt(NB, M, IP, CursorPtr, 0ULL, "morok.fco.win.next.cursor");
    Value *NextIdx =
        NB.CreateAdd(Idx, ConstantInt::get(I32, 1), "morok.fco.win.next.idx");
    NB.CreateBr(Loop);
    Cursor->addIncoming(NextCursor, Next);
    Idx->addIncoming(NextIdx, Next);
    Candidate->addIncoming(NextCandidate, Next);
    Collision->addIncoming(NextCollision, Next);

    IRBuilder<> DB(RetDone);
    Value *Unique = DB.CreateSelect(Collision, ConstantInt::get(IP, 0),
                                    Candidate, "morok.fco.win.unique");
    DB.CreateRet(DB.CreateIntToPtr(Unique, Ptr, "morok.fco.win.resolved"));

    IRBuilder<> RB(RetNull);
    RB.CreateRet(ConstantPointerNull::get(Ptr));
    return Fn;
}

Value *normalizeElfAddress(IRBuilder<> &B, Module &M, Value *Base, Value *Addr,
                           const Twine &Name) {
    auto *IP = M.getDataLayout().getIntPtrType(M.getContext());
    Value *NeedsBias =
        B.CreateAnd(B.CreateICmpNE(Addr, ConstantInt::get(IP, 0)),
                    B.CreateAnd(B.CreateICmpNE(Base, ConstantInt::get(IP, 0)),
                                B.CreateICmpULT(Addr, Base)));
    return B.CreateSelect(NeedsBias, B.CreateAdd(Base, Addr), Addr, Name);
}

Value *runtimeBaseHashName(IRBuilder<> &B, Module &M, Function *Fn, Value *Name,
                           unsigned Family) {
    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    const HashKey HK = hashKeyFor(M, Family);

    BasicBlock *Entry = B.GetInsertBlock();
    BasicBlock *Loop = BasicBlock::Create(Ctx, "morok.fco.ex.hash.loop", Fn);
    BasicBlock *Body = BasicBlock::Create(Ctx, "morok.fco.ex.hash.body", Fn);
    BasicBlock *Done = BasicBlock::Create(Ctx, "morok.fco.ex.hash.done", Fn);
    B.CreateBr(Loop);

    IRBuilder<> LB(Loop);
    auto *Idx = LB.CreatePHI(I64, 2, "morok.fco.ex.hash.idx");
    auto *Acc = LB.CreatePHI(I64, 2, "morok.fco.ex.hash.acc");
    Idx->addIncoming(ConstantInt::get(I64, 0), Entry);
    Acc->addIncoming(ConstantInt::get(I64, HK.offset), Entry);
    Value *CharPtr =
        LB.CreateInBoundsGEP(I8, Name, Idx, "morok.fco.ex.hash.ptr");
    Value *Ch = LB.CreateLoad(I8, CharPtr, "morok.fco.ex.hash.byte");
    Value *IsNul =
        LB.CreateICmpEQ(Ch, ConstantInt::get(I8, 0), "morok.fco.ex.hash.nul");
    LB.CreateCondBr(IsNul, Done, Body);

    IRBuilder<> HB(Body);
    Value *Wide = HB.CreateZExt(Ch, I64, "morok.fco.ex.hash.zext");
    Value *Next =
        HB.CreateMul(HB.CreateXor(Acc, Wide, "morok.fco.ex.hash.xor"),
                     ConstantInt::get(I64, HK.prime), "morok.fco.ex.hash.next");
    Value *NextIdx =
        HB.CreateAdd(Idx, ConstantInt::get(I64, 1), "morok.fco.ex.hash.idx2");
    HB.CreateBr(Loop);
    Idx->addIncoming(NextIdx, Body);
    Acc->addIncoming(Next, Body);

    B.SetInsertPoint(Done);
    // Mirror baseHashName()'s zero-guard exactly (its `H ? H : HK.prime` tail):
    // an FNV accumulator that lands on 0 must map to HK.prime at runtime too,
    // otherwise the runtime hash diverges from the pass-time hashName() and the
    // symbol is never matched (resolution returns null -> SIGSEGV hang).
    return B.CreateSelect(
        B.CreateICmpEQ(Acc, ConstantInt::get(I64, 0), "morok.fco.ex.hash.isz"),
        ConstantInt::get(I64, HK.prime), Acc, "morok.fco.ex.hash.nz");
}

Value *runtimeHashName(IRBuilder<> &B, Module &M, Function *Fn, Value *Name) {
    return runtimeBaseHashName(B, M, Fn, Name, 0);
}

Value *runtimeSiteHashName(IRBuilder<> &B, Module &M, Function *Fn, Value *Name,
                           unsigned Family, Value *SiteSalt,
                           const Twine &NamePrefix) {
    return emitSiteHash(B, runtimeBaseHashName(B, M, Fn, Name, Family),
                        SiteSalt, NamePrefix);
}

Function *elfModuleHashResolver(Module &M, unsigned Family) {
    const std::string FnName =
        familyName("morok.fco.resolve.elf.module", Family);
    if (auto *Existing = M.getFunction(FnName))
        return Existing;

    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I16 = Type::getInt16Ty(Ctx);
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *IP = M.getDataLayout().getIntPtrType(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);

    auto *FnTy = FunctionType::get(Ptr, {I64, I64, IP, Ptr}, false);
    auto *Fn = Function::Create(FnTy, GlobalValue::PrivateLinkage, FnName, M);
    Fn->addFnAttr(Attribute::NoInline);
    Fn->setDSOLocal(true);
    auto *Wanted = Fn->getArg(0);
    Wanted->setName("wanted");
    auto *SiteSalt = Fn->getArg(1);
    SiteSalt->setName("salt");
    auto *Base = Fn->getArg(2);
    Base->setName("base");
    auto *Dyn = Fn->getArg(3);
    Dyn->setName("dynamic");

    auto *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    auto *DynLoop = BasicBlock::Create(Ctx, "dyn.loop", Fn);
    auto *DynBody = BasicBlock::Create(Ctx, "dyn.body", Fn);
    auto *DynNext = BasicBlock::Create(Ctx, "dyn.next", Fn);
    auto *CountPrep = BasicBlock::Create(Ctx, "count.prep", Fn);
    auto *HashCount = BasicBlock::Create(Ctx, "count.hash", Fn);
    auto *LayoutCount = BasicBlock::Create(Ctx, "count.layout", Fn);
    auto *ScanPrep = BasicBlock::Create(Ctx, "scan.prep", Fn);
    auto *SymLoop = BasicBlock::Create(Ctx, "sym.loop", Fn);
    auto *SymBody = BasicBlock::Create(Ctx, "sym.body", Fn);
    auto *SymCheck = BasicBlock::Create(Ctx, "sym.check", Fn);
    auto *SymNext = BasicBlock::Create(Ctx, "sym.next", Fn);
    auto *RetFound = BasicBlock::Create(Ctx, "ret.found", Fn);
    auto *RetIfunc = BasicBlock::Create(Ctx, "ret.ifunc", Fn);
    auto *RetDirect = BasicBlock::Create(Ctx, "ret.direct", Fn);
    auto *RetNull = BasicBlock::Create(Ctx, "ret.null", Fn);

    IRBuilder<> B(Entry);
    AllocaInst *SymtabRaw =
        B.CreateAlloca(IP, nullptr, "morok.fco.elf.symtab.raw");
    AllocaInst *StrtabRaw =
        B.CreateAlloca(IP, nullptr, "morok.fco.elf.strtab.raw");
    AllocaInst *StrszSlot = B.CreateAlloca(IP, nullptr, "morok.fco.elf.strsz");
    AllocaInst *SymentSlot =
        B.CreateAlloca(IP, nullptr, "morok.fco.elf.syment");
    AllocaInst *HashRaw = B.CreateAlloca(IP, nullptr, "morok.fco.elf.hash.raw");
    AllocaInst *SymtabSlot =
        B.CreateAlloca(IP, nullptr, "morok.fco.elf.symtab");
    AllocaInst *StrtabSlot =
        B.CreateAlloca(IP, nullptr, "morok.fco.elf.strtab");
    AllocaInst *CountSlot = B.CreateAlloca(IP, nullptr, "morok.fco.elf.count");
    for (AllocaInst *Slot : {SymtabRaw, StrtabRaw, StrszSlot, SymentSlot,
                             HashRaw, SymtabSlot, StrtabSlot, CountSlot})
        B.CreateStore(ConstantInt::get(IP, 0), Slot);
    B.CreateCondBr(B.CreateICmpNE(Dyn, ConstantPointerNull::get(Ptr)), DynLoop,
                   RetNull);

    IRBuilder<> DLB(DynLoop);
    auto *DynIdx = DLB.CreatePHI(IP, 2, "morok.fco.elf.dyn.idx");
    DynIdx->addIncoming(ConstantInt::get(IP, 0), Entry);
    DLB.CreateCondBr(DLB.CreateICmpULT(DynIdx, ConstantInt::get(IP, 512)),
                     DynBody, CountPrep);

    IRBuilder<> DB(DynBody);
    Value *DynEnt =
        gepI8(DB, M, Dyn, DB.CreateMul(DynIdx, ConstantInt::get(IP, 16)),
              "morok.fco.elf.dyn.ent");
    Value *Tag = loadAt(DB, M, I64, DynEnt, 0ULL, "morok.fco.elf.dyn.tag");
    Value *Val = loadAt(DB, M, IP, DynEnt, 8, "morok.fco.elf.dyn.val");
    auto storeTag = [&](AllocaInst *Slot, std::uint64_t Want) {
        Value *Old = DB.CreateLoad(IP, Slot);
        DB.CreateStore(
            DB.CreateSelect(DB.CreateICmpEQ(Tag, ConstantInt::get(I64, Want)),
                            Val, Old),
            Slot);
    };
    storeTag(HashRaw, 4);     // DT_HASH
    storeTag(StrtabRaw, 5);   // DT_STRTAB
    storeTag(SymtabRaw, 6);   // DT_SYMTAB
    storeTag(StrszSlot, 10);  // DT_STRSZ
    storeTag(SymentSlot, 11); // DT_SYMENT
    DB.CreateCondBr(DB.CreateICmpEQ(Tag, ConstantInt::get(I64, 0)), CountPrep,
                    DynNext);

    IRBuilder<> DNB(DynNext);
    Value *DynNextIdx = DNB.CreateAdd(DynIdx, ConstantInt::get(IP, 1),
                                      "morok.fco.elf.dyn.next");
    DNB.CreateBr(DynLoop);
    DynIdx->addIncoming(DynNextIdx, DynNext);

    IRBuilder<> CPB(CountPrep);
    Value *HashAddr = normalizeElfAddress(
        CPB, M, Base, CPB.CreateLoad(IP, HashRaw), "morok.fco.elf.hash.addr");
    CPB.CreateCondBr(CPB.CreateICmpNE(HashAddr, ConstantInt::get(IP, 0)),
                     HashCount, LayoutCount);

    IRBuilder<> HCB(HashCount);
    Value *HashPtr =
        HCB.CreateIntToPtr(HashAddr, Ptr, "morok.fco.elf.hash.ptr");
    Value *NChain32 =
        loadAt(HCB, M, I32, HashPtr, 4, "morok.fco.elf.hash.nchain");
    HCB.CreateStore(HCB.CreateZExt(NChain32, IP), CountSlot);
    HCB.CreateBr(ScanPrep);

    IRBuilder<> LCB(LayoutCount);
    Value *SymtabAddr =
        normalizeElfAddress(LCB, M, Base, LCB.CreateLoad(IP, SymtabRaw),
                            "morok.fco.elf.symtab.addr");
    Value *StrtabAddr =
        normalizeElfAddress(LCB, M, Base, LCB.CreateLoad(IP, StrtabRaw),
                            "morok.fco.elf.strtab.addr");
    Value *Syment = LCB.CreateLoad(IP, SymentSlot, "morok.fco.elf.syment.v");
    Value *Gap = LCB.CreateSub(StrtabAddr, SymtabAddr, "morok.fco.elf.sym.gap");
    Value *LayoutOk = LCB.CreateAnd(
        LCB.CreateICmpUGT(StrtabAddr, SymtabAddr),
        LCB.CreateAnd(LCB.CreateICmpUGT(Syment, ConstantInt::get(IP, 0)),
                      LCB.CreateICmpULT(Gap, ConstantInt::get(IP, 1 << 20))));
    Value *LayoutCountV = LCB.CreateUDiv(
        Gap,
        LCB.CreateSelect(LCB.CreateICmpNE(Syment, ConstantInt::get(IP, 0)),
                         Syment, ConstantInt::get(IP, 24)),
        "morok.fco.elf.layout.count");
    LCB.CreateStore(
        LCB.CreateSelect(LayoutOk, LayoutCountV, ConstantInt::get(IP, 4096)),
        CountSlot);
    LCB.CreateBr(ScanPrep);

    IRBuilder<> SPB(ScanPrep);
    Value *FinalSymtab =
        normalizeElfAddress(SPB, M, Base, SPB.CreateLoad(IP, SymtabRaw),
                            "morok.fco.elf.symtab.final");
    Value *FinalStrtab =
        normalizeElfAddress(SPB, M, Base, SPB.CreateLoad(IP, StrtabRaw),
                            "morok.fco.elf.strtab.final");
    Value *FinalSyment =
        SPB.CreateLoad(IP, SymentSlot, "morok.fco.elf.syment.final");
    Value *FinalCount =
        SPB.CreateLoad(IP, CountSlot, "morok.fco.elf.count.final");
    SPB.CreateStore(FinalSymtab, SymtabSlot);
    SPB.CreateStore(FinalStrtab, StrtabSlot);
    Value *CanScan = SPB.CreateAnd(
        SPB.CreateICmpNE(FinalSymtab, ConstantInt::get(IP, 0)),
        SPB.CreateAnd(
            SPB.CreateICmpNE(FinalStrtab, ConstantInt::get(IP, 0)),
            SPB.CreateAnd(
                SPB.CreateICmpUGT(FinalSyment, ConstantInt::get(IP, 0)),
                SPB.CreateICmpUGT(FinalCount, ConstantInt::get(IP, 0)))));
    SPB.CreateCondBr(CanScan, SymLoop, RetNull);

    IRBuilder<> SLB(SymLoop);
    auto *SymIdx = SLB.CreatePHI(IP, 2, "morok.fco.elf.sym.idx");
    SymIdx->addIncoming(ConstantInt::get(IP, 0), ScanPrep);
    Value *Bound = SLB.CreateSelect(
        SLB.CreateICmpULT(FinalCount, ConstantInt::get(IP, 65536)), FinalCount,
        ConstantInt::get(IP, 65536));
    SLB.CreateCondBr(SLB.CreateICmpULT(SymIdx, Bound), SymBody, RetNull);

    IRBuilder<> SBB(SymBody);
    Value *SymBase =
        SBB.CreateLoad(IP, SymtabSlot, "morok.fco.elf.symtab.load");
    Value *StrBase =
        SBB.CreateLoad(IP, StrtabSlot, "morok.fco.elf.strtab.load");
    Value *SymEntSize =
        SBB.CreateLoad(IP, SymentSlot, "morok.fco.elf.syment.load");
    Value *SymPtr = SBB.CreateIntToPtr(
        SBB.CreateAdd(SymBase, SBB.CreateMul(SymIdx, SymEntSize)), Ptr,
        "morok.fco.elf.sym.ptr");
    Value *NameOff32 =
        loadAt(SBB, M, I32, SymPtr, 0ULL, "morok.fco.elf.st.name");
    Value *Info = loadAt(SBB, M, I8, SymPtr, 4, "morok.fco.elf.st.info");
    Value *Shndx = loadAt(SBB, M, I16, SymPtr, 6, "morok.fco.elf.st.shndx");
    Value *SymValue = loadAt(SBB, M, IP, SymPtr, 8, "morok.fco.elf.st.value");
    Value *NameOff = SBB.CreateZExt(NameOff32, IP, "morok.fco.elf.name.off");
    Value *Strsz = SBB.CreateLoad(IP, StrszSlot, "morok.fco.elf.strsz.load");
    Value *Type = SBB.CreateAnd(Info, ConstantInt::get(I8, 0x0f),
                                "morok.fco.elf.st.type");
    Value *TypeOk = SBB.CreateOr(
        SBB.CreateICmpEQ(Type, ConstantInt::get(I8, 2)),
        SBB.CreateOr(SBB.CreateICmpEQ(Type, ConstantInt::get(I8, 0)),
                     SBB.CreateICmpEQ(Type, ConstantInt::get(I8, 10))));
    Value *ValidSym = SBB.CreateAnd(
        SBB.CreateICmpULT(NameOff, Strsz),
        SBB.CreateAnd(
            SBB.CreateICmpNE(Shndx, ConstantInt::get(I16, 0)),
            SBB.CreateAnd(SBB.CreateICmpNE(SymValue, ConstantInt::get(IP, 0)),
                          TypeOk)));
    Value *NamePtr = SBB.CreateIntToPtr(SBB.CreateAdd(StrBase, NameOff), Ptr,
                                        "morok.fco.elf.name.ptr");
    Value *TargetAddr =
        SBB.CreateAdd(Base, SymValue, "morok.fco.elf.target.addr");
    SBB.CreateCondBr(ValidSym, SymCheck, SymNext);

    IRBuilder<> SCB(SymCheck);
    Value *Computed = runtimeSiteHashName(SCB, M, Fn, NamePtr, Family, SiteSalt,
                                          "morok.fco.elf.hash.site");
    SCB.CreateCondBr(
        SCB.CreateICmpEQ(Computed, Wanted, "morok.fco.elf.hash.match"),
        RetFound, SymNext);

    IRBuilder<> SNB(SymNext);
    Value *SymNextIdx = SNB.CreateAdd(SymIdx, ConstantInt::get(IP, 1),
                                      "morok.fco.elf.sym.next");
    SNB.CreateBr(SymLoop);
    SymIdx->addIncoming(SymNextIdx, SymNext);

    IRBuilder<> RFB(RetFound);
    RFB.CreateCondBr(
        RFB.CreateICmpEQ(Type, ConstantInt::get(I8, 10), "morok.fco.elf.ifunc"),
        RetIfunc, RetDirect);

    IRBuilder<> RIB(RetIfunc);
    auto *IfuncTy = FunctionType::get(Ptr, false);
    Value *IfuncResolver =
        RIB.CreateIntToPtr(TargetAddr, Ptr, "morok.fco.elf.ifunc.resolver");
    RIB.CreateRet(RIB.CreateCall(IfuncTy, IfuncResolver, {},
                                 "morok.fco.elf.ifunc.target"));

    IRBuilder<> RDB(RetDirect);
    RDB.CreateRet(RDB.CreateIntToPtr(TargetAddr, Ptr, "morok.fco.elf.target"));

    IRBuilder<> RNB(RetNull);
    RNB.CreateRet(ConstantPointerNull::get(Ptr));
    return Fn;
}

Function *elfDlIterateCallback(Module &M, unsigned Family) {
    const std::string FnName =
        familyName("morok.fco.resolve.elf.iter.cb", Family);
    if (auto *Existing = M.getFunction(FnName))
        return Existing;

    LLVMContext &Ctx = M.getContext();
    auto *I16 = Type::getInt16Ty(Ctx);
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *IP = M.getDataLayout().getIntPtrType(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    Function *ScanModule = elfModuleHashResolver(M, Family);

    auto *FnTy = FunctionType::get(I32, {Ptr, IP, Ptr}, false);
    auto *Fn = Function::Create(FnTy, GlobalValue::PrivateLinkage, FnName, M);
    Fn->addFnAttr(Attribute::NoInline);
    Fn->setDSOLocal(true);
    auto *Info = Fn->getArg(0);
    Info->setName("info");
    auto *Data = Fn->getArg(2);
    Data->setName("data");

    auto *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    auto *PhLoop = BasicBlock::Create(Ctx, "ph.loop", Fn);
    auto *PhBody = BasicBlock::Create(Ctx, "ph.body", Fn);
    auto *FoundDyn = BasicBlock::Create(Ctx, "found.dynamic", Fn);
    auto *PhNext = BasicBlock::Create(Ctx, "ph.next", Fn);
    auto *RetStop = BasicBlock::Create(Ctx, "ret.stop", Fn);
    auto *RetContinue = BasicBlock::Create(Ctx, "ret.continue", Fn);

    IRBuilder<> B(Entry);
    Value *Wanted = loadAt(B, M, I64, Data, 0ULL, "morok.fco.iter.wanted");
    Value *SiteSalt = loadAt(B, M, I64, Data, 16ULL, "morok.fco.iter.salt");
    Value *Base = loadAt(B, M, IP, Info, 0ULL, "morok.fco.iter.base");
    Value *Phdr = B.CreateLoad(
        Ptr,
        gepI8(B, M, Info, ConstantInt::get(IP, 16), "morok.fco.iter.phdr.ptr"),
        "morok.fco.iter.phdr");
    Value *PhNum16 = loadAt(B, M, I16, Info, 24, "morok.fco.iter.phnum");
    Value *PhNum = B.CreateZExt(PhNum16, IP, "morok.fco.iter.phnum.w");
    B.CreateCondBr(
        B.CreateAnd(B.CreateICmpNE(Phdr, ConstantPointerNull::get(Ptr)),
                    B.CreateICmpUGT(PhNum, ConstantInt::get(IP, 0))),
        PhLoop, RetContinue);

    IRBuilder<> PLB(PhLoop);
    auto *PhIdx = PLB.CreatePHI(IP, 2, "morok.fco.iter.ph.idx");
    PhIdx->addIncoming(ConstantInt::get(IP, 0), Entry);
    Value *PhActive =
        PLB.CreateAnd(PLB.CreateICmpULT(PhIdx, PhNum),
                      PLB.CreateICmpULT(PhIdx, ConstantInt::get(IP, 128)));
    PLB.CreateCondBr(PhActive, PhBody, RetContinue);

    IRBuilder<> PBB(PhBody);
    Value *PhPtr =
        gepI8(PBB, M, Phdr, PBB.CreateMul(PhIdx, ConstantInt::get(IP, 56)),
              "morok.fco.iter.ph.ptr");
    Value *PType = loadAt(PBB, M, I32, PhPtr, 0ULL, "morok.fco.iter.ph.type");
    Value *PVaddr = loadAt(PBB, M, IP, PhPtr, 16, "morok.fco.iter.ph.vaddr");
    PBB.CreateCondBr(PBB.CreateICmpEQ(PType, ConstantInt::get(I32, 2)),
                     FoundDyn, PhNext);

    IRBuilder<> FDB(FoundDyn);
    Value *DynPtr = FDB.CreateIntToPtr(FDB.CreateAdd(Base, PVaddr), Ptr,
                                       "morok.fco.iter.dynamic");
    Value *Resolved =
        FDB.CreateCall(ScanModule, {Wanted, SiteSalt, Base, DynPtr},
                       "morok.fco.iter.resolved");
    Value *Found = FDB.CreateICmpNE(Resolved, ConstantPointerNull::get(Ptr));
    Value *FoundAsInt =
        FDB.CreatePtrToInt(Resolved, I64, "morok.fco.iter.resolved.int");
    FDB.CreateStore(FoundAsInt, gepI8(FDB, M, Data, ConstantInt::get(IP, 8),
                                      "morok.fco.iter.found.slot"));
    FDB.CreateCondBr(Found, RetStop, RetContinue);

    IRBuilder<> PNB(PhNext);
    Value *PhNextIdx =
        PNB.CreateAdd(PhIdx, ConstantInt::get(IP, 1), "morok.fco.iter.ph.next");
    PNB.CreateBr(PhLoop);
    PhIdx->addIncoming(PhNextIdx, PhNext);

    IRBuilder<> RSB(RetStop);
    RSB.CreateRet(ConstantInt::get(I32, 1));

    IRBuilder<> RCB(RetContinue);
    RCB.CreateRet(ConstantInt::get(I32, 0));
    return Fn;
}

Function *linuxHashResolver(Module &M, unsigned Family) {
    const std::string FnName = familyName("morok.fco.resolve.elf", Family);
    if (auto *Existing = M.getFunction(FnName))
        return Existing;

    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *IP = M.getDataLayout().getIntPtrType(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    Function *ScanModule = elfModuleHashResolver(M, Family);
    Function *IterCallback = elfDlIterateCallback(M, Family);

    auto *Fn = Function::Create(FunctionType::get(Ptr, {I64, I64}, false),
                                GlobalValue::PrivateLinkage, FnName, M);
    Fn->addFnAttr(Attribute::NoInline);
    Fn->setDSOLocal(true);
    auto *Wanted = Fn->getArg(0);
    Wanted->setName("wanted");
    auto *SiteSalt = Fn->getArg(1);
    SiteSalt->setName("salt");

    auto *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    auto *PhLoop = BasicBlock::Create(Ctx, "ph.loop", Fn);
    auto *PhBody = BasicBlock::Create(Ctx, "ph.body", Fn);
    auto *PhNext = BasicBlock::Create(Ctx, "ph.next", Fn);
    auto *MainScan = BasicBlock::Create(Ctx, "main.scan", Fn);
    auto *DynLoop = BasicBlock::Create(Ctx, "dyn.loop", Fn);
    auto *DynBody = BasicBlock::Create(Ctx, "dyn.body", Fn);
    auto *DynNext = BasicBlock::Create(Ctx, "dyn.next", Fn);
    auto *MapFirst = BasicBlock::Create(Ctx, "map.first", Fn);
    auto *MapLoad = BasicBlock::Create(Ctx, "map.load", Fn);
    auto *MapLoop = BasicBlock::Create(Ctx, "map.loop", Fn);
    auto *MapBody = BasicBlock::Create(Ctx, "map.body", Fn);
    auto *MapNext = BasicBlock::Create(Ctx, "map.next", Fn);
    auto *AtBasePrep = BasicBlock::Create(Ctx, "atbase.prep", Fn);
    auto *AtBaseLoad = BasicBlock::Create(Ctx, "atbase.load", Fn);
    auto *AtBasePhLoop = BasicBlock::Create(Ctx, "atbase.ph.loop", Fn);
    auto *AtBasePhBody = BasicBlock::Create(Ctx, "atbase.ph.body", Fn);
    auto *AtBasePhNext = BasicBlock::Create(Ctx, "atbase.ph.next", Fn);
    auto *AtBaseScan = BasicBlock::Create(Ctx, "atbase.scan", Fn);
    auto *RetFound = BasicBlock::Create(Ctx, "ret.found", Fn);
    auto *RetNull = BasicBlock::Create(Ctx, "ret.null", Fn);

    IRBuilder<> B(Entry);
    AllocaInst *BaseSlot = B.CreateAlloca(IP, nullptr, "morok.fco.elf.base");
    AllocaInst *DynVaddrSlot =
        B.CreateAlloca(IP, nullptr, "morok.fco.elf.dynamic.vaddr");
    AllocaInst *DebugSlot = B.CreateAlloca(IP, nullptr, "morok.fco.elf.debug");
    AllocaInst *AtBaseSlot =
        B.CreateAlloca(IP, nullptr, "morok.fco.elf.atbase");
    AllocaInst *AtBaseDynSlot =
        B.CreateAlloca(IP, nullptr, "morok.fco.elf.atbase.dynamic");
    AllocaInst *FoundSlot = B.CreateAlloca(Ptr, nullptr, "morok.fco.elf.found");
    auto *IterCtxTy = ArrayType::get(I64, 3);
    AllocaInst *IterCtx =
        B.CreateAlloca(IterCtxTy, nullptr, "morok.fco.elf.iter.ctx");
    B.CreateStore(ConstantInt::get(IP, 0), BaseSlot);
    B.CreateStore(ConstantInt::get(IP, 0), DynVaddrSlot);
    B.CreateStore(ConstantInt::get(IP, 0), DebugSlot);
    B.CreateStore(ConstantInt::get(IP, 0), AtBaseSlot);
    B.CreateStore(ConstantInt::get(IP, 0), AtBaseDynSlot);
    B.CreateStore(ConstantPointerNull::get(Ptr), FoundSlot);
    B.CreateStore(
        Wanted,
        B.CreateInBoundsGEP(IterCtxTy, IterCtx,
                            {ConstantInt::get(IP, 0), ConstantInt::get(IP, 0)},
                            "morok.fco.elf.iter.wanted.slot"));
    B.CreateStore(
        ConstantInt::get(I64, 0),
        B.CreateInBoundsGEP(IterCtxTy, IterCtx,
                            {ConstantInt::get(IP, 0), ConstantInt::get(IP, 1)},
                            "morok.fco.elf.iter.found.slot"));
    B.CreateStore(
        SiteSalt,
        B.CreateInBoundsGEP(IterCtxTy, IterCtx,
                            {ConstantInt::get(IP, 0), ConstantInt::get(IP, 2)},
                            "morok.fco.elf.iter.salt.slot"));

    Value *AtPhdr = B.CreateCall(getauxvalDecl(M), {ConstantInt::get(IP, 3)},
                                 "morok.fco.elf.atphdr");
    Value *PhEnt = B.CreateCall(getauxvalDecl(M), {ConstantInt::get(IP, 4)},
                                "morok.fco.elf.phent");
    Value *PhNum = B.CreateCall(getauxvalDecl(M), {ConstantInt::get(IP, 5)},
                                "morok.fco.elf.phnum");
    Value *ValidPhdr = B.CreateAnd(
        validAuxvPhdrPointer(B, M, AtPhdr, "morok.fco.elf.phdr.ptr"),
        B.CreateAnd(B.CreateICmpUGE(PhEnt, ConstantInt::get(IP, 56)),
                    B.CreateICmpUGT(PhNum, ConstantInt::get(IP, 0))));
    B.CreateCondBr(ValidPhdr, PhLoop, RetNull);

    IRBuilder<> PLB(PhLoop);
    auto *PhIdx = PLB.CreatePHI(IP, 2, "morok.fco.elf.ph.idx");
    PhIdx->addIncoming(ConstantInt::get(IP, 0), Entry);
    Value *PhInRange =
        PLB.CreateAnd(PLB.CreateICmpULT(PhIdx, PhNum),
                      PLB.CreateICmpULT(PhIdx, ConstantInt::get(IP, 128)));
    PLB.CreateCondBr(PhInRange, PhBody, MainScan);

    IRBuilder<> PBB(PhBody);
    Value *PhPtr =
        PBB.CreateIntToPtr(PBB.CreateAdd(AtPhdr, PBB.CreateMul(PhIdx, PhEnt)),
                           Ptr, "morok.fco.elf.ph.ptr");
    Value *PType = loadAt(PBB, M, I32, PhPtr, 0ULL, "morok.fco.elf.ph.type");
    Value *POffset = loadAt(PBB, M, IP, PhPtr, 8, "morok.fco.elf.ph.offset");
    Value *PVaddr = loadAt(PBB, M, IP, PhPtr, 16, "morok.fco.elf.ph.vaddr");
    Value *OldBase = PBB.CreateLoad(IP, BaseSlot, "morok.fco.elf.base.old");
    Value *PageMask = ConstantInt::get(IP, ~static_cast<std::uint64_t>(0xfff));
    Value *LoadBase = PBB.CreateSub(PBB.CreateAnd(AtPhdr, PageMask),
                                    PBB.CreateAnd(PVaddr, PageMask),
                                    "morok.fco.elf.load.base");
    Value *LoadBaseOk = PBB.CreateAnd(
        PBB.CreateICmpEQ(PType, ConstantInt::get(I32, 1)),
        PBB.CreateAnd(PBB.CreateICmpEQ(POffset, ConstantInt::get(IP, 0)),
                      PBB.CreateICmpEQ(OldBase, ConstantInt::get(IP, 0))));
    Value *MaybeLoadBase = PBB.CreateSelect(LoadBaseOk, LoadBase, OldBase,
                                            "morok.fco.elf.base.load");
    Value *NewBase = PBB.CreateSelect(
        PBB.CreateICmpEQ(PType, ConstantInt::get(I32, 6)),
        PBB.CreateSub(AtPhdr, PVaddr), MaybeLoadBase, "morok.fco.elf.base.new");
    PBB.CreateStore(NewBase, BaseSlot);
    Value *OldDyn =
        PBB.CreateLoad(IP, DynVaddrSlot, "morok.fco.elf.dynamic.old");
    Value *NewDyn =
        PBB.CreateSelect(PBB.CreateICmpEQ(PType, ConstantInt::get(I32, 2)),
                         PVaddr, OldDyn, "morok.fco.elf.dynamic.new");
    PBB.CreateStore(NewDyn, DynVaddrSlot);
    PBB.CreateBr(PhNext);

    IRBuilder<> PNB(PhNext);
    Value *PhNextIdx =
        PNB.CreateAdd(PhIdx, ConstantInt::get(IP, 1), "morok.fco.elf.ph.next");
    PNB.CreateBr(PhLoop);
    PhIdx->addIncoming(PhNextIdx, PhNext);

    IRBuilder<> MSB(MainScan);
    Value *MainBase = MSB.CreateLoad(IP, BaseSlot, "morok.fco.elf.main.base");
    Value *MainDynVaddr =
        MSB.CreateLoad(IP, DynVaddrSlot, "morok.fco.elf.main.dynamic.vaddr");
    Value *MainDynAddr = MSB.CreateAdd(MainBase, MainDynVaddr,
                                       "morok.fco.elf.main.dynamic.addr");
    Value *MainDynOk = MSB.CreateICmpNE(MainDynVaddr, ConstantInt::get(IP, 0));
    Value *MainDynPtrRaw =
        MSB.CreateIntToPtr(MainDynAddr, Ptr, "morok.fco.elf.main.dynamic.ptr");
    Value *MainDynPtr = MSB.CreateSelect(MainDynOk, MainDynPtrRaw,
                                         ConstantPointerNull::get(Ptr),
                                         "morok.fco.elf.main.dynamic.sel");
    Value *MainResolved =
        MSB.CreateCall(ScanModule, {Wanted, SiteSalt, MainBase, MainDynPtr},
                       "morok.fco.elf.main.resolved");
    MSB.CreateStore(MainResolved, FoundSlot);
    MSB.CreateCondBr(
        MSB.CreateAnd(
            MainDynOk,
            MSB.CreateICmpNE(MainResolved, ConstantPointerNull::get(Ptr))),
        RetFound, DynLoop);

    IRBuilder<> DLB(DynLoop);
    auto *DynIdx = DLB.CreatePHI(IP, 2, "morok.fco.elf.main.dyn.idx");
    DynIdx->addIncoming(ConstantInt::get(IP, 0), MainScan);
    Value *Base = DLB.CreateLoad(IP, BaseSlot, "morok.fco.elf.base.final");
    Value *DynVaddr =
        DLB.CreateLoad(IP, DynVaddrSlot, "morok.fco.elf.dynamic.final");
    Value *DynAddr =
        DLB.CreateAdd(Base, DynVaddr, "morok.fco.elf.dynamic.addr");
    Value *DynActive =
        DLB.CreateAnd(DLB.CreateICmpNE(DynVaddr, ConstantInt::get(IP, 0)),
                      DLB.CreateICmpULT(DynIdx, ConstantInt::get(IP, 512)));
    DLB.CreateCondBr(DynActive, DynBody, MapFirst);

    IRBuilder<> DB(DynBody);
    Value *DynEnt = DB.CreateIntToPtr(
        DB.CreateAdd(DynAddr, DB.CreateMul(DynIdx, ConstantInt::get(IP, 16))),
        Ptr, "morok.fco.elf.main.dyn.ptr");
    Value *Tag = loadAt(DB, M, I64, DynEnt, 0ULL, "morok.fco.elf.main.dyn.tag");
    Value *Val = loadAt(DB, M, IP, DynEnt, 8, "morok.fco.elf.main.dyn.val");
    Value *OldDebug = DB.CreateLoad(IP, DebugSlot, "morok.fco.elf.debug.old");
    DB.CreateStore(
        DB.CreateSelect(DB.CreateICmpEQ(Tag, ConstantInt::get(I64, 21)), Val,
                        OldDebug),
        DebugSlot);
    DB.CreateCondBr(DB.CreateICmpEQ(Tag, ConstantInt::get(I64, 0)), MapFirst,
                    DynNext);

    IRBuilder<> DNB(DynNext);
    Value *DynNextIdx = DNB.CreateAdd(DynIdx, ConstantInt::get(IP, 1),
                                      "morok.fco.elf.main.dyn.next");
    DNB.CreateBr(DynLoop);
    DynIdx->addIncoming(DynNextIdx, DynNext);

    IRBuilder<> MFB(MapFirst);
    Value *DebugAddr =
        MFB.CreateLoad(IP, DebugSlot, "morok.fco.elf.debug.final");
    MFB.CreateCondBr(MFB.CreateICmpNE(DebugAddr, ConstantInt::get(IP, 0)),
                     MapLoad, AtBasePrep);

    IRBuilder<> MLoadB(MapLoad);
    Value *DebugPtr =
        MLoadB.CreateIntToPtr(DebugAddr, Ptr, "morok.fco.elf.debug.ptr");
    Value *FirstMap =
        MLoadB.CreateLoad(Ptr,
                          gepI8(MLoadB, M, DebugPtr, ConstantInt::get(IP, 8),
                                "morok.fco.elf.rdebug.map.ptr"),
                          "morok.fco.elf.rdebug.map");
    MLoadB.CreateBr(MapLoop);

    IRBuilder<> MLB(MapLoop);
    auto *Map = MLB.CreatePHI(Ptr, 2, "morok.fco.elf.map");
    auto *MapCount = MLB.CreatePHI(IP, 2, "morok.fco.elf.map.count");
    Map->addIncoming(FirstMap, MapLoad);
    MapCount->addIncoming(ConstantInt::get(IP, 0), MapLoad);
    Value *MapActive =
        MLB.CreateAnd(MLB.CreateICmpNE(Map, ConstantPointerNull::get(Ptr)),
                      MLB.CreateICmpULT(MapCount, ConstantInt::get(IP, 128)));
    MLB.CreateCondBr(MapActive, MapBody, AtBasePrep);

    IRBuilder<> MBB(MapBody);
    Value *MapBase = loadAt(MBB, M, IP, Map, 0ULL, "morok.fco.elf.map.base");
    Value *MapDyn = MBB.CreateLoad(Ptr,
                                   gepI8(MBB, M, Map, ConstantInt::get(IP, 16),
                                         "morok.fco.elf.map.dyn.ptr"),
                                   "morok.fco.elf.map.dyn");
    Value *NextMap = MBB.CreateLoad(Ptr,
                                    gepI8(MBB, M, Map, ConstantInt::get(IP, 24),
                                          "morok.fco.elf.map.next.ptr"),
                                    "morok.fco.elf.map.next");
    Value *Resolved =
        MBB.CreateCall(ScanModule, {Wanted, SiteSalt, MapBase, MapDyn},
                       "morok.fco.elf.map.resolved");
    MBB.CreateStore(Resolved, FoundSlot);
    MBB.CreateCondBr(MBB.CreateICmpNE(Resolved, ConstantPointerNull::get(Ptr)),
                     RetFound, MapNext);

    IRBuilder<> MNB(MapNext);
    Value *NextMapCount = MNB.CreateAdd(MapCount, ConstantInt::get(IP, 1),
                                        "morok.fco.elf.map.count.next");
    MNB.CreateBr(MapLoop);
    Map->addIncoming(NextMap, MapNext);
    MapCount->addIncoming(NextMapCount, MapNext);

    IRBuilder<> ABP(AtBasePrep);
    Value *AtBase = ABP.CreateCall(getauxvalDecl(M), {ConstantInt::get(IP, 7)},
                                   "morok.fco.elf.atbase.v");
    ABP.CreateStore(AtBase, AtBaseSlot);
    ABP.CreateCondBr(ABP.CreateICmpNE(AtBase, ConstantInt::get(IP, 0)),
                     AtBaseLoad, RetNull);

    IRBuilder<> ABL(AtBaseLoad);
    Value *AtBasePtr =
        ABL.CreateIntToPtr(AtBase, Ptr, "morok.fco.elf.atbase.ptr");
    Value *AtBaseMagic =
        loadAt(ABL, M, I32, AtBasePtr, 0ULL, "morok.fco.elf.atbase.magic");
    Value *AtBasePhOff =
        loadAt(ABL, M, I64, AtBasePtr, 32, "morok.fco.elf.atbase.phoff");
    Value *AtBasePhEntRaw = loadAt(ABL, M, Type::getInt16Ty(Ctx), AtBasePtr, 54,
                                   "morok.fco.elf.atbase.phentsize");
    Value *AtBasePhNumRaw = loadAt(ABL, M, Type::getInt16Ty(Ctx), AtBasePtr, 56,
                                   "morok.fco.elf.atbase.phnum");
    Value *AtBasePhEnt =
        ABL.CreateZExt(AtBasePhEntRaw, IP, "morok.fco.elf.atbase.phent");
    Value *AtBasePhNum =
        ABL.CreateZExt(AtBasePhNumRaw, IP, "morok.fco.elf.atbase.phnum");
    ABL.CreateCondBr(
        ABL.CreateAnd(
            ABL.CreateICmpEQ(AtBaseMagic, ConstantInt::get(I32, 0x464C457F)),
            ABL.CreateAnd(
                ABL.CreateICmpUGE(AtBasePhEnt, ConstantInt::get(IP, 56)),
                ABL.CreateICmpUGT(AtBasePhNum, ConstantInt::get(IP, 0)))),
        AtBasePhLoop, RetNull);

    IRBuilder<> ABPL(AtBasePhLoop);
    auto *AtBasePhIdx = ABPL.CreatePHI(IP, 2, "morok.fco.elf.atbase.ph.idx");
    AtBasePhIdx->addIncoming(ConstantInt::get(IP, 0), AtBaseLoad);
    Value *AtBasePhActive = ABPL.CreateAnd(
        ABPL.CreateICmpULT(AtBasePhIdx, AtBasePhNum),
        ABPL.CreateICmpULT(AtBasePhIdx, ConstantInt::get(IP, 128)));
    ABPL.CreateCondBr(AtBasePhActive, AtBasePhBody, AtBaseScan);

    IRBuilder<> ABPB(AtBasePhBody);
    Value *AtBasePhPtr = ABPB.CreateIntToPtr(
        ABPB.CreateAdd(
            AtBase, ABPB.CreateAdd(AtBasePhOff,
                                   ABPB.CreateMul(AtBasePhIdx, AtBasePhEnt))),
        Ptr, "morok.fco.elf.atbase.ph.ptr");
    Value *AtBasePType =
        loadAt(ABPB, M, I32, AtBasePhPtr, 0ULL, "morok.fco.elf.atbase.ph.type");
    Value *AtBasePVaddr =
        loadAt(ABPB, M, IP, AtBasePhPtr, 16, "morok.fco.elf.atbase.ph.vaddr");
    Value *OldAtBaseDyn =
        ABPB.CreateLoad(IP, AtBaseDynSlot, "morok.fco.elf.atbase.dyn.old");
    ABPB.CreateStore(
        ABPB.CreateSelect(
            ABPB.CreateICmpEQ(AtBasePType, ConstantInt::get(I32, 2)),
            ABPB.CreateAdd(AtBase, AtBasePVaddr), OldAtBaseDyn),
        AtBaseDynSlot);
    ABPB.CreateBr(AtBasePhNext);

    IRBuilder<> ABPN(AtBasePhNext);
    Value *AtBaseNextIdx = ABPN.CreateAdd(AtBasePhIdx, ConstantInt::get(IP, 1),
                                          "morok.fco.elf.atbase.ph.next");
    ABPN.CreateBr(AtBasePhLoop);
    AtBasePhIdx->addIncoming(AtBaseNextIdx, AtBasePhNext);

    IRBuilder<> ABS(AtBaseScan);
    Value *AtBaseDyn =
        ABS.CreateLoad(IP, AtBaseDynSlot, "morok.fco.elf.atbase.dyn.final");
    Value *AtBaseDynPtr =
        ABS.CreateIntToPtr(AtBaseDyn, Ptr, "morok.fco.elf.atbase.dyn.ptr");
    Value *AtBaseResolved =
        ABS.CreateCall(ScanModule, {Wanted, SiteSalt, AtBase, AtBaseDynPtr},
                       "morok.fco.elf.atbase.resolved");
    ABS.CreateStore(AtBaseResolved, FoundSlot);
    ABS.CreateCondBr(
        ABS.CreateICmpNE(AtBaseResolved, ConstantPointerNull::get(Ptr)),
        RetFound, RetNull);

    IRBuilder<> RFB(RetFound);
    RFB.CreateRet(RFB.CreateLoad(Ptr, FoundSlot, "morok.fco.elf.ret"));

    IRBuilder<> RNB(RetNull);
    Value *CtxPtr = RNB.CreateInBoundsGEP(
        IterCtxTy, IterCtx, {ConstantInt::get(IP, 0), ConstantInt::get(IP, 0)},
        "morok.fco.elf.iter.ctx.ptr");
    RNB.CreateCall(dlIteratePhdrDecl(M), {IterCallback, CtxPtr});
    Value *IterFoundInt =
        RNB.CreateLoad(I64,
                       RNB.CreateInBoundsGEP(
                           IterCtxTy, IterCtx,
                           {ConstantInt::get(IP, 0), ConstantInt::get(IP, 1)},
                           "morok.fco.elf.iter.ret.slot"),
                       "morok.fco.elf.iter.ret");
    RNB.CreateRet(
        RNB.CreateIntToPtr(IterFoundInt, Ptr, "morok.fco.elf.iter.ret.ptr"));
    return Fn;
}

Function *machoReadUleb(Module &M) {
    if (auto *Existing = M.getFunction("morok.fco.macho.uleb"))
        return Existing;

    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *IP = M.getDataLayout().getIntPtrType(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);

    auto *Fn = Function::Create(
        FunctionType::get(I64, {Ptr, IP, Ptr, Ptr}, false),
        GlobalValue::PrivateLinkage, "morok.fco.macho.uleb", M);
    Fn->addFnAttr(Attribute::NoInline);
    Fn->setDSOLocal(true);
    auto *Base = Fn->getArg(0);
    Base->setName("base");
    auto *Size = Fn->getArg(1);
    Size->setName("size");
    auto *CursorSlot = Fn->getArg(2);
    CursorSlot->setName("cursor");
    auto *OkSlot = Fn->getArg(3);
    OkSlot->setName("ok");

    auto *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    auto *Loop = BasicBlock::Create(Ctx, "loop", Fn);
    auto *Body = BasicBlock::Create(Ctx, "body", Fn);
    auto *Cont = BasicBlock::Create(Ctx, "cont", Fn);
    auto *Done = BasicBlock::Create(Ctx, "done", Fn);
    auto *Fail = BasicBlock::Create(Ctx, "fail", Fn);

    IRBuilder<> B(Entry);
    AllocaInst *ResSlot = B.CreateAlloca(I64, nullptr, "morok.fco.uleb.res");
    AllocaInst *ShiftSlot = B.CreateAlloca(IP, nullptr, "morok.fco.uleb.shift");
    AllocaInst *IterSlot = B.CreateAlloca(IP, nullptr, "morok.fco.uleb.iter");
    B.CreateStore(ConstantInt::get(I64, 0), ResSlot);
    B.CreateStore(ConstantInt::get(IP, 0), ShiftSlot);
    B.CreateStore(ConstantInt::get(IP, 0), IterSlot);
    B.CreateStore(ConstantInt::get(I8, 1), OkSlot);
    B.CreateBr(Loop);

    IRBuilder<> LB(Loop);
    Value *Iter = LB.CreateLoad(IP, IterSlot, "morok.fco.uleb.iter.v");
    Value *Off = LB.CreateLoad(IP, CursorSlot, "morok.fco.uleb.off");
    Value *Active =
        LB.CreateAnd(LB.CreateICmpULT(Iter, ConstantInt::get(IP, 10)),
                     LB.CreateICmpULT(Off, Size), "morok.fco.uleb.active");
    LB.CreateCondBr(Active, Body, Fail);

    IRBuilder<> BB(Body);
    Value *Byte = loadUnaligned(
        BB, I8, gepI8(BB, M, Base, Off, "morok.fco.uleb.byte.ptr"),
        "morok.fco.uleb.byte");
    Value *Payload =
        BB.CreateZExt(BB.CreateAnd(Byte, ConstantInt::get(I8, 0x7f)), I64,
                      "morok.fco.uleb.payload");
    Value *Shift = BB.CreateLoad(IP, ShiftSlot, "morok.fco.uleb.shift.v");
    Value *Part = BB.CreateShl(Payload, BB.CreateZExtOrTrunc(Shift, I64),
                               "morok.fco.uleb.part");
    Value *Res = BB.CreateOr(BB.CreateLoad(I64, ResSlot), Part,
                             "morok.fco.uleb.res.next");
    BB.CreateStore(Res, ResSlot);
    Value *NextOff =
        BB.CreateAdd(Off, ConstantInt::get(IP, 1), "morok.fco.uleb.off.next");
    BB.CreateStore(NextOff, CursorSlot);
    Value *DoneByte =
        BB.CreateICmpEQ(BB.CreateAnd(Byte, ConstantInt::get(I8, 0x80)),
                        ConstantInt::get(I8, 0));
    BB.CreateCondBr(DoneByte, Done, Cont);

    IRBuilder<> CB(Cont);
    CB.CreateStore(CB.CreateAdd(Shift, ConstantInt::get(IP, 7)), ShiftSlot);
    CB.CreateStore(CB.CreateAdd(Iter, ConstantInt::get(IP, 1)), IterSlot);
    CB.CreateBr(Loop);

    IRBuilder<> DB(Done);
    DB.CreateStore(ConstantInt::get(I8, 1), OkSlot);
    DB.CreateRet(DB.CreateLoad(I64, ResSlot));

    IRBuilder<> FB(Fail);
    FB.CreateStore(ConstantInt::get(I8, 0), OkSlot);
    FB.CreateRet(FB.CreateLoad(I64, ResSlot));
    return Fn;
}

Function *machoTrieHashResolver(Module &M, unsigned Family) {
    const std::string FnName =
        familyName("morok.fco.resolve.macho.trie", Family);
    if (auto *Existing = M.getFunction(FnName))
        return Existing;

    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *IP = M.getDataLayout().getIntPtrType(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    Function *ReadUleb = machoReadUleb(M);

    const HashKey HK = hashKeyFor(M, Family);
    const std::uint64_t FnvOffset = HK.offset;
    const std::uint64_t FnvPrime = HK.prime;
    constexpr std::uint64_t StackCap = 4096;
    constexpr std::uint64_t StepCap = 262144;

    auto *Fn =
        Function::Create(FunctionType::get(Ptr, {I64, I64, Ptr, IP, IP}, false),
                         GlobalValue::PrivateLinkage, FnName, M);
    Fn->addFnAttr(Attribute::NoInline);
    Fn->setDSOLocal(true);
    auto *Wanted = Fn->getArg(0);
    Wanted->setName("wanted");
    auto *SiteSalt = Fn->getArg(1);
    SiteSalt->setName("salt");
    auto *Trie = Fn->getArg(2);
    Trie->setName("trie");
    auto *Size = Fn->getArg(3);
    Size->setName("size");
    auto *ImageBase = Fn->getArg(4);
    ImageBase->setName("image.base");

    auto *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    auto *Loop = BasicBlock::Create(Ctx, "loop", Fn);
    auto *Node = BasicBlock::Create(Ctx, "node", Fn);
    auto *ReadTerm = BasicBlock::Create(Ctx, "term.read", Fn);
    auto *TermDispatch = BasicBlock::Create(Ctx, "term.dispatch", Fn);
    auto *Terminal = BasicBlock::Create(Ctx, "terminal", Fn);
    auto *TerminalAddr = BasicBlock::Create(Ctx, "terminal.addr", Fn);
    auto *AfterTerm = BasicBlock::Create(Ctx, "after.term", Fn);
    auto *ChildPrep = BasicBlock::Create(Ctx, "child.prep", Fn);
    auto *ChildLoop = BasicBlock::Create(Ctx, "child.loop", Fn);
    auto *ChildStart = BasicBlock::Create(Ctx, "child.start", Fn);
    auto *SuffixLoop = BasicBlock::Create(Ctx, "suffix.loop", Fn);
    auto *SuffixByte = BasicBlock::Create(Ctx, "suffix.byte", Fn);
    auto *SuffixHash = BasicBlock::Create(Ctx, "suffix.hash", Fn);
    auto *ChildOffset = BasicBlock::Create(Ctx, "child.offset", Fn);
    auto *Push = BasicBlock::Create(Ctx, "push", Fn);
    auto *ChildNext = BasicBlock::Create(Ctx, "child.next", Fn);
    auto *RetFound = BasicBlock::Create(Ctx, "ret.found", Fn);
    auto *RetNull = BasicBlock::Create(Ctx, "ret.null", Fn);

    IRBuilder<> B(Entry);
    AllocaInst *StackOff = B.CreateAlloca(IP, ConstantInt::get(IP, StackCap),
                                          "morok.fco.trie.stack.off");
    AllocaInst *StackHash = B.CreateAlloca(I64, ConstantInt::get(IP, StackCap),
                                           "morok.fco.trie.stack.hash");
    AllocaInst *StackPrefix = B.CreateAlloca(I8, ConstantInt::get(IP, StackCap),
                                             "morok.fco.trie.stack.prefix");
    AllocaInst *SpSlot = B.CreateAlloca(IP, nullptr, "morok.fco.trie.sp");
    AllocaInst *StepSlot = B.CreateAlloca(IP, nullptr, "morok.fco.trie.steps");
    AllocaInst *CurSlot = B.CreateAlloca(IP, nullptr, "morok.fco.trie.cur");
    AllocaInst *TermEndSlot =
        B.CreateAlloca(IP, nullptr, "morok.fco.trie.term.end");
    AllocaInst *OkSlot = B.CreateAlloca(I8, nullptr, "morok.fco.trie.ok");
    AllocaInst *NodeHashSlot =
        B.CreateAlloca(I64, nullptr, "morok.fco.trie.node.hash");
    AllocaInst *NodePrefixSlot =
        B.CreateAlloca(I8, nullptr, "morok.fco.trie.node.prefix");
    AllocaInst *ChildHashSlot =
        B.CreateAlloca(I64, nullptr, "morok.fco.trie.child.hash");
    AllocaInst *ChildPrefixSlot =
        B.CreateAlloca(I8, nullptr, "morok.fco.trie.child.prefix");
    AllocaInst *ChildIdxSlot =
        B.CreateAlloca(IP, nullptr, "morok.fco.trie.child.idx");
    AllocaInst *ChildCountSlot =
        B.CreateAlloca(IP, nullptr, "morok.fco.trie.child.count");
    AllocaInst *FlagsSlot =
        B.CreateAlloca(I64, nullptr, "morok.fco.trie.flags");
    AllocaInst *FoundSlot =
        B.CreateAlloca(Ptr, nullptr, "morok.fco.trie.found");

    auto gepIpStack = [&](IRBuilder<> &IB, AllocaInst *Base, Value *Idx,
                          const Twine &Name) {
        return IB.CreateInBoundsGEP(IP, Base, Idx, Name);
    };
    auto gepI64Stack = [&](IRBuilder<> &IB, AllocaInst *Base, Value *Idx,
                           const Twine &Name) {
        return IB.CreateInBoundsGEP(I64, Base, Idx, Name);
    };
    auto gepI8Stack = [&](IRBuilder<> &IB, AllocaInst *Base, Value *Idx,
                          const Twine &Name) {
        return IB.CreateInBoundsGEP(I8, Base, Idx, Name);
    };

    Value *Zero = ConstantInt::get(IP, 0);
    B.CreateStore(Zero,
                  gepIpStack(B, StackOff, Zero, "morok.fco.trie.stack.off.0"));
    B.CreateStore(
        ConstantInt::get(I64, FnvOffset),
        gepI64Stack(B, StackHash, Zero, "morok.fco.trie.stack.hash.0"));
    B.CreateStore(
        ConstantInt::get(I8, 0),
        gepI8Stack(B, StackPrefix, Zero, "morok.fco.trie.stack.prefix.0"));
    B.CreateStore(ConstantInt::get(IP, 1), SpSlot);
    B.CreateStore(Zero, StepSlot);
    B.CreateStore(ConstantPointerNull::get(Ptr), FoundSlot);
    Value *CanStart =
        B.CreateAnd(B.CreateICmpNE(Trie, ConstantPointerNull::get(Ptr)),
                    B.CreateICmpUGT(Size, Zero));
    B.CreateCondBr(CanStart, Loop, RetNull);

    IRBuilder<> LB(Loop);
    Value *Sp = LB.CreateLoad(IP, SpSlot, "morok.fco.trie.sp.v");
    Value *Steps = LB.CreateLoad(IP, StepSlot, "morok.fco.trie.steps.v");
    Value *Active =
        LB.CreateAnd(LB.CreateICmpUGT(Sp, Zero),
                     LB.CreateICmpULT(Steps, ConstantInt::get(IP, StepCap)),
                     "morok.fco.trie.active");
    LB.CreateCondBr(Active, Node, RetNull);

    IRBuilder<> NB(Node);
    Value *NodeSp = NB.CreateLoad(IP, SpSlot, "morok.fco.trie.node.sp");
    Value *NodeIdx = NB.CreateSub(NodeSp, ConstantInt::get(IP, 1),
                                  "morok.fco.trie.node.idx");
    NB.CreateStore(NodeIdx, SpSlot);
    NB.CreateStore(
        NB.CreateAdd(NB.CreateLoad(IP, StepSlot), ConstantInt::get(IP, 1)),
        StepSlot);
    Value *NodeOff = NB.CreateLoad(
        IP, gepIpStack(NB, StackOff, NodeIdx, "morok.fco.trie.node.off.ptr"),
        "morok.fco.trie.node.off");
    Value *NodeHash = NB.CreateLoad(
        I64,
        gepI64Stack(NB, StackHash, NodeIdx, "morok.fco.trie.node.hash.ptr"),
        "morok.fco.trie.node.hash.v");
    Value *NodePrefix = NB.CreateLoad(
        I8,
        gepI8Stack(NB, StackPrefix, NodeIdx, "morok.fco.trie.node.prefix.ptr"),
        "morok.fco.trie.node.prefix.v");
    NB.CreateStore(NodeHash, NodeHashSlot);
    NB.CreateStore(NodePrefix, NodePrefixSlot);
    NB.CreateStore(NodeOff, CurSlot);
    NB.CreateStore(ConstantInt::get(I8, 1), OkSlot);
    NB.CreateCondBr(NB.CreateICmpULT(NodeOff, Size), ReadTerm, Loop);

    IRBuilder<> RTB(ReadTerm);
    Value *TermSize = RTB.CreateCall(ReadUleb, {Trie, Size, CurSlot, OkSlot},
                                     "morok.fco.trie.term.size");
    Value *TermStart = RTB.CreateLoad(IP, CurSlot, "morok.fco.trie.term.start");
    Value *TermEnd =
        RTB.CreateAdd(TermStart, TermSize, "morok.fco.trie.term.end.v");
    RTB.CreateStore(TermEnd, TermEndSlot);
    Value *TermOk = RTB.CreateAnd(
        RTB.CreateICmpNE(RTB.CreateLoad(I8, OkSlot), ConstantInt::get(I8, 0)),
        RTB.CreateAnd(RTB.CreateICmpUGE(TermEnd, TermStart),
                      RTB.CreateICmpULE(TermEnd, Size)));
    RTB.CreateCondBr(TermOk, TermDispatch, Loop);

    IRBuilder<> TDB(TermDispatch);
    TDB.CreateCondBr(TDB.CreateICmpNE(TermSize, ConstantInt::get(I64, 0)),
                     Terminal, AfterTerm);

    IRBuilder<> TB(Terminal);
    Value *Flags = TB.CreateCall(ReadUleb, {Trie, Size, CurSlot, OkSlot},
                                 "morok.fco.trie.flags.v");
    TB.CreateStore(Flags, FlagsSlot);
    Value *FlagsOk =
        TB.CreateICmpNE(TB.CreateLoad(I8, OkSlot), ConstantInt::get(I8, 0));
    Value *Reexport =
        TB.CreateICmpNE(TB.CreateAnd(Flags, ConstantInt::get(I64, 0x08)),
                        ConstantInt::get(I64, 0));
    TB.CreateCondBr(TB.CreateAnd(FlagsOk, TB.CreateNot(Reexport)), TerminalAddr,
                    AfterTerm);

    IRBuilder<> TAB(TerminalAddr);
    Value *Addr = TAB.CreateCall(ReadUleb, {Trie, Size, CurSlot, OkSlot},
                                 "morok.fco.trie.addr");
    Value *AddrOk =
        TAB.CreateICmpNE(TAB.CreateLoad(I8, OkSlot), ConstantInt::get(I8, 0));
    Value *Kind =
        TAB.CreateAnd(TAB.CreateLoad(I64, FlagsSlot),
                      ConstantInt::get(I64, 0x03), "morok.fco.trie.kind");
    Value *RuntimeAddr = TAB.CreateSelect(
        TAB.CreateICmpEQ(Kind, ConstantInt::get(I64, 0x02)), Addr,
        TAB.CreateAdd(ImageBase, TAB.CreateZExtOrTrunc(Addr, IP)),
        "morok.fco.trie.runtime.addr");
    TAB.CreateStore(TAB.CreateIntToPtr(RuntimeAddr, Ptr), FoundSlot);
    Value *SiteHash = emitSiteHash(TAB, TAB.CreateLoad(I64, NodeHashSlot),
                                   SiteSalt, "morok.fco.trie.hash.site");
    Value *HashMatch =
        TAB.CreateICmpEQ(SiteHash, Wanted, "morok.fco.trie.hash.match");
    TAB.CreateCondBr(TAB.CreateAnd(AddrOk, HashMatch), RetFound, AfterTerm);

    IRBuilder<> ATB(AfterTerm);
    Value *TermEndFinal =
        ATB.CreateLoad(IP, TermEndSlot, "morok.fco.trie.term.end.final");
    ATB.CreateStore(TermEndFinal, CurSlot);
    ATB.CreateCondBr(ATB.CreateICmpULT(TermEndFinal, Size), ChildPrep, Loop);

    IRBuilder<> CPB(ChildPrep);
    Value *ChildCountByte =
        loadUnaligned(CPB, I8,
                      gepI8(CPB, M, Trie, CPB.CreateLoad(IP, CurSlot),
                            "morok.fco.trie.child.count.ptr"),
                      "morok.fco.trie.child.count.byte");
    CPB.CreateStore(CPB.CreateZExt(ChildCountByte, IP), ChildCountSlot);
    CPB.CreateStore(
        CPB.CreateAdd(CPB.CreateLoad(IP, CurSlot), ConstantInt::get(IP, 1)),
        CurSlot);
    CPB.CreateStore(Zero, ChildIdxSlot);
    CPB.CreateBr(ChildLoop);

    IRBuilder<> CLB(ChildLoop);
    Value *ChildIdx =
        CLB.CreateLoad(IP, ChildIdxSlot, "morok.fco.trie.child.idx.v");
    Value *ChildCount =
        CLB.CreateLoad(IP, ChildCountSlot, "morok.fco.trie.child.count.v");
    Value *ChildCur = CLB.CreateLoad(IP, CurSlot, "morok.fco.trie.child.cur");
    Value *ChildActive = CLB.CreateAnd(CLB.CreateICmpULT(ChildIdx, ChildCount),
                                       CLB.CreateICmpULT(ChildCur, Size),
                                       "morok.fco.trie.child.active");
    CLB.CreateCondBr(ChildActive, ChildStart, Loop);

    IRBuilder<> CSB(ChildStart);
    CSB.CreateStore(CSB.CreateLoad(I64, NodeHashSlot), ChildHashSlot);
    CSB.CreateStore(CSB.CreateLoad(I8, NodePrefixSlot), ChildPrefixSlot);
    CSB.CreateBr(SuffixLoop);

    IRBuilder<> SLB(SuffixLoop);
    SLB.CreateCondBr(SLB.CreateICmpULT(SLB.CreateLoad(IP, CurSlot), Size),
                     SuffixByte, Loop);

    IRBuilder<> SBB(SuffixByte);
    Value *SuffixChar =
        loadUnaligned(SBB, I8,
                      gepI8(SBB, M, Trie, SBB.CreateLoad(IP, CurSlot),
                            "morok.fco.trie.suffix.ptr"),
                      "morok.fco.trie.suffix.c");
    SBB.CreateStore(
        SBB.CreateAdd(SBB.CreateLoad(IP, CurSlot), ConstantInt::get(IP, 1)),
        CurSlot);
    SBB.CreateCondBr(SBB.CreateICmpEQ(SuffixChar, ConstantInt::get(I8, 0)),
                     ChildOffset, SuffixHash);

    IRBuilder<> SHB(SuffixHash);
    Value *NeedPrefixDecision = SHB.CreateICmpEQ(
        SHB.CreateLoad(I8, ChildPrefixSlot), ConstantInt::get(I8, 0));
    Value *SkipPlatformUnderscore =
        SHB.CreateAnd(NeedPrefixDecision,
                      SHB.CreateICmpEQ(SuffixChar, ConstantInt::get(I8, '_')));
    Value *OldHash =
        SHB.CreateLoad(I64, ChildHashSlot, "morok.fco.trie.child.hash.old");
    Value *NewHash = SHB.CreateMul(
        SHB.CreateXor(OldHash, SHB.CreateZExt(SuffixChar, I64)),
        ConstantInt::get(I64, FnvPrime), "morok.fco.trie.child.hash.next");
    SHB.CreateStore(SHB.CreateSelect(SkipPlatformUnderscore, OldHash, NewHash),
                    ChildHashSlot);
    SHB.CreateStore(ConstantInt::get(I8, 1), ChildPrefixSlot);
    SHB.CreateBr(SuffixLoop);

    IRBuilder<> COB(ChildOffset);
    Value *ChildOff = COB.CreateCall(ReadUleb, {Trie, Size, CurSlot, OkSlot},
                                     "morok.fco.trie.child.off");
    Value *ChildOffOk = COB.CreateAnd(
        COB.CreateICmpNE(COB.CreateLoad(I8, OkSlot), ConstantInt::get(I8, 0)),
        COB.CreateICmpULT(COB.CreateZExtOrTrunc(ChildOff, IP), Size));
    Value *PushOk = COB.CreateAnd(
        ChildOffOk, COB.CreateICmpULT(COB.CreateLoad(IP, SpSlot),
                                      ConstantInt::get(IP, StackCap)));
    COB.CreateCondBr(PushOk, Push, ChildNext);

    IRBuilder<> PB(Push);
    Value *PushIdx = PB.CreateLoad(IP, SpSlot, "morok.fco.trie.push.idx");
    PB.CreateStore(
        PB.CreateZExtOrTrunc(ChildOff, IP),
        gepIpStack(PB, StackOff, PushIdx, "morok.fco.trie.push.off.ptr"));
    PB.CreateStore(
        PB.CreateLoad(I64, ChildHashSlot),
        gepI64Stack(PB, StackHash, PushIdx, "morok.fco.trie.push.hash.ptr"));
    PB.CreateStore(
        PB.CreateLoad(I8, ChildPrefixSlot),
        gepI8Stack(PB, StackPrefix, PushIdx, "morok.fco.trie.push.prefix.ptr"));
    PB.CreateStore(PB.CreateAdd(PushIdx, ConstantInt::get(IP, 1)), SpSlot);
    PB.CreateBr(ChildNext);

    IRBuilder<> CNB(ChildNext);
    CNB.CreateStore(CNB.CreateAdd(CNB.CreateLoad(IP, ChildIdxSlot),
                                  ConstantInt::get(IP, 1)),
                    ChildIdxSlot);
    CNB.CreateBr(ChildLoop);

    IRBuilder<> RFB(RetFound);
    RFB.CreateRet(RFB.CreateLoad(Ptr, FoundSlot, "morok.fco.trie.ret"));

    IRBuilder<> RNB(RetNull);
    RNB.CreateRet(ConstantPointerNull::get(Ptr));
    return Fn;
}

Function *darwinHashResolver(Module &M, unsigned Family) {
    const std::string FnName = familyName("morok.fco.resolve.macho", Family);
    if (auto *Existing = M.getFunction(FnName))
        return Existing;

    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *IP = M.getDataLayout().getIntPtrType(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    Function *TrieResolver = machoTrieHashResolver(M, Family);

    auto *Fn = Function::Create(FunctionType::get(Ptr, {I64, I64}, false),
                                GlobalValue::PrivateLinkage, FnName, M);
    Fn->addFnAttr(Attribute::NoInline);
    Fn->setDSOLocal(true);
    auto *Wanted = Fn->getArg(0);
    Wanted->setName("wanted");
    auto *SiteSalt = Fn->getArg(1);
    SiteSalt->setName("salt");

    auto *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    auto *ImageLoop = BasicBlock::Create(Ctx, "image.loop", Fn);
    auto *ImageBody = BasicBlock::Create(Ctx, "image.body", Fn);
    auto *CmdLoop = BasicBlock::Create(Ctx, "cmd.loop", Fn);
    auto *CmdBody = BasicBlock::Create(Ctx, "cmd.body", Fn);
    auto *CmdNext = BasicBlock::Create(Ctx, "cmd.next", Fn);
    auto *ScanPrep = BasicBlock::Create(Ctx, "scan.prep", Fn);
    auto *TrieScan = BasicBlock::Create(Ctx, "trie.scan", Fn);
    auto *TrieMiss = BasicBlock::Create(Ctx, "trie.miss", Fn);
    auto *SymLoop = BasicBlock::Create(Ctx, "sym.loop", Fn);
    auto *SymBody = BasicBlock::Create(Ctx, "sym.body", Fn);
    auto *SymCheck = BasicBlock::Create(Ctx, "sym.check", Fn);
    auto *SymNext = BasicBlock::Create(Ctx, "sym.next", Fn);
    auto *ImageNext = BasicBlock::Create(Ctx, "image.next", Fn);
    auto *RetFound = BasicBlock::Create(Ctx, "ret.found", Fn);
    auto *RetNull = BasicBlock::Create(Ctx, "ret.null", Fn);

    IRBuilder<> B(Entry);
    AllocaInst *LinkVm = B.CreateAlloca(IP, nullptr, "morok.fco.macho.link.vm");
    AllocaInst *LinkFile =
        B.CreateAlloca(IP, nullptr, "morok.fco.macho.link.file");
    AllocaInst *Symoff = B.CreateAlloca(IP, nullptr, "morok.fco.macho.symoff");
    AllocaInst *Nsyms = B.CreateAlloca(IP, nullptr, "morok.fco.macho.nsyms");
    AllocaInst *Stroff = B.CreateAlloca(IP, nullptr, "morok.fco.macho.stroff");
    AllocaInst *Strsize =
        B.CreateAlloca(IP, nullptr, "morok.fco.macho.strsize");
    AllocaInst *ExportOff =
        B.CreateAlloca(IP, nullptr, "morok.fco.macho.export.off");
    AllocaInst *ExportSize =
        B.CreateAlloca(IP, nullptr, "morok.fco.macho.export.size");
    AllocaInst *Symtab = B.CreateAlloca(IP, nullptr, "morok.fco.macho.symtab");
    AllocaInst *Strtab = B.CreateAlloca(IP, nullptr, "morok.fco.macho.strtab");
    AllocaInst *FoundSlot =
        B.CreateAlloca(Ptr, nullptr, "morok.fco.macho.found");
    for (AllocaInst *Slot : {LinkVm, LinkFile, Symoff, Nsyms, Stroff, Strsize,
                             ExportOff, ExportSize, Symtab, Strtab})
        B.CreateStore(ConstantInt::get(IP, 0), Slot);
    B.CreateStore(ConstantPointerNull::get(Ptr), FoundSlot);
    Value *ImageCount =
        B.CreateCall(dyldImageCountDecl(M), {}, "morok.fco.macho.image.count");
    B.CreateBr(ImageLoop);

    IRBuilder<> ILB(ImageLoop);
    auto *ImageIdx = ILB.CreatePHI(I32, 2, "morok.fco.macho.image.idx");
    ImageIdx->addIncoming(ConstantInt::get(I32, 0), Entry);
    Value *ImageInRange =
        ILB.CreateAnd(ILB.CreateICmpULT(ImageIdx, ImageCount),
                      ILB.CreateICmpULT(ImageIdx, ConstantInt::get(I32, 128)));
    ILB.CreateCondBr(ImageInRange, ImageBody, RetNull);

    IRBuilder<> IBB(ImageBody);
    Value *Hdr = IBB.CreateCall(dyldImageHeaderDecl(M), {ImageIdx},
                                "morok.fco.macho.hdr");
    Value *Slide = IBB.CreateCall(dyldImageSlideDecl(M), {ImageIdx},
                                  "morok.fco.macho.slide");
    Value *Magic = loadAt(IBB, M, I32, Hdr, 0ULL, "morok.fco.macho.magic");
    Value *NCmds = loadAt(IBB, M, I32, Hdr, 16, "morok.fco.macho.ncmds");
    for (AllocaInst *Slot : {LinkVm, LinkFile, Symoff, Nsyms, Stroff, Strsize,
                             ExportOff, ExportSize, Symtab, Strtab})
        IBB.CreateStore(ConstantInt::get(IP, 0), Slot);
    Value *ValidImage = IBB.CreateAnd(
        IBB.CreateICmpNE(Hdr, ConstantPointerNull::get(Ptr)),
        IBB.CreateICmpEQ(Magic, ConstantInt::get(I32, 0xFEEDFACF)));
    IBB.CreateCondBr(ValidImage, CmdLoop, ImageNext);

    IRBuilder<> CLB(CmdLoop);
    auto *CmdIdx = CLB.CreatePHI(I32, 2, "morok.fco.macho.cmd.idx");
    auto *CmdOff = CLB.CreatePHI(IP, 2, "morok.fco.macho.cmd.off");
    CmdIdx->addIncoming(ConstantInt::get(I32, 0), ImageBody);
    CmdOff->addIncoming(ConstantInt::get(IP, 32), ImageBody);
    Value *CmdInRange =
        CLB.CreateAnd(CLB.CreateICmpULT(CmdIdx, NCmds),
                      CLB.CreateICmpULT(CmdIdx, ConstantInt::get(I32, 256)));
    CLB.CreateCondBr(CmdInRange, CmdBody, ScanPrep);

    IRBuilder<> CBB(CmdBody);
    Value *CmdPtr = gepI8(CBB, M, Hdr, CmdOff, "morok.fco.macho.cmd.ptr");
    Value *Cmd = loadAt(CBB, M, I32, CmdPtr, 0ULL, "morok.fco.macho.cmd");
    Value *CmdSize32 =
        loadAt(CBB, M, I32, CmdPtr, 4, "morok.fco.macho.cmd.size");
    Value *CmdSize =
        CBB.CreateZExt(CmdSize32, IP, "morok.fco.macho.cmd.size.w");
    Value *IsSymtab = CBB.CreateICmpEQ(Cmd, ConstantInt::get(I32, 0x2),
                                       "morok.fco.macho.cmd.symtab");
    Value *IsSegment64 = CBB.CreateICmpEQ(Cmd, ConstantInt::get(I32, 0x19),
                                          "morok.fco.macho.cmd.segment64");
    Value *IsDyldInfo =
        CBB.CreateOr(CBB.CreateICmpEQ(Cmd, ConstantInt::get(I32, 0x22)),
                     CBB.CreateICmpEQ(Cmd, ConstantInt::get(I32, 0x80000022u)),
                     "morok.fco.macho.cmd.dyld.info");
    Value *IsExportsTrie =
        CBB.CreateICmpEQ(Cmd, ConstantInt::get(I32, 0x80000033u),
                         "morok.fco.macho.cmd.exports.trie");
    Value *IsExportCmd =
        CBB.CreateOr(IsDyldInfo, IsExportsTrie, "morok.fco.macho.cmd.export");
    Value *SegVm = loadAt(CBB, M, I64, CmdPtr, 24, "morok.fco.macho.seg.vm");
    Value *SegFile =
        loadAt(CBB, M, I64, CmdPtr, 40, "morok.fco.macho.seg.file");
    Value *Symoff32 =
        loadAt(CBB, M, I32, CmdPtr, 8, "morok.fco.macho.symoff.raw");
    Value *Nsyms32 =
        loadAt(CBB, M, I32, CmdPtr, 12, "morok.fco.macho.nsyms.raw");
    Value *Stroff32 =
        loadAt(CBB, M, I32, CmdPtr, 16, "morok.fco.macho.stroff.raw");
    Value *Strsize32 =
        loadAt(CBB, M, I32, CmdPtr, 20, "morok.fco.macho.strsize.raw");
    Value *DyldExportOff32 =
        loadAt(CBB, M, I32, CmdPtr, 40, "morok.fco.macho.dyld.export.off.raw");
    Value *DyldExportSize32 =
        loadAt(CBB, M, I32, CmdPtr, 44, "morok.fco.macho.dyld.export.size.raw");
    Value *TrieExportOff32 =
        loadAt(CBB, M, I32, CmdPtr, 8, "morok.fco.macho.trie.export.off.raw");
    Value *TrieExportSize32 =
        loadAt(CBB, M, I32, CmdPtr, 12, "morok.fco.macho.trie.export.size.raw");
    auto storeSelect = [&](AllocaInst *Slot, Value *Cond, Value *Val) {
        Value *Old = CBB.CreateLoad(IP, Slot);
        CBB.CreateStore(CBB.CreateSelect(Cond, Val, Old), Slot);
    };
    storeSelect(LinkVm, IsSegment64, CBB.CreateZExtOrTrunc(SegVm, IP));
    storeSelect(LinkFile, IsSegment64, CBB.CreateZExtOrTrunc(SegFile, IP));
    storeSelect(Symoff, IsSymtab, CBB.CreateZExt(Symoff32, IP));
    storeSelect(Nsyms, IsSymtab, CBB.CreateZExt(Nsyms32, IP));
    storeSelect(Stroff, IsSymtab, CBB.CreateZExt(Stroff32, IP));
    storeSelect(Strsize, IsSymtab, CBB.CreateZExt(Strsize32, IP));
    storeSelect(ExportOff, IsExportCmd,
                CBB.CreateSelect(IsExportsTrie,
                                 CBB.CreateZExt(TrieExportOff32, IP),
                                 CBB.CreateZExt(DyldExportOff32, IP)));
    storeSelect(ExportSize, IsExportCmd,
                CBB.CreateSelect(IsExportsTrie,
                                 CBB.CreateZExt(TrieExportSize32, IP),
                                 CBB.CreateZExt(DyldExportSize32, IP)));
    CBB.CreateBr(CmdNext);

    IRBuilder<> CNB(CmdNext);
    Value *CmdNextIdx = CNB.CreateAdd(CmdIdx, ConstantInt::get(I32, 1),
                                      "morok.fco.macho.cmd.next");
    Value *CmdNextOff =
        CNB.CreateAdd(CmdOff, CmdSize, "morok.fco.macho.cmd.off.next");
    CNB.CreateBr(CmdLoop);
    CmdIdx->addIncoming(CmdNextIdx, CmdNext);
    CmdOff->addIncoming(CmdNextOff, CmdNext);

    IRBuilder<> SPB(ScanPrep);
    Value *LinkBase = SPB.CreateAdd(
        Slide,
        SPB.CreateSub(SPB.CreateLoad(IP, LinkVm), SPB.CreateLoad(IP, LinkFile)),
        "morok.fco.macho.link.base");
    Value *SymtabAddr = SPB.CreateAdd(LinkBase, SPB.CreateLoad(IP, Symoff),
                                      "morok.fco.macho.symtab.addr");
    Value *StrtabAddr = SPB.CreateAdd(LinkBase, SPB.CreateLoad(IP, Stroff),
                                      "morok.fco.macho.strtab.addr");
    Value *SymCount = SPB.CreateLoad(IP, Nsyms, "morok.fco.macho.nsyms.final");
    Value *StringSize =
        SPB.CreateLoad(IP, Strsize, "morok.fco.macho.strsize.final");
    Value *ExportOffset =
        SPB.CreateLoad(IP, ExportOff, "morok.fco.macho.export.off.final");
    Value *ExportBytes =
        SPB.CreateLoad(IP, ExportSize, "morok.fco.macho.export.size.final");
    Value *ExportAddr =
        SPB.CreateAdd(LinkBase, ExportOffset, "morok.fco.macho.export.addr");
    SPB.CreateStore(SymtabAddr, Symtab);
    SPB.CreateStore(StrtabAddr, Strtab);
    Value *CanScan = SPB.CreateAnd(
        SPB.CreateICmpNE(SymtabAddr, ConstantInt::get(IP, 0)),
        SPB.CreateAnd(
            SPB.CreateICmpNE(StrtabAddr, ConstantInt::get(IP, 0)),
            SPB.CreateAnd(
                SPB.CreateICmpUGT(SymCount, ConstantInt::get(IP, 0)),
                SPB.CreateICmpUGT(StringSize, ConstantInt::get(IP, 0)))));
    Value *CanTrieScan = SPB.CreateAnd(
        SPB.CreateICmpNE(LinkBase, ConstantInt::get(IP, 0)),
        SPB.CreateAnd(SPB.CreateICmpUGT(ExportOffset, ConstantInt::get(IP, 0)),
                      SPB.CreateICmpUGT(ExportBytes, ConstantInt::get(IP, 0))),
        "morok.fco.macho.trie.can.scan");
    SPB.CreateCondBr(CanTrieScan, TrieScan, TrieMiss);

    IRBuilder<> TSB(TrieScan);
    Value *TriePtr =
        TSB.CreateIntToPtr(ExportAddr, Ptr, "morok.fco.macho.trie.ptr");
    Value *TrieResolved = TSB.CreateCall(
        TrieResolver,
        {Wanted, SiteSalt, TriePtr, ExportBytes,
         TSB.CreatePtrToInt(Hdr, IP, "morok.fco.macho.image.base")},
        "morok.fco.macho.trie.resolved");
    TSB.CreateStore(TrieResolved, FoundSlot);
    TSB.CreateCondBr(
        TSB.CreateICmpNE(TrieResolved, ConstantPointerNull::get(Ptr)), RetFound,
        TrieMiss);

    IRBuilder<> TMB(TrieMiss);
    TMB.CreateCondBr(CanScan, SymLoop, ImageNext);

    IRBuilder<> SLB(SymLoop);
    auto *SymIdx = SLB.CreatePHI(IP, 2, "morok.fco.macho.sym.idx");
    SymIdx->addIncoming(ConstantInt::get(IP, 0), TrieMiss);
    Value *Bound = SLB.CreateSelect(
        SLB.CreateICmpULT(SymCount, ConstantInt::get(IP, 65536)), SymCount,
        ConstantInt::get(IP, 65536));
    SLB.CreateCondBr(SLB.CreateICmpULT(SymIdx, Bound), SymBody, ImageNext);

    IRBuilder<> SBB(SymBody);
    Value *SymBase = SBB.CreateLoad(IP, Symtab, "morok.fco.macho.symtab.load");
    Value *StrBase = SBB.CreateLoad(IP, Strtab, "morok.fco.macho.strtab.load");
    Value *SymPtr = SBB.CreateIntToPtr(
        SBB.CreateAdd(SymBase, SBB.CreateMul(SymIdx, ConstantInt::get(IP, 16))),
        Ptr, "morok.fco.macho.sym.ptr");
    Value *NameOff32 =
        loadAt(SBB, M, I32, SymPtr, 0ULL, "morok.fco.macho.n.strx");
    Value *NType = loadAt(SBB, M, I8, SymPtr, 4, "morok.fco.macho.n.type");
    Value *NValue = loadAt(SBB, M, IP, SymPtr, 8, "morok.fco.macho.n.value");
    Value *NameOff = SBB.CreateZExt(NameOff32, IP, "morok.fco.macho.name.off");
    Value *NamePtrRaw = SBB.CreateIntToPtr(SBB.CreateAdd(StrBase, NameOff), Ptr,
                                           "morok.fco.macho.name.raw");
    Value *First =
        loadAt(SBB, M, I8, NamePtrRaw, 0ULL, "morok.fco.macho.name.first");
    Value *NamePtr =
        SBB.CreateSelect(SBB.CreateICmpEQ(First, ConstantInt::get(I8, '_')),
                         gepI8(SBB, M, NamePtrRaw, ConstantInt::get(IP, 1),
                               "morok.fco.macho.name.skip"),
                         NamePtrRaw, "morok.fco.macho.name.ptr");
    Value *TypeBits = SBB.CreateAnd(NType, ConstantInt::get(I8, 0x0e),
                                    "morok.fco.macho.n.typebits");
    Value *ValidSym = SBB.CreateAnd(
        SBB.CreateICmpULT(NameOff, StringSize),
        SBB.CreateAnd(SBB.CreateICmpEQ(TypeBits, ConstantInt::get(I8, 0x0e)),
                      SBB.CreateICmpNE(NValue, ConstantInt::get(IP, 0))));
    Value *TargetAddr =
        SBB.CreateAdd(Slide, NValue, "morok.fco.macho.target.addr");
    SBB.CreateCondBr(ValidSym, SymCheck, SymNext);

    IRBuilder<> SCB(SymCheck);
    Value *Computed = runtimeSiteHashName(SCB, M, Fn, NamePtr, Family, SiteSalt,
                                          "morok.fco.macho.hash.site");
    SCB.CreateStore(SCB.CreateIntToPtr(TargetAddr, Ptr), FoundSlot);
    SCB.CreateCondBr(
        SCB.CreateICmpEQ(Computed, Wanted, "morok.fco.macho.hash.match"),
        RetFound, SymNext);

    IRBuilder<> SNB(SymNext);
    Value *SymNextIdx = SNB.CreateAdd(SymIdx, ConstantInt::get(IP, 1),
                                      "morok.fco.macho.sym.next");
    SNB.CreateBr(SymLoop);
    SymIdx->addIncoming(SymNextIdx, SymNext);

    IRBuilder<> INB(ImageNext);
    Value *ImageNextIdx = INB.CreateAdd(ImageIdx, ConstantInt::get(I32, 1),
                                        "morok.fco.macho.image.next");
    INB.CreateBr(ImageLoop);
    ImageIdx->addIncoming(ImageNextIdx, ImageNext);

    IRBuilder<> RFB(RetFound);
    RFB.CreateRet(RFB.CreateLoad(Ptr, FoundSlot, "morok.fco.macho.target"));

    IRBuilder<> RNB(RetNull);
    RNB.CreateRet(ConstantPointerNull::get(Ptr));
    return Fn;
}

bool useManualHashResolver(Module &M, const Triple &TT) {
    if (M.getDataLayout().getPointerSizeInBits(0) != 64)
        return false;
    return TT.isOSLinux() || TT.isOSDarwin() ||
           (TT.isOSWindows() && TT.getArch() == Triple::x86_64);
}

Function *manualHashResolver(Module &M, const Triple &TT, unsigned Family) {
    if (TT.isOSLinux())
        return linuxHashResolver(M, Family);
    if (TT.isOSDarwin())
        return darwinHashResolver(M, Family);
    if (TT.isOSWindows())
        return windowsHashResolver(M, Family);
    return nullptr;
}

// Length in bytes of the faulting store emitted by emitFault() (below): `movq
// %rax, (%rax)` encodes as REX.W(0x48) 0x89 0x00 = 3 bytes.  The preceding
// `xorq %rax, %rax` does not fault, so on entry the saved RIP points at this
// store; the exception handler advances RIP by exactly this many bytes to
// resume on the instruction after the fault.  Keep this in lockstep with the
// asm string in emitFault().
constexpr std::uint64_t kFaultStoreLen = 3;

Function *exceptionHandler(Module &M, ExceptionRuntime &Rt,
                           FunctionCallee Resolver, bool ManualResolver,
                           int RtldDefaultVal) {
    if (auto *Existing = M.getFunction("morok.fco.ex.handler"))
        return Existing;

    LLVMContext &Ctx = M.getContext();
    auto *Void = Type::getVoidTy(Ctx);
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    auto *FnTy = FunctionType::get(Void, {I32, Ptr, Ptr}, false);
    auto *Fn = Function::Create(FnTy, GlobalValue::InternalLinkage,
                                "morok.fco.ex.handler", M);
    Fn->setDSOLocal(true);
    auto *Sig = Fn->getArg(0);
    Sig->setName("sig");
    auto *UCtx = Fn->getArg(2);
    UCtx->setName("uctx");

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    BasicBlock *HashCheck = BasicBlock::Create(Ctx, "hash", Fn);
    BasicBlock *Resolve = BasicBlock::Create(Ctx, "resolve", Fn);
    BasicBlock *Done = BasicBlock::Create(Ctx, "done", Fn);

    IRBuilder<> B(Entry);
    constexpr int kSigSegv = 11;
    Value *IsSegv = B.CreateICmpEQ(Sig, ConstantInt::get(I32, kSigSegv),
                                   "morok.fco.ex.sigsegv");
    Value *Name = B.CreateLoad(Ptr, Rt.name, "morok.fco.ex.name.load");
    Value *Out = B.CreateLoad(Ptr, Rt.out, "morok.fco.ex.out.load");
    Value *Cont = B.CreateLoad(Ptr, Rt.cont, "morok.fco.ex.cont.load");
    Value *Hash = B.CreateLoad(I64, Rt.hash, "morok.fco.ex.hash.load");
    Value *NameOk = ManualResolver
                        ? ConstantInt::getTrue(Ctx)
                        : B.CreateICmpNE(Name, ConstantPointerNull::get(Ptr));
    Value *HasRequest = B.CreateAnd(
        NameOk,
        B.CreateAnd(
            B.CreateICmpNE(Out, ConstantPointerNull::get(Ptr)),
            B.CreateAnd(B.CreateICmpNE(Cont, ConstantPointerNull::get(Ptr)),
                        B.CreateICmpNE(Hash, ConstantInt::get(I64, 0)))));
    B.CreateCondBr(B.CreateAnd(IsSegv, HasRequest, "morok.fco.ex.claim"),
                   HashCheck, Done);

    IRBuilder<> HB(HashCheck);
    if (ManualResolver) {
        HB.CreateBr(Resolve);
    } else {
        Value *Computed = runtimeHashName(HB, M, Fn, Name);
        HB.CreateCondBr(
            HB.CreateICmpEQ(Computed, Hash, "morok.fco.ex.hash.match"), Resolve,
            Done);
    }

    IRBuilder<> RB(Resolve);
    Value *Resolved = nullptr;
    if (ManualResolver) {
        Resolved = ConstantPointerNull::get(Ptr);
    } else {
        Value *Rtld =
            RB.CreateIntToPtr(ConstantInt::getSigned(I64, RtldDefaultVal), Ptr);
        Resolved =
            RB.CreateCall(Resolver, {Rtld, Name}, "morok.fco.ex.resolved");
    }
    RB.CreateStore(Resolved, Out);
    RB.CreateStore(ConstantPointerNull::get(Ptr), Rt.name);
    RB.CreateStore(ConstantPointerNull::get(Ptr), Rt.out);
    RB.CreateStore(ConstantPointerNull::get(Ptr), Rt.cont);
    RB.CreateStore(ConstantInt::get(I64, 0), Rt.hash);
    // Resume by advancing the saved RIP PAST the faulting store, rather than
    // jumping to the recorded `Cont` blockaddress.  emitFault() always emits the
    // 3-byte `movq %rax, (%rax)` (REX.W 48 / 89 / 00) as the faulting
    // instruction, and the kernel leaves uc_mcontext.rip pointing at it, so
    // RIP += kFaultStoreLen lands on whatever the call site emitted next (the
    // branch into the resolver) along the *actual* execution path.
    //
    // The blockaddress form is unsafe: FunctionCallObfuscate runs before
    // SplitBasicBlocks and BogusControlFlow (see pipeline/Scheduler.cpp), which
    // clone and split the fault block afterwards.  That can divorce the recorded
    // continuation from the path actually taken, or drop the block whose address
    // was taken so the BlockAddress folds to null — the handler would then set
    // RIP=0 and the thread would fault on address 0 forever (observed as an
    // infinite SIGSEGV storm hanging fp_piecewise_chaos / syscall_file_ops at
    // -preset high on x86_64 Linux).  Skipping the fixed-length fault follows the
    // real instruction stream and is immune to any later CFG transform.
    auto *IP = M.getDataLayout().getIntPtrType(Ctx);
    Value *RipSlot =
        gepI8(RB, M, UCtx, constIp(M, 168), "morok.fco.ex.rip.slot");
    Value *FaultRip = RB.CreateLoad(IP, RipSlot, "morok.fco.ex.rip.cur");
    Value *NextRip = RB.CreateAdd(
        FaultRip, ConstantInt::get(IP, kFaultStoreLen), "morok.fco.ex.rip.next");
    RB.CreateStore(NextRip, RipSlot);
    (void)Cont; // retained only as a non-null claim sentinel (see HasRequest)
    RB.CreateBr(Done);

    IRBuilder<> DB(Done);
    DB.CreateRetVoid();
    return Fn;
}

void storeSigaction(IRBuilder<> &B, Module &M, AllocaInst *Action,
                    Function *Handler) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    constexpr std::uint64_t kSigactionSize = 152;
    constexpr std::uint64_t kFlagsOffset = 136;
    constexpr std::uint32_t kSaSiginfo = 4;

    zeroBytes(B, M, Action, kSigactionSize);
    B.CreateStore(Handler,
                  gepI8(B, M, Action, constIp(M, 0), "morok.fco.ex.sa.fn"));
    B.CreateStore(
        ConstantInt::get(I32, kSaSiginfo),
        gepI8(B, M, Action, constIp(M, kFlagsOffset), "morok.fco.ex.sa.flags"));
}

void moveGlobalCtorToFront(Module &M, Function *Ctor) {
    GlobalVariable *GV = M.getGlobalVariable("llvm.global_ctors");
    if (!GV || !GV->hasInitializer())
        return;
    auto *Arr = dyn_cast<ConstantArray>(GV->getInitializer());
    if (!Arr)
        return;

    SmallVector<Constant *, 16> Matches;
    SmallVector<Constant *, 16> Rest;
    for (Use &ElemUse : Arr->operands()) {
        auto *Entry = dyn_cast<Constant>(ElemUse.get());
        auto *CS = dyn_cast_or_null<ConstantStruct>(Entry);
        if (CS && CS->getNumOperands() >= 2) {
            if (auto *Target = dyn_cast<Constant>(CS->getOperand(1))) {
                if (Target->stripPointerCasts() == Ctor) {
                    Matches.push_back(Entry);
                    continue;
                }
            }
        }
        Rest.push_back(Entry);
    }

    if (Matches.empty())
        return;
    Matches.append(Rest.begin(), Rest.end());
    GV->setInitializer(ConstantArray::get(cast<ArrayType>(GV->getValueType()),
                                          Matches));
}

bool hasGlobalCtors(const Module &M) {
    const GlobalVariable *GV = M.getGlobalVariable("llvm.global_ctors");
    if (!GV || !GV->hasInitializer())
        return false;
    auto *Arr = dyn_cast<ConstantArray>(GV->getInitializer());
    return Arr && Arr->getNumOperands() != 0;
}

ExceptionRuntime ensureExceptionRuntime(Module &M, FunctionCallee Resolver,
                                        bool ManualResolver,
                                        int RtldDefaultVal) {
    ExceptionRuntime Rt;
    Rt.hash = pendingI64Global(M, "morok.fco.ex.pending.hash");
    Rt.name = pendingPtrGlobal(M, "morok.fco.ex.pending.name");
    Rt.out = pendingPtrGlobal(M, "morok.fco.ex.pending.out");
    Rt.cont = pendingPtrGlobal(M, "morok.fco.ex.pending.cont");

    if (M.getFunction("morok.fco.ex.install"))
        return Rt;

    LLVMContext &Ctx = M.getContext();
    auto *Void = Type::getVoidTy(Ctx);
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    Function *Handler =
        exceptionHandler(M, Rt, Resolver, ManualResolver, RtldDefaultVal);
    auto *Ctor = Function::Create(FunctionType::get(Void, false),
                                  GlobalValue::InternalLinkage,
                                  "morok.fco.ex.install", M);
    Ctor->setDSOLocal(true);
    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Ctor);
    IRBuilder<> B(Entry);
    auto *ActionTy = ArrayType::get(I8, 152);
    AllocaInst *Action = B.CreateAlloca(ActionTy, nullptr, "morok.fco.ex.sa");
    storeSigaction(B, M, Action, Handler);
    constexpr int kSigSegv = 11;
    B.CreateCall(sigactionDecl(M), {ConstantInt::get(I32, kSigSegv), Action,
                                    ConstantPointerNull::get(Ptr)});
    B.CreateRetVoid();
    appendToGlobalCtors(M, Ctor, 0);
    // Earlier module passes can emit priority-0 startup hooks before FCO runs.
    // If those hooks contain FCO-rewritten calls, they must not fault before the
    // FCO SIGSEGV handler is installed.
    moveGlobalCtorToFront(M, Ctor);
    return Rt;
}

void emitFault(IRBuilder<> &B) {
    auto *AsmTy = FunctionType::get(Type::getVoidTy(B.getContext()), false);
    InlineAsm *IA =
        InlineAsm::get(AsmTy, "xorq %rax, %rax\n\tmovq %rax, (%rax)",
                       "~{rax},~{dirflag},~{fpsr},~{flags},~{memory}",
                       /*hasSideEffects=*/true);
    B.CreateCall(AsmTy, IA);
}

Value *pointerKey(IRBuilder<> &B, Module &M, ir::IRRandom &rng,
                  std::uint64_t SiteKey, unsigned Variant, std::uint64_t Mul,
                  std::uint64_t Mask) {
    auto *I64 = Type::getInt64Ty(M.getContext());
    GlobalVariable *Seed = ir::cloakSeed(M, rng);
    LoadInst *SeedLoad =
        B.CreateLoad(I64, Seed, /*isVolatile=*/true, "morok.fco.ptr.seed");
    Value *K0 = B.CreateXor(SeedLoad, ConstantInt::get(I64, SiteKey),
                            "morok.fco.ptr.k0");
    Value *K = ir::emitKeystream(B, Variant, K0, 0, Mul);
    return B.CreateXor(K, ConstantInt::get(I64, Mask), "morok.fco.ptr.key");
}

AllocaInst *entryAlloca(Function &F, Type *Ty, StringRef Name);

Value *encodeResolvedPointer(IRBuilder<> &B, Module &M, Value *Resolved,
                             ir::IRRandom &rng);

Value *emitManualDlsymLookup(IRBuilder<> &B, Module &M, FunctionCallee Resolver,
                             StringRef Symbol, std::uint64_t DlsymHash,
                             std::uint64_t DlsymSalt, int RtldDefaultVal,
                             ir::IRRandom &rng) {
    LLVMContext &Ctx = M.getContext();
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *Ptr = PointerType::getUnqual(M.getContext());
    Value *DlsymPtr = B.CreateCall(
        Resolver,
        {ConstantInt::get(I64, DlsymHash), ConstantInt::get(I64, DlsymSalt)},
        "morok.fco.dlsym.resolved");
    Function *F = B.GetInsertBlock()->getParent();
    BasicBlock *CallBB = BasicBlock::Create(Ctx, "morok.fco.dlsym.call", F);
    BasicBlock *NullBB = BasicBlock::Create(Ctx, "morok.fco.dlsym.null", F);
    BasicBlock *ContBB = BasicBlock::Create(Ctx, "morok.fco.dlsym.cont", F);
    B.CreateCondBr(B.CreateICmpNE(DlsymPtr, ConstantPointerNull::get(Ptr),
                                  "morok.fco.dlsym.available"),
                   CallBB, NullBB);

    auto *DlsymTy = FunctionType::get(Ptr, {Ptr, Ptr}, false);
    IRBuilder<> CB(CallBB);
    Value *Name = ir::emitCloakedSymbol(CB, M, Symbol, rng);
    Value *Rtld = CB.CreateIntToPtr(ConstantInt::getSigned(I64, RtldDefaultVal),
                                    Ptr, "morok.fco.dlsym.rtld");
    Value *Fallback = CB.CreateCall(DlsymTy, DlsymPtr, {Rtld, Name},
                                    "morok.fco.dlsym.fallback");
    CB.CreateBr(ContBB);

    IRBuilder<> NB(NullBB);
    NB.CreateBr(ContBB);

    IRBuilder<> PB(ContBB);
    PHINode *Result = PB.CreatePHI(Ptr, 2, "morok.fco.dlsym.result");
    Result->addIncoming(Fallback, CallBB);
    Result->addIncoming(ConstantPointerNull::get(Ptr), NullBB);
    B.SetInsertPoint(ContBB);
    return Result;
}

Value *emitResolvedViaException(CallInst *CI, Module &M, ExceptionRuntime &Rt,
                                FunctionCallee Resolver, bool ManualResolver,
                                Value *Name, std::uint64_t Hash,
                                ir::IRRandom &rng) {
    Function *Parent = CI->getFunction();
    BasicBlock *Pre = CI->getParent();
    BasicBlock *Cont = SplitBlock(Pre, CI);
    Cont->setName("morok.fco.ex.cont");
    Instruction *Term = Pre->getTerminator();
    IRBuilder<> B(Term);
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *Ptr = PointerType::getUnqual(M.getContext());
    AllocaInst *Slot = entryAlloca(*Parent, Ptr, "morok.fco.ex.slot");

    B.CreateStore(ConstantPointerNull::get(Ptr), Slot);
    B.CreateStore(ConstantInt::get(I64, Hash), Rt.hash);
    B.CreateStore(Name ? Name : ConstantPointerNull::get(Ptr), Rt.name);
    B.CreateStore(Slot, Rt.out);
    B.CreateStore(BlockAddress::get(Parent, Cont), Rt.cont);
    emitFault(B);

    IRBuilder<> CB(CI);
    Value *Resolved = nullptr;
    if (ManualResolver) {
        Resolved = CB.CreateCall(Resolver, {ConstantInt::get(I64, Hash)},
                                 "morok.fco.hash.resolved");
    } else {
        LoadInst *Reload =
            CB.CreateLoad(Ptr, Slot, "morok.fco.ex.resolved.reload");
        Reload->setVolatile(true);
        Resolved = Reload;
    }
    return encodeResolvedPointer(CB, M, Resolved, rng);
}

Value *emitCachedResolvedViaException(
    CallInst *CI, Module &M, ExceptionRuntime &Rt, FunctionCallee Resolver,
    const std::vector<std::uint64_t> &Hashes, std::uint64_t SiteSalt,
    StringRef Symbol, std::uint64_t DlsymHash, std::uint64_t DlsymSalt,
    bool UseDlsymFallback, int RtldDefaultVal, ir::IRRandom &rng) {
    LLVMContext &Ctx = M.getContext();
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    const unsigned Variant = rng.range(ir::kKeystreamVariants);
    const std::uint64_t SiteKey = rng.next();
    const std::uint64_t Mul = rng.next() | 1ull;
    const std::uint64_t Mask = rng.next();

    auto *Cache = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, 0), "morok.fco.cache");
    Cache->setAlignment(Align(8));

    Function *F = CI->getFunction();
    BasicBlock *HitBB = CI->getParent();
    BasicBlock *ContBB = HitBB->splitBasicBlock(CI, "morok.fco.ex.cache.cont");
    HitBB->getTerminator()->eraseFromParent();
    BasicBlock *MissBB =
        BasicBlock::Create(Ctx, "morok.fco.ex.cache.miss", F, ContBB);
    BasicBlock *ResolveBB =
        BasicBlock::Create(Ctx, "morok.fco.ex.cache.resolve", F, ContBB);
    BasicBlock *FallbackBB = nullptr;
    BasicBlock *StoreBB = ResolveBB;
    if (UseDlsymFallback) {
        FallbackBB =
            BasicBlock::Create(Ctx, "morok.fco.ex.cache.dlsym", F, ContBB);
        StoreBB =
            BasicBlock::Create(Ctx, "morok.fco.ex.cache.store", F, ContBB);
    }

    IRBuilder<> HB(HitBB);
    LoadInst *Cached =
        HB.CreateLoad(I64, Cache, "morok.fco.cache.encoded.load");
    Cached->setVolatile(true);
    HB.CreateCondBr(HB.CreateICmpNE(Cached, ConstantInt::get(I64, 0),
                                    "morok.fco.cache.ready"),
                    ContBB, MissBB);

    IRBuilder<> MB(MissBB);
    AllocaInst *Slot = entryAlloca(*F, Ptr, "morok.fco.ex.slot");
    MB.CreateStore(ConstantPointerNull::get(Ptr), Slot);
    MB.CreateStore(ConstantInt::get(I64, Hashes.front()), Rt.hash);
    MB.CreateStore(ConstantPointerNull::get(Ptr), Rt.name);
    MB.CreateStore(Slot, Rt.out);
    MB.CreateStore(BlockAddress::get(F, ResolveBB), Rt.cont);
    emitFault(MB);
    MB.CreateBr(ResolveBB);

    IRBuilder<> RB(ResolveBB);
    Value *Resolved = RB.CreateCall(Resolver,
                                    {ConstantInt::get(I64, Hashes.front()),
                                     ConstantInt::get(I64, SiteSalt)},
                                    "morok.fco.hash.resolved");
    for (std::uint64_t AliasHash : ArrayRef(Hashes).drop_front()) {
        Value *AliasResolved = RB.CreateCall(
            Resolver,
            {ConstantInt::get(I64, AliasHash), ConstantInt::get(I64, SiteSalt)},
            "morok.fco.hash.alias.resolved");
        Resolved = RB.CreateSelect(
            RB.CreateICmpEQ(Resolved, ConstantPointerNull::get(Ptr)),
            AliasResolved, Resolved, "morok.fco.hash.resolved.alias.sel");
    }
    if (UseDlsymFallback) {
        RB.CreateCondBr(RB.CreateICmpEQ(Resolved, ConstantPointerNull::get(Ptr),
                                        "morok.fco.hash.miss"),
                        FallbackBB, StoreBB);
    }

    Value *ResolvedForStore = Resolved;
    if (UseDlsymFallback) {
        IRBuilder<> FB(FallbackBB);
        Value *FallbackResolved = emitManualDlsymLookup(
            FB, M, Resolver, Symbol, DlsymHash, DlsymSalt, RtldDefaultVal, rng);
        BasicBlock *FallbackIncoming = FB.GetInsertBlock();
        FB.CreateBr(StoreBB);

        IRBuilder<> SB(StoreBB);
        PHINode *FinalResolved =
            SB.CreatePHI(Ptr, 2, "morok.fco.hash.resolved.final");
        FinalResolved->addIncoming(Resolved, ResolveBB);
        FinalResolved->addIncoming(FallbackResolved, FallbackIncoming);
        ResolvedForStore = FinalResolved;
        RB.SetInsertPoint(StoreBB);
    }

    Value *MissKey = pointerKey(RB, M, rng, SiteKey, Variant, Mul, Mask);
    Value *NewEncoded = RB.CreateXor(RB.CreatePtrToInt(ResolvedForStore, I64),
                                     MissKey, "morok.fco.cache.encoded");
    StoreInst *CacheStore = RB.CreateStore(NewEncoded, Cache);
    CacheStore->setVolatile(true);
    RB.CreateBr(ContBB);

    IRBuilder<> CB(CI);
    PHINode *Encoded = CB.CreatePHI(I64, 2, "morok.fco.cache.encoded.phi");
    Encoded->addIncoming(Cached, HitBB);
    Encoded->addIncoming(NewEncoded, StoreBB);
    Value *HitKey = pointerKey(CB, M, rng, SiteKey, Variant, Mul, Mask);
    Value *Raw = CB.CreateXor(Encoded, HitKey, "morok.fco.cache.raw");
    return CB.CreateIntToPtr(Raw, Ptr, "morok.fco.cache.ptr");
}

AllocaInst *entryAlloca(Function &F, Type *Ty, StringRef Name) {
    IRBuilder<> EntryB(&*F.getEntryBlock().getFirstInsertionPt());
    return EntryB.CreateAlloca(Ty, nullptr, Name);
}

Value *emitCachedManualResolved(CallInst *CI, Module &M,
                                FunctionCallee Resolver,
                                const std::vector<std::uint64_t> &Hashes,
                                std::uint64_t SiteSalt, StringRef Symbol,
                                std::uint64_t DlsymHash,
                                std::uint64_t DlsymSalt, bool UseDlsymFallback,
                                int RtldDefaultVal, ir::IRRandom &rng) {
    LLVMContext &Ctx = M.getContext();
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    const unsigned Variant = rng.range(ir::kKeystreamVariants);
    const std::uint64_t SiteKey = rng.next();
    const std::uint64_t Mul = rng.next() | 1ull;
    const std::uint64_t Mask = rng.next();

    auto *Cache = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, 0), "morok.fco.cache");
    Cache->setAlignment(Align(8));

    Function *F = CI->getFunction();
    BasicBlock *HitBB = CI->getParent();
    BasicBlock *ContBB = HitBB->splitBasicBlock(CI, "morok.fco.cache.cont");
    HitBB->getTerminator()->eraseFromParent();
    BasicBlock *MissBB =
        BasicBlock::Create(Ctx, "morok.fco.cache.miss", F, ContBB);
    BasicBlock *FallbackBB = nullptr;
    BasicBlock *StoreBB = MissBB;
    if (UseDlsymFallback) {
        FallbackBB =
            BasicBlock::Create(Ctx, "morok.fco.cache.dlsym", F, ContBB);
        StoreBB = BasicBlock::Create(Ctx, "morok.fco.cache.store", F, ContBB);
    }

    IRBuilder<> HB(HitBB);
    LoadInst *Cached =
        HB.CreateLoad(I64, Cache, "morok.fco.cache.encoded.load");
    Cached->setVolatile(true);
    HB.CreateCondBr(HB.CreateICmpNE(Cached, ConstantInt::get(I64, 0)), ContBB,
                    MissBB);

    IRBuilder<> MB(MissBB);
    Value *Resolved = MB.CreateCall(Resolver,
                                    {ConstantInt::get(I64, Hashes.front()),
                                     ConstantInt::get(I64, SiteSalt)},
                                    "morok.fco.hash.resolved");
    for (std::uint64_t AliasHash : ArrayRef(Hashes).drop_front()) {
        Value *AliasResolved = MB.CreateCall(
            Resolver,
            {ConstantInt::get(I64, AliasHash), ConstantInt::get(I64, SiteSalt)},
            "morok.fco.hash.alias.resolved");
        Resolved = MB.CreateSelect(
            MB.CreateICmpEQ(Resolved, ConstantPointerNull::get(Ptr)),
            AliasResolved, Resolved, "morok.fco.hash.resolved.alias.sel");
    }
    if (UseDlsymFallback) {
        MB.CreateCondBr(MB.CreateICmpEQ(Resolved, ConstantPointerNull::get(Ptr),
                                        "morok.fco.hash.miss"),
                        FallbackBB, StoreBB);
    }

    Value *ResolvedForStore = Resolved;
    if (UseDlsymFallback) {
        IRBuilder<> FB(FallbackBB);
        Value *FallbackResolved = emitManualDlsymLookup(
            FB, M, Resolver, Symbol, DlsymHash, DlsymSalt, RtldDefaultVal, rng);
        BasicBlock *FallbackIncoming = FB.GetInsertBlock();
        FB.CreateBr(StoreBB);

        IRBuilder<> SB(StoreBB);
        PHINode *FinalResolved =
            SB.CreatePHI(Ptr, 2, "morok.fco.hash.resolved.final");
        FinalResolved->addIncoming(Resolved, MissBB);
        FinalResolved->addIncoming(FallbackResolved, FallbackIncoming);
        ResolvedForStore = FinalResolved;
        MB.SetInsertPoint(StoreBB);
    }

    Value *MissKey = pointerKey(MB, M, rng, SiteKey, Variant, Mul, Mask);
    Value *NewEncoded = MB.CreateXor(MB.CreatePtrToInt(ResolvedForStore, I64),
                                     MissKey, "morok.fco.cache.encoded");
    StoreInst *CacheStore = MB.CreateStore(NewEncoded, Cache);
    CacheStore->setVolatile(true);
    MB.CreateBr(ContBB);

    IRBuilder<> CB(CI);
    PHINode *Encoded = CB.CreatePHI(I64, 2, "morok.fco.cache.encoded.phi");
    Encoded->addIncoming(Cached, HitBB);
    Encoded->addIncoming(NewEncoded, StoreBB);
    Value *HitKey = pointerKey(CB, M, rng, SiteKey, Variant, Mul, Mask);
    Value *Raw = CB.CreateXor(Encoded, HitKey, "morok.fco.cache.raw");
    return CB.CreateIntToPtr(Raw, Ptr, "morok.fco.cache.ptr");
}

Value *encodeResolvedPointer(IRBuilder<> &B, Module &M, Value *Resolved,
                             ir::IRRandom &rng) {
    auto *I64 = Type::getInt64Ty(M.getContext());
    const unsigned Variant = rng.range(ir::kKeystreamVariants);
    const unsigned Mode = rng.range(3);
    const std::uint64_t SiteKey = rng.next();
    const std::uint64_t Mul = rng.next() | 1ull;
    const std::uint64_t Mask = rng.next();
    const std::uint64_t PtrMul = rng.next() | 1ull;
    const std::uint64_t PtrMulInv = core::modInverse64(PtrMul);

    Value *Raw = B.CreatePtrToInt(Resolved, I64, "morok.fco.ptr.raw");
    Value *EncKey = pointerKey(B, M, rng, SiteKey, Variant, Mul, Mask);
    Value *Encoded = nullptr;
    switch (Mode) {
    case 1:
        Encoded = B.CreateXor(B.CreateAdd(Raw, EncKey, "morok.fco.ptr.add"),
                              rotl64(B, EncKey, 29), "morok.fco.ptr.enc");
        break;
    case 2:
        Encoded = B.CreateXor(
            B.CreateMul(B.CreateAdd(Raw, EncKey, "morok.fco.ptr.add"),
                        ConstantInt::get(I64, PtrMul), "morok.fco.ptr.mul"),
            EncKey, "morok.fco.ptr.enc");
        break;
    default:
        Encoded = B.CreateAdd(B.CreateXor(Raw, EncKey, "morok.fco.ptr.xor"),
                              rotl64(B, EncKey, 17), "morok.fco.ptr.enc");
        break;
    }

    AllocaInst *Slot = entryAlloca(*B.GetInsertBlock()->getParent(), I64,
                                   "morok.fco.ptr.slot");
    B.CreateStore(Encoded, Slot, /*isVolatile=*/true);
    LoadInst *EncodedLoad =
        B.CreateLoad(I64, Slot, /*isVolatile=*/true, "morok.fco.ptr.reload");
    Value *DecKey = pointerKey(B, M, rng, SiteKey, Variant, Mul, Mask);
    Value *DecodedInt = nullptr;
    switch (Mode) {
    case 1:
        DecodedInt = B.CreateSub(B.CreateXor(EncodedLoad, rotl64(B, DecKey, 29),
                                             "morok.fco.ptr.unxor"),
                                 DecKey, "morok.fco.ptr.dec.i");
        break;
    case 2:
        DecodedInt = B.CreateSub(
            B.CreateMul(B.CreateXor(EncodedLoad, DecKey, "morok.fco.ptr.unxor"),
                        ConstantInt::get(I64, PtrMulInv),
                        "morok.fco.ptr.unmul"),
            DecKey, "morok.fco.ptr.dec.i");
        break;
    default:
        DecodedInt = B.CreateXor(B.CreateSub(EncodedLoad, rotl64(B, DecKey, 17),
                                             "morok.fco.ptr.unadd"),
                                 DecKey, "morok.fco.ptr.dec.i");
        break;
    }
    return B.CreateIntToPtr(DecodedInt, PointerType::getUnqual(M.getContext()),
                            "morok.fco.ptr.dec");
}

} // namespace

bool functionCallObfuscateModule(Module &M, const FcoParams &params,
                                 ir::IRRandom &rng) {
    if (params.probability == 0 || params.max_calls == 0)
        return false;

    const std::uint32_t Limit = std::min(params.max_calls, kMaxCallsPerModule);

    std::vector<CallBase *> targets;
    targets.reserve(Limit);
    for (Function &F : M) {
        if (targets.size() >= Limit)
            break;
        if (F.isDeclaration() || F.getName().starts_with("morok."))
            continue;
        for (Instruction &inst : instructions(F)) {
            if (targets.size() >= Limit)
                break;
            if (auto *cb = dyn_cast<CallBase>(&inst))
                if (eligible(cb))
                    if (rng.chance(params.probability))
                        targets.push_back(cb);
        }
    }
    if (targets.empty())
        return false;

    LLVMContext &ctx = M.getContext();
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    const Triple tt(M.getTargetTriple());
    const int rtldDefaultVal = tt.isOSDarwin() ? -2 : 0; // RTLD_DEFAULT
    const bool manualResolver = useManualHashResolver(M, tt);
    const bool manualDlsymFallback = manualResolver && tt.isOSLinux();

    // Derive resolver-family hash keys before any resolver IR is emitted, so
    // runtime hashers and pass-time hashName() share one key per family.
    {
        HashKeySet keys;
        for (unsigned family = 0; family != kResolverFamilyCount; ++family) {
            keys[family] = HashKey{kFnvOffset ^ rng.next(), rng.next() | 1ull};
            for (unsigned other = 0; other != family; ++other)
                if (keys[family].offset == keys[other].offset ||
                    keys[family].prime == keys[other].prime)
                    keys[family].prime ^= (rng.next() | 1ull);
        }
        setHashKeys(M, keys);
    }

    std::vector<TargetPlan> plans;
    plans.reserve(targets.size());
    for (CallBase *cb : targets) {
        StringRef dlName = cb->getCalledFunction()->getName();
        if (dlName.consume_front(StringRef("\x01", 1)) && tt.isOSDarwin())
            dlName.consume_front("_");

        TargetPlan plan;
        plan.call = cb;
        plan.name = dlName.str();
        plan.family = manualResolver ? rng.range(kResolverFamilyCount) : 0;
        if (manualDlsymFallback) {
            plan.dlsym_salt = rng.next() | 1ull;
            plan.dlsym_hash =
                hashName("dlsym", M, plan.family, plan.dlsym_salt);
        }

        for (unsigned attempt = 0; attempt != 64; ++attempt) {
            plan.site_salt = rng.next() | 1ull;
            plan.hashes.clear();
            plan.hashes.push_back(
                manualResolver
                    ? hashName(plan.name, M, plan.family, plan.site_salt)
                    : baseHashName(plan.name, M, 0));
            if (manualResolver && tt.isOSDarwin()) {
                std::vector<std::uint64_t> aliases = darwinAliasHashes(
                    plan.name, M, plan.family, plan.site_salt);
                plan.hashes.insert(plan.hashes.end(), aliases.begin(),
                                   aliases.end());
            }

            std::unordered_set<std::uint64_t> unique;
            bool ok = true;
            for (std::uint64_t H : plan.hashes) {
                if (H == 0 || !unique.insert(H).second) {
                    ok = false;
                    break;
                }
            }
            if (ok)
                break;
        }
        plans.push_back(std::move(plan));
    }

    auto resolverForFamily = [&](unsigned Family) -> FunctionCallee {
        if (!manualResolver)
            return dlsymDecl(M);
        Function *Fn = manualHashResolver(M, tt, Family);
        return FunctionCallee(Fn->getFunctionType(), Fn);
    };
    FunctionCallee fallbackResolver = resolverForFamily(0);
    const bool exceptionCalls = useExceptionCalls(tt) && !hasGlobalCtors(M);
    ExceptionRuntime exceptionRt;
    if (exceptionCalls)
        exceptionRt = ensureExceptionRuntime(M, fallbackResolver,
                                             manualResolver, rtldDefaultVal);

    bool changed = false;
    for (TargetPlan &plan : plans) {
        CallBase *cb = plan.call;
        Function *callee = cb->getCalledFunction();

        IRBuilder<> B(cb);
        // dlsym needs the plain C symbol name.  LLVM may carry a `\01`-escaped
        // asm name (e.g. macOS libc's `\01_fwrite`); strip the escape and the
        // platform underscore, otherwise dlsym returns null and the redirected
        // call jumps to address 0.
        const std::uint64_t symHash = plan.hashes.front();
        const std::vector<std::uint64_t> &resolverHashes = plan.hashes;
        FunctionCallee resolver = resolverForFamily(plan.family);
        Value *name = manualResolver
                          ? nullptr
                          : ir::emitCloakedSymbol(B, M, plan.name, rng);
        Value *decoded = nullptr;
        if (exceptionCalls && manualResolver && isa<CallInst>(cb)) {
            decoded = emitCachedResolvedViaException(
                cast<CallInst>(cb), M, exceptionRt, resolver, resolverHashes,
                plan.site_salt, plan.name, plan.dlsym_hash, plan.dlsym_salt,
                manualDlsymFallback, rtldDefaultVal, rng);
        } else if (exceptionCalls && isa<CallInst>(cb)) {
            decoded = emitResolvedViaException(
                cast<CallInst>(cb), M, exceptionRt, resolver, manualResolver,
                name, symHash, rng);
        } else if (manualResolver && isa<CallInst>(cb)) {
            decoded = emitCachedManualResolved(
                cast<CallInst>(cb), M, resolver, resolverHashes, plan.site_salt,
                plan.name, plan.dlsym_hash, plan.dlsym_salt,
                manualDlsymFallback, rtldDefaultVal, rng);
        } else if (manualResolver) {
            Value *resolved =
                B.CreateCall(resolver,
                             {ConstantInt::get(i64, symHash),
                              ConstantInt::get(i64, plan.site_salt)},
                             "morok.fco.hash.resolved");
            for (std::uint64_t AliasHash :
                 ArrayRef(resolverHashes).drop_front()) {
                Value *AliasResolved =
                    B.CreateCall(resolver,
                                 {ConstantInt::get(i64, AliasHash),
                                  ConstantInt::get(i64, plan.site_salt)},
                                 "morok.fco.hash.alias.resolved");
                resolved = B.CreateSelect(
                    B.CreateICmpEQ(resolved, ConstantPointerNull::get(ptr)),
                    AliasResolved, resolved,
                    "morok.fco.hash.resolved.alias.sel");
            }
            if (manualDlsymFallback) {
                Function *F = cb->getFunction();
                BasicBlock *ResolveBB = cb->getParent();
                BasicBlock *ContBB = ResolveBB->splitBasicBlock(
                    cb->getIterator(), "morok.fco.hash.cont");
                ResolveBB->getTerminator()->eraseFromParent();
                BasicBlock *FallbackBB =
                    BasicBlock::Create(ctx, "morok.fco.hash.dlsym", F, ContBB);
                IRBuilder<> RB(ResolveBB);
                RB.CreateCondBr(RB.CreateICmpEQ(resolved,
                                                ConstantPointerNull::get(ptr),
                                                "morok.fco.hash.miss"),
                                FallbackBB, ContBB);

                IRBuilder<> FB(FallbackBB);
                Value *FallbackResolved = emitManualDlsymLookup(
                    FB, M, resolver, plan.name, plan.dlsym_hash,
                    plan.dlsym_salt, rtldDefaultVal, rng);
                BasicBlock *FallbackIncoming = FB.GetInsertBlock();
                FB.CreateBr(ContBB);

                IRBuilder<> CB(&*ContBB->getFirstInsertionPt());
                PHINode *FinalResolved =
                    CB.CreatePHI(ptr, 2, "morok.fco.hash.resolved.final");
                FinalResolved->addIncoming(resolved, ResolveBB);
                FinalResolved->addIncoming(FallbackResolved, FallbackIncoming);
                decoded = encodeResolvedPointer(CB, M, FinalResolved, rng);
            } else {
                decoded = encodeResolvedPointer(B, M, resolved, rng);
            }
        } else {
            Value *rtld = B.CreateIntToPtr(
                ConstantInt::getSigned(i64, rtldDefaultVal), ptr);
            Value *resolved = B.CreateCall(resolver, {rtld, name});
            decoded = encodeResolvedPointer(B, M, resolved, rng);
        }

        std::vector<Value *> args = argsOf(*cb);
        CallBase *indirect = nullptr;
        IRBuilder<> CallB(cb);
        if (auto *ci = dyn_cast<CallInst>(cb)) {
            auto *call =
                CallB.CreateCall(callee->getFunctionType(), decoded, args);
            call->setTailCallKind(ci->getTailCallKind());
            indirect = call;
        } else {
            auto *ii = cast<InvokeInst>(cb);
            indirect = CallB.CreateInvoke(callee->getFunctionType(), decoded,
                                          ii->getNormalDest(),
                                          ii->getUnwindDest(), args);
        }
        indirect->setCallingConv(cb->getCallingConv());
        indirect->setAttributes(cb->getAttributes());
        indirect->setDebugLoc(cb->getDebugLoc());
        indirect->copyMetadata(*cb);

        cb->replaceAllUsesWith(indirect);
        cb->eraseFromParent();
        changed = true;
    }
    clearHashKey(M);
    return changed;
}

PreservedAnalyses FunctionCallObfuscatePass::run(Module &M,
                                                 ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return functionCallObfuscateModule(M, params_, rng)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
}

} // namespace morok::passes
