// SPDX-License-Identifier: MIT
//
// Tests for Annotations — per-function obfuscation opt-in/opt-out.

#include "TestHelpers.hpp"

#include "morok/ir/Annotations.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"

using namespace llvm;
using namespace morok::test;

namespace {

const char *kSimpleFn = R"ir(
define i32 @foo(i32 %x) {
entry:
  ret i32 %x
}

define i32 @bar(i32 %x) {
entry:
  ret i32 %x
}
)ir";

} // namespace

TEST_CASE("materializeAnnotations copies annotations to metadata") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleFn);
    Function *F = M->getFunction("foo");
    REQUIRE(F);

    // Manually add an annotation via llvm.global.annotations
    auto *AnnoStr = ConstantDataArray::getString(ctx, "sub");
    auto *AnnoGV = new GlobalVariable(
        *M, AnnoStr->getType(), true, GlobalValue::PrivateLinkage, AnnoStr,
        ".str");

    auto *Int8PtrTy = PointerType::getUnqual(Type::getInt8Ty(ctx));
    auto *CastExpr = ConstantExpr::getBitCast(AnnoGV, Int8PtrTy);
    auto *FnCast = ConstantExpr::getBitCast(F, Int8PtrTy);

    // Create the annotation tuple: {fn_ptr, annotation_ptr, translation_unit,
    // line}
    auto *Zero = ConstantInt::get(Type::getInt32Ty(ctx), 0);
    Constant *GEPIndices[] = {Zero, Zero};
    auto *AnnoPtr = ConstantExpr::getGetElementPtr(
        AnnoStr->getType(), AnnoGV, GEPIndices);

    StructType *AnnoTy = StructType::get(Int8PtrTy, Int8PtrTy,
                                         Type::getInt32Ty(ctx), Int8PtrTy);
    auto *AnnoStruct =
        ConstantStruct::get(AnnoTy, FnCast, AnnoPtr, Zero, CastExpr);

    auto *AnnoArray = ConstantArray::get(
        ArrayType::get(AnnoTy, 1), {AnnoStruct});
    new GlobalVariable(*M, AnnoArray->getType(), true,
                       GlobalValue::AppendingLinkage, AnnoArray,
                       "llvm.global.annotations");

    morok::ir::materializeAnnotations(*M);

    CHECK(morok::ir::hasAnnotation(*F, "sub"));
}

TEST_CASE("hasAnnotation returns false for absent annotations") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleFn);
    Function *F = M->getFunction("foo");
    REQUIRE(F);

    CHECK_FALSE(morok::ir::hasAnnotation(*F, "sub"));
    CHECK_FALSE(morok::ir::hasAnnotation(*F, "nosub"));
}

TEST_CASE("addAnnotation attaches metadata") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleFn);
    Function *F = M->getFunction("foo");
    REQUIRE(F);

    CHECK_FALSE(morok::ir::hasAnnotation(*F, "sub"));
    morok::ir::addAnnotation(*F, "sub");
    CHECK(morok::ir::hasAnnotation(*F, "sub"));
}

TEST_CASE("addAnnotation is idempotent") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleFn);
    Function *F = M->getFunction("foo");
    REQUIRE(F);

    morok::ir::addAnnotation(*F, "sub");
    morok::ir::addAnnotation(*F, "sub");
    CHECK(morok::ir::hasAnnotation(*F, "sub"));
}

TEST_CASE("shouldObfuscate with explicit annotation forces true") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleFn);
    Function *F = M->getFunction("foo");
    REQUIRE(F);

    morok::ir::addAnnotation(*F, "sub");
    CHECK(morok::ir::shouldObfuscate(*F, "sub", false));
}

TEST_CASE("shouldObfuscate with no<attr> annotation forces false") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleFn);
    Function *F = M->getFunction("foo");
    REQUIRE(F);

    morok::ir::addAnnotation(*F, "nosub");
    CHECK_FALSE(morok::ir::shouldObfuscate(*F, "sub", true));
}

TEST_CASE("shouldObfuscate defaults to defaultEnabled when no annotation") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleFn);
    Function *F = M->getFunction("foo");
    REQUIRE(F);

    CHECK(morok::ir::shouldObfuscate(*F, "sub", true));
    CHECK_FALSE(morok::ir::shouldObfuscate(*F, "sub", false));
}

TEST_CASE("shouldObfuscate returns false for declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @external(i32)
)ir");
    Function *F = M->getFunction("external");
    REQUIRE(F);

    CHECK_FALSE(morok::ir::shouldObfuscate(*F, "sub", true));
}
