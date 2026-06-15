// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/ir/Annotations.cpp

#include "morok/ir/Annotations.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"

#include <sstream>
#include <string>
#include <vector>

using namespace llvm;

namespace morok::ir {

namespace {
constexpr char kObfMetadataKind[] = "morok.obf";

std::vector<std::string> splitWords(StringRef s) {
    std::stringstream ss(s.str());
    std::string word;
    std::vector<std::string> out;
    while (ss >> word)
        out.push_back(word);
    return out;
}
} // namespace

void materializeAnnotations(Module &M) {
    GlobalVariable *annotations =
        M.getGlobalVariable("llvm.global.annotations");
    if (!annotations || !annotations->hasInitializer())
        return;
    auto *array = dyn_cast<ConstantArray>(annotations->getInitializer());
    if (!array)
        return;

    for (Value *op : array->operands()) {
        auto *entry = dyn_cast<ConstantStruct>(op);
        if (!entry || entry->getNumOperands() < 2)
            continue;
        auto *fn =
            dyn_cast<Function>(entry->getOperand(0)->stripPointerCasts());
        if (!fn)
            continue;
        auto *strGV =
            dyn_cast<GlobalVariable>(entry->getOperand(1)->stripPointerCasts());
        if (!strGV || !strGV->hasInitializer())
            continue;
        auto *str = dyn_cast<ConstantDataSequential>(strGV->getInitializer());
        if (!str || !str->isCString())
            continue;
        for (const std::string &word : splitWords(str->getAsCString()))
            addAnnotation(*fn, word);
    }
}

bool hasAnnotation(const Function &F, StringRef annotation) {
    const MDNode *md = F.getMetadata(kObfMetadataKind);
    if (!md)
        return false;
    for (const MDOperand &op : md->operands())
        if (const auto *s = dyn_cast<MDString>(op.get()))
            if (s->getString() == annotation)
                return true;
    return false;
}

void addAnnotation(Function &F, StringRef annotation) {
    if (hasAnnotation(F, annotation))
        return;
    LLVMContext &ctx = F.getContext();
    SmallVector<Metadata *, 4> entries;
    if (const MDNode *existing = F.getMetadata(kObfMetadataKind))
        for (const MDOperand &op : existing->operands())
            entries.push_back(op.get());
    entries.push_back(MDString::get(ctx, annotation));
    F.setMetadata(kObfMetadataKind, MDTuple::get(ctx, entries));
}

bool shouldObfuscate(const Function &F, StringRef attr, bool defaultEnabled) {
    if (F.isDeclaration() || F.hasAvailableExternallyLinkage())
        return false;
    if (hasAnnotation(F, ("no" + attr).str()))
        return false;
    if (hasAnnotation(F, attr))
        return true;
    return defaultEnabled;
}

} // namespace morok::ir
