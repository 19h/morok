// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/runtime/PlatformRuntime.hpp — shared platform primitive emitters.

#ifndef MOROK_RUNTIME_PLATFORM_RUNTIME_HPP
#define MOROK_RUNTIME_PLATFORM_RUNTIME_HPP

#include "llvm/ADT/Twine.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/TargetParser/Triple.h"

#include <cstdint>
#include <initializer_list>

namespace morok::runtime {

struct LinuxCoreSyscalls {
    std::uint32_t ptrace = 0;
    std::uint32_t prctl = 0;
    std::uint32_t openat = 0;
    std::uint32_t read = 0;
    std::uint32_t close = 0;
};

struct LinuxCleanCopySyscalls {
    std::uint32_t readlink = 0;
    std::uint32_t lseek = 0;
    std::uint32_t mmap = 0;
    std::uint32_t munmap = 0;
};

llvm::IntegerType *platformWordTy(llvm::Module &M);
llvm::Value *toSyscallArg(llvm::IRBuilderBase &B, llvm::Value *V);

llvm::FunctionCallee ptraceDecl(llvm::Module &M);
llvm::FunctionCallee syscallDecl(llvm::Module &M);
llvm::FunctionCallee getpidDecl(llvm::Module &M);
llvm::FunctionCallee getppidDecl(llvm::Module &M);
llvm::FunctionCallee openDecl(llvm::Module &M);
llvm::FunctionCallee readDecl(llvm::Module &M);
llvm::FunctionCallee closeDecl(llvm::Module &M);
llvm::FunctionCallee readlinkDecl(llvm::Module &M);
llvm::FunctionCallee lseekDecl(llvm::Module &M);
llvm::FunctionCallee mmapDecl(llvm::Module &M);
llvm::FunctionCallee munmapDecl(llvm::Module &M);
llvm::FunctionCallee mprotectDecl(llvm::Module &M);

// Apply the operator's syscall-surface policy (#102) to this module.  Policy is
// "auto" | "always" | "never" (from platform_runtime.direct_syscalls); "never"
// forces the import path so no inline direct syscalls are emitted.  Carried as a
// module flag that the emit helpers below honor; dropped before the final binary.
void setDirectSyscallPolicy(llvm::Module &M, llvm::StringRef Policy);

unsigned directSyscallPolicy(const llvm::Module &M);
bool useDirectLinuxSyscalls(const llvm::Module &M, const llvm::Triple &TT);
bool lookupLinuxCoreSyscalls(const llvm::Triple &TT,
                             LinuxCoreSyscalls &Out);
bool lookupLinuxCleanCopySyscalls(const llvm::Triple &TT,
                                  LinuxCleanCopySyscalls &Out);

llvm::Value *emitPtraceImport(llvm::IRBuilderBase &B, llvm::Module &M,
                              int Request);
llvm::Value *emitLinuxSyscall(llvm::IRBuilder<> &B, llvm::Module &M,
                              const llvm::Triple &TT, std::uint32_t Number,
                              std::initializer_list<llvm::Value *> Args,
                              const llvm::Twine &Name =
                                  llvm::Twine("morok.linux.syscall"));
llvm::Value *emitLinuxPtrace(llvm::IRBuilder<> &B, llvm::Module &M,
                             const llvm::Triple &TT, int Request);
llvm::Value *emitLinuxPrctl(llvm::IRBuilder<> &B, llvm::Module &M,
                            const llvm::Triple &TT, std::int64_t Option,
                            std::int64_t A2 = 0, std::int64_t A3 = 0,
                            std::int64_t A4 = 0, std::int64_t A5 = 0);

bool useDirectDarwinSyscalls(const llvm::Module &M, const llvm::Triple &TT);
llvm::Value *emitDarwinArm64Svc(llvm::IRBuilder<> &B, llvm::Module &M,
                                std::uint32_t Number,
                                std::initializer_list<llvm::Value *> Args,
                                const llvm::Twine &Name =
                                    llvm::Twine("morok.darwin.svc"));
llvm::Value *emitDarwinSyscall(llvm::IRBuilder<> &B, llvm::Module &M,
                               const llvm::Triple &TT, std::uint32_t Number,
                               std::initializer_list<llvm::Value *> Args,
                               const llvm::Twine &Name =
                                   llvm::Twine("morok.darwin.syscall"));
llvm::Value *emitDarwinGetpid(llvm::IRBuilder<> &B, llvm::Module &M,
                              const llvm::Triple &TT);
llvm::Value *emitDarwinPtrace(llvm::IRBuilder<> &B, llvm::Module &M,
                              const llvm::Triple &TT, std::int32_t Request);
llvm::Value *emitDarwinSysctl(llvm::IRBuilder<> &B, llvm::Module &M,
                              const llvm::Triple &TT, llvm::Value *Mib,
                              llvm::Value *MibLen, llvm::Value *OldP,
                              llvm::Value *OldLenP, llvm::Value *NewP,
                              llvm::Value *NewLen);
llvm::Value *emitDarwinCsops(llvm::IRBuilder<> &B, llvm::Module &M,
                             const llvm::Triple &TT, llvm::Value *Pid,
                             llvm::Value *Ops, llvm::Value *UserAddr,
                             llvm::Value *UserSize);
llvm::Value *emitDarwinCsopsAuditToken(llvm::IRBuilder<> &B, llvm::Module &M,
                                       const llvm::Triple &TT,
                                       llvm::Value *Pid, llvm::Value *Ops,
                                       llvm::Value *UserAddr,
                                       llvm::Value *UserSize,
                                       llvm::Value *AuditToken);
llvm::Value *emitDarwinTaskInfoAuditToken(
    llvm::IRBuilder<> &B, llvm::Module &M, const llvm::Triple &TT,
    llvm::Value *Task, llvm::Value *AuditToken,
    const llvm::Twine &Name = llvm::Twine("morok.darwin.task.audit_token"));
llvm::Value *emitDarwinTaskSelf(llvm::IRBuilder<> &B, llvm::Module &M,
                                const llvm::Triple &TT,
                                const llvm::Twine &Name =
                                    llvm::Twine("morok.darwin.task.self"));
llvm::Value *emitDarwinTaskForPid(
    llvm::IRBuilder<> &B, llvm::Module &M, const llvm::Triple &TT,
    llvm::Value *TargetTask, llvm::Value *Pid, llvm::Value *OutTask,
    const llvm::Twine &Name = llvm::Twine("morok.darwin.task_for_pid"));
llvm::Value *emitDarwinMachPortDeallocate(
    llvm::IRBuilder<> &B, llvm::Module &M, const llvm::Triple &TT,
    llvm::Value *Task, llvm::Value *Name,
    const llvm::Twine &CallName = llvm::Twine("morok.darwin.port.deallocate"));
llvm::Value *emitDarwinTaskGetExceptionPorts(
    llvm::IRBuilder<> &B, llvm::Module &M, const llvm::Triple &TT,
    llvm::Value *Task, llvm::Value *ExceptionMask, llvm::Value *Masks,
    llvm::Value *MaskCount, llvm::Value *Handlers, llvm::Value *Behaviors,
    llvm::Value *Flavors,
    const llvm::Twine &Name = llvm::Twine("morok.darwin.exc_ports"));

llvm::Value *emitLinuxReadlink(llvm::IRBuilder<> &B, llvm::Module &M,
                               const llvm::Triple &TT, llvm::Value *Path,
                               llvm::Value *Buf, llvm::Value *Size);
llvm::Value *emitLinuxLseek(llvm::IRBuilder<> &B, llvm::Module &M,
                            const llvm::Triple &TT, llvm::Value *Fd,
                            std::int64_t Offset, std::int32_t Whence);
llvm::Value *emitLinuxMmapAddr(llvm::IRBuilder<> &B, llvm::Module &M,
                               const llvm::Triple &TT, llvm::Value *Size,
                               llvm::Value *Fd);
void emitLinuxMunmap(llvm::IRBuilder<> &B, llvm::Module &M,
                     const llvm::Triple &TT, llvm::Value *Addr,
                     llvm::Value *Size);
llvm::Value *emitLinuxMprotect(llvm::IRBuilder<> &B, llvm::Module &M,
                               const llvm::Triple &TT, llvm::Value *Addr,
                               llvm::Value *Size, llvm::Value *Prot);
void emitLinuxClose(llvm::IRBuilder<> &B, llvm::Module &M,
                    const llvm::Triple &TT, llvm::Value *Fd);

llvm::Value *emitDarwinOpen(llvm::IRBuilder<> &B, llvm::Module &M,
                            const llvm::Triple &TT, llvm::Value *Path,
                            std::int32_t Flags, std::int32_t Mode);
void emitDarwinClose(llvm::IRBuilder<> &B, llvm::Module &M,
                     const llvm::Triple &TT, llvm::Value *Fd);
llvm::Value *emitDarwinLseek(llvm::IRBuilder<> &B, llvm::Module &M,
                             const llvm::Triple &TT, llvm::Value *Fd,
                             std::int64_t Offset, std::int32_t Whence);
llvm::Value *emitDarwinMmap(llvm::IRBuilder<> &B, llvm::Module &M,
                            const llvm::Triple &TT, llvm::Value *Size,
                            llvm::Value *Fd);
void emitDarwinMunmap(llvm::IRBuilder<> &B, llvm::Module &M,
                      const llvm::Triple &TT, llvm::Value *Mapped,
                      llvm::Value *Size);
llvm::Value *emitDarwinMprotect(llvm::IRBuilder<> &B, llvm::Module &M,
                                const llvm::Triple &TT, llvm::Value *Addr,
                                llvm::Value *Size, llvm::Value *Prot);

llvm::Value *emitPosixAnonMmapAddr(llvm::IRBuilder<> &B, llvm::Module &M,
                                   const llvm::Triple &TT, llvm::Value *Size,
                                   llvm::Value *Prot, llvm::Value *Flags,
                                   const llvm::Twine &Name);
llvm::Value *emitPosixMprotect(llvm::IRBuilder<> &B, llvm::Module &M,
                               const llvm::Triple &TT, llvm::Value *Addr,
                               llvm::Value *Size, llvm::Value *Prot);

} // namespace morok::runtime

#endif // MOROK_RUNTIME_PLATFORM_RUNTIME_HPP
