// SPDX-License-Identifier: MIT
//
// Regression fixture for VTableIntegrity:
// - ops mode is a valid C-style function-pointer table that has the same
//   load/gep/load/call shape and function type as a C++ virtual dispatch.
// - tamper mode swaps an actually constructed object's vptr to an unknown table.

#include <cstdio>
#include <cstring>

struct Base {
    int salt = 4;
    virtual int f();
    virtual int g();
};

__attribute__((noinline)) int Base::f() { return 7 + salt; }
__attribute__((noinline)) int Base::g() { return 11 + salt; }

struct Ops {
    int (*f)(void *);
    int (*g)(void *);
};

struct Ctx {
    Ops *ops;
    int value;
};

extern "C" __attribute__((noinline)) int op_f(void *p) {
    return static_cast<Ctx *>(p)->value + 13;
}

extern "C" __attribute__((noinline)) int op_g(void *p) {
    return static_cast<Ctx *>(p)->value + 17;
}

extern "C" __attribute__((noinline)) int fake_f(Base *) { return 88; }
extern "C" __attribute__((noinline)) int fake_g(Base *) { return 99; }

using FakeMethod = int (*)(Base *);

alignas(void *) static FakeMethod fake_vtable[] = {
    nullptr,
    nullptr,
    fake_f,
    fake_g,
};

__attribute__((noinline, optnone)) int call_ops(Ctx *ctx) {
    return ctx->ops->g(ctx);
}

__attribute__((noinline, optnone)) int call_virtual(Base *obj) {
    return obj->g();
}

__attribute__((noinline, optnone)) int run_ops() {
    Ops ops = {op_f, op_g};
    Ctx ctx = {&ops, 5};
    return call_ops(&ctx);
}

__attribute__((noinline, optnone)) int run_virtual() {
    Base obj;
    return call_virtual(&obj);
}

__attribute__((noinline, optnone)) int run_tamper() {
    Base obj;
    *reinterpret_cast<void **>(&obj) =
        reinterpret_cast<void *>(&fake_vtable[2]);
    return call_virtual(&obj);
}

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    if (std::strcmp(argv[1], "ops") == 0) {
        std::printf("ops=%d\n", run_ops());
        return 0;
    }
    if (std::strcmp(argv[1], "virtual") == 0) {
        std::printf("virtual=%d\n", run_virtual());
        return 0;
    }
    if (std::strcmp(argv[1], "tamper") == 0) {
        std::printf("tamper=%d\n", run_tamper());
        return 0;
    }
    return 3;
}
