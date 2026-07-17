#include <stdint.h>

static volatile uint32_t ctor_value;

__attribute__((noinline, visibility("default")))
uint32_t native_pack_eval(uint32_t x) {
    x ^= x >> 9;
    x *= UINT32_C(0x85ebca6b);
    x ^= x << 13;
    x *= UINT32_C(0xc2b2ae35);
    return x ^ (x >> 16);
}

#if defined(NATIVE_PACK_CTOR)
__attribute__((constructor)) static void native_pack_ctor(void) {
    ctor_value = native_pack_eval(UINT32_C(0x10203040));
}
#endif

__attribute__((visibility("default")))
uint32_t native_pack_ctor_value(void) {
    return ctor_value;
}
