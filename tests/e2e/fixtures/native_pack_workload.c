#include <stdio.h>

__attribute__((noinline)) static unsigned mix(unsigned x) {
    x ^= x >> 7;
    x *= 0x9e3779b1u;
    x ^= x << 11;
    x += 0x51ed270bu;
    return x ^ (x >> 13);
}

__attribute__((noinline)) static unsigned verdict(unsigned x) {
    unsigned a = mix(x + 3u);
    unsigned b = mix(a ^ 0xa5a55a5au);
    return (a + (b << 1)) ^ (b >> 3);
}

int main(void) {
    printf("native-pack-result:%08x\n", verdict(0x12345678u));
    return 0;
}
