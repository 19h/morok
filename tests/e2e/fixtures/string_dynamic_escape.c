// SPDX-License-Identifier: MIT
//
// Runtime regression for scoped string re-encryption.  The returned, stored,
// and captured pointers are read after their producer functions have returned;
// a release-before-ret scoped decryptor would therefore hand this code
// ciphertext instead of the original literals.

#include <stdint.h>
#include <stdio.h>

#if defined(__clang__)
#define MOROK_NOOPT __attribute__((noinline, optnone))
#else
#define MOROK_NOOPT __attribute__((noinline))
#endif

static const char *volatile saved_secret;

MOROK_NOOPT static const char *return_secret(void) {
    return "ret-secret";
}

MOROK_NOOPT static void store_secret(const char **out) {
    *out = "store-secret";
}

MOROK_NOOPT static void register_secret(const char *value) {
    saved_secret = value;
}

MOROK_NOOPT static void capture_secret(void) {
    register_secret("capture-secret");
}

MOROK_NOOPT static uint64_t fold_string(const char *value) {
    uint64_t h = 1469598103934665603ULL;
    while (*value != '\0') {
        h ^= (unsigned char)*value++;
        h *= 1099511628211ULL;
    }
    return h;
}

int main(void) {
    const char *stored = 0;
    const char *returned = return_secret();
    store_secret(&stored);
    capture_secret();

    uint64_t h = fold_string(returned);
    h ^= fold_string(stored);
    h *= 1099511628211ULL;
    h ^= fold_string((const char *)saved_secret);
    printf("string_escape=%llu\n", (unsigned long long)h);
    return 0;
}
