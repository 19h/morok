// SPDX-License-Identifier: MIT
//
// Trace-shaped string/format/import workload for binary adversarial tests.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static unsigned runtime_secret_byte(unsigned idx) {
    const unsigned char *secret =
        (const unsigned char *)"TRACE_RUNTIME_PLAINTEXT_761";
    return secret[idx % (sizeof("TRACE_RUNTIME_PLAINTEXT_761") - 1u)];
}

int main(void) {
    char canon[128];
    char serial[128];
    int parsed = 0;

    int fields = sscanf("  -314", "%d", &parsed);
    int n1 = snprintf(canon, sizeof(canon), "%s@%s$%s&%s", "alpha",
                      "beta", "gamma", "delta");
    int n2 = sprintf(serial, "%s:%ld:%u:%x", "lic", -37L, 42U, 0xbeefU);

    unsigned acc = 0x811c9dc5u;
    for (unsigned i = 0; i != 96u; ++i) {
        acc ^= runtime_secret_byte(i);
        acc *= 16777619u;
    }
    for (size_t i = 0; canon[i] != '\0'; ++i) {
        acc ^= (unsigned char)canon[i];
        acc *= 16777619u;
    }
    for (size_t i = 0; serial[i] != '\0'; ++i) {
        acc ^= (unsigned char)serial[i];
        acc *= 16777619u;
    }

    printf("> ");
    fprintf(stdout, "pid=%d ", parsed);
    printf("audit=%u:%d:%d:%u\n", acc, n1, n2, fields);
    return fields == 1 ? 0 : 7;
}
