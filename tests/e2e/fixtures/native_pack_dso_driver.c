#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef uint32_t (*eval_fn)(uint32_t);
typedef uint32_t (*ctor_fn)(void);

struct worker {
    eval_fn eval;
    uint32_t input;
    uint32_t output;
};

static void *run_worker(void *opaque) {
    struct worker *w = (struct worker *)opaque;
    w->output = w->eval(w->input);
    return NULL;
}

int main(int argc, char **argv) {
    enum { workers = 8 };
    pthread_t threads[workers];
    struct worker work[workers];
    uint32_t aggregate = 0;
    int i;
    if (argc != 2)
        return 2;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL)
        return 3;
    eval_fn eval = (eval_fn)dlsym(handle, "native_pack_eval");
    ctor_fn ctor_value = (ctor_fn)dlsym(handle, "native_pack_ctor_value");
    if (eval == NULL || ctor_value == NULL)
        return 4;
    for (i = 0; i < workers; ++i) {
        work[i].eval = eval;
        work[i].input = UINT32_C(0x11110000) + (uint32_t)i;
        work[i].output = 0;
        if (pthread_create(&threads[i], NULL, run_worker, &work[i]) != 0)
            return 5;
    }
    for (i = 0; i < workers; ++i) {
        if (pthread_join(threads[i], NULL) != 0)
            return 6;
        aggregate ^= work[i].output;
    }
    printf("%08x:%08x\n", ctor_value(), aggregate);
    fflush(stdout);
    dlclose(handle);
    return 0;
}
