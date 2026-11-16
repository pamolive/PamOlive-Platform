/* Build-only MIT krb5 1.21.3 regression harness. No network or private app API.
 * Link the real asn1_encode.o and asn1_k_encode.o with --wrap allocators.
 * DER below is synthetic test input; decoding is exclusively upstream MIT.
 */
#include "k5-int.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ELEMENTS 256
#define TRACKED 1024
static uintptr_t live[TRACKED];
static size_t attempts, mallocs, callocs, reallocs, fail_at;
static int tracking, allocator_error;

void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
void __real_free(void *);

static void remember(void *pointer) {
    size_t i;
    if (!pointer) return;
    for (i = 0; i < TRACKED; i++) {
        if (!live[i]) { live[i] = (uintptr_t)pointer; return; }
    }
    allocator_error = 1;
}

static void forget(uintptr_t pointer) {
    size_t i;
    if (!pointer) return;
    for (i = 0; i < TRACKED; i++) {
        if (live[i] == pointer) { live[i] = 0; return; }
    }
    allocator_error = 1;
}

static int injected_failure(void) {
    attempts++;
    return fail_at && attempts == fail_at;
}

void *__wrap_malloc(size_t size) {
    void *result;
    if (!tracking) return __real_malloc(size);
    mallocs++;
    if (injected_failure()) return NULL;
    result = __real_malloc(size); remember(result); return result;
}

void *__wrap_calloc(size_t count, size_t size) {
    void *result;
    if (!tracking) return __real_calloc(count, size);
    callocs++;
    if (injected_failure()) return NULL;
    result = __real_calloc(count, size); remember(result); return result;
}

void *__wrap_realloc(void *pointer, size_t size) {
    uintptr_t old = (uintptr_t)pointer;
    void *result;
    if (!tracking) return __real_realloc(pointer, size);
    reallocs++;
    if (injected_failure()) return NULL;
    result = __real_realloc(pointer, size);
    if (result) { forget(old); remember(result); }
    return result;
}

void __wrap_free(void *pointer) {
    if (tracking) forget((uintptr_t)pointer);
    __real_free(pointer);
}

static size_t outstanding(void) {
    size_t i, total = 0;
    for (i = 0; i < TRACKED; i++) if (live[i]) total++;
    return total;
}

static void reset(size_t failure) {
    if (outstanding()) { fputs("harness_previous_leak\n", stderr); exit(1); }
    attempts = mallocs = callocs = reallocs = 0;
    allocator_error = 0; fail_at = failure;
}

static int run(const unsigned char *wire, size_t length, int success,
               int expected_count, size_t failure) {
    krb5_data data;
    krb5_etype_list *decoded = NULL;
    krb5_error_code code;
    int ok = 1, i;
    reset(failure);
    memset(&data, 0, sizeof(data));
    data.data = (char *)wire; data.length = (unsigned int)length;
    tracking = 1;
    code = decode_krb5_etype_list(&data, &decoded);
    if (success) {
        if (code || !decoded || decoded->length != expected_count) ok = 0;
        if (!code && decoded && decoded->length == expected_count)
            for (i = 0; i < expected_count; i++)
                if (decoded->etypes[i] != 7) ok = 0;
    } else if (!code || decoded) ok = 0;
    if (decoded) { free(decoded->etypes); free(decoded); }
    tracking = 0;
    if (outstanding() || allocator_error) ok = 0;
    return ok;
}

static void result(const char *name, int success, size_t points) {
    printf("\"%s\":{\"status\":\"passed\",\"decoder_success\":%s,"
           "\"allocation_attempts\":%zu,\"malloc_calls\":%zu,"
           "\"calloc_calls\":%zu,\"realloc_calls\":%zu,"
           "\"live_allocations_after_cleanup\":%zu,\"failure_points\":%zu",
           name, success ? "true" : "false", attempts, mallocs, callocs,
           reallocs, outstanding(), points);
    if (!strcmp(name, "long_valid"))
        printf(",\"decoded_count\":%d,\"decoded_value\":7", ELEMENTS);
    putchar('}');
}

static int failed(const char *case_name) {
    fprintf(stderr, "harness_case_failed:%s attempts=%zu malloc=%zu calloc=%zu realloc=%zu live=%zu allocator_error=%d\n",
            case_name, attempts, mallocs, callocs, reallocs, outstanding(), allocator_error);
    return 1;
}

int main(int argc, char **argv) {
    unsigned char long_wire[4 + ELEMENTS * 3];
    const unsigned char empty[] = {0x30, 0x00};
    const unsigned char bad_tag[] = {0x30, 0x06, 0x02, 0x01, 0x07, 0x04, 0x01, 0x07};
    const unsigned char truncated[] = {0x30, 0x06, 0x02, 0x01, 0x07};
    const unsigned char partial[] = {0x30, 0x0a, 0x02, 0x01, 0x07,
                                   0x02, 0x05, 0x7f, 0xff, 0xff, 0xff, 0xff};
    size_t i, normal_attempts;
    int patched;
    if (argc != 2 || (strcmp(argv[1], "baseline") && strcmp(argv[1], "patched"))) return 2;
    patched = !strcmp(argv[1], "patched");
    long_wire[0] = 0x30; long_wire[1] = 0x82;
    long_wire[2] = (ELEMENTS * 3) >> 8; long_wire[3] = (ELEMENTS * 3) & 255;
    for (i = 0; i < ELEMENTS; i++) {
        long_wire[4 + i * 3] = 0x02; long_wire[5 + i * 3] = 0x01; long_wire[6 + i * 3] = 7;
    }
    if (!run(long_wire, sizeof(long_wire), 1, ELEMENTS, 0)) return failed("long_valid");
    /* Calibration makes ineffective --wrap or accidental DSO fallback fail. */
    if (mallocs || reallocs != (patched ? 0 : ELEMENTS) || callocs != (patched ? 2 : 1))
        return failed("allocation_calibration");
    normal_attempts = attempts;
    printf("{\"phase\":\"%s\",\"case_count\":6,\"element_count\":%d,\"cases\":{", argv[1], ELEMENTS);
    result("long_valid", 1, 0);
    if (!run(empty, sizeof(empty), 1, 0, 0)) return failed("empty");
    putchar(','); result("empty", 1, 0);
    if (!run(bad_tag, sizeof(bad_tag), 0, 0, 0)) return failed("bad_tag");
    putchar(','); result("bad_tag", 0, 0);
    if (!run(truncated, sizeof(truncated), 0, 0, 0)) return failed("truncated");
    putchar(','); result("truncated", 0, 0);
    for (i = 1; i <= normal_attempts; i++)
        if (!run(long_wire, sizeof(long_wire), 0, 0, i)) return failed("allocation_failure");
    putchar(','); result("allocation_failure", 0, normal_attempts);
    if (!run(partial, sizeof(partial), 0, 0, 0)) return failed("partial_cleanup");
    putchar(','); result("partial_cleanup", 0, 0);
    puts("}}");
    return 0;
}
