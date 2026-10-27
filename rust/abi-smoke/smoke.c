/*
 * A non-Python caller of the native policy engine's C ABI.
 *
 * This exists to prove the seam, not to be a library: it dlopen()s the wheel's
 * shared object (the path is argv[1]), resolves the ABI version, the stateless
 * `il_eval_plan` call and the load-once handle trio, and checks a block, an
 * allow, a fail-closed error, a null handle and a double free. A Go, Node or
 * Rust host does the same calls; nothing here is Python-shaped.
 *
 * Build and run: bash scripts/check_native_abi.sh
 */
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t (*abi_version_fn)(void);
typedef int (*eval_fn)(const char *event_json, size_t event_len,
                       const char *plan_json, size_t plan_len,
                       int32_t *out_verdict, char *out_policy, size_t policy_cap,
                       char *out_reason, size_t reason_cap);
typedef void *(*plan_load_fn)(const char *plan_json, size_t plan_len, int *err);
typedef int (*eval_handle_fn)(void *handle, const char *event_json,
                              size_t event_len, int32_t *out_verdict,
                              char *out_policy, size_t policy_cap,
                              char *out_reason, size_t reason_cap);
typedef void (*plan_free_fn)(void *handle);

static int failures = 0;

static void check(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <path-to-interlock_engine_ffi-shared-object>\n", argv[0]);
        return 2;
    }

    void *lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (lib == NULL) {
        fprintf(stderr, "dlopen(%s): %s\n", argv[1], dlerror());
        return 2;
    }

    abi_version_fn abi_version = (abi_version_fn)dlsym(lib, "il_abi_version");
    eval_fn evaluate = (eval_fn)dlsym(lib, "il_eval_plan");
    plan_load_fn plan_load = (plan_load_fn)dlsym(lib, "il_plan_load");
    eval_handle_fn evaluate_handle = (eval_handle_fn)dlsym(lib, "il_eval_plan_handle");
    plan_free_fn plan_free = (plan_free_fn)dlsym(lib, "il_plan_free");
    check(abi_version != NULL, "il_abi_version is exported");
    check(evaluate != NULL, "il_eval_plan is exported");
    check(plan_load != NULL, "il_plan_load is exported");
    check(evaluate_handle != NULL, "il_eval_plan_handle is exported");
    check(plan_free != NULL, "il_plan_free is exported");
    if (abi_version == NULL || evaluate == NULL || plan_load == NULL
            || evaluate_handle == NULL || plan_free == NULL) {
        dlclose(lib);
        return 1;
    }

    uint32_t version = abi_version();
    check(version == 2, "ABI version is 2");

    static const char *PLAN =
        "{\"version\":1,\"rules\":[{\"id\":\"no-rm\",\"verdict\":1,"
        "\"reason\":\"recursive delete\",\"when\":{\"all\":["
        "{\"action\":\"Bash\"},{\"arg\":\"command\",\"contains\":\"rm -rf\"}]}}]}";
    static const char *HIT =
        "{\"action\":\"Bash\",\"args\":{\"command\":\"rm -rf /\"}}";
    static const char *MISS =
        "{\"action\":\"Bash\",\"args\":{\"command\":\"ls\"}}";

    int32_t verdict = 9;
    char policy[64] = {0};
    char reason[128] = {0};

    /* R31 stateless call: unchanged. */
    int rc = evaluate(HIT, strlen(HIT), PLAN, strlen(PLAN), &verdict,
                      policy, sizeof policy, reason, sizeof reason);
    check(rc == 0, "a matching event evaluates");
    check(verdict == 1, "the matching event blocks");
    check(strcmp(policy, "no-rm") == 0, "the policy id is written out");
    check(strcmp(reason, "recursive delete") == 0, "the reason is written out");

    verdict = 9;
    rc = evaluate(MISS, strlen(MISS), PLAN, strlen(PLAN), &verdict,
                  policy, sizeof policy, reason, sizeof reason);
    check(rc == 0, "a non-matching event evaluates");
    check(verdict == 0, "the non-matching event allows");

    verdict = 9;
    rc = evaluate("not json", 8, PLAN, strlen(PLAN), &verdict,
                  policy, sizeof policy, reason, sizeof reason);
    check(rc == -1, "malformed input returns -1");
    check(verdict == 9, "an error writes no verdict");

    /* Load-once handle: load, evaluate twice, free. */
    int err = 42;
    void *plan = plan_load(PLAN, strlen(PLAN), &err);
    check(err == 0, "a valid plan loads with err 0");
    check(plan != NULL, "a valid plan returns a handle");

    verdict = 9;
    memset(policy, 0, sizeof policy);
    memset(reason, 0, sizeof reason);
    rc = evaluate_handle(plan, HIT, strlen(HIT), &verdict,
                         policy, sizeof policy, reason, sizeof reason);
    check(rc == 0, "the handle evaluates a matching event");
    check(verdict == 1, "the handle blocks a matching event");
    check(strcmp(policy, "no-rm") == 0, "the handle writes the policy id");

    verdict = 9;
    rc = evaluate_handle(plan, MISS, strlen(MISS), &verdict,
                         policy, sizeof policy, reason, sizeof reason);
    check(rc == 0, "the handle evaluates a non-matching event");
    check(verdict == 0, "the handle allows a non-matching event");

    verdict = 9;
    rc = evaluate_handle(plan, "not json", 8, &verdict,
                         policy, sizeof policy, reason, sizeof reason);
    check(rc == -1, "the handle returns -1 on malformed input");
    check(verdict == 9, "the handle writes no verdict on error");

    plan_free(plan);
    verdict = 9;
    rc = evaluate_handle(plan, HIT, strlen(HIT), &verdict,
                         policy, sizeof policy, reason, sizeof reason);
    check(rc == -1, "a freed handle returns -1");
    check(verdict == 9, "a freed handle writes no verdict");
    plan_free(plan);  /* double free is a no-op, not undefined behaviour */

    err = 42;
    plan = plan_load("not json", 8, &err);
    check(err == -1, "an invalid plan sets err to -1");
    check(plan == NULL, "an invalid plan returns a null handle");

    verdict = 9;
    rc = evaluate_handle(NULL, HIT, strlen(HIT), &verdict,
                         policy, sizeof policy, reason, sizeof reason);
    check(rc == -1, "a null handle returns -1");
    check(verdict == 9, "a null handle writes no verdict");
    plan_free(NULL);  /* null free is a no-op */

    dlclose(lib);
    if (failures != 0) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("C ABI smoke: version %u, stateless + handle block/allow/error ok\n",
           version);
    return 0;
}
