/*
 * A non-Python caller of the native policy engine's C ABI.
 *
 * This exists to prove the seam, not to be a library: it dlopen()s the wheel's
 * shared object (the path is argv[1]), resolves `il_abi_version` and
 * `il_eval_plan`, and checks a block, an allow and a fail-closed error. A Go,
 * Node or Rust host does the same three calls; nothing here is Python-shaped.
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

static int failures = 0;

static void check(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <path-to-interlock_scopes-shared-object>\n", argv[0]);
        return 2;
    }

    void *lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (lib == NULL) {
        fprintf(stderr, "dlopen(%s): %s\n", argv[1], dlerror());
        return 2;
    }

    abi_version_fn abi_version = (abi_version_fn)dlsym(lib, "il_abi_version");
    eval_fn evaluate = (eval_fn)dlsym(lib, "il_eval_plan");
    check(abi_version != NULL, "il_abi_version is exported");
    check(evaluate != NULL, "il_eval_plan is exported");
    if (abi_version == NULL || evaluate == NULL) {
        dlclose(lib);
        return 1;
    }

    uint32_t version = abi_version();
    check(version == 1, "ABI version is 1");

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

    dlclose(lib);
    if (failures != 0) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("C ABI smoke: version %u, block/allow/error ok\n", version);
    return 0;
}
