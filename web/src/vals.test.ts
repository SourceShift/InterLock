/**
 * `ruleDetailHref`: the link a receipt's rule value points at. A receipt's
 * `policy_id` is the deciding detector's stamped id, which is not the catalog
 * module, so the target has to be resolved through the catalog's `policy_id` -
 * and an id the catalog does not know must fall back to the policy list rather
 * than to a detail page that would answer 404.
 */
import type { VerifyResponse } from "./api";
import type { Data } from "./model";
import { chainVals, ruleDetailHref } from "./vals";

const withCatalog = (detectors: { module: string; policy_id: string | null }[]) =>
  ({ catalog: { count: detectors.length, categories: [], detectors } }) as unknown as Data;

test("a detector's stamped id links to that detector's detail page", () => {
  const D = withCatalog([{ module: "tool_result_injection_guard", policy_id: "tool_result_injection" }]);
  expect(ruleDetailHref(D, "tool_result_injection")).toBe("#/catalog/tool_result_injection_guard");
});

test("an id the catalog does not know keeps the policy list", () => {
  const D = withCatalog([{ module: "tool_result_injection_guard", policy_id: "tool_result_injection" }]);
  expect(ruleDetailHref(D, "force-push")).toBe("#/policy");
});

test("no id links nowhere, and an unloaded catalog does not throw", () => {
  expect(ruleDetailHref(withCatalog([]), null)).toBe("");
  expect(ruleDetailHref({ catalog: null } as unknown as Data, "tool_result_injection")).toBe("#/policy");
});

const intact = {
  status: "intact", problem: null, count: 3, head: "a".repeat(64),
  broken_index: null, expected_head: null,
} as VerifyResponse;

test("an intact answer reads verified until a receipt arrives", () => {
  const { ck, chain } = chainVals(intact, false, false);
  expect(ck).toBe("verified");
  expect(chain.word).toBe("verified");
  expect(chain.notBroken).toBe(true);
});

test("a stale intact answer says it changed since last check", () => {
  const { ck, chain } = chainVals(intact, true, false);
  expect(ck).toBe("verified");
  expect(chain.word).toBe("changed since last check");
  expect(chain.notBroken).toBe(true);
  expect(chain.broken).toBe(false);
});

test("a broken chain wins over a stale badge", () => {
  const broken = { ...intact, status: "broken", problem: "receipt 1: MAC mismatch" } as VerifyResponse;
  const { ck, chain } = chainVals(broken, true, false);
  expect(ck).toBe("broken");
  expect(chain.word).toBe("broken");
  expect(chain.broken).toBe(true);
  expect(chain.notBroken).toBe(false);
});

test("no log or no answer keeps unverified and checking ahead of stale", () => {
  expect(chainVals(intact, true, true).chain.word).toBe("unverified");
  expect(chainVals(null, true, false).chain.word).toBe("checking");
});
