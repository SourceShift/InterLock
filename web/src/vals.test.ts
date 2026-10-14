/**
 * `ruleDetailHref`: the link a receipt's rule value points at. A receipt's
 * `policy_id` is the deciding detector's stamped id, which is not the catalog
 * module, so the target has to be resolved through the catalog's `policy_id` -
 * and an id the catalog does not know must fall back to the policy list rather
 * than to a detail page that would answer 404.
 */
import type { Data } from "./model";
import { ruleDetailHref } from "./vals";

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
