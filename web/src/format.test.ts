/**
 * The adapters between real API data and the designed screens: annotations
 * and signatures as the design writes them, detector docstrings as blocks,
 * playground parameter text as keyword arguments, JSON error lines.
 */
import { chip, docBlocks, jsonErrorLine, left, paramValue, prettyAnn, signature } from "./format";

test("annotations read the way the design writes them", () => {
  expect(prettyAnn("Optional[Iterable[str]]")).toBe("list[str] | None");
  expect(prettyAnn("'Iterable[str]'")).toBe("list[str]");
  expect(prettyAnn("Union[int, str]")).toBe("int | str");
  expect(prettyAnn("Dict[str, List[str]]")).toBe("dict[str, list[str]]");
  expect(prettyAnn("typing.FrozenSet[str]")).toBe("set[str]");
  expect(prettyAnn(null)).toBe("");
});

test("a signature lists parameters with short defaults", () => {
  const sig = signature("network_egress_guard", [
    { name: "allowed_hosts", kind: "POSITIONAL_OR_KEYWORD", required: true, default: null, annotation: "Iterable[str]" },
    { name: "egress_actions", kind: "KEYWORD_ONLY", required: false, default: "frozenset({'http_request', 'post_webhook', 'download'})", annotation: "Iterable[str]" },
    { name: "reason", kind: "KEYWORD_ONLY", required: false, default: null, annotation: "Optional[str]" },
  ]);
  expect(sig).toBe("network_egress_guard(allowed_hosts: list[str], egress_actions: list[str] = frozenset({'http_request',…, reason: str | None = None)");
});

test("docstrings become paragraphs, headings and code", () => {
  const blocks = docBlocks("Blocks egress.\n\nExample\n-------\n\nUse it like this::\n\n    guard(allowed_hosts=[\"a\"])\n\nThat is all.");
  expect(blocks.map((b) => (b.isP ? "p" : b.isH ? "h" : "code"))).toEqual(["p", "h", "p", "code", "p"]);
  expect(blocks[2].t).toBe("Use it like this:");
  expect(blocks[3].t).toBe('guard(allowed_hosts=["a"])');
});

test("parameter text becomes the keyword argument its annotation asks for", () => {
  const list = { name: "hosts", kind: "", required: true, default: null, annotation: "Iterable[str]" };
  expect(paramValue("a.com, b.com", list)).toEqual({ set: true, value: ["a.com", "b.com"] });
  expect(paramValue("", list)).toEqual({ set: false });
  expect(paramValue("3", { ...list, annotation: "int" })).toEqual({ set: true, value: 3 });
  expect(paramValue("true", { ...list, annotation: "bool" })).toEqual({ set: true, value: true });
  expect(paramValue('{"a": 1}', { ...list, annotation: "Dict[str, int]" })).toEqual({ set: true, value: { a: 1 } });
  expect(paramValue("block", { ...list, annotation: "str" })).toEqual({ set: true, value: "block" });
});

test("a JSON error names its line", () => {
  const text = '{\n  "a": 1,\n  "b": }';
  let caught: unknown;
  try {
    JSON.parse(text);
  } catch (e) {
    caught = e;
  }
  expect(jsonErrorLine(text, caught)).toEqual({ msg: "Unexpected token '}'", line: 3 });
  expect(jsonErrorLine('{\n  "rules": [\n', new Error("x")).line).toBe(3);
});

test("observed verdicts are dashed and say what they would have done", () => {
  expect(chip("BLOCK", true)).toMatchObject({ mark: "◌", word: "would block", bs: "dashed" });
  expect(chip("MODIFY")).toMatchObject({ mark: "~", word: "rewrite", bs: "solid" });
  expect(left(65_000)).toBe("1:05");
  expect(left(3 * 3600e3 + 5 * 60e3)).toBe("3h 05m");
});
