/**
 * Verdicts, decisions, and the error a block throws.
 *
 * A port of `interlock/enforce.py`. The static factories keep Python's
 * positional order so the two files can be read side by side; the parameter
 * names are in the signatures because `block(reason, policy_id, attributed_to)`
 * is exactly the order a port gets wrong.
 */

/**
 * A plain object, in the sense Python's `isinstance(x, dict)` means.
 *
 * Not `typeof x === "object"`: an array, a `Date`, a `Buffer`, and a class
 * instance are all objects and none of them is a dict. The prototype check is
 * what separates a JSON-shaped record (literal, or `Object.create(null)`) from
 * everything else - and the distinction decides whether a result is inspected as
 * itself or wrapped, so it is load-bearing rather than stylistic.
 */
export function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Tri-state verdict. The integer values match the native engine's out-param
 * contract (0/1/2), and are what travels on the wire - a name is for a human
 * reading a corpus file, an integer is for the protocol.
 */
export enum Verdict {
  ALLOW = 0,
  BLOCK = 1,
  MODIFY = 2,
}

export interface DecisionInit {
  verdict?: Verdict;
  reason?: string;
  policy_id?: string | null;
  /** Populated only for MODIFY on the call side. */
  modified_args?: Record<string, unknown> | null;
  /**
   * The NAME of the argument that tripped the policy ("command", "path",
   * "url") - never the argument's value, which would turn a diagnostic field
   * into a data-exfiltration surface.
   */
  attributed_to?: string | null;
  /**
   * Replacement for a tool RESULT under a MODIFY verdict on a result-phase
   * event. Unlike modified_args (merged into the outgoing request), this
   * replaces the whole return value the caller receives.
   */
  modified_result?: unknown;
}

export class Decision {
  readonly verdict: Verdict;
  readonly reason: string;
  readonly policy_id: string | null;
  readonly modified_args: Record<string, unknown> | null;
  readonly attributed_to: string | null;
  readonly modified_result: unknown;

  constructor(init: DecisionInit = {}) {
    this.verdict = init.verdict ?? Verdict.ALLOW;
    this.reason = init.reason ?? "";
    this.policy_id = init.policy_id ?? null;
    this.modified_args = init.modified_args ?? null;
    this.attributed_to = init.attributed_to ?? null;
    this.modified_result = init.modified_result ?? null;
  }

  /** The verdict's name, e.g. `"BLOCK"` - Python's `decision.verdict.name`. */
  get verdictName(): string {
    return Verdict[this.verdict] ?? String(this.verdict);
  }

  static allow(reason = "", policy_id: string | null = null): Decision {
    return new Decision({ verdict: Verdict.ALLOW, reason, policy_id });
  }

  static block(
    reason: string,
    policy_id: string | null = null,
    attributed_to: string | null = null,
  ): Decision {
    return new Decision({
      verdict: Verdict.BLOCK,
      reason,
      policy_id,
      attributed_to,
    });
  }

  static modify(
    modified_args: Record<string, unknown>,
    reason = "",
    policy_id: string | null = null,
    attributed_to: string | null = null,
  ): Decision {
    return new Decision({
      verdict: Verdict.MODIFY,
      reason,
      policy_id,
      modified_args,
      attributed_to,
    });
  }

  /** Build a MODIFY that replaces a tool result instead of its args. */
  static modifyResult(
    result: unknown,
    reason = "",
    policy_id: string | null = null,
    attributed_to: string | null = null,
  ): Decision {
    return new Decision({
      verdict: Verdict.MODIFY,
      reason,
      policy_id,
      attributed_to,
      modified_result: result,
    });
  }
}

/**
 * Raised when an enforcing guard denies an action. On the call side the action
 * never runs. On the result side the tool has already run - its side effects
 * stand - and this is raised in place of delivering the payload, so the caller
 * never sees what the tool said.
 *
 * It carries the whole `Decision`, which is what lets a caller that already
 * catches it inspect `policy_id` / `attributed_to` without a second channel.
 */
export class BlockedError extends Error {
  readonly decision: Decision;
  readonly action: string;

  constructor(decision: Decision, action: string) {
    super(`blocked action '${action}': ${decision.reason}`);
    this.name = "BlockedError";
    this.decision = decision;
    this.action = action;
  }
}
