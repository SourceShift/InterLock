/**
 * The event a sensor produces for every intercepted action.
 *
 * A port of `interlock/event.py`. It is an interface plus a factory rather than
 * a class, because the wire only ever reads these fields and a plain object is
 * what a caller already has.
 */

/**
 * Which side of the call an event describes: `"call"` (the default, the
 * arguments being sent) or `"result"` (the payload coming back).
 *
 * Defaulting to the call side keeps every event that has no opinion meaning what
 * it meant - including call-shaped events whose action name says "tool_result".
 */
export type Phase = "call" | "result";

export interface SensorEvent {
  /** The tool / function / MCP-call name. */
  action: string;
  /**
   * The call arguments the policy is allowed to inspect. On a result-phase
   * event this carries the result payload instead (a dict result as itself, any
   * other shape under `"result"`).
   */
  args: Record<string, unknown>;
  /** Who is acting (agent id, user id), if known. */
  principal: string | null;
  /** Run identity, so every event is attributable to one agent run. */
  span_id: string | null;
  /** Wall-clock time the event was captured, in seconds. */
  ts: number;
  /** Audit trail: who spawned this principal. */
  parent_principal: string | null;
  phase: Phase;
}

export interface SensorEventInit {
  action: string;
  args?: Record<string, unknown>;
  principal?: string | null;
  span_id?: string | null;
  ts?: number;
  parent_principal?: string | null;
  phase?: Phase;
}

/**
 * Build a `SensorEvent`, filling the defaults `interlock/event.py` declares: an
 * empty argument object, the current time, and the call side.
 */
export function sensorEvent(init: SensorEventInit): SensorEvent {
  return {
    action: init.action,
    args: init.args ?? {},
    principal: init.principal ?? null,
    span_id: init.span_id ?? null,
    ts: init.ts ?? Date.now() / 1000,
    parent_principal: init.parent_principal ?? null,
    phase: init.phase ?? "call",
  };
}
