/**
 * The preload entry: `node --import interlock-guard/esm-hook app.mjs`.
 *
 * A side-effect module, because `--import` needs one. It reads the sidecar
 * location from the environment, builds a `RemoteEngine`, and registers the ESM
 * loader plus the native interceptors. The policy lives in the sidecar; this
 * hook only says where to reach it.
 *
 * Failing loudly when `INTERLOCK_SOCKET` is absent is deliberate. A preload that
 * shrugs at a missing socket starts an agent that *believes* it is guarded while
 * every call runs unguarded - the failure mode `installInterceptors` exists to
 * make impossible.
 *
 * Environment:
 * - `INTERLOCK_SOCKET` (required) - the sidecar's AF_UNIX path.
 * - `INTERLOCK_PRINCIPAL` (optional) - who the process acts as, for rules that
 *   name a principal and for flow provenance.
 */

import { RemoteEngine } from "./client.js";
import { registerEsmInterceptors } from "./esm.js";
import type { InstallOptions } from "./install.js";

const socket = process.env["INTERLOCK_SOCKET"];
if (socket === undefined || socket === "") {
  throw new Error(
    "interlock-guard/esm-hook: INTERLOCK_SOCKET is not set; " +
      "point it at the sidecar socket (or drop --import and guard calls explicitly)",
  );
}

const principal = process.env["INTERLOCK_PRINCIPAL"];
const options: InstallOptions = { engine: new RemoteEngine(socket) };
if (principal !== undefined && principal !== "") {
  options.principal = principal;
}

registerEsmInterceptors(options);
