/**
 * The public surface of `interlock-guard`.
 *
 * Everything is re-exported here so `import { ... } from "interlock-guard"`
 * works; the `./wire` and `./mcp` subpaths exist for callers that want a
 * narrower import, not because anything is hidden.
 */

export * from "./enforce.js";
export * from "./event.js";
export * from "./wire.js";
export * from "./client.js";
export * from "./mcp.js";
