# The console

interlock has no network surface of its own: every check runs in-process,
inside your agent. The console is the one piece that opens a socket — a local
web UI over the policy engine running in this process, for an operator sitting
at the same machine. It serves a small JSON API under `/api/` and a React
single-page app, both bound to loopback only.

You'll need: interlock installed, and Node.js to build the web bundle (only
needed once, or whenever the bundle changes — the console server itself has no
dependencies beyond the Python standard library).

## Build the web bundle

The console serves a static build of the web app; it does not build it for
you.

```bash
npm --prefix web ci
npm --prefix web run build
```

This produces `web/dist/`. Rebuild it whenever `web/src` changes.

## Launch the console

```bash
python -m interlock.console
```

or, once interlock is installed, the equivalent console script:

```bash
interlock-console
```

Either prints one line once it's listening:

```
interlock console listening on http://127.0.0.1:7878
```

Open that URL in a browser. The overview page shows whether the API is
reachable; the navigation bar links to the catalog, playground, audit log and
inspector pages as each one's spec lands.

## Flags

| Flag | Default | What it does |
|---|---|---|
| `--host` | `127.0.0.1` | The address to bind. Must be a loopback address — `127.0.0.1`, `localhost`, or `::1`. Anything else is refused before a socket opens, since the console is a local tool and never a service you expose on a network. |
| `--port` | `7878` | The port to bind. |
| `--static` | `web/dist` next to the installed `interlock` package | Where the built web app lives. Point this elsewhere to serve a different build, for example during development. |

If `--static` points at a directory that doesn't have the web app built into
it yet, the console still starts and still answers `/api/`; only the UI is
missing. Run the build command above and reload.

## Development

For UI development, run the Python server and the Vite dev server side by
side; Vite proxies `/api` requests to `127.0.0.1:7878` so the same frontend
code talks to the real backend without a build step on every change:

```bash
python -m interlock.console &
npm --prefix web run dev
```

Other `web` scripts: `npm --prefix web run typecheck` (`tsc --noEmit`) and
`npm --prefix web test` (component tests with Vitest).

## Watching a sidecar's receipt log

The audit page at `#/audit` opens one receipt log and keeps watching it: point
the console at the same `--receipts` file a running
[sidecar](../reference/sidecar.md) is writing, and decisions appear in the
table as the sidecar makes them, with no reload.

```bash
# the sidecar writes receipts as it serves decisions
interlock-sidecar --rules my_service.policies:RULES \
  --receipts audit.jsonl --key-file receipt.key

# the console reads the same log and key, and only ever reads it
python -m interlock.console --receipts audit.jsonl --key-file receipt.key
```

Open `#/audit`: the table lists every receipt in the log, newest first, with
the chain status from verifying it against `receipt.key`. Leave the page open
while the sidecar keeps writing — the live tail is on by default, so each new
receipt lands at the top of the table within a second, and the live indicator
reads `live` for as long as the stream stays connected. The verdict filter
narrows the table to `ALLOW`, `BLOCK` or `MODIFY` without a reload.

Started without `--receipts`, the page explains the two flags instead of
showing a table — there is nothing to watch yet.

## Security model

The console binds to loopback only and refuses to start otherwise. Every
`/api/` response carries `Cache-Control: no-store` and `X-Content-Type-Options:
nosniff`, and none carries a CORS header — the API only ever answers the page
that's already open, on the same origin. A request whose `Host` header doesn't
name this server (`127.0.0.1:<port>`, `localhost:<port>`, or `[::1]:<port>`) is
refused with a 403, which stops a malicious page elsewhere from reaching the
console through your browser (DNS rebinding). The web app itself loads nothing
from any other origin — no CDN scripts, fonts, or images — so there's nothing
in the page that could leak to, or be tampered with by, a third party.
