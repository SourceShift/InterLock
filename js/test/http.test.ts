/**
 * The outbound-HTTP interceptor, against a real daemon and a real server.
 *
 * A `fetch` guard is only meaningful if a blocked request really does not leave
 * the process, so the claims are checked against a local server that records
 * every hit:
 *
 * 1. an allowed fetch reaches the server;
 * 2. a blocked url is a `BlockedError` **and the server's hit list stays empty**;
 * 3. a MODIFY rewrites the url, and the rewritten url is the one fetched;
 * 4. `method` and a plain-object `headers` survive the *narrowed* view the event
 *    carries;
 * 5. a `Headers` instance is flattened (not passed through, which the wire would
 *    refuse), so an ordinary caller does not fail closed;
 * 6. `uninstall` restores `globalThis.fetch` and traffic flows again.
 */
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";

import { BlockedError } from "../src/enforce.js";
import { patchFetch } from "../src/http.js";
import { EFFECT_RULES, withEngine } from "./harness.js";

interface Hit {
  url: string;
  method: string;
  header: string | undefined;
  /** Present only when the request carried a body. */
  body?: string;
}

/** Run `body` against a throwaway server that records the requests it receives. */
async function withServer(
  body: (base: string, hits: Hit[]) => Promise<void>,
): Promise<void> {
  const hits: Hit[] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const hit: Hit = {
        url: req.url ?? "",
        method: req.method ?? "",
        header: req.headers["x-test"] as string | undefined,
      };
      if (chunks.length > 0) {
        hit.body = Buffer.concat(chunks).toString("utf8");
      }
      hits.push(hit);
      res.end("OK from server");
    });
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));
  const port = (server.address() as AddressInfo).port;
  try {
    await body(`http://127.0.0.1:${port}`, hits);
  } finally {
    await new Promise<void>((done) => server.close(() => done()));
  }
}

test("http: an allowed fetch reaches the server untouched", async () => {
  await withEngine(EFFECT_RULES, async ({ engine }) => {
    await withServer(async (base, hits) => {
      const patch = patchFetch({ engine });
      try {
        const res = await fetch(`${base}/ok`);
        assert.equal(await res.text(), "OK from server");
        assert.deepEqual(hits.map((hit) => hit.url), ["/ok"]);
      } finally {
        patch.uninstall();
      }
    });
  });
});

test("http: a blocked url never reaches the server", async () => {
  await withEngine(EFFECT_RULES, async ({ engine }) => {
    await withServer(async (base, hits) => {
      const patch = patchFetch({ engine });
      try {
        await assert.rejects(fetch(`${base}/blockme`), BlockedError);
        assert.equal(hits.length, 0, "the request must not leave the process");
      } finally {
        patch.uninstall();
      }
    });
  });
});

test("http: MODIFY rewrites the url, and the rewritten url is fetched", async () => {
  await withEngine(EFFECT_RULES, async ({ engine }) => {
    await withServer(async (base, hits) => {
      const patch = patchFetch({ engine });
      try {
        const res = await fetch(`${base}/redirectme`);
        assert.equal(await res.text(), "OK from server");
        assert.deepEqual(hits.map((hit) => hit.url), ["/target"]);
      } finally {
        patch.uninstall();
      }
    });
  });
});

test("http: method and plain-object headers survive the narrowed view", async () => {
  await withEngine(EFFECT_RULES, async ({ engine }) => {
    await withServer(async (base, hits) => {
      const patch = patchFetch({ engine });
      try {
        const res = await fetch(`${base}/post`, {
          method: "POST",
          headers: { "x-test": "1" },
        });
        assert.equal(await res.text(), "OK from server");
        assert.deepEqual(hits, [{ url: "/post", method: "POST", header: "1" }]);
      } finally {
        patch.uninstall();
      }
    });
  });
});

test("http: a Headers instance is flattened, not refused", async () => {
  await withEngine(EFFECT_RULES, async ({ engine }) => {
    await withServer(async (base, hits) => {
      const patch = patchFetch({ engine });
      try {
        const res = await fetch(`${base}/h`, {
          headers: new Headers({ "x-test": "2" }),
        });
        assert.equal(await res.text(), "OK from server");
        assert.equal(hits[0]?.header, "2");
      } finally {
        patch.uninstall();
      }
    });
  });
});

test("http: uninstall restores globalThis.fetch", async () => {
  const original = globalThis.fetch;
  await withEngine(EFFECT_RULES, async ({ engine }) => {
    await withServer(async (base) => {
      const patch = patchFetch({ engine });
      assert.notEqual(globalThis.fetch, original);
      patch.uninstall();
      assert.equal(globalThis.fetch, original);
      const res = await fetch(`${base}/after`);
      assert.equal(await res.text(), "OK from server");
    });
  });
});

test("http: a blocked Request input never reaches the server", async () => {
  await withEngine(EFFECT_RULES, async ({ engine }) => {
    await withServer(async (base, hits) => {
      const patch = patchFetch({ engine });
      try {
        // A `Request` is not a plain object; without recognition `urlOf` would
        // produce "[object Request]" and the egress rule would never match.
        await assert.rejects(fetch(new Request(`${base}/blockme`)), BlockedError);
        assert.equal(hits.length, 0, "the request must not leave the process");
      } finally {
        patch.uninstall();
      }
    });
  });
});

test("http: a benign Request keeps its method and headers", async () => {
  await withEngine(EFFECT_RULES, async ({ engine }) => {
    await withServer(async (base, hits) => {
      const patch = patchFetch({ engine });
      try {
        const request = new Request(`${base}/request`, {
          method: "POST",
          headers: { "x-test": "3" },
        });
        const res = await fetch(request);
        assert.equal(await res.text(), "OK from server");
        assert.deepEqual(hits, [{ url: "/request", method: "POST", header: "3" }]);
      } finally {
        patch.uninstall();
      }
    });
  });
});

test("http: a MODIFY of a Request input rewrites the url and keeps its method", async () => {
  await withEngine(EFFECT_RULES, async ({ engine }) => {
    await withServer(async (base, hits) => {
      const patch = patchFetch({ engine });
      try {
        const request = new Request(`${base}/redirectme`, { method: "PUT" });
        const res = await fetch(request);
        assert.equal(await res.text(), "OK from server");
        assert.deepEqual(hits, [{ url: "/target", method: "PUT", header: undefined }]);
      } finally {
        patch.uninstall();
      }
    });
  });
});

test("http: rewriting a body-carrying Request forwards the body without consuming it", async () => {
  await withEngine(EFFECT_RULES, async ({ engine }) => {
    await withServer(async (base, hits) => {
      const patch = patchFetch({ engine });
      try {
        const request = new Request(`${base}/redirectme`, {
          method: "POST",
          body: "payload",
        });
        const res = await fetch(request);
        assert.equal(await res.text(), "OK from server");
        assert.deepEqual(hits, [
          { url: "/target", method: "POST", header: undefined, body: "payload" },
        ]);
        assert.equal(
          request.bodyUsed,
          false,
          "rebuilding must not consume the caller's body",
        );
        assert.equal(
          await request.text(),
          "payload",
          "the caller's Request is still readable after the guard forwards it",
        );
      } finally {
        patch.uninstall();
      }
    });
  });
});
