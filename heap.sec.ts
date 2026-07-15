import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeHeapSnapshot } from "node:v8";
import { hashRaw, verifyRaw } from "./index.js";

/**
 * Vulnerability #3 — V8 heap inspection (zero-knowledge verification).
 *
 * A pure-JS Argon2 verifier computes the candidate hash from the submitted
 * password as a JavaScript value. That value lingers in the V8 heap until the
 * garbage collector reclaims it — long enough for anyone who can grab a heap
 * snapshot (Chrome DevTools, `v8.getHeapSnapshot()`, a crash dump) to read the
 * hashes being tested.
 *
 * This library computes and compares the candidate hash entirely inside C++
 * (`VerifyWorker`), wiping it before returning. It never becomes a
 * V8-managed object, so it cannot appear in a heap snapshot.
 *
 * The test proves both halves:
 *   - POSITIVE CONTROL: a candidate hash kept as a JS string (what a pure-JS
 *     verifier leaves behind) IS found in the snapshot.
 *   - THIS LIBRARY: a candidate hash produced only by native `verifyRaw` is
 *     NOT found — even after verifying against it thousands of times.
 */

const salt = Buffer.alloc(16, "salt");
const params = { m: 1 << 10, t: 2, p: 1 } as const;

const correct = Buffer.from("the correct password");
const wrongPublic = Buffer.from("guess-that-leaks-in-js");
const wrongPrivate = Buffer.from("guess-that-stays-in-cpp");

function occurrences(haystack: Buffer, needle: Buffer): number {
  let count = 0;
  let idx = haystack.indexOf(needle);
  while (idx !== -1) {
    count++;
    idx = haystack.indexOf(needle, idx + 1);
  }
  return count;
}

describe("V8 heap snapshot (zero-knowledge verification)", () => {
  it("computed verification hashes never enter the V8 heap", async () => {
    const expectedHash = await hashRaw({
      password: correct,
      salt,
      ...params,
      hashLength: 32,
    });

    // POSITIVE CONTROL — emulate a pure-JS verifier: the candidate hash for a
    // wrong guess is materialized as a JS string and kept referenced.
    const leakedInJs = (
      await hashRaw({ password: wrongPublic, salt, ...params, hashLength: 32 })
    ).toString("base64");

    // THIS LIBRARY — verify the other wrong guess many times. The candidate
    // hash is computed and wiped inside C++ on every call; it is never
    // returned to, or stored in, JavaScript.
    for (let i = 0; i < 500; i++) {
      const ok = await verifyRaw({
        password: wrongPrivate,
        salt,
        ...params,
        expectedHash,
      });
      assert.equal(ok, false);
    }

    const dir = mkdtempSync(join(tmpdir(), "argon-heap-"));
    const snapshotPath = join(dir, "heap.heapsnapshot");
    try {
      writeHeapSnapshot(snapshotPath);
      const snapshot = readFileSync(snapshotPath);

      // Build the needles AFTER the snapshot is on disk, so the act of
      // searching cannot plant the value we are searching for.
      const privateHash = await hashRaw({
        password: wrongPrivate,
        salt,
        ...params,
        hashLength: 32,
      });
      const privateB64 = Buffer.from(privateHash.toString("base64"), "latin1");
      const privateHex = Buffer.from(privateHash.toString("hex"), "latin1");
      const publicB64 = Buffer.from(leakedInJs, "latin1");

      const foundPublic = occurrences(snapshot, publicB64);
      const foundPrivateB64 = occurrences(snapshot, privateB64);
      const foundPrivateHex = occurrences(snapshot, privateHex);

      console.log(
        `\n  positive control (JS string hash): found ${foundPublic} time(s) in heap` +
          `\n  native verify candidate hash:      found ${foundPrivateB64 + foundPrivateHex} time(s) in heap\n`,
      );

      // Methodology check: a hash held in JS really is recoverable.
      assert(
        foundPublic >= 1,
        "positive control not found — the snapshot search is not working",
      );
      // The actual guarantee: the natively-computed hash is absent.
      assert.equal(
        foundPrivateB64 + foundPrivateHex,
        0,
        "a natively-computed verification hash leaked into the V8 heap",
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
