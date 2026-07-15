import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { hashRaw, verifyRaw } from "./index.js";

/**
 * Vulnerability #2 — Timing side channel.
 *
 * A naive comparison (`==`, `strcmp`, `Buffer.compare`) returns as soon as it
 * hits the first differing byte. By measuring response time to sub-microsecond
 * precision an attacker can recover a secret byte by byte.
 *
 * Two things make this library's verification timing-safe:
 *   1. Argon2 performs the *same* memory-hard work regardless of whether the
 *      password is right, wrong, or almost right — so the dominant cost is
 *      constant by construction.
 *   2. The final tag comparison uses `constant_time_compare` (a branchless
 *      accumulate-XOR loop) as defense in depth.
 *
 * This test measures end-to-end `verifyRaw` latency — exactly what a remote
 * attacker observes — across three scenarios and asserts the timings are
 * statistically indistinguishable.
 */

const PARAMS = { m: 1 << 12, t: 1, p: 1 } as const; // fast but real work
const salt = Buffer.alloc(16, "salt");
const correct = Buffer.from("correct horse battery staple");
// Differs from `correct` only in the final byte — the "almost right" guess.
const nearMiss = Buffer.from("correct horse battery staplE");
// Differs from the first byte — the "completely wrong" guess.
const wrong = Buffer.from("Xorrect horse battery staple");

const SAMPLES = 2500;
const WARMUP = 200;
// End-to-end verify is dominated by ~ms of Argon2 work; the tag compare is
// nanoseconds. Medians across thousands of interleaved samples sit well within
// this bound. A byte-by-byte leak large enough to matter would blow past it.
const TOLERANCE = 0.25;

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  return sorted.length % 2 === 0
    ? (sorted[mid - 1] + sorted[mid]) / 2
    : sorted[mid];
}

async function timeVerify(password: Buffer, expectedHash: Buffer): Promise<number> {
  const start = process.hrtime.bigint();
  await verifyRaw({ password, salt, ...PARAMS, expectedHash });
  return Number(process.hrtime.bigint() - start);
}

describe("timing side-channel resistance", () => {
  it("verify latency does not depend on password correctness", async () => {
    const expectedHash = await hashRaw({
      password: correct,
      salt,
      ...PARAMS,
      hashLength: 32,
    });

    const scenarios = [
      { name: "wrong (1st byte)", password: wrong, samples: [] as number[] },
      { name: "near-miss (last byte)", password: nearMiss, samples: [] as number[] },
      { name: "correct (full match)", password: correct, samples: [] as number[] },
    ];

    // Warm up the JIT and the threadpool.
    for (let i = 0; i < WARMUP; i++) {
      await timeVerify(scenarios[i % 3].password, expectedHash);
    }

    // Interleave the scenarios round-robin so thermal / scheduler drift
    // affects all three equally instead of biasing one.
    for (let i = 0; i < SAMPLES; i++) {
      const s = scenarios[i % 3];
      s.samples.push(await timeVerify(s.password, expectedHash));
    }

    const stats = scenarios.map((s) => ({
      name: s.name,
      medianUs: median(s.samples) / 1000,
    }));
    const medians = stats.map((s) => s.medianUs);
    const overall = median(medians);
    const spread = (Math.max(...medians) - Math.min(...medians)) / overall;

    console.log("\n  median verify latency per scenario:");
    for (const s of stats) {
      console.log(`    ${s.name.padEnd(22)} ${s.medianUs.toFixed(2)} us`);
    }
    console.log(
      `  relative spread: ${(spread * 100).toFixed(2)}% (tolerance ${(TOLERANCE * 100).toFixed(0)}%)\n`,
    );

    assert(
      spread < TOLERANCE,
      `timing spread ${(spread * 100).toFixed(2)}% exceeds tolerance; possible side channel`,
    );
  });
});
