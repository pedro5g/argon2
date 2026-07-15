import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { hashRaw } from "./index.js";

/**
 * Vulnerability #1 — Resource-exhaustion DoS / OOM, and why the memory bound
 * is structural rather than a per-library gimmick.
 *
 * Argon2 is deliberately memory- and CPU-hungry. The naive fear is that firing
 * N concurrent hashes makes the process try to allocate N * memoryCost at once
 * and get killed by the OOM killer.
 *
 * That fear is mostly unfounded, and this test demonstrates why: the hashing
 * runs on libuv's thread pool (default 4 threads). The Argon2 matrix is
 * allocated inside the worker's Execute(), on a pool thread — so at any instant
 * only UV_THREADPOOL_SIZE matrices exist, regardless of how many requests are
 * queued. Peak memory is bounded by the pool, not by the burst size.
 *
 * This library therefore behaves exactly like node-argon2: every request is
 * accepted and eventually resolves (predictable, no surprise rejections).
 * Load-shedding, when a deployment needs it, belongs one layer up (a semaphore,
 * a queue with a bound, an HTTP 503) where the application owns its SLA — not
 * hidden inside the hashing primitive where it would silently drop legitimate
 * traffic during a normal burst.
 */

const MEMORY_COST = 1 << 16; // 64 MiB per hash — the "expensive" knob
const password = Buffer.from("password");
const salt = Buffer.alloc(16, "salt");

function samplePeakRss(intervalMs: number): { stop: () => number } {
  let peak = process.memoryUsage().rss;
  const timer = setInterval(() => {
    const rss = process.memoryUsage().rss;
    if (rss > peak) peak = rss;
  }, intervalMs);
  timer.unref();
  return {
    stop: () => {
      clearInterval(timer);
      return peak;
    },
  };
}

async function runBurst(size: number): Promise<{
  fulfilled: number;
  rejected: number;
  peakGrowthMiB: number;
}> {
  const baselineRss = process.memoryUsage().rss;
  const sampler = samplePeakRss(2);
  const settled = await Promise.allSettled(
    Array.from({ length: size }, () =>
      hashRaw({ password, salt, m: MEMORY_COST, t: 2, p: 4, hashLength: 32 }),
    ),
  );
  const peakRss = sampler.stop();
  return {
    fulfilled: settled.filter((r) => r.status === "fulfilled").length,
    rejected: settled.filter((r) => r.status === "rejected").length,
    peakGrowthMiB: (peakRss - baselineRss) / (1024 * 1024),
  };
}

describe("DoS / OOM resilience (thread-pool-bounded concurrency)", () => {
  it("accepts every request in a large burst and never rejects", async () => {
    const BURST = 64;
    const naiveDemandGiB = (BURST * MEMORY_COST) / (1024 * 1024);
    const { fulfilled, rejected, peakGrowthMiB } = await runBurst(BURST);

    // Predictable, node-argon2-compatible behavior: all resolve, none rejected.
    assert.equal(fulfilled, BURST);
    assert.equal(rejected, 0);

    // A naive reading says "BURST * 64 MiB of demand". Reality: the thread pool
    // serializes execution, so peak stays a small multiple of 64 MiB.
    assert(
      peakGrowthMiB < 700,
      `peak RSS grew ${peakGrowthMiB.toFixed(0)} MiB, expected < 700 MiB`,
    );

    console.log(
      `\n  burst:           ${BURST} concurrent 64 MiB hashes, all resolved` +
        `\n  naive demand:    ${naiveDemandGiB.toFixed(1)} GiB (${BURST} x 64 MiB)` +
        `\n  actual peak RSS: +${peakGrowthMiB.toFixed(0)} MiB (bounded by the thread pool)\n`,
    );
  });

  it("peak memory scales with the thread pool, not with the burst size", async () => {
    // Quadrupling the burst must NOT quadruple peak memory: the pool caps how
    // many matrices are live at once. This is the real reason the server does
    // not OOM, and it holds with or without any application-level limiter.
    const small = await runBurst(16);
    const large = await runBurst(64);

    assert.equal(small.rejected, 0);
    assert.equal(large.rejected, 0);
    assert(
      large.peakGrowthMiB < small.peakGrowthMiB + 300,
      `4x the burst grew peak by ${(large.peakGrowthMiB - small.peakGrowthMiB).toFixed(0)} MiB ` +
        `(${small.peakGrowthMiB.toFixed(0)} -> ${large.peakGrowthMiB.toFixed(0)}); ` +
        `expected the thread pool to keep it flat`,
    );
  });
});
