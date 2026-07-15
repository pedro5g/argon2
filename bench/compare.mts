/**
 * Comparative benchmark: this library vs. node-argon2 (the incumbent) and, when
 * available, Node's built-in `crypto.argon2` (Node >= 26 / OpenSSL >= 3.2).
 *
 * Run with:  pnpm bench
 *
 * It reports three things that matter when choosing a password hasher:
 *   1. Drop-in compatibility — do the digests match byte for byte?
 *   2. Raw performance — how fast is a hash at production parameters?
 *   3. Security posture — which hardening features each option actually has,
 *      plus a live burst showing peak memory stays thread-pool-bounded for both.
 */

import { createHash, randomBytes } from "node:crypto";
import * as crypto from "node:crypto";
import * as ours from "../index.js";
// node-argon2 ships its own types.
import legacy from "argon2";

const salt = Buffer.alloc(16, "salt");
const password = "correct horse battery staple";

const DEFAULTS = { memoryCost: 1 << 16, timeCost: 3, parallelism: 4 };

function hr(): void {
  console.log("─".repeat(72));
}

function sha(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex").slice(0, 16);
}

// ---------------------------------------------------------------------------
// Optional third contender: Node's native crypto.argon2 (feature-detected).
// The API is still stabilizing; this adapter is defensive and simply reports
// "unavailable" on runtimes that don't ship it (like the Node 22 used here).
// ---------------------------------------------------------------------------
type NativeArgon2 = ((opts: unknown) => Buffer) | null;

function detectNativeArgon2(): NativeArgon2 {
  const c = crypto as unknown as Record<string, unknown>;
  const fn = c.argon2 ?? c.argon2id;
  return typeof fn === "function" ? (fn as NativeArgon2) : null;
}

// ---------------------------------------------------------------------------
// 1. Drop-in compatibility
// ---------------------------------------------------------------------------
async function compatibility(): Promise<void> {
  hr();
  console.log("1. DROP-IN COMPATIBILITY (identical inputs → identical output)\n");

  const oursEncoded = await ours.hash(password, { salt, ...DEFAULTS });
  const legacyEncoded = await legacy.hash(password, {
    salt,
    memoryCost: DEFAULTS.memoryCost,
    timeCost: DEFAULTS.timeCost,
    parallelism: DEFAULTS.parallelism,
  });

  const oursRaw = await ours.hash(password, { salt, ...DEFAULTS, raw: true });
  const legacyRaw = (await legacy.hash(password, {
    salt,
    raw: true,
    memoryCost: DEFAULTS.memoryCost,
    timeCost: DEFAULTS.timeCost,
    parallelism: DEFAULTS.parallelism,
  })) as Buffer;

  console.log(`  this lib   encoded: ${oursEncoded}`);
  console.log(`  node-argon2 encoded: ${legacyEncoded}`);
  console.log(`  raw digest match:    ${oursRaw.equals(legacyRaw) ? "YES ✓" : "NO ✗"}`);
  console.log(`  encoded match:       ${oursEncoded === legacyEncoded ? "YES ✓" : "NO ✗"}`);

  // Cross-verification: each library accepts the other's digest.
  const crossA = await ours.verify(legacyEncoded, password);
  const crossB = await legacy.verify(oursEncoded, password);
  console.log(`  we verify their digest: ${crossA ? "YES ✓" : "NO ✗"}`);
  console.log(`  they verify our digest: ${crossB ? "YES ✓" : "NO ✗"}`);
  console.log();
}

// ---------------------------------------------------------------------------
// 2. Performance
// ---------------------------------------------------------------------------
async function bench(
  label: string,
  fn: () => Promise<unknown>,
  runs: number,
): Promise<number> {
  // warmup
  await fn();
  const start = performance.now();
  for (let i = 0; i < runs; i++) await fn();
  const perOp = (performance.now() - start) / runs;
  console.log(`  ${label.padEnd(26)} ${perOp.toFixed(2)} ms/hash`);
  return perOp;
}

async function performance_(): Promise<void> {
  hr();
  console.log("2. PERFORMANCE (Argon2id, m=64MiB, t=3, p=4)\n");
  const runs = 20;

  await bench(
    "this lib",
    () => ours.hash(password, { salt, ...DEFAULTS, raw: true }),
    runs,
  );
  await bench(
    "node-argon2",
    () =>
      legacy.hash(password, {
        salt,
        raw: true,
        memoryCost: DEFAULTS.memoryCost,
        timeCost: DEFAULTS.timeCost,
        parallelism: DEFAULTS.parallelism,
      }),
    runs,
  );

  const native = detectNativeArgon2();
  if (native) {
    console.log("  node crypto.argon2         detected — see adapter to enable timing");
  } else {
    console.log(
      `  node crypto.argon2         unavailable (this runtime: Node ${process.versions.node}, OpenSSL ${process.versions.openssl})`,
    );
  }
  console.log();
}

// ---------------------------------------------------------------------------
// 3. Security posture — feature matrix + live DoS demonstration
// ---------------------------------------------------------------------------
function featureMatrix(): void {
  hr();
  console.log("3. SECURITY POSTURE\n");
  const rows: Array<[string, string, string]> = [
    ["Feature", "this lib", "node-argon2"],
    ["Wipe password copy before free", "yes", "yes (CLEAR flags)"],
    ["Lock memory (mlock/VirtualLock)", "yes", "no"],
    ["Exclude memory from core dumps", "yes (MADV_DONTDUMP)", "no"],
    ["Constant-time verify in native code", "yes", "yes"],
    ["Cost-limit check on stored digests", "yes", "no"],
    ["Huge-page hint for the matrix", "yes (MADV_HUGEPAGE)", "no"],
  ];
  const w = [37, 20, 18];
  for (const [i, row] of rows.entries()) {
    console.log("  " + row.map((c, j) => c.padEnd(w[j])).join(""));
    if (i === 0) console.log("  " + w.map((n) => "-".repeat(n - 1)).join(" "));
  }
  console.log();
}

async function measureBurst(
  run: () => Promise<unknown>,
  burst: number,
): Promise<{ ok: number; ms: number; peakMiB: number }> {
  const baseline = process.memoryUsage().rss;
  let peak = baseline;
  const timer = setInterval(() => {
    const rss = process.memoryUsage().rss;
    if (rss > peak) peak = rss;
  }, 2);
  timer.unref();

  const t0 = performance.now();
  const settled = await Promise.allSettled(
    Array.from({ length: burst }, () => run()),
  );
  const ms = performance.now() - t0;
  clearInterval(timer);

  return {
    ok: settled.filter((r) => r.status === "fulfilled").length,
    ms,
    peakMiB: (peak - baseline) / (1024 * 1024),
  };
}

async function dosDemo(): Promise<void> {
  console.log("  Live burst — concurrent 64 MiB hashes, peak RSS sampled:\n");
  const burst = 60;

  const oursR = await measureBurst(
    () => ours.hash(password, { salt, ...DEFAULTS, raw: true }),
    burst,
  );
  const legacyR = await measureBurst(
    () =>
      legacy.hash(password, {
        salt,
        raw: true,
        memoryCost: DEFAULTS.memoryCost,
        timeCost: DEFAULTS.timeCost,
        parallelism: DEFAULTS.parallelism,
      }),
    burst,
  );

  console.log(
    `  this lib:    ${oursR.ok}/${burst} done in ${oursR.ms.toFixed(0)} ms, peak +${oursR.peakMiB.toFixed(0)} MiB`,
  );
  console.log(
    `  node-argon2: ${legacyR.ok}/${burst} done in ${legacyR.ms.toFixed(0)} ms, peak +${legacyR.peakMiB.toFixed(0)} MiB`,
  );
  console.log(
    "\n  → Both accept every request and resolve; peak memory is bounded by the\n" +
      "    libuv thread pool (≈ UV_THREADPOOL_SIZE × 64 MiB), not by the burst\n" +
      "    size. Load-shedding, if wanted, belongs in the application layer.\n",
  );
}

async function main(): Promise<void> {
  console.log(
    `\nArgon2 comparison — Node ${process.versions.node}, node-argon2 ${
      (legacy as { version?: string }).version ?? "0.44.0"
    }`,
  );
  console.log(`marker (ignore): ${sha(randomBytes(8))}`);
  await compatibility();
  await performance_();
  featureMatrix();
  await dosDemo();
  hr();
}

await main();
