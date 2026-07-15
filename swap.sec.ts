import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import { hashRaw } from "./index.js";

/**
 * Vulnerability #4 — Secrets leaking to disk via swap.
 *
 * Under memory pressure the OS pages RAM out to the swap file. Anything
 * sensitive that gets paged out stays on disk — recoverable from a stolen
 * drive or a container image long after the process ends.
 *
 * This library locks its sensitive allocations into physical RAM with
 * `mlock` (POSIX) / `VirtualLock` (Windows), forbidding the kernel from
 * swapping them out.
 *
 * A full end-to-end proof (fill RAM, force swapping, grep the swap file)
 * requires root and is scripted in `scripts/swap-dump-test.sh`. What we can
 * assert automatically here is that the mechanism is actually wired up: while
 * a hash runs, the process's locked-memory footprint (`VmLck` in
 * /proc/self/status) rises to cover the Argon2 matrix, then falls back to
 * zero once the memory is unlocked and freed.
 */

const isLinux = process.platform === "linux";

/** Soft limit on lockable memory, in bytes (RLIMIT_MEMLOCK). */
function lockedMemoryLimit(): number {
  try {
    const limits = readFileSync("/proc/self/limits", "latin1");
    const line = limits.split("\n").find((l) => /Max locked memory/i.test(l));
    if (!line) return 0;
    const soft = line.split(/\s+/)[3];
    return soft === "unlimited" ? Number.POSITIVE_INFINITY : Number(soft);
  } catch {
    return 0;
  }
}

/** Currently locked memory reported by the kernel, in KiB. */
function vmLockedKiB(): number {
  const status = readFileSync("/proc/self/status", "latin1");
  const line = status.split("\n").find((l) => l.startsWith("VmLck"));
  return line ? Number(line.replace(/[^\d]/g, "")) : 0;
}

// 16 MiB matrix: large enough to see clearly in VmLck, small enough to fit
// under a typical RLIMIT_MEMLOCK so the lock actually succeeds.
const MEMORY_COST = 1 << 14; // 16384 KiB
const matrixBytes = MEMORY_COST * 1024;
const enoughLimit = lockedMemoryLimit() >= matrixBytes * 1.5;

describe("swap protection (memory locking)", () => {
  it(
    "locks the Argon2 matrix into RAM while hashing (VmLck rises)",
    { skip: !isLinux || !enoughLimit },
    async () => {
      assert.equal(vmLockedKiB(), 0, "expected no locked memory at rest");

      let peakLockedKiB = 0;
      let done = false;
      const promise = hashRaw({
        password: Buffer.from("password"),
        salt: Buffer.alloc(16, "salt"),
        m: MEMORY_COST,
        t: 8, // stretch the run so the poll loop can observe the lock
        p: 1,
        hashLength: 32,
      }).then((res) => {
        done = true;
        return res;
      });

      // Poll while the hash runs on the libuv threadpool.
      while (!done) {
        const locked = vmLockedKiB();
        if (locked > peakLockedKiB) peakLockedKiB = locked;
        await new Promise((resolve) => setImmediate(resolve));
      }

      await promise;

      console.log(
        `\n  peak locked memory during hash: ${(peakLockedKiB / 1024).toFixed(1)} MiB` +
          ` (matrix ~${(matrixBytes / 1024 / 1024).toFixed(0)} MiB)` +
          `\n  locked memory after hash:       ${(vmLockedKiB() / 1024).toFixed(1)} MiB\n`,
      );

      // The matrix (and password copy) were locked into RAM during hashing...
      assert(
        peakLockedKiB > 4096,
        `expected VmLck to exceed 4 MiB while hashing, saw ${peakLockedKiB} KiB`,
      );
      // ...and unlocked afterwards, so we don't pin RAM forever.
      assert.equal(vmLockedKiB(), 0, "memory stayed locked after the hash");
    },
  );
});
