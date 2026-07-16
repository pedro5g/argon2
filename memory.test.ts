import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { randomBytes } from "node:crypto";
import { closeSync, openSync, readFileSync, readSync } from "node:fs";
import { hash, hashRaw } from "./index.js";

/**
 * These tests replicate, in a verifiable way, the vulnerability class that the
 * C++ engine is designed to eliminate: plaintext passwords lingering in
 * process memory after use.
 *
 * `free()` does not erase memory. Any library that copies a password into an
 * internal buffer and releases it without wiping leaves the plaintext sitting
 * in freed heap pages, recoverable through a core dump, a debugger, swap, a
 * memory-disclosure bug (Heartbleed-style) or a compromised process.
 *
 * The scanner below reads this process's own memory through /proc/self/mem —
 * exactly what an attacker with a memory-disclosure primitive would see — and
 * counts occurrences of a unique password marker.
 */

const isLinux = process.platform === "linux";

const XOR_KEY = 0x5a;

/**
 * The needle is stored XOR-encoded so the scanner itself never materializes
 * the plaintext marker being searched (which would create the very artifact
 * the scan is looking for).
 */
function encodeNeedle(marker: Buffer): Buffer {
  const encoded = Buffer.alloc(marker.length);
  for (let i = 0; i < marker.length; i++) {
    encoded[i] = marker[i] ^ XOR_KEY;
  }
  return encoded;
}

/** Counts occurrences of the (encoded) marker in all anonymous writable memory. */
function countMarkerInProcessMemory(needleEnc: Buffer): number {
  const maps = readFileSync("/proc/self/maps", "latin1");
  const regions: Array<[bigint, bigint]> = [];
  for (const line of maps.split("\n")) {
    const parts = line.split(/\s+/);
    if (parts.length < 5) continue;
    const [range, perms, , , inode] = parts;
    // Only anonymous read-write memory: heap, stacks, mmap'd buffers. That is
    // where every password copy would live.
    if (!perms.startsWith("rw") || inode !== "0") continue;
    const [start, end] = range.split("-").map((addr) => BigInt(`0x${addr}`));
    regions.push([start, end]);
  }

  const CHUNK_SIZE = 1 << 20;
  const overlap = needleEnc.length - 1;
  const chunk = Buffer.alloc(CHUNK_SIZE);
  const fd = openSync("/proc/self/mem", "r");
  let found = 0;

  try {
    for (const [start, end] of regions) {
      let pos = start;
      while (pos < end) {
        const remaining = Number(end - pos);
        const want = remaining > CHUNK_SIZE ? CHUNK_SIZE : remaining;
        let n = 0;
        try {
          n = readSync(fd, chunk, 0, want, pos);
        } catch {
          break; // region vanished or is unreadable; skip it
        }
        if (n <= 0) break;

        // XOR the copy in place, then search for the encoded needle: a match
        // means the raw marker exists at that address. The raw marker is
        // never present in the scanner's own buffers.
        for (let i = 0; i < n; i++) chunk[i] ^= XOR_KEY;

        let idx = chunk.indexOf(needleEnc);
        while (idx !== -1 && idx <= n - needleEnc.length) {
          found++;
          idx = chunk.indexOf(needleEnc, idx + 1);
        }

        chunk.fill(0, 0, n);
        pos += BigInt(want > overlap ? want - overlap : want);
      }
    }
  } finally {
    closeSync(fd);
  }

  return found;
}

describe("memory safety (vulnerability replication)", () => {
  it(
    "VULNERABLE PATTERN: an unwiped plaintext copy is recoverable from memory",
    { skip: !isLinux },
    () => {
      const marker = randomBytes(32);
      const needleEnc = encodeNeedle(marker);

      // What a careless implementation does: hold the password in a plain,
      // un-wiped Buffer. For the whole time it is live — the realistic window,
      // since a freed-but-unzeroed buffer is just as readable until the
      // allocator happens to reuse it — a memory scan recovers it.
      //
      // We keep the copy referenced across the scan so the assertion is
      // deterministic (a freed copy may or may not have been overwritten yet,
      // which made this flaky on CI). The point stands either way: nothing
      // wipes it.
      const internalCopy = Buffer.from(marker);

      const found = countMarkerInProcessMemory(needleEnc);
      // The caller's buffer AND the un-wiped copy are both in memory.
      assert(
        found >= 2,
        `expected the plaintext copy to be recoverable, found ${found} occurrence(s)`,
      );

      // Only now do what a secure implementation does from the start.
      internalCopy.fill(0);
      marker.fill(0);
    },
  );

  it(
    "THIS LIBRARY: zero traces of the password remain after hashRaw",
    { skip: !isLinux },
    async () => {
      const marker = randomBytes(32);
      const needleEnc = encodeNeedle(marker);
      const salt = randomBytes(16);

      const digest = await hashRaw({
        password: marker,
        salt,
        m: 1 << 10,
        t: 2,
        p: 1,
        hashLength: 32,
      });
      assert.equal(digest.byteLength, 32);

      // The caller wipes the only copy it owns (documented usage pattern)...
      marker.fill(0);

      // ...and no other copy exists anywhere in the process: the native
      // SecureBuffer copy was wiped before its pages were freed, argon2
      // cleared the password after absorbing it (FLAG_CLEAR_PASSWORD), and
      // the blake2b state was cleared by the reference implementation.
      // If the C++ engine skipped any of those wipes, the marker would still
      // sit in freed heap pages and this scan would find it.
      const found = countMarkerInProcessMemory(needleEnc);
      assert.equal(
        found,
        0,
        `found ${found} unwiped cop(ies) of the password in process memory`,
      );
    },
  );

  it(
    "LIMITATION: string passwords cannot be wiped (pass Buffers instead)",
    { skip: !isLinux },
    async () => {
      // Strings are immutable in JavaScript: even though this library wipes
      // the temporary Buffer it creates from the string, the string itself
      // stays in the V8 heap until (and if) the GC discards it.
      const stringPassword = randomBytes(24).toString("hex");
      const needleEnc = encodeNeedle(Buffer.from(stringPassword, "latin1"));

      const digest = await hash(stringPassword, {
        memoryCost: 1 << 10,
        timeCost: 2,
        parallelism: 1,
      });
      assert.match(digest, /^\$argon2id\$/);

      const found = countMarkerInProcessMemory(needleEnc);
      assert(
        found >= 1,
        "expected the immutable JS string to remain in memory",
      );
    },
  );
});
