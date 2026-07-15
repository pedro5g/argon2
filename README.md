# argon

Hardened [Argon2](https://github.com/P-H-C/phc-winner-argon2) password hashing
for Node.js, built as a drop-in replacement for `node-argon2` with a stricter
security posture around **how the plaintext and derived material live in
memory** — and a test suite that proves it.

- **Drop-in compatible**: same PHC digests, byte for byte. Databases hashed
  with `node-argon2` keep verifying without migration.
- **Zero plaintext traces**: every native copy of the password is wiped before
  its memory is released — verified by a test that scans the process's own
  memory for the password after hashing ([memory.test.ts](memory.test.ts)).
- **Constant-time verify in native code**: the candidate hash is computed and
  compared inside C++; it never crosses back into the JavaScript heap.
- **Parameter-injection protection**: cost parameters parsed from a stored
  digest are validated against configurable limits *before* any memory is
  allocated.
- **Predictable under load**: like `node-argon2`, every request is accepted and
  resolves; peak memory is bounded structurally by the libuv thread pool, not by
  request count — no surprise rejections of legitimate traffic.
- **Faster big allocations**: the Argon2 memory matrix is 2 MiB-aligned and
  advised for transparent huge pages on Linux, reducing TLB pressure during
  the memory-hard passes.

Correctness is pinned to the official Argon2 reference vectors (RFC 9106) and
to `node-argon2`'s own test vectors — 107 tests in total.

## Install & build

```sh
pnpm install
pnpm build   # compiles the native addon (node-gyp)
pnpm test    # runs the full suite with the built-in node:test runner
```

## Quick start

```js
import { hash, verify, needsRehash } from "./index.js";

// Registration: hash with a random 16-byte salt and sane defaults
const digest = await hash(userPassword);
// => "$argon2id$v=19$m=65536,t=3,p=4$P0lZ4Dg...$Ilxi2BB..."
// Store `digest` — salt and parameters are embedded in it.

// Login: verify, then transparently upgrade old hashes
if (await verify(digest, submittedPassword)) {
  if (needsRehash(digest)) {
    const upgraded = await hash(submittedPassword);
    // persist `upgraded`
  }
  // grant access
}
```

### Choosing parameters

Argon2's security comes primarily from `memoryCost`. Raise it as high as your
deployment tolerates, then tune `timeCost` so one hash takes roughly 0.5–1 s
for interactive logins:

| Scenario                         | `memoryCost`     | `timeCost` | `parallelism` |
| -------------------------------- | ---------------- | ---------- | ------------- |
| Default (RFC 9106 second option) | 65536 (64 MiB)   | 3          | 4             |
| Memory-constrained (OWASP min.)  | 19456 (19 MiB)   | 2          | 1             |
| High security                    | 262144 (256 MiB) | 3          | 4             |

```js
const digest = await hash(password, {
  memoryCost: 1 << 17, // 128 MiB
  timeCost: 4,
  parallelism: 4,
});
```

### Pepper (server-side secret)

A pepper is mixed into the hash but never stored in the digest. Keep it
outside the database (env var, KMS):

```js
const pepper = Buffer.from(process.env.PEPPER, "base64");

const digest = await hash(password, { secret: pepper });
const ok = await verify(digest, password, { secret: pepper });
```

### Handling the plaintext correctly

Prefer passing passwords as `Buffer`s and wiping them when done — JavaScript
strings are immutable and can never be erased from memory:

```js
const passwordBuffer = Buffer.from(rawBodyChunk); // avoid ever creating a string
const digest = await hash(passwordBuffer);
passwordBuffer.fill(0); // you own this copy; wipe it
```

When you do pass a string, the temporary Buffer this library creates from it
is wiped automatically — but the string itself stays in the V8 heap until the
garbage collector discards it. This limitation is demonstrated, with a real
memory scan, in [memory.test.ts](memory.test.ts).

## The vulnerability this library eliminates

`free()` does not erase memory. A hashing library that copies your password
into an internal buffer and releases it without wiping leaves the plaintext
sitting in freed heap pages — recoverable through a core dump, swap, a
debugger, or any memory-disclosure bug (think Heartbleed) for as long as the
process lives.

[memory.test.ts](memory.test.ts) replicates this scenario in a testable way.
It scans the process's own memory through `/proc/self/mem` — exactly what an
attacker with a memory-disclosure primitive would see — looking for a unique
password marker:

1. **Vulnerable pattern**: an internal copy is made and dropped without
   wiping. The scan finds the password in memory after "free". ✗
2. **This library**: after `hashRaw()` completes and the caller wipes its own
   buffer, the scan finds **zero** occurrences of the password in the entire
   process. ✓
3. **Documented limitation**: with a string password, the immutable JS string
   remains findable — which is why the Buffer API is recommended.

What the C++ engine does to make (2) true:

| Measure | Where |
| --- | --- |
| Password/secret copied into page-aligned native memory | `SecureBuffer` in [argon2_core.cpp](argon2_core.cpp) |
| Pages excluded from core dumps (`MADV_DONTDUMP`) | `custom_allocate` |
| Pages locked against swapping, best effort (`mlock`) | `lock_memory` |
| Wiped with `explicit_bzero`/`SecureZeroMemory` before `free` | `secure_wipe` |
| Password cleared inside Argon2 right after absorption | `ARGON2_FLAG_CLEAR_PASSWORD \| ARGON2_FLAG_CLEAR_SECRET` |
| Whole 64 MiB matrix wiped before release | reference `core.c` (`clear_internal_memory`) |
| Derived hash wiped after delivery to JS | worker destructors |

`mlock` is deliberately *best effort*: `RLIMIT_MEMLOCK` defaults (often
8–64 MiB) sit below one hash's working memory, and failing hard would be a
denial of service on default systems. The wipe-before-free guarantee — the one
that matters for the scan above — holds regardless.

## API

### `hash(password, options?) → Promise<string | Buffer>`

Hashes a password into a self-contained PHC string (or a raw `Buffer` with
`raw: true`). Options: `hashLength`, `timeCost`, `memoryCost`, `parallelism`,
`type` (`argon2d` | `argon2i` | `argon2id`), `version`, `salt`, `saltLength`,
`secret`, `associatedData`, `raw`.

### `verify(digest, password, options?) → Promise<boolean>`

Verifies a password against a PHC digest. Reads parameters from the digest,
enforces `options.limits` (defaults: `memoryCost` ≤ 4 GiB, `timeCost` ≤ 1024,
`parallelism` ≤ 128) before allocating, and compares in constant time in
native code. Returns `false` for digests of foreign schemes (e.g. bcrypt), so
mixed user tables can be probed safely. Accepts `options.secret` for peppered
digests.

### `needsRehash(digest, options?) → boolean`

`true` when the digest was created with parameters different from the current
ones — hash again on the next successful login to upgrade.

### Low-level: `hashRaw(options)` / `verifyRaw(options)`

Direct access to the engine for KDF-style usage: you supply `password`,
`salt`, `m`, `t`, `p`, `hashLength` (and optionally `secret`, `data`,
`version`, `type`) and store everything yourself. `verifyRaw` takes
`expectedHash` and never lets the computed hash reach JavaScript.

```js
import { hashRaw, verifyRaw } from "./index.js";

const key = await hashRaw({
  password: passphrase,
  salt,             // >= 8 bytes
  m: 1 << 16,       // KiB
  t: 3,
  p: 4,
  hashLength: 32,
});

const ok = await verifyRaw({ password: passphrase, salt, m: 1 << 16, t: 3, p: 4, expectedHash: key });
```

### PHC format: `serialize` / `deserialize` ([phc.ts](phc.ts))

A typed implementation of the [PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md),
usable standalone. Compared to `@phc/format` it does not mutate its input,
preserves `version: 0`, rejects duplicate parameters and hash-without-salt,
and refuses to silently lose precision on oversized integers.

## Concurrency and memory under load

There is no built-in request limiter — behavior matches `node-argon2` exactly:
every call is queued and resolves. Hashing runs on the libuv thread pool, so at
any instant only `UV_THREADPOOL_SIZE` (default 4) Argon2 matrices are live,
regardless of how many requests are in flight. Peak memory is therefore
`≈ UV_THREADPOOL_SIZE × memoryCost` (≈ 256 MiB at the 64 MiB default), bounded
by the pool rather than by the burst size.

Load-shedding, when a deployment needs it, belongs one layer up — a semaphore, a
bounded queue, or an HTTP 503 — where the application owns its SLA and can avoid
dropping legitimate traffic. Raising `UV_THREADPOOL_SIZE` raises throughput and
peak memory together; size it against available RAM.

## Tests

```sh
pnpm test            # fast, deterministic correctness suite (107 tests)
pnpm test:security   # vulnerability demonstrations (see below)
pnpm bench           # comparative benchmark vs node-argon2
sudo pnpm test:swap  # end-to-end swap-dump proof (throwaway VM only)
```

Correctness suite:

- **RFC 9106 reference vectors** for argon2d/i/id v1.3 and v1.0, with secret
  and associated data ([argon2.test.ts](argon2.test.ts))
- **node-argon2 parity**: identical raw digests and PHC strings for identical
  inputs, including null bytes, pepper and associated data
- **Memory-safety replication** via `/proc/self/mem` scan ([memory.test.ts](memory.test.ts))
- **Concurrency**: large bursts all resolve; repeated bursts and post-failure
  recovery leave the module healthy
- Native-binding hardening (invalid types rejected instead of crashing)
- PHC serializer round-trips and error cases ([phc.test.ts](phc.test.ts))

## Security demonstrations

Each classic password-hashing vulnerability is reproduced in a runnable test
that fails if the corresponding defense regresses. Run them with
`pnpm test:security`.

| # | Attack | Defense proven | Test | Result on a dev machine |
| - | ------ | -------------- | ---- | ----------------------- |
| 1 | Resource-exhaustion DoS / OOM | Thread-pool-bounded peak memory | [dos.sec.ts](dos.sec.ts) | 64 concurrent 64 MiB hashes all resolve; peak **+260 MiB** (≈ 4 × 64), flat as the burst grows |
| 2 | Timing side channel | Identical Argon2 work + constant-time compare | [timing.sec.ts](timing.sec.ts) | wrong/near-miss/correct medians within **0.14 %** |
| 3 | V8 heap inspection | Verification runs and is wiped in C++ | [heap.sec.ts](heap.sec.ts) | JS-held hash found 1×; native hash found **0×** |
| 4 | Swap dumping | `mlock` / `VirtualLock` | [swap.sec.ts](swap.sec.ts) + [scripts/swap-dump-test.sh](scripts/swap-dump-test.sh) | 16 MiB locked during hash, 0 after; marker never reaches swap |

Notes on methodology:

- **#1** fires a burst of concurrent 64 MiB hashes and samples peak RSS. Every
  request resolves (no shedding, matching `node-argon2`); peak memory stays a
  small multiple of 64 MiB because the libuv thread pool — not a per-request
  limiter — caps how many matrices are live at once, and stays flat when the
  burst quadruples.
- **#2** interleaves thousands of `verifyRaw` calls for a wrong, near-correct
  and correct password and compares medians. Argon2 performs the same
  memory-hard work in all three cases, so the timings are indistinguishable.
- **#3** takes a real V8 heap snapshot. A candidate hash kept as a JS value
  (what a pure-JS verifier leaves behind) is recoverable from the snapshot; the
  hash computed inside `verifyRaw` never becomes a V8 object and is absent.
- **#4** is proven two ways: an automated test that watches `VmLck` in
  `/proc/self/status` rise to cover the Argon2 matrix while hashing, and a
  root-only script that fills RAM to force swapping and greps the swap file for
  the password (never found).

## Comparison with node-argon2

`pnpm bench` runs a live comparison. On Node 22 with `node-argon2@0.44.0`:

```
1. DROP-IN COMPATIBILITY
   raw digest match:       YES   (byte-for-byte identical hashes)
   we verify their digest: YES   they verify our digest: YES

2. PERFORMANCE (Argon2id, m=64MiB, t=3, p=4)
   this lib     ~60 ms/hash
   node-argon2  ~60 ms/hash   (same underlying reference core)

3. SECURITY POSTURE                     this lib   node-argon2
   Lock memory (mlock/VirtualLock)      yes        no
   Exclude memory from core dumps       yes        no
   Cost-limit check on stored digests   yes        no
   Huge-page hint for the matrix        yes        no

   Live burst (64 concurrent 64 MiB hashes):
   this lib:    64 done + 0 shed, peak +260 MiB   (thread-pool-bounded)
   node-argon2: 64 done + 0 shed, peak +260 MiB   (same behavior)
```

Same cryptographic output, speed and load behavior (both wrap the reference
Argon2 core and run on the libuv thread pool), but this library adds the
memory-locking, core-dump exclusion and digest-cost limits that `node-argon2`
leaves to the caller.

Node's built-in `crypto.argon2` (Node ≥ 26 / OpenSSL ≥ 3.2) is detected
automatically by the benchmark and included when present; on older runtimes it
is reported as unavailable.

## License

[MIT](LICENSE)
