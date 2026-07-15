//@ts-ignore
import gypBuild from "node-gyp-build";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { __dirname } from "./__dirname.js";
import { serialize, deserialize } from "./phc.js";

// node-gyp-build looks for the addon in `<dir>/build` and `<dir>/prebuilds`
// without walking up, so it must be handed the package root. When running from
// source that is this file's directory; when running from the published `dist/`
// it is one or more levels up. Walk up until we find the directory that holds
// the compiled output (or the prebuilt binaries).
function resolveNativeRoot(start: string): string {
  let dir = start;
  for (;;) {
    if (existsSync(join(dir, "build")) || existsSync(join(dir, "prebuilds"))) {
      return dir;
    }
    const parent = dirname(dir);
    if (parent === dir) return start; // reached the filesystem root
    dir = parent;
  }
}

const bindings = gypBuild(resolveNativeRoot(__dirname)) as {
  hash: (options: InternalHashOptions) => Promise<Buffer>;
  verify: (options: InternalVerifyOptions) => Promise<boolean>;
};

/** Argon2 variant identifiers */
export const argon2d = 0;
export const argon2i = 1;
export const argon2id = 2;

const names: Record<number, string> = {
  [argon2d]: "argon2d",
  [argon2i]: "argon2i",
  [argon2id]: "argon2id",
};

const types: Record<string, number> = {
  argon2d,
  argon2i,
  argon2id,
};

// ---------------------------------------------------------------------------
// Low-level (raw) API
// ---------------------------------------------------------------------------

export interface Argon2BaseOptions {
  password: Buffer;
  salt: Buffer;
  /** Memory cost (in kibibytes) */
  m: number;
  /** Time cost (number of iterations) */
  t: number;
  /** Degree of parallelism (number of threads) */
  p: number;
  /** Optional secret value */
  secret?: Buffer;
  /** Optional associated data */
  data?: Buffer;
  /** Argon2 Version (Defaults to 0x13 - v1.3) */
  version?: number;
  /** Argon2 Type: 0 = Argon2d, 1 = Argon2i, 2 = Argon2id (Defaults to 2) */
  type?: number;
}

export interface Argon2HashOptions extends Argon2BaseOptions {
  /** Desired length of the generated hash in bytes */
  hashLength: number;
}

export interface Argon2VerifyOptions extends Argon2BaseOptions {
  /** The original hash buffer to securely compare against */
  expectedHash: Buffer;
}

// Internal types mapped with defaults applied for C++
interface InternalBaseOptions extends Argon2BaseOptions {
  secret: Buffer;
  data: Buffer;
  version: number;
  type: number;
}

interface InternalHashOptions extends InternalBaseOptions {
  hashLength: number;
}

interface InternalVerifyOptions extends InternalBaseOptions {
  expectedHash: Buffer;
}

function validateInteger(
  value: number,
  name: string,
  min: number,
  max: number,
): void {
  if (!Number.isInteger(value)) {
    throw new TypeError(`'${name}' must be an integer.`);
  }
  if (value < min || value > max) {
    throw new RangeError(
      `'${name}' is out of bounds. Allowed range: ${min} to ${max}.`,
    );
  }
}

function validateBuffer(value: unknown, name: string): asserts value is Buffer {
  if (!Buffer.isBuffer(value)) {
    throw new TypeError(`'${name}' must be a Buffer.`);
  }
}

function applyDefaultsAndValidate(
  params: Argon2BaseOptions,
): InternalBaseOptions {
  validateBuffer(params.password, "password");
  validateBuffer(params.salt, "salt");

  if (params.salt.byteLength < 8) {
    throw new RangeError("'salt' must be at least 8 bytes long.");
  }

  validateInteger(params.m, "m (memory_cost)", 8, 4294967295);
  validateInteger(params.t, "t (time_cost)", 1, 4294967295);
  validateInteger(params.p, "p (parallelism)", 1, 16777215);

  //argon2 requires at least 8 KiB (2 blocks per slice) per lane
  if (params.m < 8 * params.p) {
    throw new RangeError(
      `'m (memory_cost)' must be at least 8 * p (${8 * params.p} KiB for p=${params.p}).`,
    );
  }

  const version = params.version ?? 0x13; //default to Argon2 v1.3
  if (version !== 0x10 && version !== 0x13) {
    throw new RangeError("'version' must be 0x10 (v1.0) or 0x13 (v1.3).");
  }

  const type = params.type ?? argon2id;
  if (type !== argon2d && type !== argon2i && type !== argon2id) {
    throw new RangeError(
      "'type' must be 0 (Argon2d), 1 (Argon2i) or 2 (Argon2id).",
    );
  }

  //ensure empty buffers if not provided
  const secret = params.secret ?? Buffer.alloc(0);
  const data = params.data ?? Buffer.alloc(0);

  validateBuffer(secret, "secret");
  validateBuffer(data, "data");

  return {
    ...params,
    secret,
    data,
    version,
    type,
  };
}

/**
 * Computes a raw (binary) Argon2 hash using the secure C++ engine.
 *
 * This is the low-level primitive: you provide the salt and every cost
 * parameter explicitly, and you are responsible for storing them alongside
 * the resulting hash. For password storage, prefer {@link hash}, which
 * packages everything into a standard PHC string.
 *
 * The password bytes are copied into page-aligned native memory that is
 * excluded from core dumps, locked against swapping (best effort) and wiped
 * before being released — the caller's Buffer is never modified.
 *
 * @example
 * // Deriving a 32-byte key from a passphrase (KDF usage)
 * const key = await hashRaw({
 *   password: passphraseBuffer,
 *   salt: storedSalt, // >= 8 bytes, unique per derivation
 *   m: 1 << 16,       // 64 MiB
 *   t: 3,
 *   p: 4,
 *   hashLength: 32,
 * });
 *
 * @param options Configuration parameters for the hash generation
 * @returns A Promise that resolves to the securely generated hash Buffer
 */
export async function hashRaw(options: Argon2HashOptions): Promise<Buffer> {
  const baseOptions = applyDefaultsAndValidate(options);
  validateInteger(options.hashLength, "hashLength", 4, 4294967295);
  const internalOptions: InternalHashOptions = {
    ...baseOptions,
    hashLength: options.hashLength,
  };
  return bindings.hash(internalOptions);
}

/**
 * Verifies a password against a raw expected hash entirely in C++: the
 * candidate hash is computed and compared in constant time inside native
 * code, and never crosses back into the JavaScript heap.
 *
 * @example
 * const ok = await verifyRaw({
 *   password: candidateBuffer,
 *   salt: storedSalt,
 *   m: 1 << 16,
 *   t: 3,
 *   p: 4,
 *   expectedHash: storedHash,
 * });
 *
 * @param options Configuration parameters including the 'expectedHash'
 * @returns A Promise that resolves to true if the password matches, false otherwise
 */
export async function verifyRaw(options: Argon2VerifyOptions): Promise<boolean> {
  validateBuffer(options.expectedHash, "expectedHash");
  if (options.expectedHash.byteLength < 4) {
    throw new RangeError("'expectedHash' must be at least 4 bytes long.");
  }
  const baseOptions = applyDefaultsAndValidate(options);
  const internalOptions: InternalVerifyOptions = {
    ...baseOptions,
    expectedHash: options.expectedHash,
  };
  return bindings.verify(internalOptions);
}

// ---------------------------------------------------------------------------
// High-level (PHC string) API
// ---------------------------------------------------------------------------

/**
 * Default parameters, compatible with node-argon2: Argon2id v1.3 with
 * 64 MiB of memory, 3 iterations and 4 lanes.
 */
export const defaults = Object.freeze({
  hashLength: 32,
  timeCost: 3,
  memoryCost: 1 << 16,
  parallelism: 4,
  saltLength: 16,
  type: argon2id as number,
  version: 0x13,
});

export interface HashOptions {
  /** Length of the generated hash in bytes. Default: 32. */
  hashLength?: number;
  /** Number of iterations (t). Default: 3. */
  timeCost?: number;
  /** Memory usage in KiB (m). Default: 65536 (64 MiB). */
  memoryCost?: number;
  /** Number of lanes/threads (p). Default: 4. */
  parallelism?: number;
  /** Argon2 variant. Default: argon2id (recommended). */
  type?: number;
  /** Argon2 version: 0x10 or 0x13. Default: 0x13. */
  version?: number;
  /** Salt to use. Default: `saltLength` cryptographically random bytes. */
  salt?: Buffer;
  /** Length of the generated random salt when `salt` is not given. Default: 16. */
  saltLength?: number;
  /** Server-side pepper, mixed into the hash but not stored in the digest. */
  secret?: Buffer;
  /** Associated data, stored base64-encoded in the digest (`data=` param). */
  associatedData?: Buffer;
}

export interface VerifyOptions {
  /** The pepper used when the digest was created, if any. */
  secret?: Buffer;
  /**
   * Upper bounds applied to the cost parameters parsed from the digest before
   * any memory is allocated. Protects against parameter-injection DoS when
   * digests come from an untrusted store.
   * Defaults: memoryCost <= 4194304 KiB (4 GiB), timeCost <= 1024,
   * parallelism <= 128.
   */
  limits?: {
    memoryCost?: number;
    timeCost?: number;
    parallelism?: number;
  };
}

export interface RehashOptions {
  timeCost?: number;
  memoryCost?: number;
  parallelism?: number;
  version?: number;
}

const defaultVerifyLimits = Object.freeze({
  memoryCost: 1 << 22, // 4 GiB
  timeCost: 1 << 10,
  parallelism: 128,
});

/**
 * Converts a password into a Buffer the library owns (and may wipe).
 * Buffers provided by the caller are used as-is and never modified.
 */
function toPasswordBuffer(password: string | Buffer): {
  buffer: Buffer;
  owned: boolean;
} {
  if (typeof password === "string") {
    return { buffer: Buffer.from(password, "utf8"), owned: true };
  }
  return { buffer: password as Buffer, owned: false };
}

/**
 * Hashes a password with Argon2 and returns a self-contained PHC string —
 * salt and cost parameters included — ready to store in a database:
 *
 *     $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
 *
 * Output is byte-for-byte compatible with node-argon2 for identical inputs,
 * so existing digests keep verifying after a migration.
 *
 * ### Choosing parameters
 * Argon2's security comes primarily from `memoryCost`; raise it as high as
 * your deployment tolerates, then tune `timeCost` so a hash takes ~0.5-1s
 * for interactive logins:
 *
 * | Scenario                       | memoryCost        | timeCost | parallelism |
 * |--------------------------------|-------------------|----------|-------------|
 * | Default (RFC 9106 2nd option)  | 65536 (64 MiB)    | 3        | 4           |
 * | Memory-constrained (OWASP min) | 19456 (19 MiB)    | 2        | 1           |
 * | High security                  | 262144 (256 MiB)  | 3        | 4           |
 *
 * ### Handling the plaintext
 * Prefer passing the password as a `Buffer` and calling `.fill(0)` on it when
 * you are done — JavaScript strings are immutable and cannot be erased from
 * memory. When a string is passed, the temporary Buffer created from it is
 * wiped by this function; every native copy is wiped by the C++ engine.
 *
 * @example
 * // Storing a password (random 16-byte salt generated automatically)
 * const digest = await hash("correct horse battery staple");
 * // => "$argon2id$v=19$m=65536,t=3,p=4$Wl+Yd0Y0...$kW1c9Qw..."
 *
 * @example
 * // With a server-side pepper and custom costs
 * const digest = await hash(passwordBuffer, {
 *   secret: Buffer.from(process.env.PEPPER!, "base64"),
 *   memoryCost: 1 << 17, // 128 MiB
 *   timeCost: 4,
 * });
 * passwordBuffer.fill(0);
 *
 * @example
 * // Raw output for key derivation
 * const key = await hash(passphrase, { raw: true, hashLength: 32 });
 *
 * @param password The plaintext password (Buffer recommended; see above)
 * @param options Hashing parameters; sensible defaults are applied
 * @returns The PHC-encoded digest, or the raw hash Buffer when `raw: true`
 */
export function hash(
  password: string | Buffer,
  options?: HashOptions & { raw?: false },
): Promise<string>;
export function hash(
  password: string | Buffer,
  options: HashOptions & { raw: true },
): Promise<Buffer>;
export async function hash(
  password: string | Buffer,
  options: HashOptions & { raw?: boolean } = {},
): Promise<string | Buffer> {
  const opts = { ...defaults, ...options };
  const salt = opts.salt ?? randomBytes(opts.saltLength);
  const { buffer: passwordBuffer, owned } = toPasswordBuffer(password);

  const promise = hashRaw({
    password: passwordBuffer,
    salt,
    m: opts.memoryCost,
    t: opts.timeCost,
    p: opts.parallelism,
    hashLength: opts.hashLength,
    version: opts.version,
    type: opts.type,
    ...(opts.secret !== undefined && { secret: opts.secret }),
    ...(opts.associatedData !== undefined && { data: opts.associatedData }),
  });

  // The native layer copies the password into protected memory synchronously,
  // so the temporary copy can be wiped before hashing even completes.
  if (owned) passwordBuffer.fill(0);

  const rawHash = await promise;
  if (options.raw) {
    return rawHash;
  }

  // Canonical PHC order per the Argon2 reference (encoding.c): m, t, p, then
  // the optional data field last — byte-identical to node-argon2.
  const params: Record<string, number | Buffer> = {
    m: opts.memoryCost,
    t: opts.timeCost,
    p: opts.parallelism,
  };
  if (opts.associatedData !== undefined && opts.associatedData.byteLength > 0) {
    params.data = opts.associatedData;
  }

  return serialize({
    id: names[opts.type],
    version: opts.version,
    params,
    salt,
    hash: rawHash,
  });
}

/**
 * Verifies a password against a PHC digest produced by {@link hash} (or by
 * node-argon2 — the formats are interchangeable).
 *
 * Cost parameters are read from the digest itself, validated against
 * {@link VerifyOptions.limits} before any memory is allocated, and the final
 * comparison happens in constant time inside native code.
 *
 * Returns `false` (instead of throwing) when the digest belongs to another
 * hash scheme (e.g. a bcrypt `$2a$...` string), so mixed-algorithm user
 * tables can be probed safely.
 *
 * @example
 * if (await verify(storedDigest, submittedPassword)) {
 *   // grant access
 * }
 *
 * @example
 * // Digest created with a pepper
 * await verify(storedDigest, submittedPassword, {
 *   secret: Buffer.from(process.env.PEPPER!, "base64"),
 * });
 *
 * @param digest The PHC string to check against
 * @param password The plaintext password to be verified
 * @param options Verification options (pepper, cost limits)
 * @returns `true` if the password matches the digest, `false` otherwise
 */
export async function verify(
  digest: string,
  password: string | Buffer,
  options: VerifyOptions = {},
): Promise<boolean> {
  if (typeof digest !== "string") {
    throw new TypeError("'digest' must be a string.");
  }

  const parsed = deserialize(digest);
  const type = types[parsed.id];
  if (type === undefined) {
    return false;
  }

  const { salt, hash: expectedHash, params = {} } = parsed;
  if (salt === undefined || expectedHash === undefined) {
    throw new TypeError("'digest' is missing its salt or hash fields.");
  }

  const m = Number(params.m);
  const t = Number(params.t);
  const p = Number(params.p);
  if (!Number.isFinite(m) || !Number.isFinite(t) || !Number.isFinite(p)) {
    throw new TypeError("'digest' is missing the m, t or p parameters.");
  }

  const limits = { ...defaultVerifyLimits, ...options.limits };
  if (m > limits.memoryCost) {
    throw new RangeError(
      `'digest' requests memoryCost=${m} KiB, above the limit of ${limits.memoryCost} KiB.`,
    );
  }
  if (t > limits.timeCost) {
    throw new RangeError(
      `'digest' requests timeCost=${t}, above the limit of ${limits.timeCost}.`,
    );
  }
  if (p > limits.parallelism) {
    throw new RangeError(
      `'digest' requests parallelism=${p}, above the limit of ${limits.parallelism}.`,
    );
  }

  const data =
    typeof params.data === "string"
      ? Buffer.from(params.data, "base64")
      : undefined;

  const { buffer: passwordBuffer, owned } = toPasswordBuffer(password);

  const promise = verifyRaw({
    password: passwordBuffer,
    salt,
    m,
    t,
    p,
    expectedHash,
    version: parsed.version ?? 0x10, // digests without v= predate Argon2 v1.3
    type,
    ...(options.secret !== undefined && { secret: options.secret }),
    ...(data !== undefined && { data }),
  });

  if (owned) passwordBuffer.fill(0);

  return promise;
}

/**
 * Checks whether a digest was generated with parameters weaker than (or
 * simply different from) the given ones, meaning the password should be
 * re-hashed on the next successful login.
 *
 * @example
 * if (await verify(digest, password)) {
 *   if (needsRehash(digest)) {
 *     digest = await hash(password); // upgrade to current parameters
 *   }
 *   // grant access
 * }
 *
 * @param digest The PHC string to inspect
 * @param options The parameters currently in use (defaults applied)
 * @returns `true` if the digest parameters differ from the given ones
 */
export function needsRehash(
  digest: string,
  options: RehashOptions = {},
): boolean {
  if (typeof digest !== "string") {
    throw new TypeError("'digest' must be a string.");
  }

  const { memoryCost, timeCost, parallelism, version } = {
    ...defaults,
    ...options,
  };
  const parsed = deserialize(digest);
  const { m, t, p } = parsed.params ?? {};

  return (
    Number(parsed.version ?? 0x10) !== version ||
    Number(m) !== memoryCost ||
    Number(t) !== timeCost ||
    Number(p) !== parallelism
  );
}

// ---------------------------------------------------------------------------
// PHC string format (re-exported for callers that need to build or inspect
// digests directly)
// ---------------------------------------------------------------------------

export { serialize, deserialize } from "./phc.js";
export type { PhcObject, PhcInput } from "./phc.js";
