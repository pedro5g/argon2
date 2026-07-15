/**
 * Serializer/deserializer for the PHC string format, the standard textual
 * encoding for password hashes:
 *
 *     $<id>[$v=<version>][$<param>=<value>(,<param>=<value>)*][$<salt>[$<hash>]]
 *
 * Spec: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
 *
 * Improvements over the original `@phc/format` implementation:
 * - Fully typed, no mutation of the caller's `params` object.
 * - `version: 0` is preserved (the original dropped it due to a truthiness check).
 * - A `hash` without a `salt` is rejected instead of silently dropped.
 * - Duplicate parameter names are rejected.
 * - Numeric parameter strings larger than `Number.MAX_SAFE_INTEGER` are kept
 *   as strings instead of silently losing precision.
 */

/** A parsed PHC string. */
export interface PhcObject {
  /** Symbolic name of the hash function (e.g. `argon2id`). */
  id: string;
  /** Version of the function, when present (e.g. `19` for Argon2 v1.3). */
  version?: number;
  /** Function parameters; decimal values are parsed into numbers. */
  params?: Record<string, string | number>;
  /** Decoded salt. */
  salt?: Buffer;
  /** Decoded hash. */
  hash?: Buffer;
}

/** Input accepted by {@link serialize}; Buffers in params are base64-encoded. */
export interface PhcInput {
  id: string;
  version?: number;
  params?: Record<string, string | number | Buffer>;
  salt?: Buffer;
  hash?: Buffer;
}

const idRegex = /^[a-z0-9-]{1,32}$/;
const nameRegex = /^[a-z0-9-]{1,32}$/;
const valueRegex = /^[a-zA-Z0-9/+.-]+$/;
// Deliberately looser than strict base64 (allows `.` and `-`) so digests from
// other schemes (e.g. bcrypt's `$2a$...`) still parse into an object with a
// foreign `id` — letting callers return `false` instead of throwing.
const b64Regex = /^([a-zA-Z0-9/+.-]+|)$/;
const decimalRegex = /^(-?[1-9]\d*|0)$/;
const versionRegex = /^v=(\d+)$/;

/** Standard base64 without padding, as mandated by the PHC spec. */
function toB64(buf: Buffer): string {
  return buf.toString("base64").replace(/=+$/, "");
}

/**
 * Generates a PHC string from its components.
 *
 * @example
 * serialize({
 *   id: "argon2id",
 *   version: 19,
 *   params: { m: 65536, p: 4, t: 3 },
 *   salt: Buffer.from("saltsaltsaltsalt"),
 *   hash: rawHash,
 * });
 * // => "$argon2id$v=19$m=65536,p=4,t=3$c2FsdHNhbHRzYWx0c2FsdA$..."
 */
export function serialize(opts: PhcInput): string {
  if (typeof opts !== "object" || opts === null) {
    throw new TypeError("opts must be an object");
  }

  if (typeof opts.id !== "string") {
    throw new TypeError("id must be a string");
  }
  if (!idRegex.test(opts.id)) {
    throw new TypeError(`id must satisfy ${idRegex}`);
  }

  const fields: string[] = ["", opts.id];

  if (opts.version !== undefined) {
    if (
      typeof opts.version !== "number" ||
      opts.version < 0 ||
      !Number.isInteger(opts.version)
    ) {
      throw new TypeError("version must be a non-negative integer");
    }
    fields.push(`v=${opts.version}`);
  }

  if (opts.params !== undefined) {
    if (typeof opts.params !== "object" || opts.params === null) {
      throw new TypeError("params must be an object");
    }

    const entries: string[] = [];
    for (const name of Object.keys(opts.params)) {
      if (!nameRegex.test(name)) {
        throw new TypeError(`params names must satisfy ${nameRegex}`);
      }

      const raw = opts.params[name];
      let value: string;
      if (typeof raw === "number") {
        value = raw.toString();
      } else if (Buffer.isBuffer(raw)) {
        value = toB64(raw);
      } else if (typeof raw === "string") {
        value = raw;
      } else {
        throw new TypeError("params values must be strings, numbers or Buffers");
      }

      if (!valueRegex.test(value)) {
        throw new TypeError(`params values must satisfy ${valueRegex}`);
      }
      entries.push(`${name}=${value}`);
    }

    fields.push(entries.join(","));
  }

  if (opts.salt !== undefined) {
    if (!Buffer.isBuffer(opts.salt)) {
      throw new TypeError("salt must be a Buffer");
    }
    fields.push(toB64(opts.salt));
  }

  if (opts.hash !== undefined) {
    if (opts.salt === undefined) {
      throw new TypeError("hash requires a salt to be present");
    }
    if (!Buffer.isBuffer(opts.hash)) {
      throw new TypeError("hash must be a Buffer");
    }
    fields.push(toB64(opts.hash));
  }

  return fields.join("$");
}

/**
 * Parses a PHC string into its components.
 *
 * @example
 * deserialize("$argon2id$v=19$m=65536,p=4,t=3$c2FsdA$aGFzaA");
 * // => { id: "argon2id", version: 19, params: { m: 65536, p: 4, t: 3 },
 * //      salt: <Buffer ...>, hash: <Buffer ...> }
 */
export function deserialize(phcstr: string): PhcObject {
  if (typeof phcstr !== "string" || phcstr === "") {
    throw new TypeError("phcstr must be a non-empty string");
  }
  if (phcstr[0] !== "$") {
    throw new TypeError("phcstr must contain a $ as first char");
  }

  const fields = phcstr.split("$");
  // Remove the empty field before the leading $
  fields.shift();

  const maxf = versionRegex.test(fields[1] ?? "") ? 5 : 4;
  if (fields.length > maxf) {
    throw new TypeError(
      `phcstr contains too many fields: ${fields.length}/${maxf}`,
    );
  }

  const id = fields.shift();
  if (id === undefined || !idRegex.test(id)) {
    throw new TypeError(`id must satisfy ${idRegex}`);
  }

  let version: number | undefined;
  const versionMatch = fields[0] !== undefined && versionRegex.exec(fields[0]);
  if (versionMatch) {
    fields.shift();
    version = parseInt(versionMatch[1], 10);
  }

  let hash: Buffer | undefined;
  let salt: Buffer | undefined;
  if (fields.length > 0 && b64Regex.test(fields[fields.length - 1])) {
    if (fields.length > 1 && b64Regex.test(fields[fields.length - 2])) {
      hash = Buffer.from(fields.pop() as string, "base64");
    }
    salt = Buffer.from(fields.pop() as string, "base64");
  }

  let params: Record<string, string | number> | undefined;
  if (fields.length > 0) {
    params = {};
    for (const pair of (fields.pop() as string).split(",")) {
      const parts = pair.split("=");
      if (parts.length < 2) {
        throw new TypeError("params must be in the format name=value");
      }

      const name = parts.shift() as string;
      const value = parts.join("=");
      if (!nameRegex.test(name)) {
        throw new TypeError(`params names must satisfy ${nameRegex}`);
      }
      if (!valueRegex.test(value)) {
        throw new TypeError(`params values must satisfy ${valueRegex}`);
      }
      if (name in params) {
        throw new TypeError(`params contains duplicated name: ${name}`);
      }

      // Convert decimal strings into numbers, keeping values that would lose
      // precision (or non-decimal values like base64 data) as strings.
      params[name] =
        decimalRegex.test(value) && Number.isSafeInteger(Number(value))
          ? parseInt(value, 10)
          : value;
    }
  }

  if (fields.length > 0) {
    throw new TypeError(`phcstr contains unrecognized fields: ${fields}`);
  }

  const phcobj: PhcObject = { id };
  if (version !== undefined) phcobj.version = version;
  if (params !== undefined) phcobj.params = params;
  if (salt !== undefined) phcobj.salt = salt;
  if (hash !== undefined) phcobj.hash = hash;

  return phcobj;
}
