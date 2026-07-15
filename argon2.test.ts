import assert from "node:assert/strict";
import { describe, it } from "node:test";
//@ts-ignore
import gypBuild from "node-gyp-build";
import { hashRaw, verifyRaw, argon2d, argon2i, argon2id } from "./index.js";
import { __dirname } from "./__dirname.js";

// Raw native binding, bypassing the TypeScript validation layer, to exercise
// the C++ hardening paths directly.
const bindings = gypBuild(__dirname) as {
  hash: (options: unknown) => Promise<Buffer>;
  verify: (options: unknown) => Promise<boolean>;
};

const password = Buffer.from("password");
const salt = Buffer.alloc(16, "salt");
const secret = Buffer.alloc(16, "secret");
const associatedData = Buffer.alloc(16, "ad");

/** node-argon2 default parameters, used for cross-library parity vectors */
const defaults = { m: 1 << 16, t: 3, p: 4, hashLength: 32 };

/** Cheap parameters for tests where the digest value itself doesn't matter */
const cheap = { m: 1 << 10, t: 2, p: 1, hashLength: 32 };

// Official test vectors from the Argon2 reference implementation (argon2/kats),
// as published in RFC 9106. Password 32×0x01, salt 16×0x02, secret 8×0x03,
// associated data 12×0x04, m=32 KiB, t=3, p=4, tag length 32.
const katInput = {
  password: Buffer.alloc(32, 0x01),
  salt: Buffer.alloc(16, 0x02),
  secret: Buffer.alloc(8, 0x03),
  data: Buffer.alloc(12, 0x04),
  m: 32,
  t: 3,
  p: 4,
  hashLength: 32,
};

const kats = {
  argon2d_v19:
    "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
  argon2i_v19:
    "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
  argon2id_v19:
    "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
  argon2id_v16:
    "b64615f07789b66b645b67ee9ed3b377ae350b6bfcbb0fc95141ea8f322613c0",
};

describe("official reference test vectors (RFC 9106)", () => {
  it("argon2d v1.3", async () => {
    const result = await hashRaw({ ...katInput, type: argon2d });
    assert.equal(result.toString("hex"), kats.argon2d_v19);
  });

  it("argon2i v1.3", async () => {
    const result = await hashRaw({ ...katInput, type: argon2i });
    assert.equal(result.toString("hex"), kats.argon2i_v19);
  });

  it("argon2id v1.3", async () => {
    const result = await hashRaw({ ...katInput, type: argon2id });
    assert.equal(result.toString("hex"), kats.argon2id_v19);
  });

  it("argon2id v1.0 (version 0x10)", async () => {
    const result = await hashRaw({ ...katInput, type: argon2id, version: 0x10 });
    assert.equal(result.toString("hex"), kats.argon2id_v16);
  });
});

// Parity with node-argon2: raw digests produced by the library this project
// aims to replace, for identical inputs. Guarantees drop-in compatibility.
const nodeArgon2Vectors = {
  argon2d: "56dc49365e49affc99d94221bdfbcbe2c18f743432182732e390aceeb21d16af",
  argon2i: "d42726a7b1026fe45be573e3a91c04b808c2b9f635c500ce2709c7ac1fa8ad9e",
  argon2id: "ac15942c3e63386a50cb7dab2ef19c9af40c56a2153409ab0ad7a45af500f1bc",
  withNullByte:
    "36a7210cec7059b701cc0fb482db02b72b29110c6a2857f8fcf3bf02822fa3e4",
  withSecret: Buffer.from(
    "8dZyo1MdHgdzBm+VU7+tyW06dUO7B9FyaPImH5ejVOU",
    "base64",
  ).toString("hex"),
  withAssociatedData: Buffer.from(
    "TEIIM4GBSUxvMLolL9ePXYP5G/qcr0vywQqqm/ILvsM",
    "base64",
  ).toString("hex"),
};

describe("node-argon2 parity vectors", () => {
  it("argon2d with default options", async () => {
    const result = await hashRaw({ password, salt, ...defaults, type: argon2d });
    assert.equal(result.toString("hex"), nodeArgon2Vectors.argon2d);
  });

  it("argon2i with default options", async () => {
    const result = await hashRaw({ password, salt, ...defaults, type: argon2i });
    assert.equal(result.toString("hex"), nodeArgon2Vectors.argon2i);
  });

  it("argon2id with default options", async () => {
    const result = await hashRaw({ password, salt, ...defaults });
    assert.equal(result.toString("hex"), nodeArgon2Vectors.argon2id);
  });

  it("password containing a null byte", async () => {
    const result = await hashRaw({
      password: Buffer.from("pass\0word"),
      salt,
      ...defaults,
    });
    assert.equal(result.toString("hex"), nodeArgon2Vectors.withNullByte);
  });

  it("with secret (keyed hashing)", async () => {
    const result = await hashRaw({ password, salt, secret, ...defaults });
    assert.equal(result.toString("hex"), nodeArgon2Vectors.withSecret);
  });

  it("with associated data", async () => {
    const result = await hashRaw({
      password,
      salt,
      data: associatedData,
      ...defaults,
    });
    assert.equal(result.toString("hex"), nodeArgon2Vectors.withAssociatedData);
  });
});

describe("hash behavior", () => {
  it("is deterministic for identical inputs", async () => {
    const [a, b] = await Promise.all([
      hashRaw({ password, salt, ...cheap }),
      hashRaw({ password, salt, ...cheap }),
    ]);
    assert.deepEqual(a, b);
  });

  it("different salts produce different hashes", async () => {
    const a = await hashRaw({ password, salt, ...cheap });
    const b = await hashRaw({
      password,
      salt: Buffer.alloc(16, "tlas"),
      ...cheap,
    });
    assert.notDeepEqual(a, b);
  });

  it("different types produce different hashes", async () => {
    const d = await hashRaw({ password, salt, ...cheap, type: argon2d });
    const i = await hashRaw({ password, salt, ...cheap, type: argon2i });
    const id = await hashRaw({ password, salt, ...cheap, type: argon2id });
    assert.notDeepEqual(d, i);
    assert.notDeepEqual(d, id);
    assert.notDeepEqual(i, id);
  });

  it("version 0x10 and 0x13 produce different hashes", async () => {
    const v10 = await hashRaw({ password, salt, ...cheap, version: 0x10 });
    const v13 = await hashRaw({ password, salt, ...cheap, version: 0x13 });
    assert.notDeepEqual(v10, v13);
  });

  it("respects the requested hash length", async () => {
    const short = await hashRaw({ password, salt, ...cheap, hashLength: 4 });
    const long = await hashRaw({ password, salt, ...cheap, hashLength: 64 });
    assert.equal(short.byteLength, 4);
    assert.equal(long.byteLength, 64);
  });

  it("allows an empty password", async () => {
    const result = await hashRaw({ password: Buffer.alloc(0), salt, ...cheap });
    assert.equal(result.byteLength, 32);
    assert.notDeepEqual(result, await hashRaw({ password, salt, ...cheap }));
  });

  it("allows the minimum salt length of 8 bytes", async () => {
    const result = await hashRaw({
      password,
      salt: Buffer.alloc(8, "s"),
      ...cheap,
    });
    assert.equal(result.byteLength, 32);
  });

  it("does not mutate the caller's password buffer", async () => {
    const input = Buffer.from("password");
    await hashRaw({ password: input, salt, ...cheap });
    assert.deepEqual(input, Buffer.from("password"));
  });

  it("secret changes the digest", async () => {
    const withoutSecret = await hashRaw({ password, salt, ...cheap });
    const withSecret = await hashRaw({ password, salt, secret, ...cheap });
    assert.notDeepEqual(withoutSecret, withSecret);
  });

  it("associated data changes the digest", async () => {
    const without = await hashRaw({ password, salt, ...cheap });
    const withData = await hashRaw({
      password,
      salt,
      data: associatedData,
      ...cheap,
    });
    assert.notDeepEqual(without, withData);
  });
});

describe("verify", () => {
  for (const [name, type] of [
    ["argon2d", argon2d],
    ["argon2i", argon2i],
    ["argon2id", argon2id],
  ] as const) {
    it(`${name}: accepts the correct password`, async () => {
      const expectedHash = await hashRaw({ password, salt, ...cheap, type });
      assert.equal(
        await verifyRaw({ password, salt, ...cheap, type, expectedHash }),
        true,
      );
    });

    it(`${name}: rejects a wrong password`, async () => {
      const expectedHash = await hashRaw({ password, salt, ...cheap, type });
      const wrong = Buffer.from("passworld");
      assert.equal(
        await verifyRaw({ password: wrong, salt, ...cheap, type, expectedHash }),
        false,
      );
    });
  }

  it("accepts a password containing a null byte", async () => {
    const pwd = Buffer.from("pass\0word");
    const expectedHash = await hashRaw({ password: pwd, salt, ...cheap });
    assert.equal(
      await verifyRaw({ password: pwd, salt, ...cheap, expectedHash }),
      true,
    );
    assert.equal(
      await verifyRaw({
        password: Buffer.from("password"),
        salt,
        ...cheap,
        expectedHash,
      }),
      false,
    );
  });

  it("verifies keyed hashes when the secret matches", async () => {
    const expectedHash = await hashRaw({ password, salt, secret, ...cheap });
    assert.equal(
      await verifyRaw({ password, salt, secret, ...cheap, expectedHash }),
      true,
    );
  });

  it("rejects keyed hashes with a wrong or missing secret", async () => {
    const expectedHash = await hashRaw({ password, salt, secret, ...cheap });
    const wrongSecret = Buffer.alloc(16, "terces");
    assert.equal(
      await verifyRaw({
        password,
        salt,
        secret: wrongSecret,
        ...cheap,
        expectedHash,
      }),
      false,
    );
    assert.equal(
      await verifyRaw({ password, salt, ...cheap, expectedHash }),
      false,
    );
  });

  it("verifies hashes with associated data", async () => {
    const expectedHash = await hashRaw({
      password,
      salt,
      data: associatedData,
      ...cheap,
    });
    assert.equal(
      await verifyRaw({
        password,
        salt,
        data: associatedData,
        ...cheap,
        expectedHash,
      }),
      true,
    );
    assert.equal(
      await verifyRaw({ password, salt, ...cheap, expectedHash }),
      false,
    );
  });

  it("rejects when parameters differ from those used to hash", async () => {
    const expectedHash = await hashRaw({ password, salt, ...cheap });
    assert.equal(
      await verifyRaw({ password, salt, ...cheap, t: 3, expectedHash }),
      false,
    );
    assert.equal(
      await verifyRaw({ password, salt, ...cheap, m: 1 << 11, expectedHash }),
      false,
    );
    assert.equal(
      await verifyRaw({ password, salt, ...cheap, type: argon2i, expectedHash }),
      false,
    );
    assert.equal(
      await verifyRaw({ password, salt, ...cheap, version: 0x10, expectedHash }),
      false,
    );
  });

  it("rejects a tampered hash", async () => {
    const expectedHash = await hashRaw({ password, salt, ...cheap });
    expectedHash[0] ^= 0xff;
    assert.equal(
      await verifyRaw({ password, salt, ...cheap, expectedHash }),
      false,
    );
  });

  it("rejects a truncated hash", async () => {
    const expectedHash = await hashRaw({ password, salt, ...cheap });
    const truncated = expectedHash.subarray(0, 16);
    assert.equal(
      await verifyRaw({ password, salt, ...cheap, expectedHash: truncated }),
      false,
    );
  });

  it("verifies against the official argon2id reference vector", async () => {
    const expectedHash = Buffer.from(kats.argon2id_v19, "hex");
    assert.equal(
      await verifyRaw({ ...katInput, type: argon2id, expectedHash }),
      true,
    );
  });
});

describe("input validation", () => {
  it("rejects a non-buffer password", async () => {
    await assert.rejects(
      // @ts-expect-error deliberately wrong type
      hashRaw({ password: "password", salt, ...cheap }),
      TypeError,
    );
  });

  it("rejects a non-buffer salt", async () => {
    await assert.rejects(
      // @ts-expect-error deliberately wrong type
      hashRaw({ password, salt: "saltsaltsaltsalt", ...cheap }),
      TypeError,
    );
  });

  it("rejects a salt shorter than 8 bytes", async () => {
    await assert.rejects(
      hashRaw({ password, salt: Buffer.alloc(7), ...cheap }),
      RangeError,
    );
  });

  it("rejects a non-buffer secret", async () => {
    await assert.rejects(
      // @ts-expect-error deliberately wrong type
      hashRaw({ password, salt, secret: "secret", ...cheap }),
      TypeError,
    );
  });

  it("rejects non-integer numeric parameters", async () => {
    await assert.rejects(
      hashRaw({ password, salt, ...cheap, m: 1024.5 }),
      TypeError,
    );
    await assert.rejects(hashRaw({ password, salt, ...cheap, t: 1.5 }), TypeError);
    await assert.rejects(
      hashRaw({ password, salt, ...cheap, p: Number.NaN }),
      TypeError,
    );
    await assert.rejects(
      hashRaw({ password, salt, ...cheap, hashLength: 32.5 }),
      TypeError,
    );
  });

  it("rejects out-of-range costs", async () => {
    await assert.rejects(hashRaw({ password, salt, ...cheap, m: 4 }), RangeError);
    await assert.rejects(
      hashRaw({ password, salt, ...cheap, m: 2 ** 32 }),
      RangeError,
    );
    await assert.rejects(hashRaw({ password, salt, ...cheap, t: 0 }), RangeError);
    await assert.rejects(hashRaw({ password, salt, ...cheap, p: 0 }), RangeError);
    await assert.rejects(
      hashRaw({ password, salt, ...cheap, p: 2 ** 24 }),
      RangeError,
    );
    await assert.rejects(
      hashRaw({ password, salt, ...cheap, hashLength: 3 }),
      RangeError,
    );
  });

  it("rejects m below 8 KiB per lane", async () => {
    await assert.rejects(
      hashRaw({ password, salt, m: 16, t: 2, p: 4, hashLength: 32 }),
      RangeError,
    );
  });

  it("rejects an unknown type", async () => {
    await assert.rejects(
      hashRaw({ password, salt, ...cheap, type: 3 }),
      RangeError,
    );
    await assert.rejects(
      hashRaw({ password, salt, ...cheap, type: -1 }),
      RangeError,
    );
  });

  it("rejects an unknown version", async () => {
    await assert.rejects(
      hashRaw({ password, salt, ...cheap, version: 0x12 }),
      RangeError,
    );
  });

  it("rejects a non-buffer expectedHash", async () => {
    await assert.rejects(
      // @ts-expect-error deliberately wrong type
      verifyRaw({ password, salt, ...cheap, expectedHash: "deadbeef" }),
      TypeError,
    );
  });

  it("rejects an expectedHash shorter than 4 bytes", async () => {
    await assert.rejects(
      verifyRaw({ password, salt, ...cheap, expectedHash: Buffer.alloc(3) }),
      RangeError,
    );
  });
});

describe("concurrency", () => {
  it("parallel hashes are consistent", async () => {
    const results = await Promise.all(
      Array.from({ length: 8 }, () => hashRaw({ password, salt, ...cheap })),
    );
    for (const result of results) {
      assert.deepEqual(result, results[0]);
    }
  });

  it("accepts an unbounded burst — every request resolves", async () => {
    // No circuit breaker: like node-argon2, every queued request is honored
    // and eventually resolves. The thread pool serializes execution; nothing
    // is rejected for concurrency reasons.
    const settled = await Promise.allSettled(
      Array.from({ length: 32 }, () => hashRaw({ password, salt, ...cheap })),
    );
    const fulfilled = settled.filter((r) => r.status === "fulfilled");
    assert.equal(fulfilled.length, 32);
    for (const r of settled) {
      assert.equal(r.status, "fulfilled");
    }
  });

  it("stays healthy across repeated bursts", async () => {
    // Repeated full bursts must keep resolving — a guard against any leak in
    // the worker lifecycle (buffers, handles, native memory).
    for (let round = 0; round < 3; round++) {
      const results = await Promise.all(
        Array.from({ length: 16 }, () => hashRaw({ password, salt, ...cheap })),
      );
      assert.equal(results.length, 16);
    }
  });

  it("recovers cleanly after a burst of failures", async () => {
    // An invalid type fails inside the worker; a run of failures must not
    // leave the module in a broken state for the next valid call.
    const invalid = {
      password,
      salt,
      secret: Buffer.alloc(0),
      data: Buffer.alloc(0),
      ...cheap,
      version: 0x13,
      type: 99,
    };
    await Promise.allSettled(
      Array.from({ length: 12 }, () => bindings.hash(invalid)),
    );
    const result = await hashRaw({ password, salt, ...cheap });
    assert.equal(result.byteLength, 32);
  });
});

describe("native binding hardening", () => {
  it("rejects a call without an options object instead of crashing", async () => {
    await assert.rejects(bindings.hash(undefined), TypeError);
    await assert.rejects(bindings.verify(42), TypeError);
  });

  it("rejects non-buffer fields instead of crashing", async () => {
    await assert.rejects(
      bindings.hash({
        password: "not a buffer",
        salt,
        secret: Buffer.alloc(0),
        data: Buffer.alloc(0),
        ...cheap,
        version: 0x13,
        type: argon2id,
      }),
      TypeError,
    );
  });

  it("rejects non-numeric cost fields instead of crashing", async () => {
    await assert.rejects(
      bindings.hash({
        password,
        salt,
        secret: Buffer.alloc(0),
        data: Buffer.alloc(0),
        m: "lots",
        t: 2,
        p: 1,
        hashLength: 32,
        version: 0x13,
        type: argon2id,
      }),
      TypeError,
    );
  });

  it("surfaces argon2 core errors as rejections", async () => {
    await assert.rejects(
      bindings.hash({
        password,
        salt,
        secret: Buffer.alloc(0),
        data: Buffer.alloc(0),
        ...cheap,
        version: 0x13,
        type: 99,
      }),
      /Argon2/i,
    );
  });
});
