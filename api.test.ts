import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { hash, verify, needsRehash, argon2d, argon2i } from "./index.js";

const password = "password";
const salt = Buffer.alloc(16, "salt");
const secret = Buffer.alloc(16, "secret");
const associatedData = Buffer.alloc(16, "ad");

// PHC strings produced by node-argon2 for identical inputs — the high-level
// API must be a drop-in replacement, existing databases included.
const digests = {
  argon2d:
    "$argon2d$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$VtxJNl5Jr/yZ2UIhvfvL4sGPdDQyGCcy45Cs7rIdFq8",
  argon2i:
    "$argon2i$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$1Ccmp7ECb+Rb5XPjqRwEuAjCufY1xQDOJwnHrB+orZ4",
  argon2id:
    "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$rBWULD5jOGpQy32rLvGcmvQMVqIVNAmrCtekWvUA8bw",
  oldFormat:
    "$argon2i$m=4096,p=1,t=3$tbagT6b1YH33niCo9lVzuA$htv/k+OqWk1V9zD9k5DOBi2kcfcZ6Xu3tWmwEPV3/nc",
  withNull:
    "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$NqchDOxwWbcBzA+0gtsCtyspEQxqKFf4/PO/AoIvo+Q",
  withAd:
    "$argon2id$v=19$m=65536,t=3,p=4,data=YWRhZGFkYWRhZGFkYWRhZA$c2FsdHNhbHRzYWx0c2FsdA$TEIIM4GBSUxvMLolL9ePXYP5G/qcr0vywQqqm/ILvsM",
  withSecret:
    "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$8dZyo1MdHgdzBm+VU7+tyW06dUO7B9FyaPImH5ejVOU",
  rawArgon2id: Buffer.from(
    "ac15942c3e63386a50cb7dab2ef19c9af40c56a2153409ab0ad7a45af500f1bc",
    "hex",
  ),
};

describe("hash (PHC)", () => {
  it("produces node-argon2 compatible digests (argon2id)", async () => {
    assert.equal(await hash(password, { salt }), digests.argon2id);
  });

  it("produces node-argon2 compatible digests (argon2d)", async () => {
    assert.equal(await hash(password, { salt, type: argon2d }), digests.argon2d);
  });

  it("produces node-argon2 compatible digests (argon2i)", async () => {
    assert.equal(await hash(password, { salt, type: argon2i }), digests.argon2i);
  });

  it("handles null bytes in string passwords", async () => {
    assert.equal(await hash("pass\0word", { salt }), digests.withNull);
  });

  it("embeds associated data in the digest", async () => {
    assert.equal(await hash(password, { salt, associatedData }), digests.withAd);
  });

  it("mixes in the secret without storing it", async () => {
    const digest = await hash(password, { salt, secret });
    assert.equal(digest, digests.withSecret);
    assert(!digest.includes(secret.toString("base64").replace(/=+$/, "")));
  });

  it("returns a raw Buffer with raw: true", async () => {
    const raw = await hash(password, { salt, raw: true });
    assert.deepEqual(raw, digests.rawArgon2id);
  });

  it("generates a unique random salt when none is given", async () => {
    const [a, b] = await Promise.all([hash(password), hash(password)]);
    assert.notEqual(a, b);
    assert.match(a, /^\$argon2id\$v=19\$m=65536,t=3,p=4\$/);
    assert.equal(await verify(a, password), true);
    assert.equal(await verify(b, password), true);
  });

  it("respects custom cost options in the digest", async () => {
    const digest = await hash(password, {
      memoryCost: 1 << 13,
      timeCost: 4,
      parallelism: 2,
    });
    assert.match(digest, /m=8192,t=4,p=2/);
    assert.equal(await verify(digest, password), true);
  });

  it("respects a custom hash length", async () => {
    // 16 bytes -> 22 unpadded base64 chars
    assert.match(await hash(password, { hashLength: 16 }), /\$[A-Za-z0-9+/]{22}$/);
  });

  it("accepts Buffer passwords without modifying them", async () => {
    const buf = Buffer.from("password");
    const digest = await hash(buf, { salt });
    assert.equal(digest, digests.argon2id);
    assert.deepEqual(buf, Buffer.from("password"));
  });

  it("rejects invalid options through the raw layer", async () => {
    await assert.rejects(hash(password, { salt: Buffer.alloc(4) }), RangeError);
    await assert.rejects(hash(password, { memoryCost: 4 }), RangeError);
    // @ts-expect-error deliberately wrong type
    await assert.rejects(hash(42), TypeError);
  });
});

describe("verify (PHC)", () => {
  it("accepts correct passwords for all variants", async () => {
    assert.equal(await verify(digests.argon2d, password), true);
    assert.equal(await verify(digests.argon2i, password), true);
    assert.equal(await verify(digests.argon2id, password), true);
  });

  it("rejects wrong passwords for all variants", async () => {
    assert.equal(await verify(digests.argon2d, "passworld"), false);
    assert.equal(await verify(digests.argon2i, "passworld"), false);
    assert.equal(await verify(digests.argon2id, "passworld"), false);
  });

  it("accepts Buffer passwords", async () => {
    assert.equal(await verify(digests.argon2id, Buffer.from(password)), true);
  });

  it("verifies digests with null bytes in the password", async () => {
    assert.equal(await verify(digests.withNull, "pass\0word"), true);
    assert.equal(await verify(digests.withNull, "password"), false);
  });

  it("reads associated data from the digest automatically", async () => {
    assert.equal(await verify(digests.withAd, password), true);
    assert.equal(await verify(digests.withAd, "passworld"), false);
  });

  it("verifies keyed digests when the secret is provided", async () => {
    assert.equal(await verify(digests.withSecret, password, { secret }), true);
    assert.equal(await verify(digests.withSecret, password), false);
    assert.equal(
      await verify(digests.withSecret, password, { secret: Buffer.from("wrong") }),
      false,
    );
  });

  it("verifies the pre-v1.3 format without a version field", async () => {
    assert.equal(await verify(digests.oldFormat, password), true);
    assert.equal(await verify(digests.oldFormat, "passworld"), false);
  });

  it("returns false for digests of other schemes (bcrypt)", async () => {
    assert.equal(
      await verify(
        "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
        "abc123xyz",
      ),
      false,
    );
  });

  it("rejects a tampered digest hash", async () => {
    const tampered = digests.argon2id.slice(0, -4) + "AAAA";
    assert.equal(await verify(tampered, password), false);
  });

  it("throws on malformed digests", async () => {
    await assert.rejects(verify("not a digest", password), TypeError);
    await assert.rejects(verify("$argon2id$v=19$m=65536,p=4,t=3", password), TypeError);
    // @ts-expect-error deliberately wrong type
    await assert.rejects(verify(42, password), TypeError);
  });

  it("blocks parameter-injection DoS from untrusted digests", async () => {
    // A digest asking for 1 TiB of memory must be refused before any
    // allocation happens.
    const hostile = digests.argon2id.replace("m=65536", "m=1073741824");
    await assert.rejects(verify(hostile, password), RangeError);

    const hostileT = digests.argon2id.replace("t=3", "t=100000");
    await assert.rejects(verify(hostileT, password), RangeError);

    const hostileP = digests.argon2id.replace("p=4", "p=10000");
    await assert.rejects(verify(hostileP, password), RangeError);
  });

  it("honors custom verification limits", async () => {
    await assert.rejects(
      verify(digests.argon2id, password, { limits: { memoryCost: 1 << 10 } }),
      RangeError,
    );
    assert.equal(
      await verify(digests.argon2id, password, { limits: { memoryCost: 1 << 16 } }),
      true,
    );
  });
});

describe("needsRehash", () => {
  it("returns false for digests matching the current defaults", async () => {
    assert.equal(needsRehash(await hash(password)), false);
  });

  it("flags digests hashed with an older version", () => {
    assert.equal(needsRehash(digests.oldFormat), true);
  });

  it("flags digests hashed with weaker parameters", async () => {
    const weak = await hash(password, { memoryCost: 1 << 13, timeCost: 2 });
    assert.equal(needsRehash(weak), true);
    assert.equal(
      needsRehash(weak, { memoryCost: 1 << 13, timeCost: 2 }),
      false,
    );
  });

  it("supports the full upgrade-on-login flow", async () => {
    // A user record hashed with old parameters...
    const stored = await hash(password, { memoryCost: 1 << 13 });
    // ...still verifies, gets flagged, and is upgraded transparently.
    assert.equal(await verify(stored, password), true);
    assert.equal(needsRehash(stored), true);
    const upgraded = await hash(password);
    assert.equal(needsRehash(upgraded), false);
    assert.equal(await verify(upgraded, password), true);
  });

  it("throws on non-string digests", () => {
    // @ts-expect-error deliberately wrong type
    assert.throws(() => needsRehash(42), TypeError);
  });
});
