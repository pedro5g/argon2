import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { serialize, deserialize } from "./phc.js";

const salt = Buffer.from("saltsaltsaltsalt");
const hash = Buffer.from(
  "ac15942c3e63386a50cb7dab2ef19c9af40c56a2153409ab0ad7a45af500f1bc",
  "hex",
);

const fullDigest =
  "$argon2id$v=19$m=65536,p=4,t=3$c2FsdHNhbHRzYWx0c2FsdA$rBWULD5jOGpQy32rLvGcmvQMVqIVNAmrCtekWvUA8bw";

describe("phc serialize", () => {
  it("serializes a full argon2 digest", () => {
    assert.equal(
      serialize({
        id: "argon2id",
        version: 19,
        params: { m: 65536, p: 4, t: 3 },
        salt,
        hash,
      }),
      fullDigest,
    );
  });

  it("serializes with id only", () => {
    assert.equal(serialize({ id: "argon2id" }), "$argon2id");
  });

  it("serializes without version", () => {
    assert.equal(
      serialize({ id: "argon2i", params: { m: 4096, p: 1, t: 3 }, salt }),
      "$argon2i$m=4096,p=1,t=3$c2FsdHNhbHRzYWx0c2FsdA",
    );
  });

  it("preserves version 0", () => {
    assert.equal(serialize({ id: "test", version: 0 }), "$test$v=0");
  });

  it("encodes Buffer params as unpadded base64", () => {
    assert.equal(
      serialize({ id: "test", params: { data: Buffer.from("adadadadadadadad") } }),
      "$test$data=YWRhZGFkYWRhZGFkYWRhZA",
    );
  });

  it("does not mutate the caller's params object", () => {
    const params = { m: 65536, data: Buffer.from("ad") };
    serialize({ id: "test", params });
    assert.equal(typeof params.m, "number");
    assert(Buffer.isBuffer(params.data));
  });

  it("rejects invalid ids", () => {
    assert.throws(() => serialize({ id: "UPPER" }), TypeError);
    assert.throws(() => serialize({ id: "a".repeat(33) }), TypeError);
    // @ts-expect-error deliberately wrong type
    assert.throws(() => serialize({ id: 42 }), TypeError);
  });

  it("rejects invalid versions", () => {
    assert.throws(() => serialize({ id: "test", version: -1 }), TypeError);
    assert.throws(() => serialize({ id: "test", version: 1.5 }), TypeError);
  });

  it("rejects invalid param names and values", () => {
    assert.throws(() => serialize({ id: "test", params: { BAD: 1 } }), TypeError);
    assert.throws(
      () => serialize({ id: "test", params: { k: "no spaces" } }),
      TypeError,
    );
    assert.throws(
      // @ts-expect-error deliberately wrong type
      () => serialize({ id: "test", params: { k: {} } }),
      TypeError,
    );
  });

  it("rejects a hash without a salt", () => {
    assert.throws(() => serialize({ id: "test", hash }), TypeError);
  });

  it("rejects non-buffer salt or hash", () => {
    // @ts-expect-error deliberately wrong type
    assert.throws(() => serialize({ id: "test", salt: "abc" }), TypeError);
    // @ts-expect-error deliberately wrong type
    assert.throws(() => serialize({ id: "test", salt, hash: "abc" }), TypeError);
  });
});

describe("phc deserialize", () => {
  it("deserializes a full argon2 digest", () => {
    const parsed = deserialize(fullDigest);
    assert.equal(parsed.id, "argon2id");
    assert.equal(parsed.version, 19);
    assert.deepEqual(parsed.params, { m: 65536, p: 4, t: 3 });
    assert.deepEqual(parsed.salt, salt);
    assert.deepEqual(parsed.hash, hash);
  });

  it("round-trips with serialize", () => {
    const input = {
      id: "argon2d",
      version: 16,
      params: { m: 4096, p: 2, t: 10 },
      salt,
      hash,
    };
    assert.deepEqual(deserialize(serialize(input)), input);
  });

  it("deserializes the old format without version", () => {
    const parsed = deserialize(
      "$argon2i$m=4096,p=1,t=3$tbagT6b1YH33niCo9lVzuA$htv/k+OqWk1V9zD9k5DOBi2kcfcZ6Xu3tWmwEPV3/nc",
    );
    assert.equal(parsed.id, "argon2i");
    assert.equal(parsed.version, undefined);
    assert.deepEqual(parsed.params, { m: 4096, p: 1, t: 3 });
    assert(Buffer.isBuffer(parsed.salt));
    assert(Buffer.isBuffer(parsed.hash));
  });

  it("keeps base64-looking param values as strings", () => {
    const parsed = deserialize("$argon2id$m=65536,data=YWRhZA$c2FsdHNhbHRzYWx0c2FsdA");
    assert.equal(parsed.params?.m, 65536);
    assert.equal(parsed.params?.data, "YWRhZA");
  });

  it("keeps unsafe large integers as strings", () => {
    const big = "92233720368547758079";
    const parsed = deserialize(`$test$n=${big}`);
    assert.equal(parsed.params?.n, big);
  });

  it("parses foreign scheme digests without throwing (bcrypt)", () => {
    const parsed = deserialize(
      "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
    );
    assert.equal(parsed.id, "2a");
  });

  it("rejects non-string or empty input", () => {
    // @ts-expect-error deliberately wrong type
    assert.throws(() => deserialize(42), TypeError);
    assert.throws(() => deserialize(""), TypeError);
    assert.throws(() => deserialize("no-dollar"), TypeError);
  });

  it("rejects too many fields", () => {
    assert.throws(() => deserialize("$a$b=1$c$d$e$f"), TypeError);
  });

  it("rejects malformed params", () => {
    assert.throws(() => deserialize("$test$novalue$c2FsdA$aGFzaA"), TypeError);
  });

  it("rejects duplicated param names", () => {
    assert.throws(() => deserialize("$test$m=1,m=2$c2FsdA$aGFzaA"), TypeError);
  });

  it("rejects invalid ids", () => {
    assert.throws(() => deserialize("$NOPE$m=1"), TypeError);
  });
});
