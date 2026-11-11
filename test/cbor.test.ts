import { test } from "node:test";
import assert from "node:assert/strict";
import { CborIndefinite, CborWideInt, cmap, encode, raw } from "../src/cbor.ts";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

test("RFC 8949 appendix A examples", () => {
  assert.equal(hex(encode(0)), "00");
  assert.equal(hex(encode(23)), "17");
  assert.equal(hex(encode(24)), "1818");
  assert.equal(hex(encode(1000)), "1903e8");
  assert.equal(hex(encode(1000000)), "1a000f4240");
  assert.equal(hex(encode(-1)), "20");
  assert.equal(hex(encode(-1000)), "3903e7");
  assert.equal(hex(encode("IETF")), "6449455446");
  assert.equal(hex(encode(new Uint8Array([1, 2, 3, 4]))), "4401020304");
  assert.equal(hex(encode([1, [2, 3], [4, 5]])), "8301820203820405");
  assert.equal(hex(encode(cmap(["a", 1], ["b", [2, 3]]))), "a26161016162820203");
  assert.equal(hex(encode(true)), "f5");
  assert.equal(hex(encode(null)), "f6");
});

test("malformed encodings", () => {
  assert.equal(hex(encode(cmap(["a", 1], ["a", 2]))), "a2616101616102");
  assert.equal(hex(encode(new CborWideInt(2, 2))), "190002");
  assert.equal(hex(encode(new CborWideInt(-7, 4))), "3a00000006");
  assert.equal(hex(encode(new CborIndefinite(cmap(["a", 1])))), "bf616101ff");
  assert.equal(hex(encode([raw(new Uint8Array([0xff]))])), "81ff");
});
