import { test } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import { buildCases } from "../src/cases.ts";
import { fromB64url, sha256, concat } from "../src/bytes.ts";

const cases = buildCases();

test("case ids are unique and every case has a spec reference", () => {
  assert.equal(new Set(cases.map((c) => c.id)).size, cases.length);
  for (const c of cases) {
    assert.ok(c.spec.length > 3, c.id);
    assert.ok(["accept", "reject", "either"].includes(c.expect), c.id);
    assert.equal(c.ceremony === "authentication", c.authentication !== undefined, c.id);
  }
});

test("generation is deterministic", () => {
  assert.deepEqual(JSON.parse(JSON.stringify(buildCases())), JSON.parse(JSON.stringify(cases)));
});

// Check the baseline assertions with node:crypto, independently of the
// signing code, so a bug in the generator cannot hide behind the libraries.
test("baseline assertion signatures verify with node:crypto", () => {
  const keys = {
    "auth-baseline-es256": "ES256",
    "auth-baseline-eddsa": "EdDSA",
    "auth-baseline-rs256": "RS256",
  } as const;
  for (const [id, alg] of Object.entries(keys)) {
    const c = cases.find((x) => x.id === id)!;
    const r = c.authentication!.response.response;
    const signed = concat(fromB64url(r.authenticatorData), sha256(fromB64url(r.clientDataJSON)));
    const att = fromB64url(c.registration.response.response.attestationObject);
    const key = publicKeyFromAttestation(att, alg);
    const ok = verify(alg === "EdDSA" ? null : "sha256", signed, key, fromB64url(r.signature));
    assert.ok(ok, id);
  }
});

test("clientDataJSON of the baselines matches what a browser sends", () => {
  const c = cases.find((x) => x.id === "reg-baseline-es256")!;
  const cd = JSON.parse(Buffer.from(c.registration.response.response.clientDataJSON, "base64url").toString());
  assert.deepEqual(Object.keys(cd), ["type", "challenge", "origin", "crossOrigin"]);
  assert.equal(cd.challenge, c.registration.challenge);
});

/** Minimal parser for the fixed layout of our own attestation objects. */
function publicKeyFromAttestation(att: Uint8Array, alg: "ES256" | "EdDSA" | "RS256") {
  const marker = Buffer.from("6861757468446174", "hex"); // text "authDat"
  let i = Buffer.from(att).indexOf(marker) + marker.length + 1;
  i += att[i] === 0x58 ? 2 : 3; // byte string header with a 1- or 2-byte length
  const authData = att.slice(i);
  const credIdLen = (authData[53] << 8) | authData[54];
  const cose = authData.slice(55 + credIdLen);
  const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64url");
  if (alg === "ES256") {
    // a5 01 02 03 26 20 01 21 58 20 <x> 22 58 20 <y>
    const x = cose.slice(10, 42);
    const y = cose.slice(45, 77);
    return createPublicKey({ key: { kty: "EC", crv: "P-256", x: b64(x), y: b64(y) }, format: "jwk" });
  }
  if (alg === "EdDSA") {
    // a4 01 01 03 27 20 06 21 58 20 <x>
    return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: b64(cose.slice(10, 42)) }, format: "jwk" });
  }
  // a4 01 03 03 39 01 00 20 59 01 00 <n> 21 43 <e>
  const n = cose.slice(11, 267);
  const e = cose.slice(269, 272);
  return createPublicKey({ key: { kty: "RSA", n: b64(n), e: b64(e) }, format: "jwk" });
}
