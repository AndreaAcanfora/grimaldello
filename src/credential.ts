// Software credentials with fixed keys, so every generated vector is stable.

import { createPrivateKey, createPublicKey, sign as nodeSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { p256 } from "@noble/curves/nist.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { hex } from "./bytes.ts";
import { cmap, encode, type CborMap } from "./cbor.ts";

export type Alg = "ES256" | "EdDSA" | "RS256";

export const COSE_ALG: Record<Alg, number> = { ES256: -7, EdDSA: -8, RS256: -257 };

export interface Credential {
  alg: Alg;
  credId: Uint8Array;
  /** The COSE_Key as an ordered map, so cases can tamper with it. */
  coseMap(): CborMap;
  coseKey(): Uint8Array;
  /** Sign authenticatorData || clientDataHash the way the algorithm requires. */
  sign(data: Uint8Array): Uint8Array;
}

// Test keys. They are public on purpose: never use them for anything else.
const P256_SECRET = hex("8e3f1c0d6a2b4f5e9a7c3d1b0e2f4a6c8b1d3f5e7a9c0b2d4f6e8a1c3b5d7f90");
const ED25519_SECRET = hex("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe");
const RSA_PEM = readFileSync(new URL("./keys/test-rsa-2048.pem", import.meta.url), "utf8");

export const P256_ORDER = p256.Point.Fn.ORDER;
export const ED25519_ORDER = ed25519.Point.Fn.ORDER;

export function es256(credId: Uint8Array): Credential & { publicXY: [Uint8Array, Uint8Array]; signCompact(data: Uint8Array): Uint8Array } {
  const pub = p256.getPublicKey(P256_SECRET, false);
  const x = pub.slice(1, 33);
  const y = pub.slice(33, 65);
  const coseMap = () => cmap([1, 2], [3, -7], [-1, 1], [-2, x], [-3, y]);
  const signCompact = (data: Uint8Array) => p256.sign(data, P256_SECRET, { prehash: true, lowS: true });
  return {
    alg: "ES256",
    credId,
    publicXY: [x, y],
    coseMap,
    coseKey: () => encode(coseMap()),
    signCompact,
    sign: (data) => p256.Signature.fromBytes(signCompact(data), "compact").toBytes("der"),
  };
}

export function eddsa(credId: Uint8Array): Credential & { publicKey: Uint8Array } {
  const publicKey = ed25519.getPublicKey(ED25519_SECRET);
  const coseMap = () => cmap([1, 1], [3, -8], [-1, 6], [-2, publicKey]);
  return {
    alg: "EdDSA",
    credId,
    publicKey,
    coseMap,
    coseKey: () => encode(coseMap()),
    sign: (data) => ed25519.sign(data, ED25519_SECRET),
  };
}

export function rs256(credId: Uint8Array): Credential & { modulus: Uint8Array } {
  const priv = createPrivateKey(RSA_PEM);
  const jwk = createPublicKey(priv).export({ format: "jwk" });
  const n = new Uint8Array(Buffer.from(jwk.n!, "base64url"));
  const e = new Uint8Array(Buffer.from(jwk.e!, "base64url"));
  const coseMap = () => cmap([1, 3], [3, -257], [-1, n], [-2, e]);
  return {
    alg: "RS256",
    credId,
    modulus: n,
    coseMap,
    coseKey: () => encode(coseMap()),
    sign: (data) => new Uint8Array(nodeSign("sha256", data, priv)),
  };
}

export function credentialFor(alg: Alg, credId: Uint8Array): Credential {
  return alg === "ES256" ? es256(credId) : alg === "EdDSA" ? eddsa(credId) : rs256(credId);
}

