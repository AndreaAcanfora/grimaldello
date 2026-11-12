// The test cases. Each one is a registration or an authentication ceremony
// with a single deliberate defect (or none, for the baselines), plus what the
// WebAuthn Level 3 specification says a relying party must do with it.

import { b64url, concat, filler, sha256, utf8 } from "./bytes.ts";
import { CborIndefinite, CborWideInt, cmap, encode, raw } from "./cbor.ts";
import {
  authentication,
  FLAG,
  registration,
  type AuthenticationOpts,
  type AuthenticationResponseJSON,
  type RegistrationOpts,
  type RegistrationResponseJSON,
} from "./authenticator.ts";
import { credentialFor, ED25519_ORDER, eddsa, es256, P256_ORDER, rs256, type Alg, type Credential } from "./credential.ts";
import { p256 } from "@noble/curves/nist.js";

export const RP_ID = "example.com";
export const ORIGIN = "https://example.com";

export type Expect = "accept" | "reject" | "either";

export type Category = "baseline" | "client-data" | "authenticator-data" | "cbor" | "cose-key" | "signature" | "attestation" | "encoding";

export interface Case {
  id: string;
  title: string;
  category: Category;
  ceremony: "registration" | "authentication";
  /** What a relying party following WebAuthn Level 3 must do. */
  expect: Expect;
  /** Where the requirement comes from, and why the case matters. */
  spec: string;
  /**
   * "security": an honest browser can produce this when it is under attack
   * (phishing site, replay, cross-origin iframe, missing user gesture), so
   * accepting it weakens what WebAuthn protects.
   * "hardening": only a modified client or authenticator can produce it; the
   * attacker can only affect their own credential, but parsers that disagree
   * are a liability when several components read the same data.
   */
  impact: "security" | "hardening";
  rp: { id: string; name: string; origin: string };
  requireUserVerification: boolean;
  /** COSE algorithm identifiers offered in pubKeyCredParams. */
  algorithms: number[];
  /** Algorithm of the credential, so adapters can skip unsupported ones. */
  alg: Alg;
  userHandle: string;
  registration: { challenge: string; response: RegistrationResponseJSON };
  authentication?: { challenge: string; response: AuthenticationResponseJSON; storedSignCount: number };
}

const ALGORITHMS = [-7, -8, -257];

const SECURITY = new Set([
  "reg-wrong-challenge", "reg-wrong-origin", "reg-origin-subdomain", "reg-origin-http", "reg-type-get",
  "reg-wrong-rpid-hash", "reg-rpid-hash-parent", "reg-up-clear", "reg-uv-required-clear",
  "auth-wrong-challenge", "auth-wrong-origin", "auth-type-create", "auth-wrong-rpid-hash", "auth-up-clear", "auth-uv-required-clear",
  "auth-signcount-regressed", "auth-signcount-equal",
  "sig-wrong-data", "sig-es256-zero", "sig-empty", "sig-other-credential",
  "att-packed-bad-sig",
]);

const challengeFor = (id: string, ceremony: string) => sha256(utf8(`grimaldello:${ceremony}:${id}`));

const CRED_IDS: Record<Alg, Uint8Array> = {
  ES256: filler(32, 0x11),
  EdDSA: filler(32, 0x22),
  RS256: filler(32, 0x33),
};

type Meta = Pick<Case, "id" | "title" | "category" | "expect" | "spec"> & {
  impact?: Case["impact"];
  alg?: Alg;
  requireUserVerification?: boolean;
  algorithms?: number[];
};

type RegOverrides = Partial<Omit<RegistrationOpts, "challenge">> & { challenge?: (real: Uint8Array) => Uint8Array };
type AuthOverrides = Partial<Omit<AuthenticationOpts, "challenge">> & { challenge?: (real: Uint8Array) => Uint8Array };

function base(meta: Meta) {
  const alg = meta.alg ?? "ES256";
  return {
    cred: credentialFor(alg, CRED_IDS[alg]),
    common: {
      id: meta.id,
      title: meta.title,
      category: meta.category,
      expect: meta.expect,
      spec: meta.spec,
      impact: meta.impact ?? (SECURITY.has(meta.id) ? "security" : "hardening"),
      rp: { id: RP_ID, name: "grimaldello", origin: ORIGIN },
      requireUserVerification: meta.requireUserVerification ?? false,
      algorithms: meta.algorithms ?? ALGORITHMS,
      alg,
      userHandle: b64url(utf8("grimaldello-user-1")),
    },
  };
}

function reg(meta: Meta, o: RegOverrides = {}): Case {
  const { cred, common } = base(meta);
  const challenge = challengeFor(meta.id, "create");
  const { challenge: tamper, ...rest } = o;
  const response = registration({
    cred,
    rpId: RP_ID,
    origin: ORIGIN,
    ...rest,
    challenge: tamper ? tamper(challenge) : challenge,
  });
  return { ...common, ceremony: "registration", registration: { challenge: b64url(challenge), response } };
}

function auth(meta: Meta, o: AuthOverrides = {}, storedSignCount = 0, credOverride?: Credential): Case {
  const { cred: defaultCred, common } = base(meta);
  const cred = credOverride ?? defaultCred;
  const regChallenge = challengeFor(meta.id, "create");
  const getChallenge = challengeFor(meta.id, "get");
  const { challenge: tamper, ...rest } = o;
  return {
    ...common,
    ceremony: "authentication",
    registration: {
      challenge: b64url(regChallenge),
      response: registration({ cred, rpId: RP_ID, origin: ORIGIN, challenge: regChallenge }),
    },
    authentication: {
      challenge: b64url(getChallenge),
      response: authentication({
        cred,
        rpId: RP_ID,
        origin: ORIGIN,
        ...rest,
        challenge: tamper ? tamper(getChallenge) : getChallenge,
      }),
      storedSignCount,
    },
  };
}

const flip = (b: Uint8Array) => {
  const c = b.slice();
  c[0] ^= 0x01;
  return c;
};

const bigToBytes = (n: bigint, len: number) => {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
};
const bytesToBig = (b: Uint8Array) => b.reduce((n, x) => (n << 8n) | BigInt(x), 0n);

/** Replace the first occurrence of a JSON member, keeping everything else. */
const dupKey = (key: string, value: string, first: boolean) => (json: string) =>
  first ? json.replace("{", `{"${key}":${JSON.stringify(value)},`) : json.replace(/}$/, `,"${key}":${JSON.stringify(value)}}`);

export function buildCases(): Case[] {
  const es = es256(CRED_IDS.ES256);
  const ed = eddsa(CRED_IDS.EdDSA);
  const rs = rs256(CRED_IDS.RS256);
  const wrong = (c: Uint8Array) => flip(c);

  return [
    // ── Baselines: everything here must be accepted ──────────────────────
    reg({ id: "reg-baseline-es256", title: "Valid registration, ES256, attestation none", category: "baseline", expect: "accept", spec: "§7.1: a well-formed ceremony" }),
    reg({ id: "reg-baseline-eddsa", alg: "EdDSA", title: "Valid registration, EdDSA (Ed25519)", category: "baseline", expect: "accept", spec: "§7.1, RFC 9053 §2.2" }),
    reg({ id: "reg-baseline-rs256", alg: "RS256", title: "Valid registration, RS256", category: "baseline", expect: "accept", spec: "§7.1, RFC 8812 §2" }),
    reg({ id: "reg-baseline-packed-self", title: "Valid registration, packed self-attestation", category: "baseline", expect: "accept", spec: "§8.2 packed, self attestation" }, { fmt: "packed" }),
    auth({ id: "auth-baseline-es256", title: "Valid authentication, ES256", category: "baseline", expect: "accept", spec: "§7.2: a well-formed ceremony" }),
    auth({ id: "auth-baseline-eddsa", alg: "EdDSA", title: "Valid authentication, EdDSA", category: "baseline", expect: "accept", spec: "§7.2" }),
    auth({ id: "auth-baseline-rs256", alg: "RS256", title: "Valid authentication, RS256", category: "baseline", expect: "accept", spec: "§7.2" }),
    auth({ id: "auth-signcount-zero", title: "Authenticator that never increments the counter (both 0)", category: "baseline", expect: "accept", spec: "§7.2 steps 22–23: counters that are both zero are not a clone signal" }, { signCount: 0 }),

    // ── clientDataJSON ───────────────────────────────────────────────────
    reg({ id: "reg-wrong-challenge", title: "Challenge does not match", category: "client-data", expect: "reject", spec: "§7.1 step 8" }, { challenge: wrong }),
    reg({ id: "reg-wrong-origin", title: "Origin from another site", category: "client-data", expect: "reject", spec: "§7.1 step 9" }, { origin: "https://evil.test" }),
    reg({ id: "reg-origin-subdomain", title: "Origin is a subdomain of the RP", category: "client-data", expect: "reject", spec: "§7.1 step 9: the RP did not list https://evil.example.com as an expected origin" }, { origin: "https://evil.example.com" }),
    reg({ id: "reg-origin-trailing-slash", title: "Origin with a trailing slash", category: "client-data", expect: "reject", spec: "§7.1 step 9 + §5.8.1: origin is the serialized origin, compared exactly" }, { origin: "https://example.com/" }),
    reg({ id: "reg-origin-uppercase", title: "Origin with an uppercase host", category: "client-data", expect: "reject", spec: "§5.8.1: browsers serialize the origin in lowercase, so this never comes from a real browser" }, { origin: "https://EXAMPLE.com" }),
    reg({ id: "reg-origin-default-port", title: "Origin with the default port spelled out", category: "client-data", expect: "reject", spec: "§5.8.1: the serialized origin omits the default port" }, { origin: "https://example.com:443" }),
    reg({ id: "reg-origin-http", title: "Origin over plain http", category: "client-data", expect: "reject", spec: "§7.1 step 9" }, { origin: "http://example.com" }),
    reg({ id: "reg-origin-userinfo", title: "Origin with userinfo (https://example.com@evil.test)", category: "client-data", expect: "reject", spec: "§7.1 step 9: a parser that splits on '@' sees example.com" }, { origin: "https://example.com@evil.test" }),
    reg({ id: "reg-type-get", title: "type is webauthn.get in a registration", category: "client-data", expect: "reject", spec: "§7.1 step 7" }, { clientData: (cd) => ({ ...cd, type: "webauthn.get" }) }),
    reg({ id: "reg-dup-challenge-first", title: "clientDataJSON with two challenge members, the wrong one first", category: "client-data", expect: "reject", spec: "§5.8.1.2: the JSON is not in the limited verification form; parsers disagree on which duplicate wins" }, { clientDataRaw: dupKey("challenge", b64url(filler(32, 0x99)), true) }),
    reg({ id: "reg-dup-challenge-last", title: "clientDataJSON with two challenge members, the wrong one last", category: "client-data", expect: "reject", spec: "§5.8.1.2: duplicate members; most JSON parsers keep the last one" }, { clientDataRaw: dupKey("challenge", b64url(filler(32, 0x99)), false) }),
    reg({ id: "reg-dup-origin-last", title: "clientDataJSON with a second, malicious origin member", category: "client-data", expect: "reject", spec: "§5.8.1.2: duplicate members" }, { clientDataRaw: dupKey("origin", "https://evil.test", false) }),
    reg({ id: "reg-cross-origin-true", title: "crossOrigin: true without a topOrigin the RP allows", category: "client-data", expect: "reject", spec: "§7.1 steps 10–11 (Level 3). Defence in depth only: the page must allow being framed, clients before Level 2 never send these fields, and topOrigin does not show every origin in a chain of nested iframes" }, { clientData: (cd) => ({ ...cd, crossOrigin: true, topOrigin: "https://evil.test" }) }),
    reg({ id: "reg-challenge-padded", title: "Challenge encoded as base64url with = padding", category: "client-data", expect: "reject", spec: "§5.8.1: challenge is base64url without padding; the decoded bytes still match" }, { clientData: (cd) => ({ ...cd, challenge: `${cd.challenge}=` }) }),
    reg({ id: "reg-challenge-std-base64", title: "Challenge encoded as standard base64 (+ and /)", category: "client-data", expect: "reject", spec: "§5.8.1: challenge is base64url" }, { clientData: (cd) => ({ ...cd, challenge: Buffer.from(cd.challenge as string, "base64url").toString("base64") }) }),
    reg({ id: "reg-client-data-bom", title: "clientDataJSON starting with a UTF-8 byte order mark", category: "client-data", expect: "either", spec: "§5.8.1.2: browsers never emit a BOM; JSON parsers differ" }, { clientDataRaw: (j) => `﻿${j}` }),
    auth({ id: "auth-wrong-challenge", title: "Challenge does not match", category: "client-data", expect: "reject", spec: "§7.2 step 11" }, { challenge: wrong }),
    auth({ id: "auth-wrong-origin", title: "Origin from another site", category: "client-data", expect: "reject", spec: "§7.2 step 12" }, { origin: "https://evil.test" }),
    auth({ id: "auth-type-create", title: "type is webauthn.create in an authentication", category: "client-data", expect: "reject", spec: "§7.2 step 10" }, { clientData: (cd) => ({ ...cd, type: "webauthn.create" }) }),
    auth({ id: "auth-cross-origin-true", title: "crossOrigin: true without a topOrigin the RP allows", category: "client-data", expect: "reject", spec: "§7.2 steps 13–14 (Level 3). Defence in depth only: the page must allow being framed, clients before Level 2 never send these fields, and topOrigin does not show every origin in a chain of nested iframes" }, { clientData: (cd) => ({ ...cd, crossOrigin: true, topOrigin: "https://evil.test" }) }),
    auth({ id: "auth-dup-challenge-last", title: "clientDataJSON with two challenge members, the wrong one last", category: "client-data", expect: "reject", spec: "§5.8.1.2" }, { clientDataRaw: dupKey("challenge", b64url(filler(32, 0x99)), false) }),

    // ── authenticatorData ────────────────────────────────────────────────
    reg({ id: "reg-wrong-rpid-hash", title: "rpIdHash of another RP ID", category: "authenticator-data", expect: "reject", spec: "§7.1 step 14" }, { rpIdHash: sha256(utf8("evil.test")) }),
    reg({ id: "reg-rpid-hash-parent", title: "rpIdHash of a registrable suffix (com)", category: "authenticator-data", expect: "reject", spec: "§7.1 step 14: must equal SHA-256 of the RP ID the RP expects" }, { rpIdHash: sha256(utf8("com")) }),
    reg({ id: "reg-up-clear", title: "User Present flag not set", category: "authenticator-data", expect: "reject", spec: "§7.1 step 15 (Level 3: unless conditional create was requested)" }, { flags: FLAG.UV | FLAG.AT }),
    reg({ id: "reg-uv-required-clear", requireUserVerification: true, title: "User verification required but UV flag not set", category: "authenticator-data", expect: "reject", spec: "§7.1 step 16" }, { flags: FLAG.UP | FLAG.AT }),
    reg({ id: "reg-at-clear", title: "Attested credential data present but AT flag not set", category: "authenticator-data", expect: "reject", spec: "§6.1: authData is malformed" }, { flags: FLAG.UP | FLAG.UV }),
    reg({ id: "reg-be-clear-bs-set", title: "Backup State set without Backup Eligible", category: "authenticator-data", expect: "reject", spec: "§6.1.3: BS=1 with BE=0 is an invalid combination; §7.1 step 17" }, { flags: FLAG.UP | FLAG.UV | FLAG.AT | FLAG.BS }),
    reg({ id: "reg-ed-set-no-extensions", title: "ED flag set but no extensions follow", category: "authenticator-data", expect: "reject", spec: "§6.1: authData is malformed" }, { flags: FLAG.UP | FLAG.UV | FLAG.AT | FLAG.ED }),
    reg({ id: "reg-extensions-without-ed", title: "Extension data present but ED flag not set", category: "authenticator-data", expect: "reject", spec: "§6.1: trailing data after the credential public key" }, { extensions: encode(cmap(["credProtect", 1])) }),
    reg({ id: "reg-authdata-trailing", title: "Trailing bytes after the credential public key", category: "authenticator-data", expect: "reject", spec: "§6.1: authData is malformed" }, { authDataSuffix: new Uint8Array([0x00, 0x00, 0x00, 0x00]) }),
    reg({ id: "reg-cred-id-mismatch", title: "Credential ID in authData differs from id/rawId", category: "authenticator-data", expect: "reject", spec: "§7.1: the RP stores the credential ID from authData, so a mismatch lets a client register one ID and log in with another" }, { authDataCredId: filler(32, 0x77) }),
    reg({ id: "reg-cred-id-too-long", title: "Credential ID of 1024 bytes", category: "authenticator-data", expect: "reject", spec: "§7.1 step 28: credentialId must be at most 1023 bytes" }, (() => { const id = filler(1024, 0x44); return { authDataCredId: id, id: b64url(id), rawId: b64url(id) }; })()),
    reg({ id: "reg-cred-id-length-overflow", title: "credentialIdLength larger than the remaining data", category: "authenticator-data", expect: "reject", spec: "§6.5.1: authData is truncated" }, { credIdLength: 0xffff }),
    auth({ id: "auth-wrong-rpid-hash", title: "rpIdHash of another RP ID", category: "authenticator-data", expect: "reject", spec: "§7.2 step 15" }, { rpIdHash: sha256(utf8("evil.test")) }),
    auth({ id: "auth-up-clear", title: "User Present flag not set", category: "authenticator-data", expect: "reject", spec: "§7.2 step 16" }, { flags: FLAG.UV }),
    auth({ id: "auth-uv-required-clear", requireUserVerification: true, title: "User verification required but UV flag not set", category: "authenticator-data", expect: "reject", spec: "§7.2 step 17" }, { flags: FLAG.UP }),
    auth({ id: "auth-signcount-regressed", title: "Signature counter lower than the stored one", category: "authenticator-data", expect: "reject", spec: "§7.2 steps 22–23: a possible cloned authenticator; the RP decides, but silently accepting defeats the counter" }, { signCount: 5 }, 10),
    auth({ id: "auth-signcount-equal", title: "Signature counter equal to the stored one (non-zero)", category: "authenticator-data", expect: "reject", spec: "§7.2 steps 22–23: the counter must be strictly greater" }, { signCount: 10 }, 10),
    auth({ id: "auth-authdata-short", title: "authenticatorData of 36 bytes (one short)", category: "authenticator-data", expect: "reject", spec: "§6.1: authData is at least 37 bytes" }, { authData: (a) => a.slice(0, 36) }),
    auth({ id: "auth-authdata-trailing", title: "Trailing bytes after authenticatorData", category: "authenticator-data", expect: "reject", spec: "§6.1: authData is malformed (and covered by the signature)" }, { authDataSuffix: new Uint8Array([0xde, 0xad]) }),
    auth({ id: "auth-be-clear-bs-set", title: "Backup State set without Backup Eligible", category: "authenticator-data", expect: "reject", spec: "§6.1.3, §7.2 step 18" }, { flags: FLAG.UP | FLAG.UV | FLAG.BS }),

    // ── CBOR encoding of the attestation object ──────────────────────────
    reg({ id: "cbor-attobj-trailing", title: "Trailing bytes after the attestationObject", category: "cbor", expect: "reject", spec: "RFC 8949 §5.3: not well-formed as a single data item" }, { attObj: (fmt, st, ad) => concat(encode(cmap(["fmt", fmt], ["attStmt", st], ["authData", ad])), new Uint8Array([0x00])) }),
    reg({ id: "cbor-attobj-dup-fmt", title: "attestationObject with fmt twice (packed, then none)", category: "cbor", expect: "reject", spec: "§6.5.4 + CTAP2 canonical CBOR: duplicate keys are invalid" }, { fmt: "packed", attObj: (fmt, st, ad) => encode(cmap(["fmt", fmt], ["attStmt", st], ["authData", ad], ["fmt", "none"])) }),
    reg({ id: "cbor-attobj-dup-authdata", title: "attestationObject with two authData members", category: "cbor", expect: "reject", spec: "RFC 8949 §5.6: duplicate keys" }, { attObj: (fmt, st, ad) => { const other = concat(sha256(utf8("evil.test")), ad.slice(32)); return encode(cmap(["fmt", fmt], ["attStmt", st], ["authData", ad], ["authData", other])); } }),
    reg({ id: "cbor-attobj-indefinite", title: "attestationObject as an indefinite-length map", category: "cbor", expect: "either", spec: "CTAP2 canonical CBOR forbids it; WebAuthn does not say an RP must reject it" }, { attObj: (fmt, st, ad) => encode(new CborIndefinite(cmap(["fmt", fmt], ["attStmt", st], ["authData", ad]))) }),
    reg({ id: "cbor-cose-dup-key", title: "COSE key with a duplicate x coordinate", category: "cbor", expect: "reject", spec: "RFC 9052 §7: duplicate labels make the key invalid" }, { coseKey: encode(cmap([1, 2], [3, -7], [-1, 1], [-2, filler(32, 0x01)], [-3, es.publicXY[1]], [-2, es.publicXY[0]])) }),
    reg({ id: "cbor-cose-nonminimal-int", title: "COSE key with a non-minimal integer (kty as 2-byte uint)", category: "cbor", expect: "either", spec: "CTAP2 canonical CBOR forbids it; tolerant decoders accept it" }, { coseKey: encode(cmap([1, new CborWideInt(2, 2)], [3, -7], [-1, 1], [-2, es.publicXY[0]], [-3, es.publicXY[1]])) }),

    // ── COSE public key ──────────────────────────────────────────────────
    reg({ id: "cose-missing-alg", title: "COSE key without alg (3)", category: "cose-key", expect: "reject", spec: "§7.1 step 20 (Level 3): alg must be present and match pubKeyCredParams" }, { coseKey: encode(cmap([1, 2], [-1, 1], [-2, es.publicXY[0]], [-3, es.publicXY[1]])) }),
    reg({ id: "cose-alg-not-offered", algorithms: [-7], alg: "EdDSA", title: "Credential algorithm not in pubKeyCredParams (EdDSA when only ES256 is offered)", category: "cose-key", expect: "reject", spec: "§7.1 step 20: alg must be one of the requested algorithms" }),
    reg({ id: "cose-es256-p384", title: "alg ES256 with crv P-384", category: "cose-key", expect: "reject", spec: "RFC 9053 §2.1: ES256 is ECDSA with P-256" }, { coseKey: encode(cmap([1, 2], [3, -7], [-1, 2], [-2, es.publicXY[0]], [-3, es.publicXY[1]])) }),
    reg({ id: "cose-es256-okp", title: "alg ES256 with an OKP (Ed25519) key", category: "cose-key", expect: "reject", spec: "RFC 9053: algorithm and key type do not match" }, { coseKey: encode(cmap([1, 1], [3, -7], [-1, 6], [-2, ed.publicKey])) }),
    reg({ id: "cose-eddsa-rsa", alg: "RS256", title: "alg EdDSA with an RSA key", category: "cose-key", expect: "reject", spec: "RFC 9053: algorithm and key type do not match" }, { coseKey: encode(cmap([1, 3], [3, -8], [-1, rs.modulus], [-2, new Uint8Array([1, 0, 1])])) }),
    reg({ id: "cose-point-not-on-curve", title: "EC2 point not on P-256", category: "cose-key", expect: "reject", spec: "SEC 1 §3.2.2: public key validation" }, { coseKey: encode(cmap([1, 2], [3, -7], [-1, 1], [-2, es.publicXY[0]], [-3, flip(es.publicXY[1])])) }),
    reg({ id: "cose-ec2-short-x", title: "EC2 x coordinate of 31 bytes", category: "cose-key", expect: "reject", spec: "RFC 9053 §7.1.1: x is the curve size, leading zeros included" }, { coseKey: encode(cmap([1, 2], [3, -7], [-1, 1], [-2, es.publicXY[0].slice(1)], [-3, es.publicXY[1]])) }),
    reg({ id: "cose-ed25519-small-order", alg: "EdDSA", title: "Ed25519 public key of small order (the identity point)", category: "cose-key", expect: "reject", spec: "RFC 8032 §5.1.7 / ZIP-215: a small-order key lets any signature with S=0 verify" }, { coseKey: encode(cmap([1, 1], [3, -8], [-1, 6], [-2, concat(new Uint8Array([1]), new Uint8Array(31))])) }),
    reg({ id: "cose-rsa-small-exponent", alg: "RS256", title: "RSA key with public exponent 1", category: "cose-key", expect: "reject", spec: "e=1 makes every 'signature' equal to the padded message" }, { coseKey: encode(cmap([1, 3], [3, -257], [-1, rs.modulus], [-2, new Uint8Array([1])])) }),
    reg({ id: "cose-rsa-1024", alg: "RS256", title: "RSA key with a 1024-bit modulus", category: "cose-key", expect: "either", spec: "Weak, but the specification sets no minimum size" }, { coseKey: encode(cmap([1, 3], [3, -257], [-1, rs.modulus.slice(0, 128)], [-2, new Uint8Array([1, 0, 1])])) }),

    // ── Signatures ───────────────────────────────────────────────────────
    auth({ id: "sig-wrong-data", title: "Signature over different data", category: "signature", expect: "reject", spec: "§7.2 step 21" }, { signature: (d) => es.sign(concat(d, new Uint8Array([0]))) }),
    auth({ id: "sig-es256-high-s", title: "ECDSA signature with high S (n - s)", category: "signature", expect: "either", spec: "WebAuthn does not require low-S; libraries disagree (malleability)" }, { signature: (d) => { const s = p256.Signature.fromBytes(es.signCompact(d), "compact"); return new p256.Signature(s.r, P256_ORDER - s.s).toBytes("der"); } }),
    auth({ id: "sig-es256-raw", title: "ECDSA signature as raw r||s instead of DER", category: "signature", expect: "reject", spec: "§6.5.6: ES256 signatures are ASN.1 DER Ecdsa-Sig-Value" }, { signature: (d) => es.signCompact(d) }),
    auth({ id: "sig-es256-der-trailing", title: "DER signature with a trailing byte", category: "signature", expect: "reject", spec: "X.690: DER has one encoding; trailing data is not DER" }, { signature: (d) => concat(es.sign(d), new Uint8Array([0])) }),
    auth({ id: "sig-es256-der-long-length", title: "DER signature with a non-minimal (long-form) length", category: "signature", expect: "reject", spec: "X.690 §10.1: DER requires the shortest length form" }, { signature: (d) => { const der = es.sign(d); return concat(new Uint8Array([0x30, 0x81, der[1]]), der.slice(2)); } }),
    auth({ id: "sig-es256-der-padded-int", title: "DER signature with a needless leading zero in r", category: "signature", expect: "reject", spec: "X.690 §8.3.2: integers use the minimum number of bytes" }, { signature: (d) => { const s = p256.Signature.fromBytes(es.signCompact(d), "compact"); const r = bigToBytes(s.r, 32); const sb = bigToBytes(s.s, 32); const int = (b: Uint8Array) => { let i = 0; while (i < b.length - 1 && b[i] === 0 && b[i + 1] < 0x80) i++; let v: Uint8Array = b.slice(i); if (v[0] >= 0x80) v = concat(new Uint8Array([0]), v); return v; }; const rr = concat(new Uint8Array([0]), int(r)); const ss = int(sb); return concat(new Uint8Array([0x30, 4 + rr.length + ss.length, 0x02, rr.length]), rr, new Uint8Array([0x02, ss.length]), ss); } }),
    auth({ id: "sig-es256-zero", title: "ECDSA signature with r = s = 0", category: "signature", expect: "reject", spec: "FIPS 186-5 §6.4.2: r and s must be in [1, n-1]" }, { signature: () => new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]) }),
    auth({ id: "sig-es256-s-equals-n", title: "ECDSA signature with s = n", category: "signature", expect: "reject", spec: "FIPS 186-5 §6.4.2: s must be < n" }, { signature: (d) => { const s = p256.Signature.fromBytes(es.signCompact(d), "compact"); const r = bigToBytes(s.r, 32); const n = bigToBytes(P256_ORDER, 32); const enc = (b: Uint8Array) => (b[0] >= 0x80 ? concat(new Uint8Array([0]), b) : b); const rr = enc(r); const nn = enc(n); return concat(new Uint8Array([0x30, 4 + rr.length + nn.length, 0x02, rr.length]), rr, new Uint8Array([0x02, nn.length]), nn); } }),
    auth({ id: "sig-eddsa-s-plus-l", alg: "EdDSA", title: "Ed25519 signature with S + L (non-canonical S)", category: "signature", expect: "reject", spec: "RFC 8032 §5.1.7: S must be < L" }, { signature: (d) => { const sig = ed.sign(d); const sLe = sig.slice(32); const s = bytesToBig(sLe.slice().reverse()) + ED25519_ORDER; const out = bigToBytes(s, 32).reverse(); return concat(sig.slice(0, 32), out); } }),
    auth({ id: "sig-eddsa-truncated", alg: "EdDSA", title: "Ed25519 signature of 63 bytes", category: "signature", expect: "reject", spec: "RFC 8032: signatures are 64 bytes" }, { signature: (d) => ed.sign(d).slice(0, 63) }),
    auth({ id: "sig-rs256-leading-zero", alg: "RS256", title: "RSA signature with an extra leading zero byte", category: "signature", expect: "reject", spec: "RFC 8017 §8.2.2: the signature must be exactly k bytes" }, { signature: (d) => concat(new Uint8Array([0]), rs.sign(d)) }),
    auth({ id: "sig-empty", title: "Empty signature", category: "signature", expect: "reject", spec: "§7.2 step 21" }, { signature: () => new Uint8Array() }),
    auth({ id: "sig-other-credential", title: "Assertion signed by a different key than the registered one", category: "signature", expect: "reject", spec: "§7.2 step 21: verify with the stored credential public key" }, { signature: (d) => eddsa(CRED_IDS.EdDSA).sign(d) }),

    // ── Attestation statements ───────────────────────────────────────────
    reg({ id: "att-none-with-statement", title: "fmt none with a non-empty attStmt", category: "attestation", expect: "reject", spec: "§8.7: the none attStmt is an empty map" }, { attStmt: () => cmap(["sig", filler(8)]) }),
    reg({ id: "att-unknown-fmt", title: "Unknown attestation format", category: "attestation", expect: "reject", spec: "§7.1 step 21: fmt must be a supported format" }, { fmt: "grimaldello", attStmt: () => cmap() }),
    reg({ id: "att-packed-bad-sig", title: "Packed self-attestation with an invalid signature", category: "attestation", expect: "reject", spec: "§8.2 verification procedure" }, { fmt: "packed", attStmt: (ad, h) => cmap(["alg", -7], ["sig", es.sign(concat(ad, flip(h)))]) }),
    reg({ id: "att-packed-alg-mismatch", title: "Packed self-attestation whose alg differs from the credential's", category: "attestation", expect: "reject", spec: "§8.2: in self attestation, alg must match the credential public key's alg" }, { fmt: "packed", attStmt: (ad, h) => cmap(["alg", -257], ["sig", es.sign(concat(ad, h))]) }),
    reg({ id: "att-packed-missing-sig", title: "Packed attestation without sig", category: "attestation", expect: "reject", spec: "§8.2: attStmt must contain sig" }, { fmt: "packed", attStmt: () => cmap(["alg", -7]) }),

    // ── JSON encoding of the response ────────────────────────────────────
    reg({ id: "enc-id-padded", title: "Credential id with base64url padding", category: "encoding", expect: "either", spec: "§5.1: id is base64url without padding; the bytes still match rawId" }, { id: `${b64url(es.credId)}=` }),
    reg({ id: "enc-type-wrong", title: "Credential type other than public-key", category: "encoding", expect: "reject", spec: "§5.1: type is \"public-key\"" }, { type: "password" }),
    reg({ id: "enc-id-rawid-mismatch", title: "id and rawId refer to different credentials", category: "encoding", expect: "reject", spec: "§5.1: id is the base64url encoding of rawId" }, { id: b64url(filler(32, 0x77)) }),
    auth({ id: "enc-auth-raw-padding", title: "authenticatorData as base64url with = padding", category: "encoding", expect: "either", spec: "Tolerated by many decoders; the bytes are the same" }, {}, 0),
  ].map((c) => (c.id === "enc-auth-raw-padding" ? padAuthData(c) : c));
}

function padAuthData(c: Case): Case {
  const r = c.authentication!.response;
  const s = r.response.authenticatorData;
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  return { ...c, authentication: { ...c.authentication!, response: { ...r, response: { ...r.response, authenticatorData: s + (pad || "") } } } };
}
