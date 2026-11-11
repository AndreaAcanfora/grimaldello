// Builds WebAuthn registration and authentication responses in the JSON form
// browsers return from PublicKeyCredential.toJSON(). Every field can be
// overridden, which is how the test cases produce their malformed variants.

import { b64url, concat, sha256, u16be, u32be, utf8 } from "./bytes.ts";
import { cmap, encode, type CborValue } from "./cbor.ts";
import { COSE_ALG, type Credential } from "./credential.ts";

export const FLAG = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40, ED: 0x80 } as const;

export const USER_HANDLE = utf8("grimaldello-user-1");

export interface ClientDataOpts {
  /** Edit the clientData object before it is serialized. */
  clientData?: (cd: Record<string, unknown>) => Record<string, unknown>;
  /** Edit the serialized JSON string (for duplicate keys, odd whitespace...). */
  clientDataRaw?: (json: string) => string;
}

export interface RegistrationOpts extends ClientDataOpts {
  cred: Credential;
  rpId: string;
  origin: string;
  challenge: Uint8Array;
  flags?: number;
  rpIdHash?: Uint8Array;
  signCount?: number;
  aaguid?: Uint8Array;
  /** Credential ID written into authenticatorData (defaults to cred.credId). */
  authDataCredId?: Uint8Array;
  /** Override the 2-byte credentialIdLength field. */
  credIdLength?: number;
  coseKey?: Uint8Array;
  /** Raw CBOR extension map appended after the credential public key. */
  extensions?: Uint8Array;
  /** Bytes appended to authenticatorData. */
  authDataSuffix?: Uint8Array;
  fmt?: string;
  /** Build the attestation statement; gets authData and clientDataHash. */
  attStmt?: (authData: Uint8Array, clientDataHash: Uint8Array) => CborValue;
  /** Build the whole attestationObject. */
  attObj?: (fmt: string, attStmt: CborValue, authData: Uint8Array) => Uint8Array;
  id?: string;
  rawId?: string;
  type?: string;
}

export interface RegistrationResponseJSON {
  id: string;
  rawId: string;
  type: string;
  response: { clientDataJSON: string; attestationObject: string; transports: string[] };
  clientExtensionResults: Record<string, unknown>;
}

export interface AuthenticationOpts extends ClientDataOpts {
  cred: Credential;
  rpId: string;
  origin: string;
  challenge: Uint8Array;
  flags?: number;
  rpIdHash?: Uint8Array;
  signCount?: number;
  /** Bytes appended to authenticatorData before signing. */
  authDataSuffix?: Uint8Array;
  /** Replace authenticatorData entirely (signed as given). */
  authData?: (authData: Uint8Array) => Uint8Array;
  /** Produce the signature from the signed data (defaults to cred.sign). */
  signature?: (signedData: Uint8Array) => Uint8Array;
  id?: string;
  userHandle?: Uint8Array | null;
}

export interface AuthenticationResponseJSON {
  id: string;
  rawId: string;
  type: string;
  response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle?: string };
  clientExtensionResults: Record<string, unknown>;
}

function clientDataJSON(type: string, challenge: Uint8Array, origin: string, o: ClientDataOpts): Uint8Array {
  let cd: Record<string, unknown> = { type, challenge: b64url(challenge), origin, crossOrigin: false };
  if (o.clientData) cd = o.clientData(cd);
  let json = JSON.stringify(cd);
  if (o.clientDataRaw) json = o.clientDataRaw(json);
  return utf8(json);
}

export function registration(o: RegistrationOpts): RegistrationResponseJSON {
  const cdj = clientDataJSON("webauthn.create", o.challenge, o.origin, o);
  const clientDataHash = sha256(cdj);
  const credId = o.authDataCredId ?? o.cred.credId;
  const flags = o.flags ?? FLAG.UP | FLAG.UV | FLAG.AT;
  const authData = concat(
    o.rpIdHash ?? sha256(utf8(o.rpId)),
    new Uint8Array([flags]),
    u32be(o.signCount ?? 0),
    o.aaguid ?? new Uint8Array(16),
    u16be(o.credIdLength ?? credId.length),
    credId,
    o.coseKey ?? o.cred.coseKey(),
    o.extensions ?? new Uint8Array(),
    o.authDataSuffix ?? new Uint8Array(),
  );
  const fmt = o.fmt ?? "none";
  const attStmt: CborValue = o.attStmt
    ? o.attStmt(authData, clientDataHash)
    : fmt === "packed"
      ? cmap(["alg", COSE_ALG[o.cred.alg]], ["sig", o.cred.sign(concat(authData, clientDataHash))])
      : cmap();
  const attObj = o.attObj
    ? o.attObj(fmt, attStmt, authData)
    : encode(cmap(["fmt", fmt], ["attStmt", attStmt], ["authData", authData]));
  return {
    id: o.id ?? b64url(o.cred.credId),
    rawId: o.rawId ?? b64url(o.cred.credId),
    type: o.type ?? "public-key",
    response: { clientDataJSON: b64url(cdj), attestationObject: b64url(attObj), transports: ["internal"] },
    clientExtensionResults: {},
  };
}

export function authentication(o: AuthenticationOpts): AuthenticationResponseJSON {
  const cdj = clientDataJSON("webauthn.get", o.challenge, o.origin, o);
  let authData = concat(
    o.rpIdHash ?? sha256(utf8(o.rpId)),
    new Uint8Array([o.flags ?? FLAG.UP | FLAG.UV]),
    u32be(o.signCount ?? 1),
    o.authDataSuffix ?? new Uint8Array(),
  );
  if (o.authData) authData = o.authData(authData);
  const signed = concat(authData, sha256(cdj));
  const signature = o.signature ? o.signature(signed) : o.cred.sign(signed);
  const userHandle = o.userHandle === undefined ? USER_HANDLE : o.userHandle;
  return {
    id: o.id ?? b64url(o.cred.credId),
    rawId: o.id ?? b64url(o.cred.credId),
    type: "public-key",
    response: {
      clientDataJSON: b64url(cdj),
      authenticatorData: b64url(authData),
      signature: b64url(signature),
      ...(userHandle ? { userHandle: b64url(userHandle) } : {}),
    },
    clientExtensionResults: {},
  };
}
