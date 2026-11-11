import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

export const sha256 = (data: Uint8Array): Uint8Array => nobleSha256(data);

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function b64url(data: Uint8Array): string {
  return Buffer.from(data).toString("base64url");
}

export function fromB64url(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

export function hex(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "hex"));
}

export function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0);
  return b;
}

export function u16be(n: number): Uint8Array {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, n);
  return b;
}

/** Deterministic filler bytes, so vectors are stable across runs. */
export function filler(len: number, seed = 0x5a): Uint8Array {
  const b = new Uint8Array(len);
  for (let i = 0; i < len; i++) b[i] = (seed + i * 31) & 0xff;
  return b;
}
