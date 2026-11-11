// A small CBOR encoder that can also produce the malformed or non-canonical
// encodings the test cases need: duplicate map keys, non-minimal integer
// widths, indefinite-length containers and raw byte splices.

import { concat } from "./bytes.ts";

export type CborValue =
  | number
  | bigint
  | string
  | boolean
  | null
  | Uint8Array
  | CborValue[]
  | CborMap
  | CborRaw
  | CborWideInt
  | CborIndefinite;

/** An ordered map that keeps duplicate keys. */
export class CborMap {
  readonly entries: [CborValue, CborValue][];
  constructor(entries: [CborValue, CborValue][]) {
    this.entries = entries;
  }
}

/** Bytes inserted verbatim. */
export class CborRaw {
  readonly bytes: Uint8Array;
  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }
}

/** An integer encoded with a forced argument width (1, 2, 4 or 8 bytes). */
export class CborWideInt {
  readonly value: number;
  readonly width: 1 | 2 | 4 | 8;
  constructor(value: number, width: 1 | 2 | 4 | 8) {
    this.value = value;
    this.width = width;
  }
}

/** A map or array encoded with indefinite length (0xbf / 0x9f ... 0xff). */
export class CborIndefinite {
  readonly inner: CborMap | CborValue[];
  constructor(inner: CborMap | CborValue[]) {
    this.inner = inner;
  }
}

export const cmap = (...entries: [CborValue, CborValue][]) => new CborMap(entries);
export const raw = (bytes: Uint8Array) => new CborRaw(bytes);

function head(major: number, arg: number | bigint, width?: 1 | 2 | 4 | 8): Uint8Array {
  const m = major << 5;
  const n = BigInt(arg);
  if (width === undefined) {
    if (n < 24n) return new Uint8Array([m | Number(n)]);
    if (n < 0x100n) width = 1;
    else if (n < 0x10000n) width = 2;
    else if (n < 0x100000000n) width = 4;
    else width = 8;
  }
  const info = { 1: 24, 2: 25, 4: 26, 8: 27 }[width];
  const out = new Uint8Array(1 + width);
  out[0] = m | info;
  let v = n;
  for (let i = width; i >= 1; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function encodeInt(n: number | bigint, width?: 1 | 2 | 4 | 8): Uint8Array {
  const v = BigInt(n);
  return v >= 0n ? head(0, v, width) : head(1, -1n - v, width);
}

export function encode(v: CborValue): Uint8Array {
  if (v instanceof CborRaw) return v.bytes;
  if (v instanceof CborWideInt) return encodeInt(v.value, v.width);
  if (v instanceof CborIndefinite) {
    const inner = v.inner;
    if (inner instanceof CborMap) {
      const parts = inner.entries.flatMap(([k, val]) => [encode(k), encode(val)]);
      return concat(new Uint8Array([0xbf]), ...parts, new Uint8Array([0xff]));
    }
    return concat(new Uint8Array([0x9f]), ...inner.map(encode), new Uint8Array([0xff]));
  }
  if (v instanceof CborMap) {
    const parts = v.entries.flatMap(([k, val]) => [encode(k), encode(val)]);
    return concat(head(5, v.entries.length), ...parts);
  }
  if (v instanceof Uint8Array) return concat(head(2, v.length), v);
  if (Array.isArray(v)) return concat(head(4, v.length), ...v.map(encode));
  if (typeof v === "string") {
    const b = new TextEncoder().encode(v);
    return concat(head(3, b.length), b);
  }
  if (typeof v === "number" || typeof v === "bigint") {
    if (typeof v === "number" && !Number.isInteger(v)) throw new Error("floats are not supported");
    return encodeInt(v);
  }
  if (v === true) return new Uint8Array([0xf5]);
  if (v === false) return new Uint8Array([0xf4]);
  if (v === null) return new Uint8Array([0xf6]);
  throw new Error(`cannot encode ${String(v)}`);
}
