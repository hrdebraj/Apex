/**
 * BOF argument packer – produces binary data compatible with
 * Cobalt-Strike-style BeaconDataParse / BeaconDataExtract / BeaconDataInt / BeaconDataShort.
 *
 * Type prefixes (inspired by bof_pack format string):
 *   i:<value>   → 4-byte little-endian int32
 *   s:<value>   → 2-byte little-endian int16 (short)
 *   z:<value>   → length-prefixed narrow string (UTF-8 + null terminator)
 *   Z:<value>   → length-prefixed wide string  (UTF-16LE + null terminator)  [default]
 *   b:<base64>  → length-prefixed raw binary blob
 *
 * If no prefix is present the argument is treated as a wide string (Z:).
 */

function writeU32LE(value: number): Uint8Array {
  const buf = new Uint8Array(4);
  const v = new DataView(buf.buffer);
  v.setUint32(0, value, true);
  return buf;
}

function writeU16LE(value: number): Uint8Array {
  const buf = new Uint8Array(2);
  const v = new DataView(buf.buffer);
  v.setUint16(0, value, true);
  return buf;
}

function encodeNarrowString(str: string): Uint8Array {
  const encoder = new TextEncoder();
  const encoded = encoder.encode(str + "\0");
  return concat(writeU32LE(encoded.length), encoded);
}

function encodeWideString(str: string): Uint8Array {
  const withNull = str + "\0";
  const wide = new Uint8Array(withNull.length * 2);
  for (let i = 0; i < withNull.length; i++) {
    const code = withNull.charCodeAt(i);
    wide[i * 2] = code & 0xff;
    wide[i * 2 + 1] = (code >> 8) & 0xff;
  }
  return concat(writeU32LE(wide.length), wide);
}

function encodeBlob(b64: string): Uint8Array {
  const raw = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return concat(writeU32LE(raw.length), raw);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((a, b) => a + b.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function packBOFArgs(args: string[]): Uint8Array {
  const parts: Uint8Array[] = [];

  for (const raw of args) {
    const colonIdx = raw.indexOf(":");
    let prefix = "";
    let value = raw;

    if (colonIdx === 1 && "iszZb".includes(raw[0])) {
      prefix = raw[0];
      value = raw.slice(2);
    }

    switch (prefix) {
      case "i":
        parts.push(writeU32LE(parseInt(value, 10) | 0));
        break;
      case "s":
        parts.push(writeU16LE(parseInt(value, 10) & 0xffff));
        break;
      case "z":
        parts.push(encodeNarrowString(value));
        break;
      case "b":
        parts.push(encodeBlob(value));
        break;
      case "Z":
      default:
        parts.push(encodeWideString(value));
        break;
    }
  }

  return concat(...parts);
}

export function uint8ToBase64(buf: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < buf.length; i++) {
    binary += String.fromCharCode(buf[i]);
  }
  return btoa(binary);
}
