/**
 * SHA-256 + HMAC-SHA256 primitives for the PDA protocol.
 *
 * All primitives use Web Crypto SubtleCrypto; the SDK's existing
 * `hash.ts` module wraps `globalThis.crypto.subtle.digest` the same way.
 * These helpers are additive: they preserve the byte-level concat
 * pattern the Python and Rust references require for the PDA outer
 * hash and Merkle internal nodes.
 *
 * Scope: research use only, nonclinical.
 */

import { bytesToHex, concatBytes, hexToBytes } from '../hash.js';

/**
 * SHA-256 digest, returning raw 32-byte output.
 *
 * Accepts any number of chunks, concatenates them unframed, and
 * forwards the result to SubtleCrypto. Matches the Python
 * `sha256(*chunks)` helper and the Rust `sha256(&[&[u8]])` helper.
 */
export async function pdaSha256(...chunks: Array<Uint8Array | string>): Promise<Uint8Array> {
  const input = concatBytes(...chunks);
  const subtle = getSubtle();
  const digest = await subtle.digest('SHA-256', input as BufferSource);
  return new Uint8Array(digest);
}

/**
 * HMAC-SHA256 over `message` under `key`. Returns 32 bytes.
 *
 * Used exclusively to verify the V1 TEE simulator's signature: the
 * simulator signs with `HMAC-SHA256(SIMULATOR_SIGNING_KEY, transcript)`.
 * A production verifier refusing the simulator does not reach this
 * helper.
 */
export async function pdaHmacSha256(
  key: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array> {
  const subtle = getSubtle();
  const cryptoKey = await subtle.importKey(
    'raw',
    key as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await subtle.sign('HMAC', cryptoKey, message as BufferSource);
  return new Uint8Array(sig);
}

/**
 * Convenience: SHA-256 over `domain || canonical_json_bytes`, returning
 * raw 32 bytes. The Python and Rust references expose the same helper
 * (`component_hash`); callers pass a domain separator string plus the
 * canonical JSON bytes of a pydantic dump.
 */
export async function pdaComponentHash(
  domain: string,
  canonicalJsonBytes: Uint8Array,
): Promise<Uint8Array> {
  return pdaSha256(domain, canonicalJsonBytes);
}

/**
 * Constant-time comparison of two byte slices. Returns false on length
 * mismatch without leaking the mismatch point.
 */
export function pdaTimingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] as number) ^ (b[i] as number);
  }
  return diff === 0;
}

/**
 * Serialize a 4-byte big-endian unsigned integer. Used for the schema
 * version prefix in the top-level PDA hash.
 */
export function pdaU32BE(n: number): Uint8Array {
  if (n < 0 || n > 0xffff_ffff || !Number.isInteger(n)) {
    throw new RangeError(`pdaU32BE: value out of range: ${n}`);
  }
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

/**
 * Parse a lowercase 64-char hex digest to raw 32 bytes. Returns null on
 * malformed input rather than throwing so verifier callers can flag the
 * issue via a `blocked_reasons` code.
 */
export function parseDigestHex(hex: string): Uint8Array | null {
  if (typeof hex !== 'string') return null;
  const stripped = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  if (stripped.length !== 64) return null;
  if (!/^[0-9a-f]{64}$/.test(stripped)) return null;
  try {
    return hexToBytes(stripped);
  } catch {
    return null;
  }
}

/**
 * Lowercase-hex-encode a raw byte slice. Delegates to the SDK's
 * existing `bytesToHex`; re-exported under the PDA namespace for
 * discoverability.
 */
export function digestHex(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}

function getSubtle(): SubtleCrypto {
  const c: Crypto | undefined = (globalThis as { crypto?: Crypto }).crypto;
  if (!c || !c.subtle) {
    throw new Error(
      'Web Crypto SubtleCrypto is not available. Node 20+ exposes it via ' +
        'globalThis.crypto; older runtimes must import node:crypto webcrypto ' +
        'and assign to globalThis.crypto.',
    );
  }
  return c.subtle;
}
