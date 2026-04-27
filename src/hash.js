/**
 * SHA-256 wrapper using Web Crypto SubtleCrypto. Works in browsers, Node
 * (globalThis.crypto since 20.x), Bun, and edge runtimes.
 */
/**
 * Return the global SubtleCrypto instance or throw a clear error when the
 * runtime does not expose one. Required for environments that forget to
 * polyfill globalThis.crypto (very old Node, some sandboxes).
 */
function getSubtle() {
    const c = globalThis.crypto;
    if (!c || !c.subtle) {
        throw new Error('Web Crypto SubtleCrypto is not available in this runtime. ' +
            'Node 20+ exposes it via globalThis.crypto; in older runtimes, ' +
            'import node:crypto webcrypto and assign to globalThis.crypto.');
    }
    return c.subtle;
}
const TEXT_ENCODER = new TextEncoder();
/**
 * Hash an input (string or bytes) with SHA-256, returning a lowercase hex
 * string of length 64.
 */
export async function sha256Hex(input) {
    const bytes = typeof input === 'string' ? TEXT_ENCODER.encode(input) : input;
    // SubtleCrypto.digest types accept BufferSource; pass the backing buffer.
    const digest = await getSubtle().digest('SHA-256', bytes);
    return bytesToHex(new Uint8Array(digest));
}
/**
 * Hash an input (string or bytes) with SHA-256, returning the raw digest
 * bytes (32 bytes).
 */
export async function sha256Bytes(input) {
    const bytes = typeof input === 'string' ? TEXT_ENCODER.encode(input) : input;
    const digest = await getSubtle().digest('SHA-256', bytes);
    return new Uint8Array(digest);
}
/**
 * Convert a Uint8Array to a lowercase hex string.
 */
export function bytesToHex(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i];
        out += b.toString(16).padStart(2, '0');
    }
    return out;
}
/**
 * Convert a lowercase hex string to a Uint8Array. Accepts uppercase as well;
 * throws on odd length or non-hex characters.
 */
export function hexToBytes(hex) {
    if (hex.length % 2 !== 0) {
        throw new Error(`hexToBytes: odd-length input (${hex.length})`);
    }
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        const byte = Number.parseInt(hex.slice(i, i + 2), 16);
        if (Number.isNaN(byte)) {
            throw new Error(`hexToBytes: invalid hex at offset ${i}`);
        }
        out[i / 2] = byte;
    }
    return out;
}
/**
 * Concatenate multiple byte sequences into a single Uint8Array.
 */
export function concatBytes(...parts) {
    const arrs = parts.map((p) => typeof p === 'string' ? TEXT_ENCODER.encode(p) : p);
    let total = 0;
    for (const a of arrs)
        total += a.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrs) {
        out.set(a, off);
        off += a.length;
    }
    return out;
}
/**
 * Constant-time hex string comparison. Both strings must have equal length;
 * otherwise the comparison returns false without leaking the mismatch point.
 */
export function timingSafeEqualHex(a, b) {
    if (a.length !== b.length)
        return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return diff === 0;
}
