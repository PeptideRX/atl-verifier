/**
 * Merkle root verifier for multi-endpoint commitments. Section 6.1:
 *
 *     c_i = SHA256(D || V || S_i || JCS(P_i))  for i = 1..n
 *     root = MerkleRoot(c_1, c_2, ..., c_n)
 *
 * We use the RFC 6962-style Merkle tree: leaf inputs are hashed once,
 * internal nodes are SHA-256(left || right), and an odd trailing leaf at
 * any level is duplicated and paired with itself (Bitcoin-style
 * deduplication) to reach the next power of two.
 *
 * This implementation accepts either raw leaf values (which will be hashed
 * before being inserted as leaves) or pre-hashed leaf digests (hex).
 */

import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  sha256Bytes,
  timingSafeEqualHex,
} from './hash.js';

export interface MerkleOptions {
  /**
   * When true, treats each input string as a pre-computed SHA-256 leaf
   * digest in hex form. When false, hashes each input first.
   */
  prehashed?: boolean;
}

/**
 * Compute the Merkle root of the supplied leaves.
 *
 * An empty input returns the sentinel SHA-256 of the empty string. This
 * matches the convention used by the Go ATL-verifier in Track F so that
 * both sides agree on the empty-set case.
 */
export async function computeMerkleRoot(
  leaves: readonly string[],
  options: MerkleOptions = {},
): Promise<string> {
  if (leaves.length === 0) {
    const empty = await sha256Bytes('');
    return bytesToHex(empty);
  }

  // Convert leaves to their leaf-digest bytes.
  let level: Uint8Array[] = await Promise.all(
    leaves.map((leaf) => toLeafBytes(leaf, options.prehashed === true)),
  );

  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i] as Uint8Array;
      const right = (level[i + 1] ?? left) as Uint8Array;
      next.push(await sha256Bytes(concatBytes(left, right)));
    }
    level = next;
  }

  return bytesToHex(level[0] as Uint8Array);
}

/**
 * Verify that the supplied leaves hash to the claimed root.
 *
 * Returns true iff computeMerkleRoot(leaves, options) equals
 * expectedRoot (constant-time hex comparison).
 */
export async function verifyMerkleRoot(
  leaves: readonly string[],
  expectedRoot: string,
  options: MerkleOptions = {},
): Promise<boolean> {
  const expected = normalizeHex(expectedRoot);
  if (expected.length !== 64) return false;
  let computed: string;
  try {
    computed = await computeMerkleRoot(leaves, options);
  } catch {
    return false;
  }
  return timingSafeEqualHex(computed, expected);
}

async function toLeafBytes(
  leaf: string,
  prehashed: boolean,
): Promise<Uint8Array> {
  if (prehashed) {
    return hexToBytes(normalizeHex(leaf));
  }
  return sha256Bytes(leaf);
}

function normalizeHex(s: string): string {
  const stripped = s.startsWith('0x') || s.startsWith('0X') ? s.slice(2) : s;
  return stripped.toLowerCase();
}
