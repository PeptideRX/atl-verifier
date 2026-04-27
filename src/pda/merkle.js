/**
 * RFC 6962-style Merkle tree over 32-byte candidate commit leaves.
 *
 * Port of `src/peptide_design/pda/merkle.py` and
 * `crates/pda/src/merkle.rs`. Tree shape rules (identical to both
 * references):
 *
 *   * Leaves are 32 raw bytes. They are NOT re-hashed as they enter the
 *     tree; the PDA producer has already run them through the V1
 *     candidate-commit domain separator.
 *   * Internal nodes: `parent = SHA256(0x01 || left || right)`.
 *   * Odd-count levels duplicate the final node before pairing (RFC 6962
 *     convention). A one-leaf tree returns the leaf unchanged.
 *   * The root depends on leaf order; callers must establish canonical
 *     order before building.
 *
 * Scope: research use only, nonclinical.
 */
import { PDA_DIGEST_LEN, PDA_DOMAIN_MERKLE_INTERNAL } from './constants.js';
import { pdaSha256, pdaTimingSafeEqual } from './hashing.js';
/**
 * Compute the 32-byte Merkle root over `leaves`.
 *
 * Throws if any leaf is not exactly 32 bytes or if `leaves` is empty;
 * the zero-leaf root is not defined in the PDA spec.
 */
export async function pdaMerkleRoot(leaves) {
    if (leaves.length === 0) {
        throw new Error('pdaMerkleRoot: requires at least one leaf');
    }
    for (let i = 0; i < leaves.length; i++) {
        const leaf = leaves[i];
        if (!(leaf instanceof Uint8Array) || leaf.length !== PDA_DIGEST_LEN) {
            throw new Error(`pdaMerkleRoot: leaf ${i} must be exactly ${PDA_DIGEST_LEN} bytes`);
        }
    }
    let level = leaves.map((l) => new Uint8Array(l));
    while (level.length > 1) {
        if (level.length % 2 === 1) {
            const last = level[level.length - 1];
            level.push(new Uint8Array(last));
        }
        const next = [];
        for (let i = 0; i < level.length; i += 2) {
            const left = level[i];
            const right = level[i + 1];
            next.push(await hashInternal(left, right));
        }
        level = next;
    }
    return level[0];
}
/**
 * Verify that folding `leaf` through `path` yields `expectedRoot`.
 *
 * Each path entry is `(siblingBytes, side)` where `side` is `"right"`
 * if the sibling is the RIGHT child at that level (and the candidate
 * is the LEFT), `"left"` otherwise. An empty path is valid for a
 * single-leaf tree; `expectedRoot` must equal `leaf` in that case.
 *
 * Returns `false` on any malformed input (wrong byte lengths, bad side
 * label) so the verifier can treat inclusion checks uniformly.
 */
export async function pdaVerifyInclusionProof(leaf, path, expectedRoot) {
    if (!(leaf instanceof Uint8Array) || leaf.length !== PDA_DIGEST_LEN)
        return false;
    if (!(expectedRoot instanceof Uint8Array) ||
        expectedRoot.length !== PDA_DIGEST_LEN) {
        return false;
    }
    let current = new Uint8Array(leaf);
    for (const step of path) {
        if (!Array.isArray(step) || step.length !== 2)
            return false;
        const [sibling, side] = step;
        if (!(sibling instanceof Uint8Array) || sibling.length !== PDA_DIGEST_LEN) {
            return false;
        }
        if (side === 'right') {
            current = await hashInternal(current, sibling);
        }
        else if (side === 'left') {
            current = await hashInternal(sibling, current);
        }
        else {
            return false;
        }
    }
    return pdaTimingSafeEqual(current, expectedRoot);
}
/**
 * Generate the inclusion-proof path for `leaves[leafIndex]`.
 *
 * Useful for publishers that have the full leaf set and need to emit a
 * reveal bundle; the verifier only needs
 * {@link pdaVerifyInclusionProof}. The returned path is empty for a
 * one-leaf tree.
 */
export async function pdaGenerateInclusionProof(leaves, leafIndex) {
    if (leafIndex < 0 || leafIndex >= leaves.length) {
        throw new RangeError(`pdaGenerateInclusionProof: leafIndex ${leafIndex} out of range for ${leaves.length} leaves`);
    }
    for (let i = 0; i < leaves.length; i++) {
        const leaf = leaves[i];
        if (!(leaf instanceof Uint8Array) || leaf.length !== PDA_DIGEST_LEN) {
            throw new Error(`pdaGenerateInclusionProof: leaf ${i} must be 32 bytes`);
        }
    }
    let level = leaves.map((l) => new Uint8Array(l));
    let idx = leafIndex;
    const proof = [];
    while (level.length > 1) {
        if (level.length % 2 === 1) {
            const last = level[level.length - 1];
            level.push(new Uint8Array(last));
        }
        if (idx % 2 === 0) {
            const sibling = level[idx + 1];
            proof.push([new Uint8Array(sibling), 'right']);
        }
        else {
            const sibling = level[idx - 1];
            proof.push([new Uint8Array(sibling), 'left']);
        }
        const next = [];
        for (let i = 0; i < level.length; i += 2) {
            const left = level[i];
            const right = level[i + 1];
            next.push(await hashInternal(left, right));
        }
        level = next;
        idx = Math.floor(idx / 2);
    }
    return proof;
}
async function hashInternal(left, right) {
    if (left.length !== PDA_DIGEST_LEN || right.length !== PDA_DIGEST_LEN) {
        throw new Error(`pdaMerkle hashInternal: children must be ${PDA_DIGEST_LEN} bytes each`);
    }
    return pdaSha256(PDA_DOMAIN_MERKLE_INTERNAL, left, right);
}
