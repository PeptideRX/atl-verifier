/**
 * Peptide Design Attestation (PDA) protocol, V1 TypeScript reference.
 *
 * Public surface:
 *
 *   * {@link verifyPDA}                · verify a PDAOutput end-to-end.
 *   * {@link verifyCandidateReveal}    · verify a commit-reveal bundle.
 *   * {@link computePdaComponentHashes} · recompute the five component hashes.
 *   * {@link recomputePdaHex}          · re-derive the 32-byte PDA.
 *   * {@link pdaMerkleRoot}            · RFC 6962 Merkle root builder.
 *   * {@link pdaVerifyInclusionProof}  · Merkle inclusion proof verifier.
 *   * Primitive helpers (`pdaSha256`, `pdaHmacSha256`, `pdaU32BE`, etc.).
 *
 * Types:
 *
 *   * {@link PDAOutput}, {@link PDAVerificationReport}, {@link VerifyPDAOptions}.
 *   * {@link TargetSpec}, {@link PipelineManifest}, {@link BiosecurityPolicy},
 *     {@link TierDistribution}, {@link TEEAttestation}.
 *   * {@link CandidateCommitment}, {@link CandidateRevealInput},
 *     {@link MerkleProof}, {@link MerklePathEntry}.
 *
 * Byte-for-byte determinism with the Python reference at
 * `src/peptide_design/pda/` and the Rust reference at `crates/pda/` is
 * the load-bearing contract. All three implementations must agree on
 * the same 32-byte PDA for Vectors A, B, and C; see
 * `tests/pda-vectors/` and the cross-language parity script at
 * `scripts/cross_lang_pda_parity.py`.
 *
 * Scope: research use only, nonclinical.
 */
export { PDA_DIGEST_LEN, PDA_SCHEMA_VERSION_V1, PDA_DOMAIN_SEPARATOR, PDA_DOMAIN_TARGET_SPEC, PDA_DOMAIN_PIPELINE_MANIFEST, PDA_DOMAIN_BIOSECURITY_POLICY, PDA_DOMAIN_TIER_DIST, PDA_DOMAIN_CANDIDATE_COMMIT, PDA_DOMAIN_TEE_ATTESTATION, PDA_DOMAIN_MERKLE_INTERNAL, PDA_SIMULATOR_MEASUREMENT_HEX, PDA_SIMULATOR_SIGNING_KEY_HEX, PDA_TEE_TYPES, } from './constants.js';
export { pdaSha256, pdaHmacSha256, pdaComponentHash, pdaTimingSafeEqual, pdaU32BE, parseDigestHex, digestHex, } from './hashing.js';
export { pdaMerkleRoot, pdaVerifyInclusionProof, pdaGenerateInclusionProof, } from './merkle.js';
export { canonicalizePythonJSON, parsePythonJSON, asPythonFloat, isPyFloatNumber, } from './canonical-json.js';
export { verifyPDA, recomputePdaHex, computePdaComponentHashes, } from './verifier.js';
export { verifyCandidateReveal, computeCandidateCommitLeaf, computeCandidateMetadataHash, } from './reveal.js';
