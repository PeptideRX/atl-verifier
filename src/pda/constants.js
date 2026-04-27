/**
 * Peptide Design Attestation (PDA) protocol constants.
 *
 * These are byte-identical to `src/peptide_design/pda/hashing.py` and
 * `crates/pda/src/hashing.rs`. Any change here must land in both
 * reference implementations as well; silent drift breaks the patent-
 * enablement cross-language contract.
 *
 * Scope: research use only, nonclinical.
 */
/**
 * SHA-256 output width in bytes. All PDA component hashes and the PDA
 * itself use this fixed length.
 */
export const PDA_DIGEST_LEN = 32;
/**
 * Protocol schema version. V1 = 1. Folded into the top-level PDA hash
 * as a 4-byte big-endian unsigned integer.
 */
export const PDA_SCHEMA_VERSION_V1 = 1;
/**
 * Top-level PDA domain separator, ASCII. 16 bytes. Folded into the
 * outermost SHA-256 input before the schema version.
 */
export const PDA_DOMAIN_SEPARATOR = 'PEPTIDERX_PDA_V1';
/** Domain separator for the TargetSpec component hash. */
export const PDA_DOMAIN_TARGET_SPEC = 'PEPTIDERX_PDA_TARGET_SPEC_V1';
/** Domain separator for the PipelineManifest component hash. */
export const PDA_DOMAIN_PIPELINE_MANIFEST = 'PEPTIDERX_PDA_PIPELINE_MANIFEST_V1';
/** Domain separator for the BiosecurityPolicy component hash. */
export const PDA_DOMAIN_BIOSECURITY_POLICY = 'PEPTIDERX_PDA_BIOSECURITY_POLICY_V1';
/** Domain separator for the TierDistribution component hash. */
export const PDA_DOMAIN_TIER_DIST = 'PEPTIDERX_PDA_TIER_DISTRIBUTION_V1';
/** Domain separator used for per-candidate Merkle leaf commitments. */
export const PDA_DOMAIN_CANDIDATE_COMMIT = 'PEPTIDERX_CANDIDATE_COMMIT_V1';
/** Domain separator for the TEEAttestation component hash + transcript. */
export const PDA_DOMAIN_TEE_ATTESTATION = 'PEPTIDERX_PDA_TEE_ATTESTATION_V1';
/**
 * Internal-node tag for the RFC 6962-style Merkle tree. Matches the
 * Python reference (`b"\x01"`) and `INTERNAL_NODE_TAG` in
 * `crates/atl_crypto/src/merkle.rs`.
 */
export const PDA_DOMAIN_MERKLE_INTERNAL = new Uint8Array([0x01]);
/**
 * Public simulator measurement. A documented constant (not a secret).
 * ASCII `PEPTIDERX-SIM-V1-MEASUREMENT` (28 bytes) padded with four zero
 * bytes to reach the canonical 32-byte width.
 */
export const PDA_SIMULATOR_MEASUREMENT_HEX = '5045505449444552582d53494d2d56312d4d4541535552454d454e5400000000';
/**
 * Public simulator signing key. A documented constant (not a secret).
 * ASCII `PEPTIDERX-SIM-V1-SIGN-KEY01` (27 bytes) padded with five zero
 * bytes to reach 32 bytes. Used by the TEE simulator to sign every
 * attestation transcript with HMAC-SHA256. A production verifier that
 * refuses simulator attestations does not need this key.
 */
export const PDA_SIMULATOR_SIGNING_KEY_HEX = '5045505449444552582d53494d2d56312d5349474e2d4b455930310000000000';
/**
 * The four TEE backend identifiers registered by the V1 protocol. Only
 * the simulator is shipped in V1; the others are reserved enum values
 * for the signed TEEAttestation.tee_type field.
 */
export const PDA_TEE_TYPES = ['sgx', 'nitro', 'h100_cc', 'oasis_rofl', 'simulator'];
