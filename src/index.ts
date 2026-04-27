/**
 * @peptiderx/atl-verifier
 *
 * EXPERIMENTAL · ACTIVE DEVELOPMENT.
 * Published in the open as part of building peptideRx in public. The
 * protocol, schemas, and APIs are not stable. Pin exact versions if you
 * depend on it. The cross-language byte-identical property is locked on
 * the three published test vectors; everything else may change.
 *
 * Client-side verifier for the ATL (Autonomous Thesis Loop) commit-reveal
 * protocol, Merkle root construction, state root replay, and the Peptide
 * Design Attestation (PDA) protocol. Implements Chapter 6 of the ATL
 * dissertation and the PDA V1 spec.
 *
 * All primitives use Web Crypto SubtleCrypto and work in browsers, Node 20+,
 * Deno, Bun, and edge runtimes. No native dependencies.
 *
 * Repository: https://github.com/PeptideRX/atl-verifier
 * Docs:       https://peptiderx.io/atl.html
 * License:    Apache-2.0
 */

export {
  canonicalizeJSON,
  type JsonPrimitive,
  type JsonValue,
} from './canonical-json.js';

export {
  DOMAIN_SEPARATOR,
  DEFAULT_SCHEMA_VERSION,
  MIN_SALT_BITS,
  EVIDENCE_GRADES,
  ATL_STATES,
  type EvidenceGrade,
  type AtlState,
} from './constants.js';

export {
  sha256Hex,
  sha256Bytes,
  bytesToHex,
  hexToBytes,
  concatBytes,
  timingSafeEqualHex,
} from './hash.js';

export {
  VerifyCommit,
  computeCommitHex,
  computeCommitBytes,
  type CommitOptions,
} from './commit.js';

export {
  computeMerkleRoot,
  verifyMerkleRoot,
  type MerkleOptions,
} from './merkle.js';

export {
  computeStateRoot,
  verifyStateRoot,
  type AtlEvent,
  type StateRootOptions,
} from './state-root.js';

// ---------------------------------------------------------------------------
// Peptide Design Attestation (PDA) protocol
// ---------------------------------------------------------------------------

export {
  verifyPDA,
  recomputePdaHex,
  computePdaComponentHashes,
  verifyCandidateReveal,
  computeCandidateCommitLeaf,
  computeCandidateMetadataHash,
  pdaMerkleRoot,
  pdaVerifyInclusionProof,
  pdaGenerateInclusionProof,
  canonicalizePythonJSON,
  parsePythonJSON,
  asPythonFloat,
  isPyFloatNumber,
  pdaSha256,
  pdaHmacSha256,
  pdaComponentHash,
  pdaTimingSafeEqual,
  pdaU32BE,
  parseDigestHex,
  digestHex,
  PDA_DIGEST_LEN,
  PDA_SCHEMA_VERSION_V1,
  PDA_DOMAIN_SEPARATOR,
  PDA_DOMAIN_TARGET_SPEC,
  PDA_DOMAIN_PIPELINE_MANIFEST,
  PDA_DOMAIN_BIOSECURITY_POLICY,
  PDA_DOMAIN_TIER_DIST,
  PDA_DOMAIN_CANDIDATE_COMMIT,
  PDA_DOMAIN_TEE_ATTESTATION,
  PDA_DOMAIN_MERKLE_INTERNAL,
  PDA_SIMULATOR_MEASUREMENT_HEX,
  PDA_SIMULATOR_SIGNING_KEY_HEX,
  PDA_TEE_TYPES,
  type TeeType,
  type PyFloatNumber,
  type PyJsonValue,
  type PdaJsonPrimitive,
  type PdaJsonValue,
  type PocketCoordinate,
  type TargetSpec,
  type ModelPin,
  type PipelineManifest,
  type BiosecurityPolicy,
  type TierDistribution,
  type TEEAttestation,
  type MerklePathEntry,
  type MerkleProof,
  type CandidateCommitment,
  type PDAOutput,
  type PDAVerificationReport,
  type VerifyPDAOptions,
  type CandidateRevealInput,
} from './pda/index.js';
