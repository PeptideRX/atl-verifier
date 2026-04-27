/**
 * TypeScript types mirroring the pydantic v2 schemas in
 * `src/peptide_design/pda/schemas.py`.
 *
 * Each shape corresponds byte-for-byte to the Python reference model_dump
 * output. The canonicalizer in `canonical-json.ts` consumes these
 * directly and emits the Python dialect of canonical JSON that feeds
 * the domain-separated SHA-256 component hashes.
 *
 * Scope: research use only, nonclinical.
 */

import type { TeeType } from './constants.js';

/**
 * Fixed-precision (x, y, z) in integer nanometers.
 */
export interface PocketCoordinate {
  /** X coordinate in integer nanometers. */
  x_nm: number;
  /** Y coordinate in integer nanometers. */
  y_nm: number;
  /** Z coordinate in integer nanometers. */
  z_nm: number;
}

/**
 * Locked target definition for a Phase 4 design run.
 *
 * `target_pdb_hash` binds the exact structural state of the target used
 * during design. `pocket_coordinates` pins the pocket (or the set of
 * interface residues) the designer was instructed to engage. The length
 * range and modification whitelist pin the modality envelope.
 */
export interface TargetSpec {
  /** Lowercase 64-char hex SHA-256 of the PDB bytes. */
  target_pdb_hash: string;
  /** Ordered list of pocket centroid or interface residue coordinates. */
  pocket_coordinates: PocketCoordinate[];
  /** Inclusive lower bound on candidate length (residues). */
  length_min: number;
  /** Inclusive upper bound on candidate length (residues). */
  length_max: number;
  /** Allowed chemical modification identifiers. */
  modifications_whitelist: string[];
  /**
   * Pinned nonclinical scope string. Must equal the V1 constant
   * `"research use only, nonclinical, no human-use claim"`; the
   * verifier rejects anything else.
   */
  scope: string;
}

/**
 * One pinned model reference.
 */
export interface ModelPin {
  /** Canonical model name, lowercase snake_case. */
  name: string;
  /** Version string (semver or git SHA prefix). */
  version: string;
  /** Lowercase 64-char hex SHA-256 of the loaded weights blob. */
  weights_sha256: string;
}

/**
 * Locked manifest of every model and weights pinned for a design run.
 * Four named slots match the Phase 4 stack: backbone design, sequence
 * design, structure prediction, and a post-design sequence filter.
 */
export interface PipelineManifest {
  /** Backbone scaffold generator (e.g. RFdiffusion). */
  backbone_model: ModelPin;
  /** Sequence designer (e.g. ProteinMPNN). */
  sequence_model: ModelPin;
  /** Structure and affinity predictor (e.g. Boltz-2). */
  structure_model: ModelPin;
  /** Post-design sequence filter. Sentinel pin allowed. */
  sequence_filter: ModelPin;
}

/**
 * Locked biosecurity-screening policy for a design run.
 */
export interface BiosecurityPolicy {
  /** Version token for the pathogen similarity database. */
  pathogen_db_version: string;
  /** Lowercase 64-char hex SHA-256 of the pathogen database blob. */
  pathogen_db_hash: string;
  /** Version token for the toxin similarity database. */
  toxin_db_version: string;
  /** Lowercase 64-char hex SHA-256 of the toxin database blob. */
  toxin_db_hash: string;
  /** Pathogen similarity threshold (integer percent 0..=100). */
  t_pathogen: number;
  /** Toxin similarity threshold (integer percent 0..=100). */
  t_toxin: number;
  /** Blacklist-motif similarity threshold (integer percent 0..=100). */
  t_motif: number;
  /** Regex patterns for blacklisted motifs. */
  blacklist_motif_patterns: string[];
}

/**
 * Histogram of PoP-Shield tier assignments for one design run.
 */
export interface TierDistribution {
  /** Number of candidates assigned PoP-Shield tier green. */
  green_count: number;
  /** Number of candidates assigned PoP-Shield tier amber. */
  amber_count: number;
  /** Number of candidates assigned PoP-Shield tier red. */
  red_count: number;
  /** Number of candidates assigned PoP-Shield tier black. */
  black_count: number;
  /** Total. Must equal green + amber + red + black. */
  total_count: number;
}

/**
 * Signed attestation from a TEE (or the V1 simulator).
 */
export interface TEEAttestation {
  /** Vendor or trust-type identifier. */
  tee_type: TeeType;
  /** Lowercase 64-char hex 32-byte public measurement. */
  measurement_hex: string;
  /** Lowercase hex signature over the transcript bytes. */
  signature_hex: string;
  /** Lowercase 64-char hex 256-bit nonce. */
  nonce_hex: string;
}

/**
 * One (hex-encoded sibling, side) pair on a Merkle inclusion path.
 *
 * The Python and Rust references emit this as a two-element tuple:
 * `["ab12...", "left"]`. In TypeScript we expose the more idiomatic
 * named form; the reveal helper also accepts the tuple form for wire
 * compatibility with JSON produced by the Python/Rust references.
 */
export interface MerklePathEntry {
  /** Sibling node digest at this level (lowercase 64-char hex). */
  sibling_hex: string;
  /**
   * Side of the sibling at this level: `"left"` if the sibling is the
   * LEFT child (and the candidate is the RIGHT), `"right"` otherwise.
   */
  side: 'left' | 'right';
}

/**
 * Inclusion proof for one leaf in the candidate-commit Merkle tree.
 */
export interface MerkleProof {
  /** Zero-based index of the leaf in the producer's input order. */
  leaf_index: number;
  /** Lowercase 64-char hex of the leaf commitment. */
  leaf_hash_hex: string;
  /** Ordered list of sibling entries from leaf to root (exclusive). */
  path: MerklePathEntry[];
}

/**
 * Commit-phase handle for a single candidate.
 *
 * The actual 32-byte leaf commitment is
 * `SHA256(DOMAIN_CANDIDATE_COMMIT || salt || sequence_bytes || metadata_bytes)`.
 * This struct carries the inputs a reveal-path verifier needs to
 * reconstruct that leaf.
 */
export interface CandidateCommitment {
  /** UUID v4 candidate identifier. */
  candidate_id: string;
  /** Lowercase 64-char hex 256-bit salt. */
  salt_hex: string;
  /** Lowercase 64-char hex SHA-256 of the uppercase IUPAC-20 sequence bytes. */
  canonical_sequence_hash: string;
  /**
   * Lowercase 64-char hex SHA-256 of the canonical-JSON-encoded metadata
   * (everything on the PeptideCandidate record except `sequence`).
   */
  metadata_hash: string;
}

/**
 * Full producer output for one design run.
 *
 * Published by the Phase 4 producer; consumed unchanged by
 * {@link PDAVerifier}. Sequences are NOT included; only the Merkle leaf
 * digests are stored, so a PDAOutput can be published alongside a
 * sequence-free public report without breaking the binding.
 */
export interface PDAOutput {
  /** Lowercase 64-char hex of the 32-byte PDA. */
  pda_hex: string;
  /** Protocol schema version. V1 = 1. */
  schema_version: number;
  /** TEE attestation bundled with the PDA. */
  tee_attestation: TEEAttestation;
  /** Pinned pipeline manifest used during the run. */
  pipeline_manifest: PipelineManifest;
  /** Pinned PoP-Shield policy used during the run. */
  biosecurity_policy: BiosecurityPolicy;
  /** Pinned target spec used during the run. */
  target_spec: TargetSpec;
  /** PoP-Shield tier histogram. */
  tier_distribution: TierDistribution;
  /** Lowercase 64-char hex Merkle root over the per-candidate commit leaves. */
  candidate_commit_root_hex: string;
  /** Ordered list of per-candidate commit leaf hashes (hex). */
  merkle_leaves_hex: string[];
}

/**
 * Structured verdict emitted by {@link verifyPDA}.
 */
export interface PDAVerificationReport {
  /**
   * `true` iff every recomputed component hash and the final PDA match
   * the claim AND the TEE attestation signature is valid against the
   * public measurement.
   */
  passed: boolean;
  /**
   * Machine-readable reason codes for any failure. Empty when
   * `passed === true`. Codes mirror the Python reference's
   * `PDAVerifyResult.blocked_reasons`.
   */
  blocked_reasons: string[];
  /**
   * Map of component name to per-field verification flag. Populated
   * even on partial success for audit trails.
   */
  verified_fields: Record<string, boolean>;
}

/**
 * Options for {@link verifyPDA}. Defaults mirror the Python reference's
 * `PDAVerifier(accept_simulator=True)` posture: research audiences
 * accept the simulator, buyer/regulatory audiences override.
 */
export interface VerifyPDAOptions {
  /**
   * When false, any attestation tagged `tee_type === "simulator"` is
   * rejected outright with `blocked_reasons` including
   * `"simulator_refused"`. Default `true`.
   */
  acceptSimulator?: boolean;
  /**
   * Expected public TEE measurement (64-char lowercase hex). Defaults
   * to the documented simulator constant. Buyer / regulatory callers
   * should pass a hardware measurement here.
   */
  expectedMeasurementHex?: string;
  /**
   * Optional registry mapping tee_type to expected measurement hex.
   * When present, the verifier additionally rejects an attestation
   * whose measurement does not match the registry entry for its type.
   */
  publicMeasurementRegistry?: Readonly<Record<string, string>>;
  /**
   * Set of previously-seen nonces (lowercase hex). An attestation whose
   * nonce appears in this set is flagged `tee_nonce_replayed`. Default
   * empty.
   */
  seenNoncesHex?: readonly string[];
  /**
   * Schema version expected by this verifier. Defaults to 1. A PDA
   * whose `schema_version` does not match is rejected.
   */
  schemaVersion?: number;
}

/**
 * Input to {@link verifyCandidateReveal}. Mirrors the Python helper's
 * kwargs.
 */
export interface CandidateRevealInput {
  /** The published PDAOutput the reveal is grounded against. */
  pdaOutput: PDAOutput;
  /** The per-candidate commit handle from the producer. */
  commitment: CandidateCommitment;
  /** The revealed peptide sequence (uppercase IUPAC-20). */
  revealedSequence: string;
  /**
   * The revealed candidate metadata JSON string, as emitted by the
   * producer's `candidate.model_dump(mode="json")` with the `sequence`
   * field removed. MUST be a raw JSON string so the Python float
   * dialect can be preserved through {@link parsePythonJSON}.
   */
  revealedMetadataJSON: string;
  /** The Merkle inclusion proof for the revealed candidate's leaf. */
  inclusionProof: MerkleProof;
}
