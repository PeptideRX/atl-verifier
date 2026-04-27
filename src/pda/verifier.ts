/**
 * PDA verifier: reproduce the 32-byte Peptide Design Attestation from a
 * PDAOutput JSON blob and confirm it matches the published `pda_hex`.
 *
 * This file is the TypeScript equivalent of
 * `src/peptide_design/pda/verifier.py::PDAVerifier.verify` and
 * `crates/pda/src/verifier.rs::PdaVerifier::verify`. It is a pure-TS
 * port: no native deps, WebCrypto only, byte-identical to both
 * reference implementations on Vectors A, B, and C.
 *
 * Scope: research use only, nonclinical.
 */

import { bytesToHex, hexToBytes } from '../hash.js';
import {
  canonicalizePythonJSON,
  type JsonValue,
  type PyFloatNumber,
} from './canonical-json.js';
import {
  PDA_DIGEST_LEN,
  PDA_DOMAIN_BIOSECURITY_POLICY,
  PDA_DOMAIN_PIPELINE_MANIFEST,
  PDA_DOMAIN_SEPARATOR,
  PDA_DOMAIN_TARGET_SPEC,
  PDA_DOMAIN_TEE_ATTESTATION,
  PDA_DOMAIN_TIER_DIST,
  PDA_SCHEMA_VERSION_V1,
  PDA_SIMULATOR_MEASUREMENT_HEX,
  PDA_SIMULATOR_SIGNING_KEY_HEX,
} from './constants.js';
import {
  digestHex,
  parseDigestHex,
  pdaComponentHash,
  pdaHmacSha256,
  pdaSha256,
  pdaTimingSafeEqual,
  pdaU32BE,
} from './hashing.js';
import type {
  BiosecurityPolicy,
  PDAOutput,
  PDAVerificationReport,
  PipelineManifest,
  TargetSpec,
  TEEAttestation,
  TierDistribution,
  VerifyPDAOptions,
} from './types.js';

const NONCLINICAL_SCOPE = 'research use only, nonclinical, no human-use claim';

/**
 * Verify a PDAOutput end-to-end.
 *
 * Recomputes every component hash, folds the final PDA, and checks the
 * TEE attestation signature against the public measurement. Returns a
 * structured report whether verification passes or fails; callers
 * treat `passed === false` as a rejection with the reasons attached.
 *
 * @param output - the published PDAOutput blob.
 * @param options - verifier posture + nonce registry.
 */
export async function verifyPDA(
  output: PDAOutput,
  options: VerifyPDAOptions = {},
): Promise<PDAVerificationReport> {
  const reasons: string[] = [];
  const verified: Record<string, boolean> = {};

  // --- shape checks on the PDAOutput itself ---
  const pdaBytes = parseDigestHex(output.pda_hex ?? '');
  if (!pdaBytes) {
    reasons.push('pda_hex_malformed');
    return report(false, reasons, verified);
  }
  const commitRootBytes = parseDigestHex(output.candidate_commit_root_hex ?? '');
  if (!commitRootBytes) {
    reasons.push('candidate_commit_root_malformed');
  }
  const schemaVersion = options.schemaVersion ?? PDA_SCHEMA_VERSION_V1;
  if (output.schema_version !== schemaVersion) {
    reasons.push('schema_version_mismatch');
  }
  // Target-spec scope invariant per Section 11 of the PDA spec: a PDA
  // whose target_spec carries a scope other than the pinned V1 string
  // MUST be refused.
  if (output.target_spec?.scope !== NONCLINICAL_SCOPE) {
    reasons.push('target_spec_scope_mismatch');
  }

  const tee = output.tee_attestation;
  if (!tee) {
    reasons.push('tee_attestation_missing');
    return report(false, reasons, verified);
  }

  // --- TEE type gate ---
  const acceptSimulator = options.acceptSimulator ?? true;
  if (tee.tee_type === 'simulator' && !acceptSimulator) {
    reasons.push('simulator_refused');
    verified['tee_type_accepted'] = false;
  } else {
    verified['tee_type_accepted'] = true;
  }

  // --- measurement check ---
  const attMeasurement = parseDigestHex(tee.measurement_hex ?? '');
  if (!attMeasurement) {
    reasons.push('tee_measurement_malformed_hex');
  }
  const expectedMeasurementHex =
    options.expectedMeasurementHex ?? PDA_SIMULATOR_MEASUREMENT_HEX;
  const expectedMeasurement = parseDigestHex(expectedMeasurementHex);
  if (!expectedMeasurement) {
    reasons.push('expected_measurement_malformed');
    return report(false, reasons, verified);
  }
  if (!attMeasurement || !pdaTimingSafeEqual(attMeasurement, expectedMeasurement)) {
    reasons.push('tee_measurement_mismatch');
    verified['tee_measurement_matches'] = false;
  } else {
    verified['tee_measurement_matches'] = true;
  }

  // Registry check.
  const registry = options.publicMeasurementRegistry;
  if (registry && Object.prototype.hasOwnProperty.call(registry, tee.tee_type)) {
    const registered = parseDigestHex(registry[tee.tee_type] ?? '');
    if (!registered || !pdaTimingSafeEqual(registered, expectedMeasurement)) {
      reasons.push('public_measurement_not_in_registry');
      verified['public_measurement_registered'] = false;
    } else {
      verified['public_measurement_registered'] = true;
    }
  } else {
    verified['public_measurement_registered'] = true;
  }

  // --- nonce replay ---
  const nonceBytes = parseDigestHex(tee.nonce_hex ?? '');
  if (!nonceBytes) {
    reasons.push('tee_nonce_malformed_hex');
  }
  const seenNonces = new Set<string>(
    (options.seenNoncesHex ?? []).map((s) => s.toLowerCase()),
  );
  if (nonceBytes && seenNonces.has((tee.nonce_hex ?? '').toLowerCase())) {
    reasons.push('tee_nonce_replayed');
    verified['tee_nonce_fresh'] = false;
  } else {
    verified['tee_nonce_fresh'] = true;
  }

  // --- recompute component hashes ---
  const targetSpecHash = await hashTargetSpec(output.target_spec);
  const pipelineManifestHash = await hashPipelineManifest(output.pipeline_manifest);
  const biosecurityPolicyHash = await hashBiosecurityPolicy(output.biosecurity_policy);
  const tierDistributionHash = await hashTierDistribution(output.tier_distribution);
  const teeAttestationHash = await hashTEEAttestation(tee);
  verified['target_spec_hash'] = true;
  verified['pipeline_manifest_hash'] = true;
  verified['biosecurity_policy_hash'] = true;
  verified['tier_distribution_hash'] = true;
  verified['tee_attestation_hash'] = true;

  // --- TEE signature check ---
  const transcript = commitRootBytes
    ? buildTeeTranscript({
        schemaVersion,
        targetSpecHash,
        pipelineManifestHash,
        biosecurityPolicyHash,
        candidateCommitRoot: commitRootBytes,
        tierDistributionHash,
      })
    : null;

  let sigOk = false;
  if (transcript && nonceBytes) {
    const transcriptWithNonce = new Uint8Array(transcript.length + nonceBytes.length);
    transcriptWithNonce.set(transcript, 0);
    transcriptWithNonce.set(nonceBytes, transcript.length);
    const claimedSig = hexToBytesSafe(tee.signature_hex);
    if (!claimedSig) {
      reasons.push('tee_signature_malformed_hex');
    } else {
      sigOk = await verifyTeeSignature({
        teeType: tee.tee_type,
        transcript: transcriptWithNonce,
        signature: claimedSig,
      });
    }
  }
  verified['tee_signature_valid'] = sigOk;
  if (!sigOk) {
    reasons.push('tee_signature_invalid');
  }

  // --- recompute PDA ---
  let recomputed: Uint8Array | null = null;
  if (commitRootBytes && expectedMeasurement) {
    recomputed = await buildPdaBytes({
      schemaVersion,
      targetSpecHash,
      pipelineManifestHash,
      biosecurityPolicyHash,
      candidateCommitRoot: commitRootBytes,
      tierDistributionHash,
      teeMeasurement: expectedMeasurement,
      teeAttestationHash,
    });
  }
  const pdaMatches = recomputed !== null && pdaTimingSafeEqual(recomputed, pdaBytes);
  verified['pda_matches'] = pdaMatches;
  if (!pdaMatches) {
    reasons.push('pda_mismatch');
  }

  const passed =
    reasons.length === 0 &&
    verified['pda_matches'] === true &&
    verified['tee_signature_valid'] === true &&
    verified['tee_measurement_matches'] === true &&
    verified['tee_type_accepted'] === true &&
    verified['tee_nonce_fresh'] === true &&
    verified['public_measurement_registered'] === true;
  return report(passed, reasons, verified);
}

// ---------------------------------------------------------------------------
// Component hashes
// ---------------------------------------------------------------------------

async function hashTargetSpec(ts: TargetSpec): Promise<Uint8Array> {
  const payload: JsonValue = {
    target_pdb_hash: ts.target_pdb_hash,
    pocket_coordinates: ts.pocket_coordinates.map((c) => ({
      x_nm: c.x_nm,
      y_nm: c.y_nm,
      z_nm: c.z_nm,
    })),
    length_min: ts.length_min,
    length_max: ts.length_max,
    modifications_whitelist: [...ts.modifications_whitelist],
    scope: ts.scope,
  };
  const canonical = canonicalizePythonJSON(payload);
  return pdaComponentHash(PDA_DOMAIN_TARGET_SPEC, encodeUtf8(canonical));
}

async function hashPipelineManifest(pm: PipelineManifest): Promise<Uint8Array> {
  const payload: JsonValue = {
    backbone_model: { ...pm.backbone_model },
    sequence_model: { ...pm.sequence_model },
    structure_model: { ...pm.structure_model },
    sequence_filter: { ...pm.sequence_filter },
  };
  const canonical = canonicalizePythonJSON(payload);
  return pdaComponentHash(PDA_DOMAIN_PIPELINE_MANIFEST, encodeUtf8(canonical));
}

async function hashBiosecurityPolicy(bp: BiosecurityPolicy): Promise<Uint8Array> {
  const payload: JsonValue = {
    pathogen_db_version: bp.pathogen_db_version,
    pathogen_db_hash: bp.pathogen_db_hash,
    toxin_db_version: bp.toxin_db_version,
    toxin_db_hash: bp.toxin_db_hash,
    t_pathogen: bp.t_pathogen,
    t_toxin: bp.t_toxin,
    t_motif: bp.t_motif,
    blacklist_motif_patterns: [...bp.blacklist_motif_patterns],
  };
  const canonical = canonicalizePythonJSON(payload);
  return pdaComponentHash(PDA_DOMAIN_BIOSECURITY_POLICY, encodeUtf8(canonical));
}

async function hashTierDistribution(td: TierDistribution): Promise<Uint8Array> {
  const payload: JsonValue = {
    green_count: td.green_count,
    amber_count: td.amber_count,
    red_count: td.red_count,
    black_count: td.black_count,
    total_count: td.total_count,
  };
  const canonical = canonicalizePythonJSON(payload);
  return pdaComponentHash(PDA_DOMAIN_TIER_DIST, encodeUtf8(canonical));
}

async function hashTEEAttestation(tee: TEEAttestation): Promise<Uint8Array> {
  const payload: JsonValue = {
    tee_type: tee.tee_type,
    measurement_hex: tee.measurement_hex,
    signature_hex: tee.signature_hex,
    nonce_hex: tee.nonce_hex,
  };
  const canonical = canonicalizePythonJSON(payload);
  return pdaComponentHash(PDA_DOMAIN_TEE_ATTESTATION, encodeUtf8(canonical));
}

// ---------------------------------------------------------------------------
// Transcript + PDA fold
// ---------------------------------------------------------------------------

interface TranscriptInputs {
  schemaVersion: number;
  targetSpecHash: Uint8Array;
  pipelineManifestHash: Uint8Array;
  biosecurityPolicyHash: Uint8Array;
  candidateCommitRoot: Uint8Array;
  tierDistributionHash: Uint8Array;
}

function buildTeeTranscript(inputs: TranscriptInputs): Uint8Array {
  const parts: Uint8Array[] = [
    encodeUtf8(PDA_DOMAIN_TEE_ATTESTATION),
    pdaU32BE(inputs.schemaVersion),
    inputs.targetSpecHash,
    inputs.pipelineManifestHash,
    inputs.biosecurityPolicyHash,
    inputs.candidateCommitRoot,
    inputs.tierDistributionHash,
  ];
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

interface PdaFoldInputs extends TranscriptInputs {
  teeMeasurement: Uint8Array;
  teeAttestationHash: Uint8Array;
}

async function buildPdaBytes(inputs: PdaFoldInputs): Promise<Uint8Array> {
  for (const [name, blob] of [
    ['target_spec_hash', inputs.targetSpecHash],
    ['pipeline_manifest_hash', inputs.pipelineManifestHash],
    ['biosecurity_policy_hash', inputs.biosecurityPolicyHash],
    ['candidate_commit_root', inputs.candidateCommitRoot],
    ['tier_distribution_hash', inputs.tierDistributionHash],
    ['tee_measurement', inputs.teeMeasurement],
    ['tee_attestation_hash', inputs.teeAttestationHash],
  ] as const) {
    if (!(blob instanceof Uint8Array) || blob.length !== PDA_DIGEST_LEN) {
      throw new Error(`buildPdaBytes: ${name} must be ${PDA_DIGEST_LEN} bytes`);
    }
  }
  return pdaSha256(
    PDA_DOMAIN_SEPARATOR,
    pdaU32BE(inputs.schemaVersion),
    inputs.targetSpecHash,
    inputs.pipelineManifestHash,
    inputs.biosecurityPolicyHash,
    inputs.candidateCommitRoot,
    inputs.tierDistributionHash,
    inputs.teeMeasurement,
    inputs.teeAttestationHash,
  );
}

// ---------------------------------------------------------------------------
// TEE signature verification
// ---------------------------------------------------------------------------

interface VerifyTeeSignatureInput {
  teeType: string;
  transcript: Uint8Array;
  signature: Uint8Array;
}

async function verifyTeeSignature(input: VerifyTeeSignatureInput): Promise<boolean> {
  if (input.teeType === 'simulator') {
    const key = hexToBytes(PDA_SIMULATOR_SIGNING_KEY_HEX);
    const expected = await pdaHmacSha256(key, input.transcript);
    if (input.signature.length !== expected.length) return false;
    return pdaTimingSafeEqual(input.signature, expected);
  }
  // V1 only ships the simulator. Real TEE backends must subclass the
  // Python TEEAttester and register a verifier here; until then,
  // refuse non-simulator attestations outright.
  return false;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexToBytesSafe(hex: string): Uint8Array | null {
  if (typeof hex !== 'string' || hex.length % 2 !== 0) return null;
  if (!/^[0-9a-f]*$/.test(hex)) return null;
  try {
    return hexToBytes(hex);
  } catch {
    return null;
  }
}

function encodeUtf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function report(
  passed: boolean,
  reasons: string[],
  verified: Record<string, boolean>,
): PDAVerificationReport {
  return {
    passed,
    blocked_reasons: [...reasons],
    verified_fields: { ...verified },
  };
}

// ---------------------------------------------------------------------------
// Exposed helpers for tests + the CLI
// ---------------------------------------------------------------------------

/**
 * Compute the component hash of each top-level PDA input. Used by the
 * cross-language parity script to verify that the TypeScript layer
 * lands on exactly the same seven component digests as the Python and
 * Rust references.
 */
export async function computePdaComponentHashes(output: PDAOutput): Promise<{
  target_spec_hash_hex: string;
  pipeline_manifest_hash_hex: string;
  biosecurity_policy_hash_hex: string;
  tier_distribution_hash_hex: string;
  tee_attestation_hash_hex: string;
}> {
  const targetSpecHash = await hashTargetSpec(output.target_spec);
  const pipelineManifestHash = await hashPipelineManifest(output.pipeline_manifest);
  const biosecurityPolicyHash = await hashBiosecurityPolicy(output.biosecurity_policy);
  const tierDistributionHash = await hashTierDistribution(output.tier_distribution);
  const teeAttestationHash = await hashTEEAttestation(output.tee_attestation);
  return {
    target_spec_hash_hex: digestHex(targetSpecHash),
    pipeline_manifest_hash_hex: digestHex(pipelineManifestHash),
    biosecurity_policy_hash_hex: digestHex(biosecurityPolicyHash),
    tier_distribution_hash_hex: digestHex(tierDistributionHash),
    tee_attestation_hash_hex: digestHex(teeAttestationHash),
  };
}

/**
 * Re-derive the 32-byte PDA from a PDAOutput, ignoring the published
 * `pda_hex`. Useful for callers that want to display or log the
 * recomputed value alongside the claimed one.
 */
export async function recomputePdaHex(
  output: PDAOutput,
  options: { schemaVersion?: number; expectedMeasurementHex?: string } = {},
): Promise<string> {
  const schemaVersion = options.schemaVersion ?? PDA_SCHEMA_VERSION_V1;
  const commitRoot = parseDigestHex(output.candidate_commit_root_hex);
  if (!commitRoot) {
    throw new Error('recomputePdaHex: candidate_commit_root_hex malformed');
  }
  const measurementHex =
    options.expectedMeasurementHex ?? output.tee_attestation.measurement_hex;
  const measurement = parseDigestHex(measurementHex);
  if (!measurement) {
    throw new Error('recomputePdaHex: TEE measurement malformed');
  }
  const targetSpecHash = await hashTargetSpec(output.target_spec);
  const pipelineManifestHash = await hashPipelineManifest(output.pipeline_manifest);
  const biosecurityPolicyHash = await hashBiosecurityPolicy(output.biosecurity_policy);
  const tierDistributionHash = await hashTierDistribution(output.tier_distribution);
  const teeAttestationHash = await hashTEEAttestation(output.tee_attestation);
  const pda = await buildPdaBytes({
    schemaVersion,
    targetSpecHash,
    pipelineManifestHash,
    biosecurityPolicyHash,
    candidateCommitRoot: commitRoot,
    tierDistributionHash,
    teeMeasurement: measurement,
    teeAttestationHash,
  });
  return bytesToHex(pda);
}

// Re-export the internal types so downstream tests/scripts can
// instantiate them without reaching into the internals.
export type { JsonValue, PyFloatNumber } from './canonical-json.js';
