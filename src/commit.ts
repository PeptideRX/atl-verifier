/**
 * Commit-reveal verifier. Implements Section 6.1 and 6.3 of the ATL
 * dissertation.
 *
 * Single-endpoint commitment:
 *     C = SHA256(D || V || S || JCS(P))
 *
 * Where:
 *   D = domain separator "PEPTIDE_RX_ATL_PREDICTION_V1"
 *   V = schema version identifier
 *   S = 256-bit salt (hex-encoded)
 *   P = structured prediction payload
 *   JCS(P) = canonical JSON per RFC 8785
 *
 * VerifyCommit succeeds iff the recomputed hash equals the claimed
 * commitment.
 */

import { canonicalizeJSON, type JsonValue } from './canonical-json.js';
import {
  DEFAULT_SCHEMA_VERSION,
  DOMAIN_SEPARATOR,
  MIN_SALT_BITS,
} from './constants.js';
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  sha256Bytes,
  timingSafeEqualHex,
} from './hash.js';

/**
 * Options for ComputeCommit / VerifyCommit.
 */
export interface CommitOptions {
  /** Schema version V. Defaults to DEFAULT_SCHEMA_VERSION. */
  schemaVersion?: string;
  /** Domain separator D. Defaults to DOMAIN_SEPARATOR. */
  domainSeparator?: string;
}

/**
 * Compute the canonical commitment bytes for a single-endpoint prediction.
 * Returns the 32-byte SHA-256 digest.
 *
 * Enforces a minimum salt length of MIN_SALT_BITS / 4 hex chars (default
 * 32 hex chars = 128 bits). Standard ATL deployments use a 256-bit salt
 * (64 hex chars). Anything shorter is rejected up front so a downstream
 * caller cannot accidentally make commitments under-saturated.
 */
export async function computeCommitBytes(
  payload: JsonValue,
  saltHex: string,
  options: CommitOptions = {},
): Promise<Uint8Array> {
  const domain = options.domainSeparator ?? DOMAIN_SEPARATOR;
  const version = options.schemaVersion ?? DEFAULT_SCHEMA_VERSION;
  const normalized = normalizeHex(saltHex);
  if (normalized.length * 4 < MIN_SALT_BITS) {
    throw new Error(
      `computeCommitBytes: salt is only ${normalized.length * 4} bits ` +
      `(min ${MIN_SALT_BITS}); standard ATL salt is 256 bits / 64 hex chars`,
    );
  }
  // hexToBytes (now strict) rejects any non-hex characters.
  const saltBytes = hexToBytes(normalized);
  const jcs = canonicalizeJSON(payload);
  const input = concatBytes(domain, version, saltBytes, jcs);
  return sha256Bytes(input);
}

/**
 * Compute the canonical commitment for a single-endpoint prediction.
 * Returns a lowercase hex string (64 chars).
 */
export async function computeCommitHex(
  payload: JsonValue,
  saltHex: string,
  options: CommitOptions = {},
): Promise<string> {
  return bytesToHex(await computeCommitBytes(payload, saltHex, options));
}

/**
 * VerifyCommit(payload, salt, commitment) per Section 6.3.
 *
 * Returns true iff SHA256(D || V || S || JCS(P)) equals the claimed
 * commitment. Uses constant-time comparison on hex-normalized inputs.
 *
 * @param payload - the prediction object P
 * @param saltHex - 256-bit salt as hex string (with or without 0x prefix)
 * @param claimedCommitment - the commitment hex string (with or without 0x prefix)
 * @param options - schema version and domain separator overrides
 */
export async function VerifyCommit(
  payload: JsonValue,
  saltHex: string,
  claimedCommitment: string,
  options: CommitOptions = {},
): Promise<boolean> {
  let computed: string;
  try {
    computed = await computeCommitHex(payload, saltHex, options);
  } catch {
    return false;
  }
  const claim = normalizeHex(claimedCommitment);
  if (claim.length !== 64) return false;
  return timingSafeEqualHex(computed, claim);
}

function normalizeHex(s: string): string {
  const stripped = s.startsWith('0x') || s.startsWith('0X') ? s.slice(2) : s;
  return stripped.toLowerCase();
}
