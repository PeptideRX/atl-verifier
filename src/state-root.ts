/**
 * State root verifier. Section 6.5:
 *
 *     state_root_0 = SHA256(thesis_id || "genesis")
 *     state_root_t = SHA256(
 *         thesis_id ||
 *         state_root_{t-1} ||
 *         event_type ||
 *         canonical_event_payload ||
 *         artifact_hashes
 *     )
 *
 * Every thesis must replay to the same final state root for any verifier.
 * Divergence signals implementation error or tampering.
 */

import { canonicalizeJSON, type JsonValue } from './canonical-json.js';
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  sha256Bytes,
  timingSafeEqualHex,
} from './hash.js';

export interface AtlEvent {
  /** Thesis identifier. Must equal the replay target. */
  thesis_id: string;
  /** Event type, e.g. THESIS_COMMITTED. */
  event_type: string;
  /** Canonical event payload. Any JSON value. */
  payload: JsonValue;
  /**
   * List of artifact hashes (hex strings). The verifier concatenates them
   * in order; an empty array is valid.
   */
  artifact_hashes?: readonly string[];
}

export interface StateRootOptions {
  /**
   * Genesis suffix. Defaults to "genesis" per Section 6.5. Exposed for
   * interop with pre-protocol test fixtures.
   */
  genesisSuffix?: string;
}

/**
 * Compute the final state root for an ordered sequence of events against a
 * given thesis_id. Returns the 64-char lowercase hex digest.
 */
export async function computeStateRoot(
  thesisId: string,
  events: readonly AtlEvent[],
  options: StateRootOptions = {},
): Promise<string> {
  const genesis = options.genesisSuffix ?? 'genesis';
  let root = await sha256Bytes(concatBytes(thesisId, genesis));
  for (const ev of events) {
    if (ev.thesis_id !== thesisId) {
      throw new Error(
        `computeStateRoot: event thesis_id "${ev.thesis_id}" does not match root thesis_id "${thesisId}"`,
      );
    }
    const artifactConcat = concatArtifactHashes(ev.artifact_hashes ?? []);
    const input = concatBytes(
      ev.thesis_id,
      root,
      ev.event_type,
      canonicalizeJSON(ev.payload),
      artifactConcat,
    );
    root = await sha256Bytes(input);
  }
  return bytesToHex(root);
}

/**
 * Verify that the supplied ordered event log replays to the expected final
 * state root for the given thesis_id. Returns true iff the computed root
 * matches.
 *
 * The thesisId is inferred from the first event unless all events share a
 * thesis_id and the caller did not explicitly provide one in the options.
 */
export async function verifyStateRoot(
  events: readonly AtlEvent[],
  expectedRoot: string,
  options: StateRootOptions & { thesisId?: string } = {},
): Promise<boolean> {
  const expected = normalizeHex(expectedRoot);
  if (expected.length !== 64) return false;
  const thesisId = options.thesisId ?? events[0]?.thesis_id;
  if (!thesisId) return false;
  let computed: string;
  try {
    computed = await computeStateRoot(thesisId, events, options);
  } catch {
    return false;
  }
  return timingSafeEqualHex(computed, expected);
}

function concatArtifactHashes(hashes: readonly string[]): Uint8Array {
  if (hashes.length === 0) return new Uint8Array(0);
  const parts = hashes.map((h) => hexToBytes(normalizeHex(h)));
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

function normalizeHex(s: string): string {
  const stripped = s.startsWith('0x') || s.startsWith('0X') ? s.slice(2) : s;
  return stripped.toLowerCase();
}
