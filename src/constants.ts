/**
 * ATL protocol constants. See Chapter 6 of the ATL dissertation.
 */

/**
 * Domain separator for ATL prediction commitments.
 * Fixed string per Section 6.1.
 */
export const DOMAIN_SEPARATOR = 'PEPTIDE_RX_ATL_PREDICTION_V1';

/**
 * Default schema version identifier used when a commitment does not carry one
 * explicitly. Callers should always prefer the version stored in the
 * commitment payload.
 */
export const DEFAULT_SCHEMA_VERSION = 'peptide_rx_prediction_v1';

/**
 * Minimum salt entropy (bits) per Property 2 · Commitment hiding.
 * Peptide Rx generates 256-bit salts in practice; 128 is the minimum
 * acceptable by the protocol.
 */
export const MIN_SALT_BITS = 128;

/**
 * Evidence grade alphabet used by the Peptide Rx pipeline.
 * X denotes excluded or rejected evidence.
 */
export const EVIDENCE_GRADES = ['A', 'B', 'C', 'D', 'X'] as const;
export type EvidenceGrade = (typeof EVIDENCE_GRADES)[number];

/**
 * ATL state machine states. See Chapter 6.4.
 */
export const ATL_STATES = [
  'DRAFTED',
  'THESIS_COMMITTED',
  'PREDICTIONS_LOCKED',
  'INTENT_PUBLISHED',
  'FUNDED',
  'SYNTHESIS_ORDERED',
  'SYNTHESIS_ATTESTED',
  'SAMPLE_RECEIVED',
  'EXPERIMENT_REGISTERED',
  'EXPERIMENT_STARTED',
  'OUTCOME_COMMITTED',
  'PREDICTIONS_REVEALED',
  'SCORED',
  'POSTERIOR_UPDATED',
  'CLOSED',
  'DISPUTED',
  'VOIDED',
] as const;
export type AtlState = (typeof ATL_STATES)[number];
