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
export {};
