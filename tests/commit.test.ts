import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { VerifyCommit, computeCommitHex } from '../src/commit.js';
import { DOMAIN_SEPARATOR } from '../src/constants.js';
import type { JsonValue } from '../src/canonical-json.js';

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, '../../../tests/vectors/commit.vectors.json');

interface CommitVector {
  name: string;
  payload: JsonValue;
  salt_hex: string;
  commit_hex: string;
}

const { domain_separator, schema_version, vectors } = JSON.parse(
  readFileSync(vectorsPath, 'utf8'),
) as {
  domain_separator: string;
  schema_version: string;
  vectors: CommitVector[];
};

describe('commit vectors', () => {
  it('uses the canonical domain separator', () => {
    expect(domain_separator).toBe(DOMAIN_SEPARATOR);
  });

  for (const v of vectors) {
    it(`computeCommitHex reproduces vector ${v.name}`, async () => {
      const got = await computeCommitHex(v.payload, v.salt_hex, {
        schemaVersion: schema_version,
      });
      expect(got).toBe(v.commit_hex);
    });

    it(`VerifyCommit accepts valid reveal ${v.name}`, async () => {
      const ok = await VerifyCommit(v.payload, v.salt_hex, v.commit_hex, {
        schemaVersion: schema_version,
      });
      expect(ok).toBe(true);
    });

    it(`VerifyCommit rejects payload tampering ${v.name}`, async () => {
      const tampered = { ...(v.payload as Record<string, JsonValue>), _tamper: 1 };
      const ok = await VerifyCommit(tampered, v.salt_hex, v.commit_hex, {
        schemaVersion: schema_version,
      });
      expect(ok).toBe(false);
    });

    it(`VerifyCommit rejects salt tampering ${v.name}`, async () => {
      const badSalt = v.salt_hex.slice(0, -1) + 'f';
      const ok = await VerifyCommit(v.payload, badSalt, v.commit_hex, {
        schemaVersion: schema_version,
      });
      expect(ok).toBe(false);
    });
  }

  it('VerifyCommit accepts 0x-prefixed hex', async () => {
    const v = vectors[0]!;
    const ok = await VerifyCommit(v.payload, '0x' + v.salt_hex, '0x' + v.commit_hex, {
      schemaVersion: schema_version,
    });
    expect(ok).toBe(true);
  });

  it('VerifyCommit rejects wrong-length commitments', async () => {
    const v = vectors[0]!;
    const ok = await VerifyCommit(v.payload, v.salt_hex, 'abcd', {
      schemaVersion: schema_version,
    });
    expect(ok).toBe(false);
  });

  it('VerifyCommit rejects a commitment from a different domain', async () => {
    const v = vectors[0]!;
    const differentDomainCommit = await computeCommitHex(v.payload, v.salt_hex, {
      schemaVersion: schema_version,
      domainSeparator: 'PEPTIDE_RX_ATL_PREDICTION_V999',
    });
    // Sanity: the two commits should differ.
    expect(differentDomainCommit).not.toBe(v.commit_hex);
    // Using the stored commit under a mismatched domain must fail.
    const ok = await VerifyCommit(v.payload, v.salt_hex, v.commit_hex, {
      schemaVersion: schema_version,
      domainSeparator: 'PEPTIDE_RX_ATL_PREDICTION_V999',
    });
    expect(ok).toBe(false);
  });
});
