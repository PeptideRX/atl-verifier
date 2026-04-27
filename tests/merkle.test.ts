import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { computeMerkleRoot, verifyMerkleRoot } from '../src/merkle.js';

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, '../../../tests/vectors/merkle.vectors.json');

interface MerkleVector {
  name: string;
  leaves: string[];
  prehashed: boolean;
  root_hex: string;
}

const { vectors } = JSON.parse(readFileSync(vectorsPath, 'utf8')) as {
  vectors: MerkleVector[];
};

describe('merkle vectors', () => {
  for (const v of vectors) {
    it(`computeMerkleRoot matches vector ${v.name}`, async () => {
      const root = await computeMerkleRoot(v.leaves, { prehashed: v.prehashed });
      expect(root).toBe(v.root_hex);
    });

    it(`verifyMerkleRoot accepts vector ${v.name}`, async () => {
      const ok = await verifyMerkleRoot(v.leaves, v.root_hex, { prehashed: v.prehashed });
      expect(ok).toBe(true);
    });

    it(`verifyMerkleRoot rejects wrong root for vector ${v.name}`, async () => {
      const wrong = 'f' + v.root_hex.slice(1);
      const ok = await verifyMerkleRoot(v.leaves, wrong, { prehashed: v.prehashed });
      expect(ok).toBe(false);
    });
  }

  it('duplicates an odd trailing leaf at every level', async () => {
    const single = await computeMerkleRoot(['x', 'x']);
    const double = await computeMerkleRoot(['x']);
    // A one-leaf tree should not equal the two-identical-leaf tree, because
    // RFC 6962-style odd duplication only applies when the leaf count is odd
    // at a given level and greater than one.
    expect(single).not.toBe(double);
  });

  it('is order sensitive', async () => {
    const a = await computeMerkleRoot(['x', 'y']);
    const b = await computeMerkleRoot(['y', 'x']);
    expect(a).not.toBe(b);
  });
});
