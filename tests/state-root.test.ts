import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { computeStateRoot, verifyStateRoot, type AtlEvent } from '../src/state-root.js';

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, '../../../tests/vectors/state-root.vectors.json');

interface StateRootVector {
  name: string;
  thesis_id: string;
  events: AtlEvent[];
  state_root_hex: string;
}

const { vectors } = JSON.parse(readFileSync(vectorsPath, 'utf8')) as {
  vectors: StateRootVector[];
};

describe('state root vectors', () => {
  for (const v of vectors) {
    it(`computeStateRoot reproduces vector ${v.name}`, async () => {
      const got = await computeStateRoot(v.thesis_id, v.events);
      expect(got).toBe(v.state_root_hex);
    });

    it(`verifyStateRoot accepts vector ${v.name}`, async () => {
      const ok = await verifyStateRoot(v.events, v.state_root_hex, {
        thesisId: v.thesis_id,
      });
      expect(ok).toBe(true);
    });

    it(`verifyStateRoot rejects tampered event order ${v.name}`, async () => {
      if (v.events.length < 2) return;
      const shuffled = [v.events[1]!, v.events[0]!, ...v.events.slice(2)];
      const ok = await verifyStateRoot(shuffled, v.state_root_hex, {
        thesisId: v.thesis_id,
      });
      expect(ok).toBe(false);
    });
  }

  it('rejects event with mismatched thesis_id', async () => {
    await expect(
      computeStateRoot('ATL-001', [
        {
          thesis_id: 'ATL-999',
          event_type: 'THESIS_COMMITTED',
          payload: {},
        },
      ]),
    ).rejects.toThrow();
  });

  it('emits a genesis root for an empty event log', async () => {
    const got = await computeStateRoot('ATL-001', []);
    expect(got).toHaveLength(64);
  });
});
