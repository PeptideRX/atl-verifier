import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { canonicalizeJSON } from '../src/canonical-json.js';

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, '../tests/vectors/canonical-json.vectors.json');

interface Vector {
  name: string;
  input: unknown;
  canonical: string;
}

const { vectors } = JSON.parse(readFileSync(vectorsPath, 'utf8')) as {
  vectors: Vector[];
};

describe('canonicalizeJSON (RFC 8785)', () => {
  for (const v of vectors) {
    it(`vector: ${v.name}`, () => {
      expect(canonicalizeJSON(v.input)).toBe(v.canonical);
    });
  }

  it('sorts object keys lexicographically by UTF-16 code units', () => {
    expect(canonicalizeJSON({ b: 1, a: 2, A: 3, Z: 4 })).toBe('{"A":3,"Z":4,"a":2,"b":1}');
  });

  it('serializes empty containers', () => {
    expect(canonicalizeJSON({})).toBe('{}');
    expect(canonicalizeJSON([])).toBe('[]');
  });

  it('escapes control characters and quotes', () => {
    expect(canonicalizeJSON('a"b\\c\nd')).toBe('"a\\"b\\\\c\\nd"');
  });

  it('rejects non-finite numbers', () => {
    expect(() => canonicalizeJSON({ n: Number.POSITIVE_INFINITY })).toThrow();
    expect(() => canonicalizeJSON({ n: Number.NaN })).toThrow();
  });

  it('normalizes negative zero to 0', () => {
    expect(canonicalizeJSON(-0)).toBe('0');
  });

  it('preserves array order', () => {
    expect(canonicalizeJSON([3, 1, 2])).toBe('[3,1,2]');
  });
});
