// Copies the plain-JS bin script into dist/bin/ so the published
// package's "bin" field resolves cleanly. The bin file is intentionally
// not TypeScript: it's a thin CLI wrapper, not part of the verifier
// surface, and keeping it as JS removes a TypeScript build path that
// fights with package self-imports during fresh CI installs.

import { mkdirSync, copyFileSync, chmodSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..');

const src = resolve(repoRoot, 'bin', 'atl-verify-pda.js');
const destDir = resolve(repoRoot, 'dist', 'bin');
const dest = resolve(destDir, 'atl-verify-pda.js');

mkdirSync(destDir, { recursive: true });
copyFileSync(src, dest);
try {
  chmodSync(dest, 0o755);
} catch {
  // chmod may fail on Windows in CI; the shebang + npm bin install handle it.
}

console.log(`copied: ${src} -> ${dest}`);
