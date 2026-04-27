#!/usr/bin/env node
/**
 * atl-verify-pda · command-line Peptide Design Attestation verifier.
 *
 * Usage:
 *
 *   atl-verify-pda <path-to-pda-output.json> [--no-simulator]
 *                   [--measurement <hex>] [--nonce <hex>...]
 *                   [--schema-version <n>]
 *
 * Reads a PDAOutput JSON blob from disk, runs the shipped verifier,
 * and prints a one-line PASS/FAIL verdict plus per-field details.
 *
 * Exit codes:
 *   0 = PASS
 *   1 = FAIL
 *   2 = malformed input or unexpected crash
 *
 * Scope: research use only, nonclinical.
 */

import { readFileSync } from 'node:fs';
import { argv, exit, stdout } from 'node:process';

// Resolves via the package's own "exports" entry after build. The
// published bin under dist/bin/ hits "../pda/index.js"; in development
// the project references the source tree via the tsconfig "paths"
// mapping so typecheck does not require a built dist/.
import {
  verifyPDA,
  type PDAOutput,
  type VerifyPDAOptions,
} from '@peptiderx/atl-verifier/pda';

interface CliArgs {
  path?: string;
  acceptSimulator: boolean;
  measurementHex?: string;
  seenNonces: string[];
  schemaVersion?: number;
  showHelp: boolean;
}

function parseArgs(args: readonly string[]): CliArgs {
  const out: CliArgs = {
    acceptSimulator: true,
    seenNonces: [],
    showHelp: false,
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    switch (a) {
      case '-h':
      case '--help':
        out.showHelp = true;
        break;
      case '--no-simulator':
        out.acceptSimulator = false;
        break;
      case '--measurement': {
        i++;
        const v = args[i];
        if (!v) throw new Error('--measurement requires a hex argument');
        out.measurementHex = v;
        break;
      }
      case '--nonce': {
        i++;
        const v = args[i];
        if (!v) throw new Error('--nonce requires a hex argument');
        out.seenNonces.push(v);
        break;
      }
      case '--schema-version': {
        i++;
        const v = args[i];
        if (!v) throw new Error('--schema-version requires an integer');
        const n = Number.parseInt(v, 10);
        if (!Number.isFinite(n)) throw new Error('--schema-version must be an integer');
        out.schemaVersion = n;
        break;
      }
      default:
        if (typeof a === 'string' && a.startsWith('--')) {
          throw new Error(`unknown flag: ${a}`);
        }
        if (!out.path) {
          out.path = a;
        } else {
          throw new Error(`unexpected positional argument: ${a}`);
        }
    }
  }
  return out;
}

function printHelp(): void {
  stdout.write(
    [
      'atl-verify-pda · Peptide Design Attestation verifier',
      '',
      'Usage:',
      '  atl-verify-pda <path-to-pda-output.json> [flags]',
      '',
      'Flags:',
      '  --no-simulator            Refuse attestations tagged tee_type="simulator".',
      '  --measurement <hex64>     Override the expected public TEE measurement.',
      '                            Defaults to the documented simulator constant.',
      '  --nonce <hex64>           Mark a nonce as already seen (replay gate).',
      '                            May be repeated.',
      '  --schema-version <int>    Expected schema version (default 1).',
      '  -h, --help                Show this help and exit 0.',
      '',
      'Exit codes:',
      '  0 PASS · 1 FAIL · 2 malformed input or unexpected error',
      '',
      'Scope: research use only, nonclinical.',
      '',
    ].join('\n'),
  );
}

async function main(): Promise<void> {
  let args: CliArgs;
  try {
    args = parseArgs(argv.slice(2));
  } catch (e) {
    stdout.write(`atl-verify-pda: ${(e as Error).message}\n`);
    exit(2);
    return;
  }
  if (args.showHelp) {
    printHelp();
    exit(0);
    return;
  }
  if (!args.path) {
    stdout.write('atl-verify-pda: missing PDAOutput JSON path.\nRun --help for usage.\n');
    exit(2);
    return;
  }

  let raw: string;
  try {
    raw = readFileSync(args.path, 'utf8');
  } catch (e) {
    stdout.write(`atl-verify-pda: cannot read ${args.path}: ${(e as Error).message}\n`);
    exit(2);
    return;
  }

  let output: PDAOutput;
  try {
    output = JSON.parse(raw) as PDAOutput;
  } catch (e) {
    stdout.write(`atl-verify-pda: invalid JSON at ${args.path}: ${(e as Error).message}\n`);
    exit(2);
    return;
  }

  const options: VerifyPDAOptions = {
    acceptSimulator: args.acceptSimulator,
    seenNoncesHex: args.seenNonces,
  };
  if (args.measurementHex !== undefined) {
    options.expectedMeasurementHex = args.measurementHex;
  }
  if (args.schemaVersion !== undefined) {
    options.schemaVersion = args.schemaVersion;
  }

  try {
    const report = await verifyPDA(output, options);
    const verdict = report.passed ? 'PASS' : 'FAIL';
    stdout.write(`atl-verify-pda: ${verdict}\n`);
    stdout.write(`  path             ${args.path}\n`);
    stdout.write(`  pda_hex          ${output.pda_hex}\n`);
    stdout.write(`  schema_version   ${output.schema_version}\n`);
    stdout.write(`  tee_type         ${output.tee_attestation.tee_type}\n`);
    stdout.write(`  commit_root_hex  ${output.candidate_commit_root_hex}\n`);
    stdout.write('  verified_fields:\n');
    const fields = Object.entries(report.verified_fields).sort(
      ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0),
    );
    for (const [name, ok] of fields) {
      stdout.write(`    ${ok ? '[ok]' : '[!!]'}  ${name}\n`);
    }
    if (report.blocked_reasons.length > 0) {
      stdout.write('  blocked_reasons:\n');
      for (const r of report.blocked_reasons) {
        stdout.write(`    - ${r}\n`);
      }
    }
    exit(report.passed ? 0 : 1);
  } catch (e) {
    stdout.write(`atl-verify-pda: verifier crashed: ${(e as Error).message}\n`);
    exit(2);
  }
}

void main();
