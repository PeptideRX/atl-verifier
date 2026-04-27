# Contributing

This package is **EXPERIMENTAL** and under active development as part of
building peptideRx in public. Contributions are welcome but the protocol
is not yet stable; large structural PRs may need to wait for v1.0.

## What's in scope

- Bug reports and reproductions for failing test vectors
- Performance improvements that do not change byte output
- Documentation, examples, and README clarity
- Cross-runtime compatibility fixes (Node, Deno, Bun, browsers, edge)
- Security findings (please file privately, see below)

## What's out of scope right now

- Changes to the canonical JSON dialect
- Changes to the domain separators or Merkle tag
- Changes to the TEE simulator key
- Changes that would break byte-identical parity with the Python or
  Rust reference implementations on Vec A / Vec B / Vec C

These are locked until v1.0 of the protocol ships.

## Local development

```bash
git clone https://github.com/PeptideRX/atl-verifier.git
cd atl-verifier
npm install
npm run build
npm test
```

99 tests should pass across `canonical-json`, `state-root`, `merkle`,
`commit`, and `pda-verifier` suites.

## Filing issues

For functional bugs, open an issue:
https://github.com/PeptideRX/atl-verifier/issues

For security findings (privacy boundary violations, signature forgery,
attestation bypass, etc.), please email **security@peptiderx.io**
directly. Do not file public issues for cryptographic vulnerabilities.

## Licensing

By contributing, you agree your contributions are licensed under
Apache-2.0, the same license as the project.

## Code of conduct

Be specific. Bring evidence. Cite the line. The protocol exists to make
research claims provably grounded; the same standard applies to claims
about the protocol itself.
