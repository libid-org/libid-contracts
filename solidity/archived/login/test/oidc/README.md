# OIDC contract tests

Tests for `contracts/login/oidc/IOidcVerifier.sol` and its implementers
(`GoogleOidcVerifier.sol`) plus the new `Registry.register_session_oidc`
entry point.

## Running

```bash
forge test -vv
```

(These run in the default profile — the OIDC verifier compiles fine under
`via_ir = true` with the current solc/bb toolchain.)

## Fixtures

Two kinds of fixtures, in different states of permanence:

### Committed fixtures (`contracts/login/test/fixtures/oidc/`)

- `jwks-snapshot.json` — verbatim Google JWKS response, captured once at
  fixture-generation time. The rotation proof binds to this exact byte
  sequence via Merkle leaves.
- `jwks-proof.json` — TLSN-notarized attestation over the snapshot,
  signed by the deterministic test notary `0x6f4c…b87a` (privkey
  `0x00…0042`). The `timestamp` in this proof must overlap with the
  user JWT's `exp` for the integration test to pass. Freshness window:
  `jwksProof.timestamp + ROTATION_TTL >= jwtExp > block.timestamp`
  (see `GoogleOidcVerifier` constants).

### Per-run fixtures (`circuits/jwt_email/target/`)

- `proof`, `public_inputs`, `proof_meta.json` — produced by running
  the OIDC prover CLI from the original monorepo (after the Rust lift
  completes). These ARE gitignored: each is bound to a specific OAuth
  code + session keypair + JWT `exp`, so they go stale after ~1 hour.

A test that depends on these guards itself with a file-existence check
and emits a clear "skipped" message rather than failing CI. To
regenerate, run the CLI (web flow OAuths against Google live, writes
all three files):

```bash
# in the OIDC prover CLI's directory (original monorepo)
cargo run --release
```

The CLI drives an OAuth → JWT → Noir witness → proof → fixture-write
pipeline; the fixtures it emits feed back into `forge test`.
