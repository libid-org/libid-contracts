# libID contracts

Smart contracts for libID, laid out per chain. `solidity/` is a self-contained
Foundry project holding the EVM contracts: the ceremony verification path
(Notary Service, Proof Verifier, Platform Verifiers, and the Google JWT root
list the Google verifier reads), the identity naming system, and the
deterministic deployment factory. `rust/` and `ts/` hold the ABI wrapper packages; room is reserved
for `solana/` and other networks.

## Layout

```
solidity/            # Foundry project root
  contracts/
    ceremony/        # NotaryService, CeremonyProofVerifier, Platform Verifiers,
                     # GoogleJwtRoots
    identity/        # IdentityNames, handle normalization
    factory/         # LibidFactory: deterministic CREATE3 deployment
    WTIA9.sol        # wrapped TIA
  script/Deploy.s.sol
  lib/               # git submodules (openzeppelin, forge-std)
rust/contracts/      # libid-contracts crate: alloy bindings + embedded artifacts
ts/packages/contracts/  # @libid/contracts: viem ABIs, call builders, identity helpers
scripts/
  vendor-artifacts.sh
  regen-identity-handles.py
```

## Build and test

```sh
git submodule update --init --recursive
cd solidity
forge build
forge test
```

`forge build` is the input to the two generated trees, neither of which is
committed. Generate them once after cloning, and again after any change to a
contract they cover:

```sh
scripts/vendor-artifacts.sh   # -> rust/contracts/artifacts (the crate embeds
                              #    this with include_dir!, so cargo commands
                              #    fail at macro expansion without it)
pnpm -C ts codegen            # -> ts/packages/contracts/src/abis (tsc reads
                              #    these, so `pnpm -C ts build` needs them)
```

CI runs both in every job that compiles the crate or the package, and again in
the publish jobs — the published crate and npm package carry the generated
output even though git does not.

## Handle vectors

`solidity/contracts/identity/handles.json` is the source of truth for platform
handle rules and the shared normalization vector table. After editing it:

```sh
python3 scripts/regen-identity-handles.py          # rewrite generated outputs
python3 scripts/regen-identity-handles.py --check  # verify nothing drifted
```

This generates `solidity/contracts/identity/HandleVectors.sol`,
`rust/identity/src/handle_vectors.rs` and
`ts/packages/contracts/src/identity/handleVectors.ts`; CI's handle-tables job
fails when any of them drifts from `handles.json`.

## Releasing

The Rust crate ([`libid-contracts`](https://crates.io/crates/libid-contracts))
and the npm package
([`@libid/contracts`](https://www.npmjs.com/package/@libid/contracts)) release
together under a single version number. A release is cut by publishing a
GitHub Release tagged `v<version>`; nothing publishes from pushes or PRs.

```sh
./scripts/bump-version.sh 0.2.0        # sets Cargo.toml, Cargo.lock, package.json
git checkout -b release/v0.2.0
git commit -sam "chore: release v0.2.0"
# open a PR, get it merged, then:
gh release create v0.2.0 --title "v0.2.0" --generate-notes
```

Publishing the release triggers CI's release jobs:

1. `verify-tag` — the tag must equal the version in both manifests (the tag
   is a pointer, never a source; the `versions` job also enforces crate/npm
   equality on every PR).
2. `publish-crates` — after the Solidity, Rust and publish dry-run jobs pass,
   `cargo publish` with `CARGO_REGISTRY_TOKEN`. If the version is already on
   crates.io (a re-run after a partial release), it skips with a notice.
3. `publish-npm` — after `publish-crates`, builds and publishes
   `@libid/contracts` via npm OIDC trusted publishing (no token secret), with
   provenance. A prerelease publishes under its first prerelease identifier
   as the dist-tag (`1.2.0-rc.1` → `rc`); a plain version under `latest`.

## License

Dual-licensed under MIT and Apache-2.0; see `LICENSE-MIT`, `LICENSE-APACHE`
and `CONTRIBUTING.md`.
