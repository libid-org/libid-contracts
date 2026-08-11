# libID contracts

Smart contracts for libID, laid out per chain. `solidity/` is a self-contained
Foundry project holding the EVM contracts (login wallets, transfer bank
diamond, identity naming); room is reserved for `solana/` and other networks,
and `rust/` and `ts/` ABI wrapper packages are coming.

## Layout

```
solidity/            # Foundry project root
  contracts/
    login/           # registry, web wallets, OIDC + ZK session verifiers
    transfer/        # bank diamond and facets
    identity/        # platform handle naming and identity verifiers
    WTIA9.sol        # wrapped TIA
  script/Deploy.s.sol
  lib/               # git submodules (openzeppelin, forge-std)
scripts/
  regen-identity-handles.py
```

## Build and test

```sh
git submodule update --init --recursive
cd solidity
forge build
forge test
```

Some login OIDC flow tests read locally generated proof artifacts from
`circuits/jwt_email/target/`; when those files are absent the tests skip
themselves — that is expected.

## Handle vectors

`solidity/contracts/identity/handles.json` is the source of truth for platform
handle rules and the shared normalization vector table. After editing it:

```sh
python3 scripts/regen-identity-handles.py          # rewrite generated outputs
python3 scripts/regen-identity-handles.py --check  # verify nothing drifted
```

Today this generates `solidity/contracts/identity/HandleVectors.sol`; the Rust
and TypeScript outputs activate once those packages exist in this repo.

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

One-time setup (repo admin):

- Repo secret `CARGO_REGISTRY_TOKEN`: a crates.io API token with publish
  rights for `libid-contracts`.
- GitHub environment `npm-deploy` (Settings → Environments). Optionally add
  required reviewers to make npm publishing a manually approved gate.
- npmjs.com trusted publisher for `@libid/contracts`: package Settings →
  Trusted Publisher → GitHub Actions, with organization `libid-org`,
  repository `libid-contracts`, workflow filename `ci.yml`, environment
  `npm-deploy`.

## License

Dual-licensed under MIT and Apache-2.0; see `LICENSE-MIT`, `LICENSE-APACHE`
and `CONTRIBUTING.md`.
