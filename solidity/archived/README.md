# Archived contracts

Reference only. Nothing under this directory is compiled, tested, shipped,
or deployed by this repository.

## What is here

- `login/` — the wallet product's login stack: `Registry` (the one place a
  notarized or zero-knowledge session became a platform → wallet binding),
  `WebWallet` and `WalletFactory` (the smart-account wallets it minted), the
  `XZkVerifier` ZK session verifier and the `GoogleOidcVerifier` OIDC verifier,
  together with the two bb-generated UltraHonk verifiers they called
  (`oidc/Verifier.sol`, `zk/XHonkVerifier.sol`), their tests, fixtures and
  deploy scripts.
- `transfer/` — the transfer product: the `Bank` EIP-2535 diamond (facets,
  init, libraries, storage), its deployer, the `MockERC20` dev token, and its
  tests.
- `notary/` — the legacy `Notary`: a single-key attestation verifier that
  took a caller-computed digest. Everything in `contracts/` now verifies
  notary attestations through `ceremony/NotaryService`, which derives the
  digest from the attested bytes itself (REQ-COMMON-49) and charges the
  Notary Fee.

They are kept, rather than deleted, as a record of how a full product was
built on notarized sessions: the login stack is the worked example of turning
a session into an on-chain binding, and the bank is the worked example of a
consumer spending one. Git history has every version of them; this directory
holds the last.

## Status

Frozen as of the commit that moved them here. They last built and passed
their tests at tag `v0.6.0`, against that tag's `foundry.toml` and
submodules. Nothing regenerates them: the bb-generated verifiers are not
re-derived from a circuits release, no Rust bindings or TypeScript ABIs are
produced for them, and CI does not look at them.

This directory sits outside forge's `src`, `test` and `script` roots, so
`forge build` never sees it. Moving a file back under `contracts/` is what
would make it compile again — and it would need to be brought up to the
current bases (ERC-7201 namespaced storage + UUPS + Ownable2Step) and to
`NotaryService` before it could be deployed alongside the rest.

The wallet product is not deployed by this repository any more.
`script/Deploy.s.sol` deploys the identity stack only.
