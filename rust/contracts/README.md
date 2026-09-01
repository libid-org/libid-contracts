# libid-contracts

Typed [alloy](https://github.com/alloy-rs/alloy) bindings, embedded forge
artifacts, and deploy/upgrade helpers for the libid contract stack: the login
contracts (`Registry`, `WebWallet`, `WalletFactory`, verifiers), the Bank
EIP-2535 diamond, and the identity-names contracts.

The compiled artifacts are vendored into the crate, so a consumer can deploy
or upgrade the whole stack against a live network with **zero filesystem
dependencies at runtime**. They are generated, not committed:
`scripts/vendor-artifacts.sh` produces `artifacts/` from `solidity/` and CI
runs it before every build, test and publish. Working in this repo, run it
once after cloning — the crate embeds the directory with `include_dir!`, so
until it exists `cargo build` fails at macro expansion. Signing stays on the consumer's
side: every helper is generic over an alloy `Provider` you have already wired
with a wallet.

## Example: deploy the login stack

```rust,no_run
use alloy::{primitives::Address, providers::ProviderBuilder};
use libid_contracts::{
    bindings::login::{IRegistryAdmin, Registry, WalletFactory},
    deploy::{deploy_behind_proxy, deploy_contract},
    Artifacts,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Any alloy provider with a wallet: HTTP + your signer of choice.
    let provider = ProviderBuilder::new()
        .wallet(/* your signer */ todo!())
        .connect_http("https://rpc.example.org".parse()?);
    let artifacts = Artifacts::embedded();
    let (owner, notary, backend): (Address, Address, Address) = todo!();

    // WebWallet implementation, then WalletFactory + Registry behind
    // ERC1967 proxies.
    let wallet_impl = deploy_contract(
        &provider,
        artifacts.bytecode("WebWallet")?,
        "WebWallet (impl)",
    )
    .await?;
    let factory = deploy_behind_proxy(
        &provider,
        &artifacts,
        "WalletFactory",
        &WalletFactory::initializeCall {
            owner_: owner,
            walletImpl_: wallet_impl,
            registry_: Address::ZERO,
        },
        None,
    )
    .await?;
    let registry = deploy_behind_proxy(
        &provider,
        &artifacts,
        "Registry",
        &IRegistryAdmin::initializeCall {
            _notary: notary,
            _backend: backend,
            _walletFactory: factory,
            _owner: owner,
        },
        None,
    )
    .await?;
    WalletFactory::new(factory, &provider)
        .setRegistry(registry)
        .send()
        .await?
        .get_receipt()
        .await?;

    println!("registry {registry:#x}, resolves via {:#x}", registry);
    Ok(())
}
```

Other entry points:

- `diamond::deploy_bank_diamond` / `diamond::replace_bank_facets` — the Bank
  EIP-2535 deploy and facet upgrade.
- `deploy::load_linked_bytecode` (or `Artifacts::linked_bytecode`) — deploys
  and links external libraries (`ZKTranscriptLib` for the generated UltraHonk
  verifiers) before returning the creation bytecode.
- `deploy::upgrade_uups` — deploy a fresh implementation and
  `upgradeToAndCall` a UUPS proxy onto it.
- `Artifacts::facet_selectors` / `Artifacts::method_identifiers` — selector
  extraction from the vendored `methodIdentifiers`.

## Testing

Unit tests run everywhere; the integration tests in `tests/anvil.rs` spawn
`anvil` (foundry) and deploy every stack for real. From `rust/`:

```sh
cargo +nightly fmt --all      # nightly only — stable rustfmt mangles imports
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```
