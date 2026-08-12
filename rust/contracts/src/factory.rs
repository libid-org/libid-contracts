//! Bootstrap and use of the deterministic deployment factory.
//!
//! The [`LibidFactory`] proxy lives at the same address on every EVM network
//! because every byte that feeds its address is frozen: it is deployed
//! through the canonical keyless CREATE2 deployer (Arachnid's
//! deterministic-deployment proxy at [`CREATE2_DEPLOYER`]) with fixed salts
//! and init codes that carry no per-network data — the admin is the baked
//! [`FACTORY_GENESIS_ADMIN`] constant, so initialization happens atomically
//! inside the deployment. Protocol proxies are then deployed *through* the
//! factory via CREATE3, which makes their addresses a function of
//! `(factory, name)` only — see `solidity/contracts/factory/README.md`.
//!
//! [`ensure_factory`] is the whole bootstrap: check → install the CREATE2
//! deployer if missing (via its well-known presigned transaction) → deploy
//! the factory impl and proxy at their canonical addresses. There is
//! deliberately no fallback deployment path: anything else would change the
//! factory address and defeat the cross-network guarantee, so a chain that
//! cannot take the presigned install transaction is a hard error.

use alloy::{
    hex,
    network::TransactionBuilder,
    primitives::{
        address,
        keccak256,
        Address,
        Bytes,
        B256,
        U256,
    },
    providers::Provider,
    rpc::types::TransactionRequest,
    sol_types::{
        SolCall,
        SolValue,
    },
};

use crate::{
    artifacts::Artifacts,
    bindings::factory::LibidFactory,
    error::{
        Error,
        Result,
    },
};

/// Arachnid's deterministic-deployment proxy — deployed from a keyless
/// one-time account, so it has this address on every chain that has it.
/// Calldata format: 32-byte salt ++ init code.
pub const CREATE2_DEPLOYER: Address =
    address!("4e59b44847b379578588920cA78FbF26c0B4956C");

/// The keyless one-time account the presigned install transaction spends
/// from. It must hold the exact transaction cost (see
/// [`CREATE2_DEPLOYER_FUNDING_WEI`]) before the broadcast.
pub const CREATE2_DEPLOYER_SIGNER: Address =
    address!("3fab184622dc19b6109349b94811493bf2a45362");

/// What the install transaction costs: 100 gwei gas price × 100 000 gas
/// limit = 0.01 ETH. The keyless account can never refund the surplus, so
/// fund it with exactly this.
pub const CREATE2_DEPLOYER_FUNDING_WEI: u128 = 10_000_000_000_000_000;

/// The canonical presigned transaction that installs the CREATE2 deployer.
///
/// This is a pre-EIP-155 (no chain id, v = 27) legacy transaction whose
/// signature was fixed *before any key existed* — r = s =
/// 0x2222…22 — so nobody holds the sending key and the deployer lands at
/// [`CREATE2_DEPLOYER`] on every chain that accepts it. Chains that enforce
/// EIP-155 replay protection on all transactions reject it; per policy that
/// is a hard error (see [`ensure_create2_deployer`]), not a cue for an
/// alternate deployment path.
pub const CREATE2_DEPLOYER_INSTALL_TX: &str = "0xf8a58085174876e800830186a08080b853604580600e600039806000f350fe7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf31ba02222222222222222222222222222222222222222222222222222222222222222a02222222222222222222222222222222222222222222222222222222222222222";

/// The genesis admin baked into the frozen factory-proxy init code.
/// PLACEHOLDER until the owner substitutes the protocol-admin KMS address.
/// Keep in sync with `solidity/contracts/factory/FactoryGenesis.sol`.
pub const FACTORY_GENESIS_ADMIN: Address =
    address!("1111111111111111111111111111111111111111");

/// The 16-byte CREATE3 proxy init code (`Create3.PROXY_INITCODE`). Constant
/// forever — its hash feeds every predicted address.
pub const CREATE3_PROXY_INITCODE: [u8; 16] = [
    0x67, 0x36, 0x3d, 0x3d, 0x37, 0x36, 0x3d, 0x34, 0xf0, 0x3d, 0x52, 0x60, 0x08, 0x60,
    0x18, 0xf3,
];

/// Fixed salt of the factory implementation (`FactoryDeployer.IMPL_SALT`).
pub fn factory_impl_salt() -> B256 {
    keccak256("libid.factory.impl.v1")
}

/// Fixed salt of the factory proxy (`FactoryDeployer.PROXY_SALT`).
pub fn factory_proxy_salt() -> B256 {
    keccak256("libid.factory.v1")
}

/// The frozen implementation init code: LibidFactory's creation code, no
/// constructor args.
pub fn factory_impl_init_code(artifacts: &Artifacts) -> Result<Bytes> {
    artifacts.bytecode("LibidFactory")
}

/// Where the factory implementation lands.
pub fn predict_factory_impl_address(artifacts: &Artifacts) -> Result<Address> {
    let init_code = factory_impl_init_code(artifacts)?;
    Ok(CREATE2_DEPLOYER.create2(factory_impl_salt(), keccak256(&init_code)))
}

/// The frozen proxy init code: ERC1967Proxy creation code ++
/// abi.encode(implAddress, initialize(FACTORY_GENESIS_ADMIN)). Every byte is
/// network-invariant; `FactoryDeployer.proxyInitCode()` produces the same
/// bytes (asserted against the vendored artifacts by the Solidity tests).
pub fn factory_proxy_init_code(artifacts: &Artifacts) -> Result<Bytes> {
    let impl_addr = predict_factory_impl_address(artifacts)?;
    let init_data = LibidFactory::initializeCall {
        owner_: FACTORY_GENESIS_ADMIN,
    }
    .abi_encode();
    let mut code = artifacts.bytecode("ERC1967Proxy")?.to_vec();
    code.extend_from_slice(&(impl_addr, Bytes::from(init_data)).abi_encode_params());
    Ok(code.into())
}

/// The canonical factory address — the same on every EVM network.
pub fn predict_factory_address(artifacts: &Artifacts) -> Result<Address> {
    let init_code = factory_proxy_init_code(artifacts)?;
    Ok(CREATE2_DEPLOYER.create2(factory_proxy_salt(), keccak256(&init_code)))
}

/// The CREATE3 address `factory.deploy(name, ·)` lands on: the factory
/// CREATE2-deploys the constant 16-byte proxy under `keccak256(name)`, and
/// that proxy CREATE-deploys the target at its nonce 1. A pure function of
/// `(factory, name)` — computable offline, before anything is deployed.
pub fn predict_address(factory: Address, name: &str) -> Address {
    let salt = keccak256(name.as_bytes());
    let create3_proxy = factory.create2(salt, keccak256(CREATE3_PROXY_INITCODE));
    create3_proxy.create(1)
}

/// Make sure the canonical CREATE2 deployer exists, installing it via the
/// keyless presigned transaction if absent: fund the one-time signer with
/// the exact transaction cost, then broadcast [`CREATE2_DEPLOYER_INSTALL_TX`].
///
/// Hard-errors on a chain that rejects the pre-EIP-155 transaction: there is
/// no alternate deployment path (one would change the factory address), so
/// such a network cannot host the deterministic factory.
pub async fn ensure_create2_deployer<P: Provider>(provider: &P) -> Result<()> {
    let code = provider
        .get_code_at(CREATE2_DEPLOYER)
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("failed to read code at the CREATE2 deployer: {e}"),
        })?;
    if !code.is_empty() {
        return Ok(());
    }

    // Fund the keyless one-time account up to the exact transaction cost.
    let balance = provider
        .get_balance(CREATE2_DEPLOYER_SIGNER)
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("failed to read the CREATE2 deployer signer balance: {e}"),
        })?;
    let needed = U256::from(CREATE2_DEPLOYER_FUNDING_WEI);
    if balance < needed {
        let tx = TransactionRequest::default()
            .with_to(CREATE2_DEPLOYER_SIGNER)
            .with_value(needed - balance);
        let pending = provider
            .send_transaction(tx)
            .await
            .map_err(|e| Error::Rpc {
                detail: format!("failed to fund the CREATE2 deployer signer: {e}"),
            })?;
        pending.get_receipt().await.map_err(|e| Error::Rpc {
            detail: format!("CREATE2 deployer funding confirmation failed: {e}"),
        })?;
    }

    let raw = hex::decode(CREATE2_DEPLOYER_INSTALL_TX).map_err(|e| Error::Rpc {
        detail: format!("bad CREATE2 deployer install tx constant: {e}"),
    })?;
    let pending = provider
        .send_raw_transaction(&raw)
        .await
        .map_err(|e| Error::Rpc {
            detail: format!(
                "this chain rejected the keyless (pre-EIP-155) install transaction \
                 for the canonical CREATE2 deployer: {e}. There is deliberately no \
                 fallback deployment path — any other route would change the \
                 factory address and defeat the cross-network guarantee — so this \
                 network cannot host the deterministic factory and must be \
                 reconsidered."
            ),
        })?;
    pending.get_receipt().await.map_err(|e| Error::Rpc {
        detail: format!("CREATE2 deployer install confirmation failed: {e}"),
    })?;

    let code = provider
        .get_code_at(CREATE2_DEPLOYER)
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("failed to re-read code at the CREATE2 deployer: {e}"),
        })?;
    if code.is_empty() {
        return Err(Error::Rpc {
            detail: "the CREATE2 deployer install transaction landed but left no code"
                .into(),
        });
    }
    Ok(())
}

/// Deploy `salt ++ init_code` through the CREATE2 deployer and verify code
/// landed at `predicted`.
async fn deploy_via_create2<P: Provider>(
    provider: &P,
    salt: B256,
    init_code: &[u8],
    predicted: Address,
    label: &str,
) -> Result<()> {
    let mut input = salt.to_vec();
    input.extend_from_slice(init_code);
    let tx = TransactionRequest::default()
        .with_to(CREATE2_DEPLOYER)
        .with_input(Bytes::from(input));
    let pending = provider
        .send_transaction(tx)
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("{label}: CREATE2 deploy send failed: {e}"),
        })?;
    pending.get_receipt().await.map_err(|e| Error::Rpc {
        detail: format!("{label}: CREATE2 deploy confirmation failed: {e}"),
    })?;
    let code = provider
        .get_code_at(predicted)
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("{label}: failed to read code at {predicted}: {e}"),
        })?;
    if code.is_empty() {
        return Err(Error::Rpc {
            detail: format!("{label}: no code at the predicted address {predicted}"),
        });
    }
    Ok(())
}

/// Make sure the canonical factory exists at [`predict_factory_address`],
/// bootstrapping whatever is missing: the CREATE2 deployer (via the keyless
/// presigned transaction), the factory implementation, and the factory
/// proxy — each at its deterministic address. Idempotent: reruns are
/// read-only no-ops once the factory is up.
pub async fn ensure_factory<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
) -> Result<Address> {
    let factory = predict_factory_address(artifacts)?;
    let code = provider
        .get_code_at(factory)
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("failed to read code at the factory address: {e}"),
        })?;
    if !code.is_empty() {
        return Ok(factory);
    }

    ensure_create2_deployer(provider).await?;

    let impl_addr = predict_factory_impl_address(artifacts)?;
    let impl_code = provider
        .get_code_at(impl_addr)
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("failed to read code at the factory impl address: {e}"),
        })?;
    if impl_code.is_empty() {
        deploy_via_create2(
            provider,
            factory_impl_salt(),
            &factory_impl_init_code(artifacts)?,
            impl_addr,
            "LibidFactory (impl)",
        )
        .await?;
    }

    deploy_via_create2(
        provider,
        factory_proxy_salt(),
        &factory_proxy_init_code(artifacts)?,
        factory,
        "LibidFactory (proxy)",
    )
    .await?;
    Ok(factory)
}

/// Deploy `creation_code` under `name` through the factory (the provider's
/// wallet must be the factory owner). Returns the deployed address, which
/// always equals [`predict_address`]`(factory, name)`.
pub async fn factory_deploy<P: Provider>(
    provider: &P,
    factory: Address,
    name: &str,
    creation_code: Bytes,
) -> Result<Address> {
    // `deploy` is built as raw calldata: alloy's `sol!` reserves the `deploy`
    // method name on generated contract instances, so the typed call struct
    // is used directly instead.
    let call = LibidFactory::deployCall {
        name: name.to_string(),
        creationCode: creation_code,
    };
    let tx = TransactionRequest::default()
        .with_to(factory)
        .with_input(Bytes::from(call.abi_encode()));
    let pending = provider
        .send_transaction(tx)
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("factory deploy of {name} send failed: {e}"),
        })?;
    pending.get_receipt().await.map_err(|e| Error::Rpc {
        detail: format!("factory deploy of {name} confirmation failed: {e}"),
    })?;

    let contract = LibidFactory::new(factory, provider);
    let addr = contract
        .deployedAt(name.to_string())
        .call()
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("factory deployedAt({name}) read failed: {e}"),
        })?;
    if addr == Address::ZERO {
        return Err(Error::Rpc {
            detail: format!("factory deploy of {name} landed no recorded address"),
        });
    }
    Ok(addr)
}
