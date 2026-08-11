//! Generic deploy and upgrade primitives, usable over any alloy
//! [`Provider`] that has a wallet wired in. Signing is the consumer's
//! concern; nothing here constructs or holds keys.

use alloy::{
    hex,
    primitives::{
        Address,
        Bytes,
    },
    providers::Provider,
    sol_types::SolCall,
};

use crate::{
    artifacts::Artifacts,
    bindings::proxy::IUUPSUpgradeable,
    error::{
        Error,
        Result,
    },
};

/// Send a contract call with automatic retry on "nonce too low" errors.
///
/// Alloy's nonce manager can get stale when earlier calls fail at dry-run
/// (e.g. a call reverting "already applied"). On each attempt the real nonce
/// is fetched from the chain and set explicitly, bypassing the cached nonce
/// manager entirely.
///
/// Usage:
/// `send_with_nonce_retry!(contract.doSomething(args), "label", provider, sender)?;`
#[macro_export]
macro_rules! send_with_nonce_retry {
    ($call_expr:expr, $label:expr, $provider:expr, $sender:expr) => {{
        const MAX_RETRIES: u32 = 3;
        let mut result: $crate::Result<alloy::rpc::types::TransactionReceipt> =
            Err($crate::Error::Rpc {
                detail: "unreachable".into(),
            });
        for attempt in 0..MAX_RETRIES {
            let nonce =
                alloy::providers::Provider::get_transaction_count($provider, $sender)
                    .await
                    .map_err(|e| $crate::Error::Rpc {
                        detail: format!("{} failed to fetch nonce: {e}", $label),
                    })?;
            match ($call_expr).nonce(nonce).send().await {
                Ok(pending) => {
                    result =
                        pending.get_receipt().await.map_err(|e| $crate::Error::Rpc {
                            detail: format!("{} confirmation failed: {e}", $label),
                        });
                    break;
                }
                Err(e) => {
                    let msg = e.to_string();
                    let next_attempt = attempt.saturating_add(1);
                    if msg.contains("nonce too low") && next_attempt < MAX_RETRIES {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        continue;
                    }
                    result = Err($crate::Error::Rpc {
                        detail: format!("{} send failed: {e}", $label),
                    });
                    break;
                }
            }
        }
        result
    }};
}

/// Deploy a contract and return its address.
pub async fn deploy_contract<P: Provider>(
    provider: &P,
    bytecode: Bytes,
    label: &str,
) -> Result<Address> {
    deploy_contract_from(provider, bytecode, label, None).await
}

/// Deploy a contract, optionally fetching the sender's nonce explicitly.
///
/// Pass `sender` when mixing provider-managed and manually-nonce'd
/// transactions in one run: the cached nonce manager goes stale otherwise.
pub async fn deploy_contract_from<P: Provider>(
    provider: &P,
    bytecode: Bytes,
    label: &str,
    sender: Option<Address>,
) -> Result<Address> {
    use alloy::{
        network::TransactionBuilder,
        rpc::types::TransactionRequest,
    };

    let mut tx = TransactionRequest::default().with_deploy_code(bytecode);

    if let Some(addr) = sender {
        let nonce =
            provider
                .get_transaction_count(addr)
                .await
                .map_err(|e| Error::Rpc {
                    detail: format!("failed to fetch nonce for {label}: {e}"),
                })?;
        tx = tx.with_nonce(nonce);
    }

    let pending = provider
        .send_transaction(tx)
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("failed to send {label} deploy tx: {e}"),
        })?;

    let receipt = pending.get_receipt().await.map_err(|e| Error::Rpc {
        detail: format!("failed to get {label} deploy receipt: {e}"),
    })?;

    receipt.contract_address.ok_or_else(|| Error::Rpc {
        detail: format!("{label} deploy did not return contract address"),
    })
}

/// Deploy `bytecode` with ABI-encoded constructor args appended.
pub async fn deploy_with_ctor<P: Provider>(
    provider: &P,
    bytecode: &Bytes,
    constructor_args: &[u8],
    label: &str,
    sender: Option<Address>,
) -> Result<Address> {
    let mut deploy_bytecode = bytecode.to_vec();
    deploy_bytecode.extend_from_slice(constructor_args);
    deploy_contract_from(provider, Bytes::from(deploy_bytecode), label, sender).await
}

/// Deploy an ERC1967 proxy pointing at `implementation` with `init_data` (the
/// ABI-encoded initializer call).
pub async fn deploy_proxy<P: Provider>(
    provider: &P,
    proxy_bytecode: &Bytes,
    implementation: Address,
    init_data: Bytes,
    label: &str,
    sender: Option<Address>,
) -> Result<Address> {
    // ERC1967Proxy constructor: (address implementation, bytes memory _data)
    let constructor_args =
        alloy::sol_types::SolValue::abi_encode_params(&(implementation, init_data));
    deploy_with_ctor(provider, proxy_bytecode, &constructor_args, label, sender).await
}

/// Deploy an implementation from `artifacts` and put it behind a fresh
/// ERC1967 proxy whose init data is `init_call` ABI-encoded. Returns the
/// proxy address. The common shape of every UUPS deploy in the stack.
pub async fn deploy_behind_proxy<P: Provider, C: SolCall>(
    provider: &P,
    artifacts: &Artifacts,
    contract: &str,
    init_call: &C,
    sender: Option<Address>,
) -> Result<Address> {
    let implementation = deploy_contract_from(
        provider,
        artifacts.bytecode(contract)?,
        &format!("{contract} (impl)"),
        sender,
    )
    .await?;
    let proxy_bytecode = artifacts.bytecode("ERC1967Proxy")?;
    deploy_proxy(
        provider,
        &proxy_bytecode,
        implementation,
        init_call.abi_encode().into(),
        &format!("{contract} (proxy)"),
        sender,
    )
    .await
}

/// Upgrade a UUPS proxy: deploy `contract`'s current implementation from
/// `artifacts`, then call `upgradeToAndCall(new_impl, data)` on the proxy.
/// Returns the new implementation address. `data` is usually empty (state is
/// already initialized); pass a re-initializer call when the upgrade needs
/// one.
pub async fn upgrade_uups<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    proxy: Address,
    contract: &str,
    data: Bytes,
    sender: Option<Address>,
) -> Result<Address> {
    let new_impl = deploy_contract_from(
        provider,
        artifacts.bytecode(contract)?,
        &format!("{contract} (new impl)"),
        sender,
    )
    .await?;
    let proxied = IUUPSUpgradeable::new(proxy, provider);
    let call = proxied.upgradeToAndCall(new_impl, data);
    let pending =
        match sender {
            Some(addr) => {
                let nonce = provider.get_transaction_count(addr).await.map_err(|e| {
                    Error::Rpc {
                        detail: format!("{contract} upgrade failed to fetch nonce: {e}"),
                    }
                })?;
                call.nonce(nonce).send().await
            }
            None => call.send().await,
        }
        .map_err(|e| Error::Rpc {
            detail: format!("{contract} upgradeToAndCall send failed: {e}"),
        })?;
    pending.get_receipt().await.map_err(|e| Error::Rpc {
        detail: format!("{contract} upgradeToAndCall confirmation failed: {e}"),
    })?;
    Ok(new_impl)
}

/// Load a contract's creation bytecode, deploying and linking any external
/// libraries it references (the bb-generated UltraHonk verifiers link
/// `ZKTranscriptLib`). Mirrors what `forge` does automatically. For artifacts
/// with no `linkReferences` this behaves like [`Artifacts::bytecode_named`]
/// and sends nothing.
pub async fn load_linked_bytecode<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    file: &str,
    contract: &str,
    sender: Option<Address>,
) -> Result<Bytes> {
    let mut hex_str = artifacts.bytecode_hex(file, contract)?;

    // Resolve each linked library: deploy it (recursively linking its own
    // deps) then substitute its address into the placeholder slots.
    for (lib_file, libs) in artifacts.link_references(file, contract)? {
        let lib_stem = std::path::Path::new(&lib_file)
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| Error::Artifact {
                detail: format!("bad library file path {lib_file}"),
            })?;
        for (lib_name, refs) in libs.as_object().into_iter().flatten() {
            let lib_bytecode = Box::pin(load_linked_bytecode(
                provider, artifacts, lib_stem, lib_name, sender,
            ))
            .await?;
            let lib_addr = deploy_contract_from(
                provider,
                lib_bytecode,
                &format!("{lib_name} (library)"),
                sender,
            )
            .await?;
            let addr_hex = hex::encode(lib_addr.as_slice()); // 40 hex chars
            for r in refs.as_array().into_iter().flatten() {
                let start = r["start"]
                    .as_u64()
                    .and_then(|v| usize::try_from(v).ok())
                    .ok_or_else(|| Error::Artifact {
                        detail: format!("bad linkReference start for {lib_name}"),
                    })?;
                let length = r["length"]
                    .as_u64()
                    .and_then(|v| usize::try_from(v).ok())
                    .ok_or_else(|| Error::Artifact {
                    detail: format!("bad linkReference length for {lib_name}"),
                })?;
                // Byte offsets → hex-char offsets (×2).
                let begin = start.checked_mul(2);
                let end = start.checked_add(length).and_then(|v| v.checked_mul(2));
                let (begin, end) = begin.zip(end).ok_or_else(|| Error::Artifact {
                    detail: format!("linkReference offset overflow for {lib_name}"),
                })?;
                hex_str.replace_range(begin..end, &addr_hex);
            }
        }
    }

    let bytes = hex::decode(&hex_str).map_err(|e| Error::Artifact {
        detail: format!("invalid bytecode hex after linking {file}.{contract}: {e}"),
    })?;
    Ok(Bytes::from(bytes))
}
