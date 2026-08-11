//! The Bank EIP-2535 diamond: deploy and facet-replace flows. Mirrors
//! `solidity/contracts/transfer/script/BankDiamondDeployer.sol`.

use alloy::{
    primitives::{
        Address,
        Bytes,
    },
    providers::Provider,
    sol_types::SolCall,
};

use crate::{
    artifacts::Artifacts,
    bindings::transfer::{
        BankInit,
        IDiamondCut,
    },
    deploy::{
        deploy_contract_from,
        deploy_with_ctor,
    },
    error::{
        Error,
        Result,
    },
};

/// Every facet cut into the Bank diamond after construction.
///
/// `DiamondCutFacet` is absent on purpose: the Diamond constructor wires that
/// one in itself. Deploy and upgrade both read this list, so a facet added
/// for one is not forgotten by the other.
pub const BANK_FACETS: &[&str] = &[
    "DiamondLoupeFacet",
    "OwnershipFacet",
    "AdminFacet",
    "VaultFacet",
    "TransferFacet",
];

/// `IDiamondCut.FacetCutAction` values, as their ABI underlying `uint8`.
pub mod facet_cut_action {
    /// Add new selectors.
    pub const ADD: u8 = 0;
    /// Replace the facet behind existing selectors.
    pub const REPLACE: u8 = 1;
    /// Remove selectors.
    pub const REMOVE: u8 = 2;
}

/// Deploy a fresh Bank as an EIP-2535 diamond and return the diamond address.
///
/// Deploys DiamondCutFacet, constructs `Diamond(owner, cutFacet)` (the ctor
/// auto-registers the diamondCut selector, so the cut below must NOT re-add
/// DiamondCutFacet), deploys the five remaining facets + `BankInit`, then one
/// `diamondCut` that adds every facet's selectors and delegatecalls
/// `BankInit.init(notary, backend, registry)` to seed the trusted-party
/// pointers, ERC-165 ids, templates, and prefixes.
///
/// `notary` is the NotaryRegistry address; `backend` and `registry` come from
/// the login deploy. All three must be nonzero or the init reverts.
pub async fn deploy_bank_diamond<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    owner: Address,
    notary_registry: Address,
    backend: Address,
    registry: Address,
) -> Result<Address> {
    // DiamondCutFacet — the one facet the Diamond ctor wires in itself.
    let cut_facet_addr = deploy_contract_from(
        provider,
        artifacts.bytecode("DiamondCutFacet")?,
        "DiamondCutFacet",
        None,
    )
    .await?;

    // Diamond(address owner, address diamondCutFacet).
    let ctor_args =
        alloy::sol_types::SolValue::abi_encode_params(&(owner, cut_facet_addr));
    let diamond_addr = deploy_with_ctor(
        provider,
        &artifacts.bytecode("Diamond")?,
        &ctor_args,
        "Diamond",
        None,
    )
    .await?;

    // Remaining facets: deploy each, then read its selectors from the
    // artifact. (DiamondCutFacet is intentionally absent — already cut in.)
    let cut = deploy_facet_cut(provider, artifacts, facet_cut_action::ADD, None).await?;

    // One-shot initializer, delegatecalled by diamondCut in diamond storage.
    let bank_init_addr =
        deploy_contract_from(provider, artifacts.bytecode("BankInit")?, "BankInit", None)
            .await?;

    let init_calldata: Bytes = BankInit::initCall {
        notary: notary_registry,
        backend,
        registry,
    }
    .abi_encode()
    .into();

    let diamond = IDiamondCut::new(diamond_addr, provider);
    diamond
        .diamondCut(cut, bank_init_addr, init_calldata)
        .send()
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("Diamond.diamondCut send failed: {e}"),
        })?
        .get_receipt()
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("Diamond.diamondCut confirmation failed: {e}"),
        })?;

    Ok(diamond_addr)
}

/// Upgrade a deployed Bank diamond: re-deploy every facet in [`BANK_FACETS`]
/// and REPLACE its selectors in one `diamondCut`. There is no implementation
/// slot to re-point — the diamond IS the storage, the facets are the code.
pub async fn replace_bank_facets<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    diamond: Address,
    sender: Option<Address>,
) -> Result<()> {
    let cut =
        deploy_facet_cut(provider, artifacts, facet_cut_action::REPLACE, sender).await?;
    let diamond = IDiamondCut::new(diamond, provider);
    let call = diamond.diamondCut(cut, Address::ZERO, Bytes::new());
    let pending =
        match sender {
            Some(addr) => {
                let nonce = provider.get_transaction_count(addr).await.map_err(|e| {
                    Error::Rpc {
                        detail: format!("Bank.diamondCut failed to fetch nonce: {e}"),
                    }
                })?;
                call.nonce(nonce).send().await
            }
            None => call.send().await,
        }
        .map_err(|e| Error::Rpc {
            detail: format!("Bank.diamondCut send failed: {e}"),
        })?;
    pending.get_receipt().await.map_err(|e| Error::Rpc {
        detail: format!("Bank.diamondCut confirmation failed: {e}"),
    })?;
    Ok(())
}

/// Deploy every facet in [`BANK_FACETS`] and build the corresponding
/// `FacetCut` array with `action` for each facet's full selector set.
async fn deploy_facet_cut<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    action: u8,
    sender: Option<Address>,
) -> Result<Vec<IDiamondCut::FacetCut>> {
    let mut cut = Vec::with_capacity(BANK_FACETS.len());
    for &name in BANK_FACETS {
        let facet_addr =
            deploy_contract_from(provider, artifacts.bytecode(name)?, name, sender)
                .await?;
        cut.push(IDiamondCut::FacetCut {
            facetAddress: facet_addr,
            action,
            functionSelectors: artifacts.facet_selectors(name)?,
        });
    }
    Ok(cut)
}
