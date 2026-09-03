//! Anvil integration tests: deploy the identity stack from the embedded
//! artifacts and read views back. Requires the `anvil` binary on PATH
//! (foundry).

use alloy::{
    primitives::{
        keccak256,
        Address,
        U256,
    },
    providers::{
        Provider,
        ProviderBuilder,
    },
};
use libid_contracts::{
    bindings::{
        ceremony::{
            CeremonyProofVerifier,
            GoogleJwtRoots,
            NotaryService,
        },
        identity::IdentityNames,
    },
    deploy::{
        deploy_behind_proxy,
        deploy_contract,
        upgrade_uups,
    },
    Artifacts,
};

fn test_provider() -> impl Provider + Clone {
    ProviderBuilder::new().connect_anvil_with_wallet()
}

async fn default_signer(provider: &impl Provider) -> Address {
    provider.get_accounts().await.expect("accounts")[0]
}

/// (a) The identity stack in the order `script/Deploy.s.sol` uses: the
/// Notary Service first, then the Proof Verifier, the naming system given a
/// keyspace and pointed at the Proof Verifier, and the Google JWT root list
/// pointed at the Notary Service — every one behind an ERC1967 proxy. Then the views
/// that prove the wiring took.
#[tokio::test]
async fn deploys_the_identity_stack_behind_proxies() {
    let provider = test_provider();
    let artifacts = Artifacts::embedded();
    let deployer = default_signer(&provider).await;
    let notary_key = Address::repeat_byte(0x11);
    let fee = U256::from(1_000);

    let notary_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "NotaryService",
        &NotaryService::initializeCall {
            owner_: deployer,
            notary_: notary_key,
            fee_: fee,
        },
        None,
    )
    .await
    .unwrap();

    let verifier_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "CeremonyProofVerifier",
        &CeremonyProofVerifier::initializeCall { owner_: deployer },
        None,
    )
    .await
    .unwrap();

    let names_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "IdentityNames",
        &IdentityNames::initializeCall { owner_: deployer },
        None,
    )
    .await
    .unwrap();

    let roots_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "GoogleJwtRoots",
        &GoogleJwtRoots::initializeCall {
            owner_: deployer,
            notary_: notary_proxy,
        },
        None,
    )
    .await
    .unwrap();

    // Wire the naming system: the Proof Verifier it dispatches through, and
    // a keyspace. The platform id is the platform's own bare name: libID
    // namespaces only its own strings.
    let names = IdentityNames::new(names_proxy, &provider);
    names
        .setProofVerifier(verifier_proxy)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    let platform_id = keccak256(b"github");
    names
        .setPlatform(
            platform_id,
            IdentityNames::Rules {
                maxLength: 39,
                stripLeadingAt: true,
                isEmail: false,
                allowUnderscore: false,
                allowHyphen: true,
            },
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // The Notary Service holds the key and the fee it was given.
    let notary = NotaryService::new(notary_proxy, &provider);
    assert!(notary.isTrustedNotary(notary_key).call().await.unwrap());
    assert_eq!(notary.fee().call().await.unwrap(), fee);

    // Nothing is registered against any version yet, and the Proof Verifier
    // says so rather than answering for a platform it cannot verify.
    let verifier = CeremonyProofVerifier::new(verifier_proxy, &provider);
    assert!(!verifier.verifiesPlatform(platform_id).call().await.unwrap());
    assert_eq!(
        verifier.verifierOf(platform_id, 1).call().await.unwrap(),
        Address::ZERO
    );

    assert_eq!(names.proofVerifier().call().await.unwrap(), verifier_proxy);
    // A platform that owns a keyspace and can verify nothing says so:
    // answering `address(0)` would tell the caller "nobody holds this name"
    // about a platform that is not wired yet.
    let unwired = names.resolveId(platform_id, "12345".into()).call().await;
    assert!(
        unwired.is_err(),
        "an unwired platform answered instead of reverting UnknownPlatform"
    );

    // The root list points at the Notary Service, quotes its fee, and starts
    // with both generations empty — so it wants a rotation before any Google
    // name can bind.
    let roots = GoogleJwtRoots::new(roots_proxy, &provider);
    assert_eq!(roots.notaryService().call().await.unwrap(), notary_proxy);
    assert_eq!(roots.quoteRotation().call().await.unwrap(), fee);
    assert!(roots.needsRotation().call().await.unwrap());
    let keys = roots.currentKeys().call().await.unwrap();
    assert_eq!(keys.current.observedAt, 0);
    assert!(keys.current.moduli.is_empty());
    assert_eq!(keys.previous.observedAt, 0);
    assert!(keys.previous.moduli.is_empty());
}

/// (b) The Notary Service lifecycle: deploy behind a proxy, add a second
/// trusted key with `setNotary`, change the fee with `setFee`, upgrade the
/// proxy to a freshly deployed implementation via `upgrade_uups`, and check
/// the rotated state survives the upgrade.
#[tokio::test]
async fn rotates_and_upgrades_the_notary_service() {
    let provider = test_provider();
    let artifacts = Artifacts::embedded();
    let deployer = default_signer(&provider).await;
    let first = Address::repeat_byte(0x11);
    let incoming = Address::repeat_byte(0x33);

    let notary_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "NotaryService",
        &NotaryService::initializeCall {
            owner_: deployer,
            notary_: first,
            fee_: U256::ZERO,
        },
        None,
    )
    .await
    .unwrap();

    let notary = NotaryService::new(notary_proxy, &provider);
    assert!(notary.isTrustedNotary(first).call().await.unwrap());
    assert!(!notary.isTrustedNotary(incoming).call().await.unwrap());
    assert_eq!(notary.fee().call().await.unwrap(), U256::ZERO);

    // Rotate: the incoming key is trusted before the outgoing one goes, so
    // attestations already made under `first` stay presentable meanwhile.
    notary
        .setNotary(incoming, true)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    notary
        .setNotary(first, false)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    notary
        .setFee(U256::from(7))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(!notary.isTrustedNotary(first).call().await.unwrap());
    assert!(notary.isTrustedNotary(incoming).call().await.unwrap());
    assert_eq!(notary.fee().call().await.unwrap(), U256::from(7));

    // Upgrade the proxy to a re-deployed implementation; state survives.
    let new_impl = upgrade_uups(
        &provider,
        &artifacts,
        notary_proxy,
        "NotaryService",
        Default::default(),
        None,
    )
    .await
    .unwrap();
    assert_ne!(new_impl, notary_proxy);
    assert!(!notary.isTrustedNotary(first).call().await.unwrap());
    assert!(notary.isTrustedNotary(incoming).call().await.unwrap());
    assert_eq!(notary.fee().call().await.unwrap(), U256::from(7));
    assert_eq!(notary.owner().call().await.unwrap(), deployer);
}

/// (c) The deterministic factory, from truly nothing: anvil is started
/// WITHOUT its predeployed CREATE2 deployer, so `ensure_factory` must
/// install it via the keyless presigned transaction (funding the one-time
/// signer first), then deploy the factory impl + proxy at their canonical
/// addresses. Then a Notary Service proxy goes through the factory at its
/// name-derived CREATE3 address.
#[tokio::test]
async fn bootstraps_the_deterministic_factory_and_deploys_through_it() {
    use alloy::{
        primitives::Bytes,
        sol_types::{
            SolCall,
            SolValue,
        },
    };
    use libid_contracts::{
        bindings::factory::LibidFactory,
        factory::{
            ensure_factory,
            factory_deploy,
            predict_address,
            predict_factory_address,
            CREATE2_DEPLOYER,
            FACTORY_GENESIS_ADMIN,
        },
    };

    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| {
            anvil.arg("--disable-default-create2-deployer")
        })
        .expect("anvil spawns");
    let artifacts = Artifacts::embedded();
    let deployer0 = default_signer(&provider).await;

    // Truly bare chain: no CREATE2 deployer.
    assert!(provider
        .get_code_at(CREATE2_DEPLOYER)
        .await
        .unwrap()
        .is_empty());

    let factory = ensure_factory(&provider, &artifacts).await.unwrap();
    assert_eq!(factory, predict_factory_address(&artifacts).unwrap());
    assert!(!provider.get_code_at(factory).await.unwrap().is_empty());

    // The instant the proxy exists it is owned by the baked genesis admin —
    // initialization was atomic with deployment.
    let factory_contract = LibidFactory::new(factory, &provider);
    assert_eq!(
        factory_contract.owner().call().await.unwrap(),
        FACTORY_GENESIS_ADMIN
    );

    // Rerun = read-only no-op.
    assert_eq!(
        ensure_factory(&provider, &artifacts).await.unwrap(),
        factory
    );

    // Hand ownership to the test signer: impersonate the genesis admin
    // (a placeholder address nobody holds a key for) through anvil.
    provider
        .raw_request::<_, serde_json::Value>(
            "anvil_setBalance".into(),
            (FACTORY_GENESIS_ADMIN, "0xde0b6b3a7640000"),
        )
        .await
        .unwrap();
    provider
        .raw_request::<_, serde_json::Value>(
            "anvil_impersonateAccount".into(),
            (FACTORY_GENESIS_ADMIN,),
        )
        .await
        .unwrap();
    let transfer = LibidFactory::transferOwnershipCall {
        newOwner: deployer0,
    }
    .abi_encode();
    provider
        .raw_request::<_, serde_json::Value>(
            "eth_sendTransaction".into(),
            (serde_json::json!({
                "from": FACTORY_GENESIS_ADMIN,
                "to": factory,
                "data": Bytes::from(transfer),
            }),),
        )
        .await
        .unwrap();
    factory_contract
        .acceptOwnership()
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert_eq!(factory_contract.owner().call().await.unwrap(), deployer0);

    // A Notary Service PROXY through the factory: impl via plain CREATE (its
    // address doesn't matter), proxy creation code = ERC1967Proxy ++ (impl,
    // initData).
    let notary_key = Address::repeat_byte(0x11);
    let notary_impl = deploy_contract(
        &provider,
        artifacts.bytecode("NotaryService").unwrap(),
        "NotaryService (impl)",
    )
    .await
    .unwrap();
    let init_data = NotaryService::initializeCall {
        owner_: deployer0,
        notary_: notary_key,
        fee_: U256::from(7),
    }
    .abi_encode();
    let mut creation_code = artifacts.bytecode("ERC1967Proxy").unwrap().to_vec();
    creation_code
        .extend_from_slice(&(notary_impl, Bytes::from(init_data)).abi_encode_params());

    let predicted = predict_address(factory, "libid.notary");
    let deployed =
        factory_deploy(&provider, factory, "libid.notary", creation_code.into())
            .await
            .unwrap();
    assert_eq!(deployed, predicted);

    let notary = NotaryService::new(deployed, &provider);
    assert!(notary.isTrustedNotary(notary_key).call().await.unwrap());
    assert_eq!(notary.fee().call().await.unwrap(), U256::from(7));
    assert_eq!(notary.owner().call().await.unwrap(), deployer0);
}
