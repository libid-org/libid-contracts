//! Anvil integration tests: deploy each stack from the embedded artifacts and
//! read a view back. Requires the `anvil` binary on PATH (foundry).

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
        identity::{
            GitHubIdentityVerifier,
            IdentityNames,
        },
        login::{
            IRegistryAdmin,
            Registry,
            WalletFactory,
        },
        notary::Notary,
        transfer::{
            Bank,
            IDiamondLoupe,
        },
    },
    deploy::{
        deploy_behind_proxy,
        deploy_contract,
        load_linked_bytecode,
        upgrade_uups,
    },
    diamond::{
        deploy_bank_diamond,
        BANK_FACETS,
    },
    Artifacts,
};

fn test_provider() -> impl Provider + Clone {
    ProviderBuilder::new().connect_anvil_with_wallet()
}

async fn default_signer(provider: &impl Provider) -> Address {
    provider.get_accounts().await.expect("accounts")[0]
}

/// (a) The login stack: Notary behind ERC1967 proxy first, then WebWallet
/// impl + WalletFactory behind proxy + Registry behind proxy pointing at the
/// Notary, wired together, then view calls.
#[tokio::test]
async fn deploys_the_login_stack_behind_proxies() {
    let provider = test_provider();
    let artifacts = Artifacts::embedded();
    let deployer = default_signer(&provider).await;
    let notary = Address::repeat_byte(0x11);
    let backend = Address::repeat_byte(0x22);

    let notary_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "Notary",
        &Notary::initializeCall {
            owner_: deployer,
            notary_: notary,
        },
        None,
    )
    .await
    .unwrap();

    let wallet_impl = deploy_contract(
        &provider,
        artifacts.bytecode("WebWallet").unwrap(),
        "WebWallet (impl)",
    )
    .await
    .unwrap();

    let factory_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "WalletFactory",
        &WalletFactory::initializeCall {
            owner_: deployer,
            walletImpl_: wallet_impl,
            registry_: Address::ZERO, // registry not yet deployed
        },
        None,
    )
    .await
    .unwrap();

    let registry_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "Registry",
        &IRegistryAdmin::initializeCall {
            _notaryContract: notary_proxy,
            _backend: backend,
            _walletFactory: factory_proxy,
            _owner: deployer,
        },
        None,
    )
    .await
    .unwrap();

    let factory = WalletFactory::new(factory_proxy, &provider);
    factory
        .setRegistry(registry_proxy)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let registry = Registry::new(registry_proxy, &provider);
    // notaryContract() is the pointer; notary() reads THROUGH it.
    assert_eq!(
        registry.notaryContract().call().await.unwrap(),
        notary_proxy
    );
    assert_eq!(registry.notary().call().await.unwrap(), notary);
    assert_eq!(registry.backend().call().await.unwrap(), backend);
    assert_eq!(
        registry.walletFactory().call().await.unwrap(),
        factory_proxy
    );
    let factory = WalletFactory::new(factory_proxy, &provider);
    assert_eq!(
        factory.latestImplementation().call().await.unwrap(),
        wallet_impl
    );
}

/// (b) The full Bank diamond via the diamond helper + BankInit, then loupe
/// and Bank views.
#[tokio::test]
async fn deploys_the_bank_diamond() {
    let provider = test_provider();
    let artifacts = Artifacts::embedded();
    let deployer = default_signer(&provider).await;

    let bank_addr = deploy_bank_diamond(
        &provider,
        &artifacts,
        deployer,
        Address::repeat_byte(0x11), // notary registry
        Address::repeat_byte(0x22), // backend
        Address::repeat_byte(0x33), // registry
    )
    .await
    .unwrap();

    // Loupe: DiamondCutFacet (ctor-wired) + the five BANK_FACETS.
    let loupe = IDiamondLoupe::new(bank_addr, &provider);
    let facets = loupe.facetAddresses().call().await.unwrap();
    assert_eq!(facets.len(), BANK_FACETS.len() + 1);

    // BankInit ran in diamond storage: the registry pointer is seeded and the
    // initialize templates exist for both platforms.
    let bank = Bank::new(bank_addr, &provider);
    assert_eq!(
        bank.registry().call().await.unwrap(),
        Address::repeat_byte(0x33)
    );
    assert!(!bank.paused().call().await.unwrap());
    // BankInit seeds 4 templates for api.x.com (2 recipient-full + 2
    // recipient-less) and 2 for api.github.com.
    assert_eq!(
        bank.platformTemplateCount("api.x.com".into())
            .call()
            .await
            .unwrap(),
        U256::from(4)
    );
    assert_eq!(
        bank.platformTemplateCount("api.github.com".into())
            .call()
            .await
            .unwrap(),
        U256::from(2)
    );
}

/// (c) IdentityNames behind proxy + GitHubIdentityVerifier behind proxy,
/// wired via setPlatform, then views.
#[tokio::test]
async fn deploys_the_identity_stack() {
    let provider = test_provider();
    let artifacts = Artifacts::embedded();
    let deployer = default_signer(&provider).await;

    let names_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "IdentityNames",
        &IdentityNames::initializeCall { owner_: deployer },
        None,
    )
    .await
    .unwrap();

    let notary_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "Notary",
        &Notary::initializeCall {
            owner_: deployer,
            notary_: Address::repeat_byte(0x11),
        },
        None,
    )
    .await
    .unwrap();

    let github_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "GitHubIdentityVerifier",
        &GitHubIdentityVerifier::initializeCall {
            owner_: deployer,
            notaryContract_: notary_proxy,
            backend_: Address::repeat_byte(0x22),
            shape_: GitHubIdentityVerifier::ResponseShape {
                endpoint: "/user".into(),
                handlePrefix: "\"login\":\"".into(),
                idPrefix: "\"id\":".into(),
                idSuffix: ",".into(),
            },
        },
        None,
    )
    .await
    .unwrap();

    let github = GitHubIdentityVerifier::new(github_proxy, &provider);
    assert_eq!(
        github.platformName().call().await.unwrap(),
        "api.github.com"
    );

    let platform_id = keccak256(b"libid.identity.platform.github");
    let names = IdentityNames::new(names_proxy, &provider);
    names
        .setPlatform(
            platform_id,
            github_proxy,
            3600,
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

    assert_eq!(
        names.verifierOf(platform_id).call().await.unwrap(),
        github_proxy
    );
    // An unbound id resolves to nobody rather than reverting.
    assert_eq!(
        names
            .resolveId(platform_id, "12345".into())
            .call()
            .await
            .unwrap(),
        Address::ZERO
    );
}

/// (d) XHonkVerifier via linked bytecode — exercises the recursive library
/// deploy + link-reference substitution (ZKTranscriptLib).
#[tokio::test]
async fn deploys_the_x_honk_verifier_via_library_linking() {
    // The generated UltraHonk verifiers exceed EIP-170 (the target chains
    // raise the limit); anvil must be told to accept them.
    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| {
            anvil.arg("--disable-code-size-limit")
        })
        .expect("anvil spawns");
    let artifacts = Artifacts::embedded();

    // The raw artifact must refuse the unlinked path…
    assert!(artifacts.bytecode("XHonkVerifier").is_err());

    // …and link + deploy through the linking path.
    let linked = load_linked_bytecode(
        &provider,
        &artifacts,
        "XHonkVerifier",
        "XHonkVerifier",
        None,
    )
    .await
    .unwrap();
    let addr = deploy_contract(&provider, linked, "XHonkVerifier")
        .await
        .unwrap();

    let code = provider.get_code_at(addr).await.unwrap();
    assert!(!code.is_empty(), "XHonkVerifier has no runtime code");

    // The Google OIDC circuit verifier links the same library under
    // Verifier.sol/HonkVerifier — cover the file != contract path too.
    let linked = artifacts
        .linked_bytecode(&provider, "Verifier", "HonkVerifier", None)
        .await
        .unwrap();
    let addr = deploy_contract(&provider, linked, "HonkVerifier")
        .await
        .unwrap();
    assert!(!provider.get_code_at(addr).await.unwrap().is_empty());
}

/// (e) The Notary lifecycle: deploy behind a proxy, rotate the signer with
/// `setNotary`, upgrade the proxy to a freshly deployed implementation via
/// `upgrade_uups`, and check the rotated state survives the upgrade.
#[tokio::test]
async fn rotates_and_upgrades_the_notary() {
    let provider = test_provider();
    let artifacts = Artifacts::embedded();
    let deployer = default_signer(&provider).await;
    let first = Address::repeat_byte(0x11);
    let rotated = Address::repeat_byte(0x33);

    let notary_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "Notary",
        &Notary::initializeCall {
            owner_: deployer,
            notary_: first,
        },
        None,
    )
    .await
    .unwrap();

    let notary = Notary::new(notary_proxy, &provider);
    assert_eq!(notary.notary().call().await.unwrap(), first);

    // A garbage proof answers false rather than reverting.
    assert!(!notary
        .verify(keccak256(b"digest"), vec![0u8; 65].into())
        .call()
        .await
        .unwrap());

    // Rotate the signer.
    notary
        .setNotary(rotated)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert_eq!(notary.notary().call().await.unwrap(), rotated);

    // Upgrade the proxy to a re-deployed implementation; state survives.
    let new_impl = upgrade_uups(
        &provider,
        &artifacts,
        notary_proxy,
        "Notary",
        Default::default(),
        None,
    )
    .await
    .unwrap();
    assert_ne!(new_impl, notary_proxy);
    assert_eq!(notary.notary().call().await.unwrap(), rotated);
}

/// (f) The deterministic factory, from truly nothing: anvil is started
/// WITHOUT its predeployed CREATE2 deployer, so `ensure_factory` must
/// install it via the keyless presigned transaction (funding the one-time
/// signer first), then deploy the factory impl + proxy at their canonical
/// addresses. Then a Notary proxy goes through the factory at its
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

    // A Notary PROXY through the factory: impl via plain CREATE (its address
    // doesn't matter), proxy creation code = ERC1967Proxy ++ (impl, initData).
    let notary_signer = Address::repeat_byte(0x11);
    let notary_impl = deploy_contract(
        &provider,
        artifacts.bytecode("Notary").unwrap(),
        "Notary (impl)",
    )
    .await
    .unwrap();
    let init_data = Notary::initializeCall {
        owner_: deployer0,
        notary_: notary_signer,
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

    let notary = Notary::new(deployed, &provider);
    assert_eq!(notary.notary().call().await.unwrap(), notary_signer);
}
