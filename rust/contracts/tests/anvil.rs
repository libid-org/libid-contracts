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
/// wired via setPlatform + setVerifier, then views.
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
    // The keyspace and the proof format are configured separately: rules do
    // not vary by version, verifiers do.
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

    let version = names.INITIAL_VERSION().call().await.unwrap();
    names
        .setVerifier(platform_id, version, github_proxy, 3600)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    assert_eq!(
        names.verifierOf(platform_id, version).call().await.unwrap(),
        github_proxy
    );
    // The first version installed becomes the platform's default.
    assert_eq!(
        names.latestVersionOf(platform_id).call().await.unwrap(),
        version
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
