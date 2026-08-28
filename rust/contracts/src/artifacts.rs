//! Access to the compiled forge artifacts the crate ships.
//!
//! The default source is [`Artifacts::embedded`]: the pruned artifact JSONs
//! vendored by `scripts/vendor-artifacts.sh` into `artifacts/` are compiled
//! into the binary, so deployment has zero filesystem dependencies at runtime.
//! [`Artifacts::from_dir`] reads the same `<File>.sol/<Name>.json` layout from
//! disk instead — it accepts a raw forge `out/` directory too, since the crate
//! only reads fields forge emits.

use std::{
    collections::BTreeMap,
    path::PathBuf,
};

use alloy::{
    hex,
    primitives::{
        Bytes,
        FixedBytes,
    },
    providers::Provider,
};
use include_dir::{
    include_dir,
    Dir,
};

use crate::error::{
    Error,
    Result,
};

/// The vendored artifacts, embedded at compile time.
static EMBEDDED: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/artifacts");

/// Every deployable contract the crate covers, as `(file, contract)` — the
/// artifact lives at `<file>.sol/<contract>.json`. Interfaces (`IBank`) are
/// vendored for their `methodIdentifiers` but carry no bytecode, so they are
/// not listed here. Keep in sync with `scripts/vendor-artifacts.sh`.
pub const COVERED: &[(&str, &str)] = &[
    // login
    ("Registry", "Registry"),
    ("Notary", "Notary"),
    ("WalletFactory", "WalletFactory"),
    ("WebWallet", "WebWallet"),
    ("ERC1967Proxy", "ERC1967Proxy"),
    ("XZkVerifier", "XZkVerifier"),
    ("XHonkVerifier", "XHonkVerifier"),
    // oidc — the Google OIDC circuit verifier is generated into `Verifier.sol`
    // under the contract name `HonkVerifier`
    ("Verifier", "HonkVerifier"),
    ("GoogleOidcVerifier", "GoogleOidcVerifier"),
    // transfer (bank diamond)
    ("Diamond", "Diamond"),
    ("DiamondCutFacet", "DiamondCutFacet"),
    ("DiamondLoupeFacet", "DiamondLoupeFacet"),
    ("OwnershipFacet", "OwnershipFacet"),
    ("AdminFacet", "AdminFacet"),
    ("VaultFacet", "VaultFacet"),
    ("TransferFacet", "TransferFacet"),
    ("BankInit", "BankInit"),
    ("MockERC20", "MockERC20"),
    ("WTIA9", "WTIA9"),
    // identity
    ("IdentityNames", "IdentityNames"),
    ("HandleResolver", "HandleResolver"),
    ("IdentityJwksRoots", "IdentityJwksRoots"),
    // factory
    ("LibidFactory", "LibidFactory"),
];

enum Source {
    Embedded,
    Dir(PathBuf),
}

/// A source of compiled contract artifacts.
pub struct Artifacts {
    source: Source,
}

impl Artifacts {
    /// The artifacts vendored into the crate. The default, filesystem-free
    /// path.
    pub const fn embedded() -> Self {
        Self {
            source: Source::Embedded,
        }
    }

    /// Artifacts read from a directory laid out as `<File>.sol/<Name>.json`
    /// (a forge `out/` directory qualifies).
    pub fn from_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            source: Source::Dir(dir.into()),
        }
    }

    /// The raw artifact JSON for `out/<file>.sol/<contract>.json`.
    pub fn raw(&self, file: &str, contract: &str) -> Result<serde_json::Value> {
        let rel = format!("{file}.sol/{contract}.json");
        let contents = match &self.source {
            Source::Embedded => EMBEDDED
                .get_file(&rel)
                .and_then(|f| f.contents_utf8())
                .map(str::to_owned)
                .ok_or_else(|| Error::Artifact {
                    detail: format!("no embedded artifact {rel}"),
                })?,
            Source::Dir(dir) => {
                let path = dir.join(&rel);
                std::fs::read_to_string(&path).map_err(|e| Error::Artifact {
                    detail: format!("failed to read artifact {}: {e}", path.display()),
                })?
            }
        };
        serde_json::from_str(&contents).map_err(|e| Error::Artifact {
            detail: format!("failed to parse artifact {rel}: {e}"),
        })
    }

    /// Creation bytecode of a contract whose `.sol` file name matches the
    /// contract name. Fails on artifacts with unresolved link references —
    /// deploy those through [`Self::linked_bytecode`].
    pub fn bytecode(&self, contract: &str) -> Result<Bytes> {
        self.bytecode_named(contract, contract)
    }

    /// Creation bytecode where the source file and contract names differ
    /// (`Verifier.sol` → `HonkVerifier`).
    pub fn bytecode_named(&self, file: &str, contract: &str) -> Result<Bytes> {
        let hex_str = self.bytecode_hex(file, contract)?;
        if hex_str.contains("__$") {
            return Err(Error::Artifact {
                detail: format!(
                    "{file}.sol:{contract} has unresolved link references; deploy it \
                     via linked_bytecode"
                ),
            });
        }
        let bytes = hex::decode(&hex_str).map_err(|e| Error::Artifact {
            detail: format!("invalid bytecode hex for {file}.sol:{contract}: {e}"),
        })?;
        Ok(Bytes::from(bytes))
    }

    /// Creation bytecode with every external library it references deployed
    /// (recursively) through `provider` and linked in. Mirrors what forge does
    /// automatically: the generated UltraHonk verifiers link `ZKTranscriptLib`.
    /// For artifacts with no link references this behaves like
    /// [`Self::bytecode_named`] (no transaction is sent).
    ///
    /// `sender` opts into explicit nonce management (see
    /// [`deploy_contract_from`](crate::deploy::deploy_contract_from)).
    pub async fn linked_bytecode<P: Provider>(
        &self,
        provider: &P,
        file: &str,
        contract: &str,
        sender: Option<alloy::primitives::Address>,
    ) -> Result<Bytes> {
        crate::deploy::load_linked_bytecode(provider, self, file, contract, sender).await
    }

    /// The artifact's `methodIdentifiers`: `"sig(args)" -> 4-byte selector`
    /// (8 hex chars, no `0x`).
    pub fn method_identifiers(&self, contract: &str) -> Result<BTreeMap<String, String>> {
        let json = self.raw(contract, contract)?;
        let methods =
            json["methodIdentifiers"]
                .as_object()
                .ok_or_else(|| Error::Artifact {
                    detail: format!(
                        "no methodIdentifiers in {contract}.sol/{contract}.json"
                    ),
                })?;
        methods
            .iter()
            .map(|(sig, value)| {
                let sel = value.as_str().ok_or_else(|| Error::Artifact {
                    detail: format!("non-string selector for {sig} in {contract}"),
                })?;
                Ok((sig.clone(), sel.to_owned()))
            })
            .collect()
    }

    /// All external function selectors of a facet, decoded from its
    /// `methodIdentifiers`. Mirrors `BankDiamondDeployer._selectors`.
    pub fn facet_selectors(&self, contract: &str) -> Result<Vec<FixedBytes<4>>> {
        let methods = self.method_identifiers(contract)?;
        let mut selectors = Vec::with_capacity(methods.len());
        for (sig, hex_sel) in &methods {
            let bytes = hex::decode(hex_sel).map_err(|e| Error::Artifact {
                detail: format!("invalid selector hex for {sig}: {e}"),
            })?;
            let arr: [u8; 4] =
                bytes.as_slice().try_into().map_err(|_| Error::Artifact {
                    detail: format!(
                        "selector for {sig} is {} bytes, expected 4",
                        bytes.len()
                    ),
                })?;
            selectors.push(FixedBytes::<4>::from(arr));
        }
        Ok(selectors)
    }

    /// The raw `bytecode.object` hex (no `0x`), link placeholders intact.
    pub(crate) fn bytecode_hex(&self, file: &str, contract: &str) -> Result<String> {
        let json = self.raw(file, contract)?;
        let raw = json["bytecode"]["object"]
            .as_str()
            .ok_or_else(|| Error::Artifact {
                detail: format!("no bytecode.object in {file}.sol/{contract}.json"),
            })?;
        Ok(raw.strip_prefix("0x").unwrap_or(raw).to_owned())
    }

    /// The artifact's `bytecode.linkReferences` object, empty when absent.
    pub(crate) fn link_references(
        &self,
        file: &str,
        contract: &str,
    ) -> Result<serde_json::Map<String, serde_json::Value>> {
        let json = self.raw(file, contract)?;
        Ok(json["bytecode"]["linkReferences"]
            .as_object()
            .cloned()
            .unwrap_or_default())
    }
}

impl Default for Artifacts {
    fn default() -> Self {
        Self::embedded()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every covered contract's creation bytecode is present and non-empty.
    /// The Honk verifiers carry link placeholders, so only the hex is checked
    /// here; linking is exercised by the anvil tests.
    #[test]
    fn every_covered_contract_has_bytecode() {
        let artifacts = Artifacts::embedded();
        for &(file, contract) in COVERED {
            let hex_str = artifacts
                .bytecode_hex(file, contract)
                .unwrap_or_else(|e| panic!("{file}.sol:{contract}: {e}"));
            assert!(
                !hex_str.is_empty(),
                "{file}.sol:{contract} has empty bytecode"
            );
        }
    }

    /// Contracts without link references decode straight to bytes.
    #[test]
    fn unlinked_contracts_decode() {
        let artifacts = Artifacts::embedded();
        for &(file, contract) in COVERED {
            if artifacts
                .link_references(file, contract)
                .unwrap()
                .is_empty()
            {
                let bytecode = artifacts
                    .bytecode_named(file, contract)
                    .unwrap_or_else(|e| panic!("{file}.sol:{contract}: {e}"));
                assert!(!bytecode.is_empty());
            }
        }
    }

    /// The Honk verifiers link `ZKTranscriptLib`, and the library artifact
    /// they resolve against is vendored alongside them.
    #[test]
    fn honk_verifiers_link_the_transcript_lib() {
        let artifacts = Artifacts::embedded();
        for (file, contract) in [
            ("XHonkVerifier", "XHonkVerifier"),
            ("Verifier", "HonkVerifier"),
        ] {
            let refs = artifacts.link_references(file, contract).unwrap();
            assert!(!refs.is_empty(), "{contract} should carry link references");
            for (lib_path, libs) in &refs {
                let stem = std::path::Path::new(lib_path)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap();
                for lib_name in libs.as_object().unwrap().keys() {
                    let lib_hex = artifacts.bytecode_hex(stem, lib_name).unwrap();
                    assert!(!lib_hex.is_empty(), "{lib_name} library missing");
                }
            }
        }
    }

    /// Facet selector extraction: every Bank facet exposes selectors, they are
    /// 4 bytes each, and none repeats across facets (a diamondCut would revert
    /// on a duplicate).
    #[test]
    fn facet_selectors_extract_and_are_disjoint() {
        let artifacts = Artifacts::embedded();
        let mut all = std::collections::BTreeSet::new();
        for facet in [
            "DiamondCutFacet",
            "DiamondLoupeFacet",
            "OwnershipFacet",
            "AdminFacet",
            "VaultFacet",
            "TransferFacet",
        ] {
            let selectors = artifacts.facet_selectors(facet).unwrap();
            assert!(!selectors.is_empty(), "{facet} has no selectors");
            for sel in selectors {
                assert!(all.insert(sel), "duplicate selector {sel} in {facet}");
            }
        }
        // diamondCut(FacetCut[],address,bytes) — the one selector the Diamond
        // constructor wires in itself.
        let cut = artifacts.method_identifiers("DiamondCutFacet").unwrap();
        assert!(cut.keys().any(|sig| sig.starts_with("diamondCut(")));
    }
}
