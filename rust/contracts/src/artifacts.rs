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
    primitives::Bytes,
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
/// artifact lives at `<file>.sol/<contract>.json`. Keep in sync with
/// `scripts/vendor-artifacts.sh`.
pub const COVERED: &[(&str, &str)] = &[
    // ceremony
    ("NotaryService", "NotaryService"),
    ("CeremonyProofVerifier", "CeremonyProofVerifier"),
    ("ERC1967Proxy", "ERC1967Proxy"),
    ("GoogleJwtRoots", "GoogleJwtRoots"),
    // identity
    ("IdentityNames", "IdentityNames"),
    // factory
    ("LibidFactory", "LibidFactory"),
    ("WTIA9", "WTIA9"),
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
    /// (a bb-generated `Verifier.sol` holding `HonkVerifier`, say).
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
    /// automatically. Nothing covered today links a library; the UltraHonk
    /// verifiers the ceremony circuits bring link `ZKTranscriptLib`, and this
    /// is the path they will deploy through. For artifacts with no link
    /// references this behaves like [`Self::bytecode_named`] (no transaction
    /// is sent).
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
    /// Only the hex is checked here so a future artifact with link
    /// placeholders still passes; linking is the anvil tests' business.
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

    /// Contracts without link references decode straight to bytes — which is
    /// every covered contract today, so this doubles as the check that none of
    /// them silently grew a library dependency the vendor script must follow.
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
}
