/// Crate error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A vendored artifact is missing, unparsable, or malformed.
    #[error("artifact error: {detail}")]
    Artifact {
        /// What went wrong.
        detail: String,
    },
    /// An RPC send, receipt wait, or read failed.
    #[error("rpc error: {detail}")]
    Rpc {
        /// What went wrong.
        detail: String,
    },
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;
